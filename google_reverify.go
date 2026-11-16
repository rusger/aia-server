package main

// Google Play subscription re-verification + RTDN watchdog (A105, owner 16.11.2026).
//
// Android premium is decided only by users.subscription_expiry, which
// recordPurchase sets at purchase time. Renewals used to rely on RTDN
// (Pub/Sub push → google.go), but that handler only logs, and the Pub/Sub
// subscription itself was auto-deleted by Google after 31 days without
// deliveries (~29.10.2026). So the server now polls Play for every Google
// subscription whose window is about to end (or ended recently) and moves the
// window FORWARD when Play reports the subscription renewed. A watchdog warns
// the owner when RTDN goes silent while events that must produce RTDN happen.

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	googleReverifyAhead    = 48 * time.Hour     // check windows ending within the next 48 h …
	googleReverifyBehind   = 7 * 24 * time.Hour // … or ended within the last 7 days
	googleReverifyInterval = 6 * time.Hour
	googleReverifyFirstRun = 3 * time.Minute
	googleReverifyPause    = 500 * time.Millisecond // between Play API calls

	rtdnWatchdogInterval = time.Hour
	rtdnWatchdogFirstRun = 10 * time.Minute
	rtdnSilenceWindow    = 3 * 24 * time.Hour
	rtdnPurchaseGrace    = time.Hour // a purchase this fresh may still be in flight
	rtdnWatchdogTag      = "[rtdn-watchdog]"
	googleReverifyLogTag = "[google-reverify]"
)

// googleReverifyMu serialises re-verification runs (the 6 h loop and the
// RTDN-triggered single-token checks) so two writers never race on one row.
var googleReverifyMu sync.Mutex

// googleRenewalsSeen records when the re-verifier found a renewal (window
// advanced). Each renewal must have produced an RTDN, so it is a watchdog signal.
var googleRenewalsSeen struct {
	sync.Mutex
	times []time.Time
}

// maskToken keeps a purchase token recognisable in logs without leaking it.
func maskToken(tok string) string {
	if len(tok) <= 10 {
		return "***"
	}
	return tok[:6] + "…" + tok[len(tok)-4:]
}

// googleReverifyDue reports whether a current window expiry falls into the
// re-verification window (now−7d, now+48h].
func googleReverifyDue(expiry, now time.Time) bool {
	return expiry.After(now.Add(-googleReverifyBehind)) && !expiry.After(now.Add(googleReverifyAhead))
}

// googlePlayStateActive reports whether a Play subscription state grants
// access: payment received (1) or free trial (2) with an expiry in the future.
// Pending (0) / deferred (3), missing or past expiry → not active.
func googlePlayStateActive(paymentState int, expiry *time.Time, now time.Time) bool {
	if expiry == nil || !expiry.After(now) {
		return false
	}
	return paymentState == 1 || paymentState == 2
}

// applyGoogleVerifiedExpiry moves users.subscription_expiry forward to a
// Play-verified expiry. Never shortens a later window, never touches a
// lifetime account (subscriptionWindowUpdate rules, same as recordPurchase and
// Apple S2S). Returns whether the window advanced.
func applyGoogleVerifiedExpiry(email, productID string, expiry *time.Time, now time.Time) (bool, error) {
	if expiry == nil {
		return false, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var curLength string
	var curExpiry sql.NullString
	if err := tx.QueryRow(`SELECT COALESCE(subscription_length, ''), subscription_expiry FROM users WHERE email = ?`, email).
		Scan(&curLength, &curExpiry); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("current window lookup: %v", err)
	}
	newLength, newExpiry, advance := subscriptionWindowUpdate(curLength, curExpiry, productToLength(productID), expiry, now)
	if !advance {
		return false, nil
	}
	if _, err := tx.Exec(`UPDATE users SET subscription_type = 'paid', subscription_length = ?,
		subscription_expiry = ?, last_payment_method = 'google', updated_at = CURRENT_TIMESTAMP
		WHERE email = ?`, newLength, newExpiry, email); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

type googleSubCandidate struct {
	email, productID, token, curLength string
	curExpiry                          sql.NullString
}

// googleReverifyCandidates returns, per user, the newest Google subscription
// purchase token whose current window falls into the re-verification window.
// If token != "", only rows for that purchase token are considered (RTDN path),
// regardless of the window.
func googleReverifyCandidates(now time.Time, token string) ([]googleSubCandidate, error) {
	q := `SELECT p.email, p.product_id, p.purchase_token,
			COALESCE(u.subscription_length, ''), u.subscription_expiry
		FROM purchase_history p
		JOIN users u ON u.email = p.email
		WHERE p.store = 'google' AND p.purchase_token IS NOT NULL AND p.purchase_token != ''
		  AND p.id = (SELECT MAX(p2.id) FROM purchase_history p2
		              WHERE p2.email = p.email AND p2.store = 'google'
		                AND p2.purchase_token IS NOT NULL AND p2.purchase_token != '')`
	args := []interface{}{}
	if token != "" {
		q += ` AND p.purchase_token = ?`
		args = append(args, token)
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []googleSubCandidate
	for rows.Next() {
		var c googleSubCandidate
		if err := rows.Scan(&c.email, &c.productID, &c.token, &c.curLength, &c.curExpiry); err != nil {
			return nil, err
		}
		if productToLength(c.productID) == "lifetime" || c.curLength == "lifetime" {
			continue
		}
		if token == "" {
			if !c.curExpiry.Valid || strings.TrimSpace(c.curExpiry.String) == "" {
				continue
			}
			cur, perr := parseDBTime(c.curExpiry.String)
			if perr != nil {
				log.Printf("⚠️ %s unparseable expiry for %s (raw=%q) — skipped", googleReverifyLogTag, c.email, c.curExpiry.String)
				continue
			}
			if !googleReverifyDue(cur, now) {
				continue
			}
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// reverifyGoogleSubscriptions polls Play for due subscriptions (token == "")
// or for one purchase token (RTDN-triggered). Fail-closed: any Play error
// leaves the row untouched.
func reverifyGoogleSubscriptions(token string) {
	googleReverifyMu.Lock()
	defer googleReverifyMu.Unlock()

	now := time.Now()
	cands, err := googleReverifyCandidates(now, token)
	if err != nil {
		log.Printf("⚠️ %s candidate query failed: %v", googleReverifyLogTag, err)
		return
	}
	if token == "" {
		log.Printf("🔄 %s run: %d subscription(s) due", googleReverifyLogTag, len(cands))
	}
	for i, c := range cands {
		if i > 0 {
			time.Sleep(googleReverifyPause)
		}
		state, expiry, err := queryGooglePlaySubscriptionState(c.productID, c.token)
		if err != nil {
			log.Printf("⚠️ %s %s token=%s Play error, unchanged: %v", googleReverifyLogTag, c.email, maskToken(c.token), err)
			continue
		}
		if !googlePlayStateActive(state, expiry, time.Now()) {
			log.Printf("%s %s token=%s state=%d expiry=%v current=%q → not active, unchanged",
				googleReverifyLogTag, c.email, maskToken(c.token), state, expiry, c.curExpiry.String)
			continue
		}
		advanced, err := applyGoogleVerifiedExpiry(c.email, c.productID, expiry, time.Now())
		if err != nil {
			log.Printf("⚠️ %s %s token=%s update failed: %v", googleReverifyLogTag, c.email, maskToken(c.token), err)
			continue
		}
		if advanced {
			googleRenewalsSeen.Lock()
			googleRenewalsSeen.times = append(googleRenewalsSeen.times, time.Now())
			googleRenewalsSeen.Unlock()
			log.Printf("✅ %s %s token=%s state=%d expiry %q → %v (extended)",
				googleReverifyLogTag, c.email, maskToken(c.token), state, c.curExpiry.String, *expiry)
		} else {
			log.Printf("%s %s token=%s state=%d expiry=%v current=%q → kept (not later)",
				googleReverifyLogTag, c.email, maskToken(c.token), state, *expiry, c.curExpiry.String)
		}
	}
}

// startGoogleSubscriptionReverifier launches the 6 h loop and the RTDN
// watchdog. No-op without Play credentials (nothing to poll).
func startGoogleSubscriptionReverifier() {
	if GOOGLE_PLAY_CREDENTIALS_FILE == "" {
		log.Printf("ℹ️ %s disabled (no Play credentials)", googleReverifyLogTag)
		return
	}
	log.Printf("ℹ️ %s started: every %v, window −%v/+%v; %s every %v",
		googleReverifyLogTag, googleReverifyInterval, googleReverifyBehind, googleReverifyAhead, rtdnWatchdogTag, rtdnWatchdogInterval)
	go func() {
		time.Sleep(googleReverifyFirstRun)
		for {
			reverifyGoogleSubscriptions("")
			time.Sleep(googleReverifyInterval)
		}
	}()
	go func() {
		time.Sleep(rtdnWatchdogFirstRun)
		for {
			checkRTDNSilence(time.Now())
			time.Sleep(rtdnWatchdogInterval)
		}
	}()
}

// googleRTDNTriggersReverify: RECOVERED(1), RENEWED(2), RESTARTED(7).
func googleRTDNTriggersReverify(notificationType int) bool {
	return notificationType == 1 || notificationType == 2 || notificationType == 7
}

// ---------------------------------------------------------------------------
// RTDN watchdog
// ---------------------------------------------------------------------------

var rtdnWatchdogLastAlertDay string // UTC yyyy-mm-dd of the last alert (in memory)

// rtdnAlertSend is the alert transport (swapped in tests).
var rtdnAlertSend = sendPlainEmail

// rtdnSilent reports whether RTDN looks dead: there were events that must
// have produced RTDN (signals > 0) but no notification row since `since`.
func rtdnSilent(signals int, lastNotif time.Time, since time.Time) bool {
	return signals > 0 && lastNotif.Before(since)
}

// checkRTDNSilence returns whether RTDN looked silent and whether an alert
// was sent on this call (at most one per UTC day).
func checkRTDNSilence(now time.Time) (silent, alerted bool) {
	ensureGoogleNotificationsTable()
	since := now.Add(-rtdnSilenceWindow)
	sinceStr := since.UTC().Format("2006-01-02 15:04:05")
	graceStr := now.Add(-rtdnPurchaseGrace).UTC().Format("2006-01-02 15:04:05")

	var purchases int
	if err := db.QueryRow(`SELECT COUNT(*) FROM purchase_history
		WHERE store = 'google' AND created_at >= ? AND created_at <= ?`, sinceStr, graceStr).Scan(&purchases); err != nil {
		log.Printf("⚠️ %s purchase count failed: %v", rtdnWatchdogTag, err)
		return false, false
	}
	googleRenewalsSeen.Lock()
	renewals := 0
	kept := googleRenewalsSeen.times[:0]
	for _, t := range googleRenewalsSeen.times {
		if t.After(since) {
			kept = append(kept, t)
			if t.Before(now.Add(-rtdnPurchaseGrace)) {
				renewals++
			}
		}
	}
	googleRenewalsSeen.times = kept
	googleRenewalsSeen.Unlock()

	var lastStr sql.NullString
	if err := db.QueryRow(`SELECT MAX(created_at) FROM google_notifications`).Scan(&lastStr); err != nil {
		log.Printf("⚠️ %s last notification lookup failed: %v", rtdnWatchdogTag, err)
		return false, false
	}
	var lastNotif time.Time
	if lastStr.Valid && lastStr.String != "" {
		if t, err := parseDBTime(lastStr.String); err == nil {
			lastNotif = t
		} else {
			log.Printf("⚠️ %s unparseable last notification time %q", rtdnWatchdogTag, lastStr.String)
		}
	}

	if !rtdnSilent(purchases+renewals, lastNotif, since) {
		return false, false
	}
	last := "never"
	if !lastNotif.IsZero() {
		last = lastNotif.UTC().Format("2006-01-02 15:04 UTC")
	}
	log.Printf("⚠️ WARN %s Google RTDN silent: %d purchase(s) + %d renewal(s) in last 3 days, last google_notifications row: %s",
		rtdnWatchdogTag, purchases, renewals, last)

	day := now.UTC().Format("2006-01-02")
	if rtdnWatchdogLastAlertDay == day {
		return true, false
	}
	rtdnWatchdogLastAlertDay = day
	subject := "Astrolytix: Google Play RTDN молчит"
	body := fmt.Sprintf(`Сторож RTDN (сервер astrolog-api).

За последние 3 суток: Google-покупок %d, продлений (найдено перепроверкой) %d,
а уведомлений Google Play (google_notifications) нет. Последнее: %s.

Проверьте Pub/Sub-подписку RTDN в Google Cloud (её могли автоудалить за неактивность)
и push-эндпоинт https://astrolytix.com/api/google/notifications.
Продления подписок сервер всё равно подтягивает перепроверкой Play раз в 6 ч.
Письмо — не чаще раза в сутки.`, purchases, renewals, last)
	for _, to := range ADMIN_EMAILS {
		if err := rtdnAlertSend(to, subject, body); err != nil {
			log.Printf("⚠️ %s alert email failed: %v", rtdnWatchdogTag, err)
		} else {
			log.Printf("📧 %s alert emailed to owner", rtdnWatchdogTag)
		}
	}
	return true, true
}
