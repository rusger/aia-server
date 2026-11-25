package main

// Repairs users.subscription_expiry from Apple's authoritative subscription
// status.
//
// WHY: 23 monthly and 3 yearly paid accounts carry no expiry date at all. The
// column is only written when a client-side purchase sync happens to include
// one, and most Apple purchases arrived without it — purchase_history has an
// empty expiry_date for all but one of them. Everything downstream then reads
// wrong: entitlementNotExpired() treats a NULL expiry as "never expires"
// (correct for lifetime, wrong for a lapsed monthly), and the active/expired
// split in the admin stats is fiction.
//
// The fix asks Apple rather than guessing: getAllSubscriptionStatuses returns
// the current expiresDate for an originalTransactionId, including renewals we
// never saw. Derivation from purchase_date + period was rejected — it silently
// invents entitlement for people who cancelled.
//
// Runs on demand (POST /api/admin/expiry-sync), dry-run by default.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// appleSubscriptionStatusResponse is the shape of
// GET /inApps/v1/subscriptions/{originalTransactionId}.
type appleSubscriptionStatusResponse struct {
	Data []struct {
		SubscriptionGroupIdentifier string `json:"subscriptionGroupIdentifier"`
		LastTransactions            []struct {
			OriginalTransactionID string `json:"originalTransactionId"`
			Status                int    `json:"status"` // 1 active, 2 expired, 3 retry, 4 grace, 5 revoked
			SignedTransactionInfo string `json:"signedTransactionInfo"`
		} `json:"lastTransactions"`
	} `json:"data"`
}

// expiryRepair is one account's proposed change, for the dry-run report.
type expiryRepair struct {
	Email     string `json:"email"`
	Plan      string `json:"plan"`
	OrigTxn   string `json:"original_transaction_id"`
	LookupBy  string `json:"lookup_by,omitempty"` // "original_transaction_id" | "transaction_id" (A203)
	Kind      string `json:"kind,omitempty"`      // "missing_expiry" | "lapsed_renewed" (A203)
	NewExpiry string `json:"new_expiry,omitempty"`
	Status    string `json:"status"`
	Applied   bool   `json:"applied"`
	Note      string `json:"note,omitempty"`
}

// appleStatusLabel turns Apple's numeric subscription status into a word.
func appleStatusLabel(status int) string {
	switch status {
	case 1:
		return "active"
	case 2:
		return "expired"
	case 3:
		return "billing_retry"
	case 4:
		return "grace_period"
	case 5:
		return "revoked"
	}
	return fmt.Sprintf("unknown(%d)", status)
}

// accountsMissingExpiry lists paid, non-lifetime accounts with no expiry date
// and the Apple transaction id we can look them up by (original_transaction_id, else transaction_id — A203).
func accountsMissingExpiry() ([]expiryRepair, error) {
	rows, err := db.Query(`
		SELECT u.email,
		       u.subscription_length,
		       COALESCE((SELECT p.original_transaction_id
		                 FROM purchase_history p
		                 WHERE p.email = u.email
		                   AND p.store = 'apple'
		                   AND p.original_transaction_id IS NOT NULL
		                   AND p.original_transaction_id <> ''
		                 ORDER BY p.id DESC LIMIT 1), ''),
		       COALESCE((SELECT p.transaction_id
		                 FROM purchase_history p
		                 WHERE p.email = u.email
		                   AND p.store = 'apple'
		                   AND p.transaction_id IS NOT NULL
		                   AND p.transaction_id <> ''
		                 ORDER BY p.id DESC LIMIT 1), '')
		FROM users u
		WHERE u.subscription_type = 'paid'
		  AND (u.subscription_expiry IS NULL OR u.subscription_expiry = '')
		  AND u.subscription_length <> 'lifetime'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []expiryRepair
	for rows.Next() {
		var r expiryRepair
		var txn string
		if err := rows.Scan(&r.Email, &r.Plan, &r.OrigTxn, &txn); err != nil {
			return nil, err
		}
		// A203 (25.11.2026): 21 of 25 accounts had a transaction_id but no original_transaction_id on record.
		// Apple's Get All Subscription Statuses accepts any transaction id of the customer, so fall back to it.
		switch {
		case r.OrigTxn != "":
			r.LookupBy = "original_transaction_id"
		case txn != "":
			r.OrigTxn = txn
			r.LookupBy = "transaction_id"
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// fetchAppleExpiry asks Apple for the current expiry of one subscription.
func fetchAppleExpiry(base, jwtToken, origTxn string) (time.Time, int, error) {
	req, err := http.NewRequest("GET", base+"/inApps/v1/subscriptions/"+origTxn, nil)
	if err != nil {
		return time.Time{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, 0, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var parsed appleSubscriptionStatusResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return time.Time{}, 0, fmt.Errorf("parse: %w", err)
	}

	// Take the newest expiry across the group: an upgrade (monthly → yearly)
	// leaves the old transaction present but expired.
	var newest time.Time
	status := 0
	for _, group := range parsed.Data {
		for _, txn := range group.LastTransactions {
			payload, vErr := verifyAppleJWS(txn.SignedTransactionInfo)
			if vErr != nil {
				log.Printf("⚠️ [expiry sync] signature check failed for %s: %v", origTxn, vErr)
				continue
			}
			var info appleTransactionInfo
			if json.Unmarshal(payload, &info) != nil || info.ExpiresDate == 0 {
				continue
			}
			if when := time.UnixMilli(info.ExpiresDate); when.After(newest) {
				newest = when
				status = txn.Status
			}
		}
	}
	if newest.IsZero() {
		return time.Time{}, 0, fmt.Errorf("no expiry in Apple response")
	}
	return newest, status, nil
}

// syncAppleExpiries repairs (or, in dry-run, reports) missing expiry dates.
//
// dryRun defaults on at the call site: this writes entitlement state, so the
// numbers get eyeballed before anything changes.
// accountsLapsedButRenewed lists accounts whose stored window has run out although Apple sent a payment
// notification (Production) after that date and no end/refund after the payment — people who pay but read as
// free because DID_RENEW never reached users (A203: two such on 25.11.2026). Looked up by their newest Apple id.
// Production = the shared rule of renewals.go (appleProductionNotifications): environment <> 'Sandbox', rows
// written before the column existed count as production. Empty ids never join (a stray row cannot seed a candidate).
func accountsLapsedButRenewed() ([]expiryRepair, error) {
	rows, err := db.Query(`
		WITH m AS (
			SELECT DISTINCT p.email, a.original_transaction_id AS ot
			FROM purchase_history p
			JOIN apple_notifications a ON COALESCE(a.environment, '') <> 'Sandbox'
			 AND (a.original_transaction_id = p.transaction_id
			      OR a.original_transaction_id = p.original_transaction_id
			      OR a.transaction_id = p.transaction_id)
			WHERE p.store = 'apple' AND p.email NOT LIKE 'apple:%'
			  AND COALESCE(p.transaction_id, '') <> '' AND COALESCE(a.original_transaction_id, '') <> ''
		), x AS (
			SELECT u.email, u.subscription_length AS plan, u.subscription_expiry AS exp,
			       (SELECT MAX(a.created_at) FROM apple_notifications a
			         WHERE COALESCE(a.environment, '') <> 'Sandbox'
			           AND a.notification_type IN ('DID_RENEW','SUBSCRIBED','OFFER_REDEEMED','DID_CHANGE_RENEWAL_PREF')
			           AND a.original_transaction_id IN (SELECT ot FROM m WHERE m.email = u.email)) AS lastpay,
			       (SELECT MAX(a.created_at) FROM apple_notifications a
			         WHERE COALESCE(a.environment, '') <> 'Sandbox'
			           AND a.notification_type IN ('EXPIRED','GRACE_PERIOD_EXPIRED','REFUND','REVOKE')
			           AND a.original_transaction_id IN (SELECT ot FROM m WHERE m.email = u.email)) AS lastend,
			       (SELECT MAX(ot) FROM m WHERE m.email = u.email) AS ot
			FROM users u
			WHERE COALESCE(u.subscription_expiry, '') <> ''
			  AND u.subscription_length <> 'lifetime'
			  AND substr(u.subscription_expiry, 1, 19) < strftime('%Y-%m-%d %H:%M:%S', 'now')
		)
		SELECT email, plan, ot FROM x
		WHERE lastpay IS NOT NULL
		  AND substr(lastpay, 1, 19) > substr(exp, 1, 19)
		  AND (lastend IS NULL OR lastend < lastpay)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []expiryRepair
	for rows.Next() {
		var r expiryRepair
		if err := rows.Scan(&r.Email, &r.Plan, &r.OrigTxn); err != nil {
			return nil, err
		}
		r.Kind, r.LookupBy = "lapsed_renewed", "original_transaction_id"
		out = append(out, r)
	}
	return out, rows.Err()
}

// expiryRepairWrite says what an apply may write for one Apple answer: missing expiries take the signed date
// whatever the status (an expired date is the truth that ends "paid forever"); a lapsed-but-renewed account is
// re-opened only when Apple says active (status 1) with a date in the future.
func expiryRepairWrite(kind string, status int, expiry, now time.Time) (writeExpiry, setPaid bool) {
	switch kind {
	case "lapsed_renewed":
		ok := status == 1 && expiry.After(now)
		return ok, ok
	default:
		return true, false
	}
}

func syncAppleExpiries(sandbox, dryRun bool) ([]expiryRepair, error) {
	if appleRootPool == nil {
		return nil, fmt.Errorf("apple root CA not loaded; cannot verify payloads")
	}
	cfg, err := loadAppStoreAPIConfig()
	if err != nil {
		return nil, err
	}
	jwtToken, err := mintAppStoreAPIToken(cfg)
	if err != nil {
		return nil, err
	}
	base := appStoreAPIBaseURL(sandbox)

	repairs, err := accountsMissingExpiry()
	if err != nil {
		return nil, err
	}
	for i := range repairs {
		repairs[i].Kind = "missing_expiry"
	}
	lapsed, err := accountsLapsedButRenewed()
	if err != nil {
		return nil, err
	}
	repairs = append(repairs, lapsed...)

	for i := range repairs {
		r := &repairs[i]
		if r.OrigTxn == "" {
			r.Status = "skipped"
			r.Note = "no Apple transaction id on record"
			continue
		}
		expiry, status, fErr := fetchAppleExpiry(base, jwtToken, r.OrigTxn)
		if fErr != nil {
			r.Status = "error"
			r.Note = fErr.Error()
			continue
		}
		r.Status = appleStatusLabel(status)
		r.NewExpiry = expiry.UTC().Format("2006-01-02 15:04:05")

		writeExpiry, setPaid := expiryRepairWrite(r.Kind, status, expiry, time.Now())
		if !writeExpiry {
			r.Note = "not applied: Apple does not confirm an active paid period"
		}
		if dryRun || !writeExpiry {
			continue
		}
		q := `UPDATE users SET subscription_expiry = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`
		if setPaid {
			q = `UPDATE users SET subscription_type = 'paid', subscription_expiry = ?, last_payment_method = 'apple',
				updated_at = CURRENT_TIMESTAMP WHERE email = ?`
		}
		if _, uErr := db.Exec(q, r.NewExpiry, r.Email); uErr != nil {
			r.Status = "error"
			r.Note = uErr.Error()
			continue
		}
		r.Applied = true
		log.Printf("🗓 [expiry sync] %s → %s (%s)", r.Email, r.NewExpiry, appleStatusLabel(status))
	}
	return repairs, nil
}

// POST /api/admin/expiry-sync — {"admin_secret": "...", "apply": false}
func expirySyncHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		AdminSecret string `json:"admin_secret"`
		Sandbox     bool   `json:"sandbox"`
		Apply       bool   `json:"apply"` // absent = dry run
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid body"})
		return
	}
	if ADMIN_SECRET_KEY == "" || req.AdminSecret != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "unauthorized"})
		return
	}

	log.Printf("🗓 [expiry sync] starting (sandbox=%v apply=%v)", req.Sandbox, req.Apply)
	repairs, err := syncAppleExpiries(req.Sandbox, !req.Apply)
	if err != nil {
		log.Printf("❌ [expiry sync] %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	t := summarizeExpiryRepairs(repairs)
	recordExpirySyncRun(!req.Apply, t)
	log.Printf("✅ [expiry sync] candidates=%d applied=%d reopened=%d not_confirmed=%d errors=%d skipped=%d",
		t.Candidates, t.Applied, t.Reopened, t.NotConfirmed, t.Errors, t.Skipped)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"dry_run":       !req.Apply,
		"candidates":    t.Candidates,
		"applied":       t.Applied,
		"reopened":      t.Reopened,
		"not_confirmed": t.NotConfirmed,
		"errors":        t.Errors,
		"skipped":       t.Skipped,
		"repairs":       repairs,
	})
}

// entitlementNotExpiredStrict is the subscription entitlement check (A203 д,
// 25.11.2026): a NULL/empty expiry only means "forever" for lifetime plans.
// Switched on after the nightly Apple sync filled every paid monthly/yearly
// row (first run 25.11: 23 applied, 0 paid non-lifetime rows left without a date).
func entitlementNotExpiredStrict(expiry sql.NullString, plan string) bool {
	if expiryMissingForPlan(expiry, plan) {
		return false
	}
	return entitlementNotExpired(expiry)
}

// expiryMissingForPlan: a subscription row with no window on a non-lifetime
// plan — fail closed, the nightly sync / S2S hook fills the date from Apple.
func expiryMissingForPlan(expiry sql.NullString, plan string) bool {
	return (!expiry.Valid || expiry.String == "") && plan != "lifetime"
}

// ---------------------------------------------------------------------------
// Nightly run (A203, owner 25.11.2026: «такие случаи автоматически грамотно оформлять… чтоб не руками каждый
// раз»). Applies only what Apple answered with a verified signed transaction; a lapsed account is re-opened
// only on an active status (expiryRepairWrite). Every run leaves one row in apple_expiry_sync_runs for the
// weekly report. APPLE_EXPIRY_SYNC_NIGHTLY=0 switches the loop off.
// ---------------------------------------------------------------------------

const (
	appleExpirySyncFirstRun = 20 * time.Minute
	appleExpirySyncInterval = 24 * time.Hour
)

func migrateAppleExpirySyncRuns() {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS apple_expiry_sync_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ran_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		dry_run INTEGER NOT NULL,
		candidates INTEGER NOT NULL,
		applied INTEGER NOT NULL,
		errors INTEGER NOT NULL,
		skipped INTEGER NOT NULL,
		not_confirmed INTEGER NOT NULL,
		reopened INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		log.Printf("⚠️ [expiry sync] runs table: %v", err)
	}
}

type expirySyncTotals struct {
	Candidates, Applied, Errors, Skipped, NotConfirmed, Reopened int
}

func summarizeExpiryRepairs(repairs []expiryRepair) expirySyncTotals {
	t := expirySyncTotals{Candidates: len(repairs)}
	for _, r := range repairs {
		switch {
		case r.Applied:
			t.Applied++
			if r.Kind == "lapsed_renewed" {
				t.Reopened++
			}
		case r.Status == "error":
			t.Errors++
		case r.Status == "skipped":
			t.Skipped++
		case r.Note != "":
			t.NotConfirmed++
		}
	}
	return t
}

func recordExpirySyncRun(dryRun bool, t expirySyncTotals) {
	if _, err := db.Exec(`INSERT INTO apple_expiry_sync_runs
		(dry_run, candidates, applied, errors, skipped, not_confirmed, reopened) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		dryRun, t.Candidates, t.Applied, t.Errors, t.Skipped, t.NotConfirmed, t.Reopened); err != nil {
		log.Printf("⚠️ [expiry sync] run row: %v", err)
	}
}

func startAppleExpirySyncLoop() {
	if getEnv("APPLE_EXPIRY_SYNC_NIGHTLY", "1") == "0" {
		log.Printf("ℹ️ [expiry sync] nightly loop disabled (APPLE_EXPIRY_SYNC_NIGHTLY=0)")
		return
	}
	if _, err := loadAppStoreAPIConfig(); err != nil {
		log.Printf("ℹ️ [expiry sync] nightly loop disabled: %v", err)
		return
	}
	log.Printf("ℹ️ [expiry sync] nightly loop started: first run in %v, then every %v", appleExpirySyncFirstRun, appleExpirySyncInterval)
	go func() {
		time.Sleep(appleExpirySyncFirstRun)
		for {
			repairs, err := syncAppleExpiries(false, false)
			if err != nil {
				log.Printf("❌ [expiry sync] nightly: %v", err)
			} else {
				t := summarizeExpiryRepairs(repairs)
				recordExpirySyncRun(false, t)
				log.Printf("✅ [expiry sync] nightly: candidates=%d applied=%d reopened=%d not_confirmed=%d errors=%d skipped=%d",
					t.Candidates, t.Applied, t.Reopened, t.NotConfirmed, t.Errors, t.Skipped)
			}
			time.Sleep(appleExpirySyncInterval)
		}
	}()
}
