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
// and the original transaction we can look them up by.
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
		if err := rows.Scan(&r.Email, &r.Plan, &r.OrigTxn); err != nil {
			return nil, err
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
		r := &repairs[i]
		if r.OrigTxn == "" {
			r.Status = "skipped"
			r.Note = "no Apple original_transaction_id on record"
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

		if dryRun {
			continue
		}
		if _, uErr := db.Exec(
			`UPDATE users SET subscription_expiry = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`,
			r.NewExpiry, r.Email); uErr != nil {
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

	applied, errors, skipped := 0, 0, 0
	for _, r := range repairs {
		switch {
		case r.Applied:
			applied++
		case r.Status == "error":
			errors++
		case r.Status == "skipped":
			skipped++
		}
	}
	log.Printf("✅ [expiry sync] candidates=%d applied=%d errors=%d skipped=%d",
		len(repairs), applied, errors, skipped)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"dry_run":    !req.Apply,
		"candidates": len(repairs),
		"applied":    applied,
		"errors":     errors,
		"skipped":    skipped,
		"repairs":    repairs,
	})
}

// entitlementNotExpiredStrict is the shape entitlement checks should move to
// once expiries are populated: a NULL expiry only means "forever" for lifetime
// plans. Kept unused-by-default deliberately — flipping it before the backfill
// runs would drop paying monthly subscribers to free.
func entitlementNotExpiredStrict(expiry sql.NullString, plan string) bool {
	if !expiry.Valid || expiry.String == "" {
		return plan == "lifetime"
	}
	return entitlementNotExpired(expiry)
}
