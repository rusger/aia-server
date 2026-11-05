package main

// Former subscribers get ZERO paid-model requests (owner policy 2026-11-05).
//
// A physical device (identity_key, so a reinstall does not escape) that EVER
// held a store subscription — trial or paid — and has no access now (trial
// ended unpaid, not renewed, REFUND, REVOKE) is refused on every route that
// reaches OpenAI / Azure Speech / Groq / OpenAI realtime: 402
// code=former_subscriber, before any upstream call. Devices that never
// subscribed keep the normal free tier — that is the conversion funnel.
//
// Not a subscription here: admin gifts (store=admin), the server-side 7-day
// trial (trial_grants), and Apple Sandbox/TestFlight purchases — App Review
// buys a sandbox subscription that expires, and cutting the reviewer off
// would reject the release.

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	formerSubscriberCode     = "former_subscriber"
	formerSubscriberCacheTTL = 60 * time.Second
)

// formerSubscriberStores are purchase_history.store values that mean the user
// subscribed through a store (or paid directly). store=admin is a gift.
var formerSubscriberStores = []string{"apple", "google", "yookassa"}

// formerSubscriberRoutes lists every route the gate wraps — the routes whose
// handlers reach a paid model (traced 2026-11-05 from the router through the
// handlers to the upstream calls). The router test pins it.
var formerSubscriberRoutes = []string{
	"/api/chatgpt",
	"/api/chatgpt-stream",
	"/api/ai/arbiter",
	"/api/speech/stt",
	"/api/speech/tts",
	"/api/tts",
	"/api/presenter/jobs",
	"/api/voice/ticket",
	"/api/radio/call/{id}/intro",
	"/api/radio/call/{id}/question",
}

type formerSubscriberCacheEntry struct {
	blocked bool
	at      time.Time
}

var (
	formerSubscriberCacheMu sync.Mutex
	formerSubscriberCache   = map[string]formerSubscriberCacheEntry{}
	formerSubscriberNow     = time.Now
)

// formerSubscriberGate wraps a jwtAuthMiddleware-protected handler.
func formerSubscriberGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value("claims").(*JWTClaims)
		if ok && claims != nil && isFormerSubscriber(claims.Email, claims.DeviceID) {
			log.Printf("🚫 former subscriber: no paid-model call device=%s email=%s path=%s",
				claims.DeviceID, claims.Email, r.URL.Path)
			writeFormerSubscriber(w)
			return
		}
		next(w, r)
	}
}

func writeFormerSubscriber(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"code":    formerSubscriberCode,
		"reason":  formerSubscriberCode, // speech endpoints of app ≤2.1.25 read "reason"
		"tier":    "former",
		"error":   "Subscription ended. Renew to continue.",
	})
}

// isFormerSubscriber: the caller's own entitlement is read uncached, so a
// purchase or restore lifts the block on the very next request; the identity
// walk is cached for formerSubscriberCacheTTL. Any DB error fails OPEN.
func isFormerSubscriber(email, deviceID string) bool {
	if db == nil {
		return false
	}
	if paid, super := userEntitlement(email, deviceID); paid || super {
		return false
	}
	key := email + "\x00" + deviceID
	now := formerSubscriberNow()
	formerSubscriberCacheMu.Lock()
	if e, ok := formerSubscriberCache[key]; ok && now.Sub(e.at) < formerSubscriberCacheTTL {
		formerSubscriberCacheMu.Unlock()
		return e.blocked
	}
	formerSubscriberCacheMu.Unlock()

	blocked := computeFormerSubscriber(email, deviceID)

	formerSubscriberCacheMu.Lock()
	if len(formerSubscriberCache) > 20000 {
		formerSubscriberCache = map[string]formerSubscriberCacheEntry{}
	}
	formerSubscriberCache[key] = formerSubscriberCacheEntry{blocked: blocked, at: now}
	formerSubscriberCacheMu.Unlock()
	return blocked
}

func computeFormerSubscriber(email, deviceID string) bool {
	installs := identityInstalls(deviceID)
	accounts := identityAccounts(email, installs)
	for _, acc := range accounts {
		if accountHasAccess(acc) {
			return false
		}
	}
	return everSubscribed(accounts, installs)
}

// identityInstalls: the install itself plus every install sharing its
// identity_key. Deliberately NOT the churn bucket of quotaDeviceIDs — that
// groups by model+network and could cut off an unrelated person.
func identityInstalls(deviceID string) []string {
	if deviceID == "" {
		return nil
	}
	ids := []string{deviceID}
	di, ok := lookupIdentity(deviceID)
	if !ok {
		return ids
	}
	rows, err := db.Query(`SELECT device_id FROM device_identity WHERE identity_key = ?`, di.key)
	if err != nil {
		log.Printf("⚠️ former-subscriber installs(%s key=%s): %v", deviceID, di.key, err)
		return ids
	}
	defer rows.Close()
	seen := map[string]bool{deviceID: true}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			log.Printf("⚠️ former-subscriber installs scan(%s): %v", deviceID, err)
			continue
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("⚠️ former-subscriber installs rows(%s key=%s): %v", deviceID, di.key, err)
	}
	return ids
}

// identityAccounts: the JWT email, each install's anonymous device account,
// and every account any of these installs signed in to.
func identityAccounts(email string, installs []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	add(email)
	if len(installs) == 0 {
		return out
	}
	ph, args := sqlIn(installs)
	for _, a := range installs {
		add(a + "@device.astrolytix.app")
	}
	for _, q := range []string{
		`SELECT email FROM devices WHERE device_id IN (` + ph + `)`,
		`SELECT email FROM users WHERE current_device_id IN (` + ph + `)`,
	} {
		rows, err := db.Query(q, args...)
		if err != nil {
			log.Printf("⚠️ former-subscriber accounts(%v): %s: %v", installs, q, err)
			continue
		}
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				log.Printf("⚠️ former-subscriber accounts scan(%v): %v", installs, err)
				continue
			}
			add(a)
		}
		if err := rows.Err(); err != nil {
			log.Printf("⚠️ former-subscriber accounts rows(%v): %v", installs, err)
		}
		rows.Close()
	}
	return out
}

// accountHasAccess mirrors userEntitlement for one account, plus an active
// referral premium. Unknown accounts have no access.
func accountHasAccess(account string) bool {
	var subType string
	var expiry sql.NullString
	var isSuper int
	if err := db.QueryRow(
		`SELECT subscription_type, subscription_expiry, COALESCE(is_super,0) FROM users WHERE email = ?`,
		account).Scan(&subType, &expiry, &isSuper); err != nil {
		return false
	}
	if isSuper == 1 || (subType == "paid" && entitlementNotExpired(expiry)) {
		return true
	}
	var ref sql.NullString
	if err := db.QueryRow(`SELECT referral_premium_until FROM users WHERE email = ?`, account).
		Scan(&ref); err == nil && ref.Valid && ref.String != "" && entitlementNotExpired(ref) {
		return true
	}
	return false
}

// everSubscribed: a production store purchase on any account or install.
func everSubscribed(accounts, installs []string) bool {
	keys := append(append([]string{}, accounts...), installs...)
	if len(keys) == 0 {
		return false
	}
	ph, args := sqlIn(keys)
	sph, sargs := sqlIn(formerSubscriberStores)
	rows, err := db.Query(
		`SELECT store, COALESCE(transaction_id,''), COALESCE(original_transaction_id,''),
		        COALESCE(purchase_token,'')
		 FROM purchase_history
		 WHERE (email IN (`+ph+`) OR device_id IN (`+ph+`)) AND store IN (`+sph+`)`,
		append(append(append([]interface{}{}, args...), args...), sargs...)...)
	if err != nil {
		// Fail open (a DB hiccup must not lock paying-adjacent users out), but loudly.
		log.Printf("⚠️ former-subscriber purchases(accounts=%v installs=%v): %v", accounts, installs, err)
		return false
	}
	type row struct{ store, txn, otxn, token string }
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.store, &r.txn, &r.otxn, &r.token); err != nil {
			log.Printf("⚠️ former-subscriber purchases scan(%v): %v", accounts, err)
			continue
		}
		found = append(found, r)
	}
	if err := rows.Err(); err != nil {
		log.Printf("⚠️ former-subscriber purchases rows(%v): %v", accounts, err)
	}
	rows.Close()
	for _, r := range found {
		if r.store != "apple" || !appleSandboxPurchase(r.txn, r.otxn, r.token) {
			return true
		}
	}
	return false
}

// appleSandboxPurchase: the JWS says environment=Sandbox, or the transaction
// has a Sandbox App Store notification and no non-Sandbox one (same
// COALESCE(environment,”) <> 'Sandbox' convention as renewals.go).
func appleSandboxPurchase(txn, otxn, token string) bool {
	if env := jwsEnvironment(token); env != "" {
		return env == "Sandbox"
	}
	var sandbox, live int
	if err := db.QueryRow(
		`SELECT COALESCE(SUM(COALESCE(environment,'') = 'Sandbox'),0),
		        COALESCE(SUM(COALESCE(environment,'') <> 'Sandbox'),0)
		 FROM apple_notifications
		 WHERE (transaction_id <> '' AND transaction_id IN (?, ?))
		    OR (original_transaction_id <> '' AND original_transaction_id IN (?, ?))`,
		txn, otxn, txn, otxn).Scan(&sandbox, &live); err != nil {
		log.Printf("⚠️ former-subscriber sandbox check(txn=%s otxn=%s): %v", txn, otxn, err)
		return false // counted as production: the purchase row itself is the stronger fact
	}
	return sandbox > 0 && live == 0
}

// jwsEnvironment reads "environment" from a StoreKit 2 JWS payload without
// verifying it (verification happened when the purchase was recorded).
func jwsEnvironment(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var p struct {
		Environment string `json:"environment"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return ""
	}
	return p.Environment
}

func sqlIn(vals []string) (string, []interface{}) {
	args := make([]interface{}, len(vals))
	for i, v := range vals {
		args[i] = v
	}
	return strings.TrimSuffix(strings.Repeat("?,", len(vals)), ","), args
}
