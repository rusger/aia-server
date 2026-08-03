package main

// Device identity — the anchor for the free trial and the daily AI quota.
//
// WHY THIS FILE EXISTS
//
// A client device_id is composite: "<hardware>|<install-uuid>". The install
// UUID lives in secure storage and is regenerated on every reinstall, so
// before this layer BOTH abuse counters keyed on device_id reset for free:
//
//   * withinTrialWindow() was anchored on users.created_at, and a reinstall
//     creates a brand-new anonymous account → a fresh 7-day trial at 80
//     AI calls/day, repeatable forever;
//   * the daily quota counted `WHERE device_id = ?` → a fresh 15/day bucket.
//
// The hardware half cannot carry the identity on its own: on Android the
// client sends Build.ID (a ROM build number). In production a single build id
// like "QKR1.191246.002" is shared by 324 unrelated accounts, so grouping by
// it alone would throttle strangers together.
//
// So identity is resolved in two tiers:
//
//   strong — the app sent X-Device-Fingerprint: a value that genuinely
//            survives reinstall (Android Settings.Secure.ANDROID_ID, iOS
//            identifierForVendor). Stored hashed. All installs that present
//            the same fingerprint are one identity: one trial, one quota.
//
//   weak   — old or patched clients that send no fingerprint. We fall back to
//            (build id, IP /24), which is NOT an identity on its own, so it is
//            used only when that pair shows install churn: identityChurnMin
//            distinct installs inside identityChurnWindowDays. A household
//            with two phones never trips it; a reinstall farm trips it in
//            days. Churn also merges installs that rotate a spoofed
//            fingerprint, so faking the header buys nothing.
//
// The goal is normalization, not punishment: a heavy reinstaller keeps the app
// and the free tier, they just stop getting a new trial and a new daily
// allowance with every wipe.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strings"
)

const (
	identityStrong = "strong" // fingerprint that survives reinstall
	identityWeak   = "weak"   // (build id, IP /24) fallback
	identityLegacy = "legacy" // backfilled from users.created_at at migration

	// identityChurnMin installs from one (build id, IP /24) inside
	// identityChurnWindowDays mark that pair as a reinstall farm: two
	// reinstalls still get a fresh trial each, the third stops. Far below the
	// 15 installs the known farm produced in 5 weeks.
	identityChurnMin        = 3
	identityChurnWindowDays = 30

	// coexistenceDays undoes that verdict when the installs turn out to belong
	// to different people. Measured on real data: a reinstall farm REPLACES
	// itself — each install goes silent for good when the next one appears, so
	// no two of its installs were ever alive together for more than a day.
	// Two people with the same phone model behind the same router use their
	// installs side by side for weeks. Overlapping activity is therefore the
	// signal that separates them, and it is checked before any trial is
	// withheld.
	coexistenceDays = 7

	trialWindowDays = 7 // must match the trial the client advertises
)

// identityHashSalt keeps raw hardware fingerprints out of the database. It is
// obfuscation, not a security boundary — a stable default is fine.
func identityHashSalt() string {
	if s := os.Getenv("IDENTITY_SALT"); s != "" {
		return s
	}
	return "astrolytix-identity-v1"
}

func hashIdentity(raw string) string {
	sum := sha256.Sum256([]byte(identityHashSalt() + "|" + raw))
	return hex.EncodeToString(sum[:16])
}

// hwPrefix returns the hardware half of a composite device_id (everything
// before the install UUID).
func hwPrefix(deviceID string) string {
	if i := strings.Index(deviceID, "|"); i > 0 {
		return deviceID[:i]
	}
	return deviceID
}

// ipBucket collapses an address to its /24 (IPv4) or /48 (IPv6) so that a
// changing last octet — normal on mobile networks — does not look like a new
// location. Unparseable input is returned as-is; empty stays empty.
func ipBucket(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	v6 := parsed.To16()
	return fmt.Sprintf("%x:%x:%x::/48",
		int(v6[0])<<8|int(v6[1]),
		int(v6[2])<<8|int(v6[3]),
		int(v6[4])<<8|int(v6[5]))
}

// initIdentityTables creates the identity tables and backfills them from the
// existing users table. Idempotent; safe to run on every boot.
func initIdentityTables() error {
	if _, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS device_identity (
		device_id    TEXT PRIMARY KEY,
		identity_key TEXT NOT NULL,
		kind         TEXT NOT NULL,
		hw_prefix    TEXT NOT NULL DEFAULT '',
		ip_bucket    TEXT NOT NULL DEFAULT '',
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_identity_key ON device_identity(identity_key);
	CREATE INDEX IF NOT EXISTS idx_identity_bucket ON device_identity(hw_prefix, ip_bucket, created_at);
	`); err != nil {
		return fmt.Errorf("failed to create device_identity: %v", err)
	}

	// One row per identity that has been given its 7-day trial. Absence of a
	// row means "no trial" — which is why the backfill below matters.
	if _, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS trial_grants (
		identity_key TEXT PRIMARY KEY,
		granted_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		bucket       TEXT NOT NULL DEFAULT '',
		revoked      INTEGER NOT NULL DEFAULT 0,
		note         TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_trial_bucket ON trial_grants(bucket, granted_at);
	`); err != nil {
		return fmt.Errorf("failed to create trial_grants: %v", err)
	}

	backfillIdentities()
	return nil
}

// backfillIdentities gives every account that existed before this layer its
// own identity, keyed on its own device_id, with the trial clock set to the
// account's created_at. Existing users therefore keep exactly the trial they
// have today — the new rules only bite on installs created from here on.
func backfillIdentities() {
	res, err := db.Exec(`
		INSERT OR IGNORE INTO device_identity
			(device_id, identity_key, kind, hw_prefix, ip_bucket, created_at, last_seen)
		SELECT current_device_id,
		       'legacy:' || current_device_id,
		       'legacy',
		       CASE WHEN instr(current_device_id, '|') > 0
		            THEN substr(current_device_id, 1, instr(current_device_id, '|') - 1)
		            ELSE current_device_id END,
		       '',
		       MIN(created_at),
		       MIN(created_at)
		FROM users
		WHERE current_device_id IS NOT NULL AND current_device_id <> ''
		GROUP BY current_device_id`)
	if err != nil {
		log.Printf("⚠️ identity backfill (device_identity): %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("🔑 Identity backfill: %d legacy device identities created", n)
	}

	res, err = db.Exec(`
		INSERT OR IGNORE INTO trial_grants (identity_key, granted_at, bucket, note)
		SELECT identity_key, created_at, '', 'backfill'
		FROM device_identity WHERE kind = 'legacy'`)
	if err != nil {
		log.Printf("⚠️ identity backfill (trial_grants): %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("🔑 Identity backfill: %d legacy trial grants preserved", n)
	}
}

type deviceIdentity struct {
	key      string
	kind     string
	hwPrefix string
	ipBucket string
}

// lookupIdentity reads the stored identity for a device_id. found is false for
// devices we have never registered (e.g. a request arriving before the first
// /user/register), in which case callers fall back to the old per-device rules.
func lookupIdentity(deviceID string) (di deviceIdentity, found bool) {
	if deviceID == "" || db == nil {
		return di, false
	}
	err := db.QueryRow(
		`SELECT identity_key, kind, hw_prefix, ip_bucket FROM device_identity WHERE device_id = ?`,
		deviceID).Scan(&di.key, &di.kind, &di.hwPrefix, &di.ipBucket)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("⚠️ lookupIdentity(%s): %v", deviceID, err)
		}
		return di, false
	}
	return di, true
}

// resolveDeviceIdentity records which identity owns this install and returns
// it. Called from registration, where the fingerprint header and client IP are
// still available.
//
// A strong identity is never downgraded by a later fingerprint-less call (an
// app rollback, or a patched build dropping the header) — otherwise dropping
// the header would be a way to escape the group.
func resolveDeviceIdentity(deviceID, fingerprint, ip string) deviceIdentity {
	di := deviceIdentity{
		hwPrefix: hwPrefix(deviceID),
		ipBucket: ipBucket(ip),
	}
	if fingerprint = strings.TrimSpace(fingerprint); fingerprint != "" {
		di.key = "fp:" + hashIdentity(fingerprint)
		di.kind = identityStrong
	} else {
		// Deliberately per-install, NOT keyed on (build, IP): that pair is a
		// neighbourhood, not a device. Keying the identity on it would make a
		// genuinely new phone inherit — and find already spent — the trial of
		// whoever shares its router and ROM build. The bucket is recorded for
		// churn detection only, which is what denies the serial reinstaller.
		di.key = "dev:" + deviceID
		di.kind = identityWeak
	}

	if _, err := db.Exec(`
		INSERT INTO device_identity (device_id, identity_key, kind, hw_prefix, ip_bucket, last_seen)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(device_id) DO UPDATE SET
			identity_key = CASE WHEN excluded.kind = 'strong' OR device_identity.kind <> 'strong'
			                    THEN excluded.identity_key ELSE device_identity.identity_key END,
			kind         = CASE WHEN excluded.kind = 'strong' OR device_identity.kind <> 'strong'
			                    THEN excluded.kind ELSE device_identity.kind END,
			hw_prefix    = excluded.hw_prefix,
			ip_bucket    = excluded.ip_bucket,
			last_seen    = CURRENT_TIMESTAMP`,
		deviceID, di.key, di.kind, di.hwPrefix, di.ipBucket); err != nil {
		log.Printf("⚠️ device_identity upsert for %s: %v", deviceID, err)
		return di
	}

	// Re-read: a pre-existing strong identity wins over what we just computed.
	if stored, ok := lookupIdentity(deviceID); ok {
		return stored
	}
	return di
}

// installUUID returns the install-UUID half of a composite device_id, or ""
// when the suffix is not a canonical UUID. The strict shape check doubles as
// input sanitising: the suffix goes into a LIKE pattern in
// adoptIdentityOnLogin, and a client-crafted device_id ending in "%" or "_"
// must not be able to match — and join — an arbitrary identity group.
func installUUID(deviceID string) string {
	i := strings.Index(deviceID, "|")
	if i < 0 {
		return ""
	}
	u := deviceID[i+1:]
	if len(u) != 36 {
		return ""
	}
	for pos, c := range u {
		switch pos {
		case 8, 13, 18, 23:
			if c != '-' {
				return ""
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return ""
			}
		}
	}
	return u
}

// adoptIdentityOnLogin keeps an install inside its identity group when the
// hardware half of its device_id drifts (seen live 2026-08-03: an OS update
// moved a device from "V1UGS35H.75-14-9-3-1-2|<uuid>" to "…-1-3|<uuid>").
// Identity rows are normally created only at /user/register, the one place
// the fingerprint header is available; login carries no fingerprint, so a
// drifted id would otherwise sit outside its group and collect a fresh daily
// AI allowance. The install UUID lives in secure storage and survives the
// drift, so an unknown device_id inherits the identity of the most recent row
// sharing its UUID. No trial is granted here — that stays a register-only
// decision (the inherited identity_key already carries whatever grant exists).
func adoptIdentityOnLogin(deviceID string) {
	if deviceID == "" || db == nil {
		return
	}
	if _, ok := lookupIdentity(deviceID); ok {
		if _, err := db.Exec(
			`UPDATE device_identity SET last_seen = CURRENT_TIMESTAMP WHERE device_id = ?`,
			deviceID); err != nil {
			log.Printf("⚠️ adoptIdentityOnLogin touch(%s): %v", deviceID, err)
		}
		return
	}
	uuid := installUUID(deviceID)
	if uuid == "" {
		return
	}
	var key, kind, ipB string
	err := db.QueryRow(`
		SELECT identity_key, kind, ip_bucket FROM device_identity
		WHERE device_id LIKE '%|' || ?
		ORDER BY last_seen DESC LIMIT 1`, uuid).Scan(&key, &kind, &ipB)
	if err == sql.ErrNoRows {
		return // genuinely new install: register owns fresh-identity creation
	}
	if err != nil {
		log.Printf("⚠️ adoptIdentityOnLogin(%s): %v", deviceID, err)
		return
	}
	if _, err := db.Exec(`
		INSERT INTO device_identity (device_id, identity_key, kind, hw_prefix, ip_bucket, last_seen)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(device_id) DO NOTHING`,
		deviceID, key, kind, hwPrefix(deviceID), ipB); err != nil {
		log.Printf("⚠️ adoptIdentityOnLogin insert(%s): %v", deviceID, err)
		return
	}
	log.Printf("🔑 Identity adopted after hardware drift: device=%s identity=%s kind=%s", deviceID, key, kind)
}

// bucketInstalls lists the installs seen recently from one (build id, IP /24).
func bucketInstalls(hw, ipb string) []string {
	if hw == "" || ipb == "" || db == nil {
		return nil
	}
	rows, err := db.Query(fmt.Sprintf(`
		SELECT device_id FROM device_identity
		WHERE hw_prefix = ? AND ip_bucket = ?
		  AND created_at >= datetime('now', '-%d day')`, identityChurnWindowDays),
		hw, ipb)
	if err != nil {
		log.Printf("⚠️ bucketInstalls(%s,%s): %v", hw, ipb, err)
		return nil
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// installsCoexist reports whether any two of these installs were BOTH in use
// over a stretch of at least coexistenceDays — one person cannot use two
// installs of the same app on one phone, so that is two people, not a farm.
//
// Spans come from AI call history: [first call, last call] per install. A
// reinstaller's spans sit end to end; two users' spans overlap for as long as
// they both keep using the app.
func installsCoexist(deviceIDs []string) bool {
	if len(deviceIDs) < 2 || analyticsDB == nil {
		return false
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(deviceIDs)), ",")
	args := make([]interface{}, len(deviceIDs))
	for i, id := range deviceIDs {
		args[i] = id
	}
	rows, err := analyticsDB.Query(
		`SELECT MIN(julianday(created_at)), MAX(julianday(created_at))
		 FROM api_calls WHERE device_id IN (`+placeholders+`) GROUP BY device_id`, args...)
	if err != nil {
		log.Printf("⚠️ installsCoexist: %v", err)
		return false
	}
	defer rows.Close()

	type span struct{ first, last float64 }
	var spans []span
	for rows.Next() {
		var s span
		if err := rows.Scan(&s.first, &s.last); err == nil {
			spans = append(spans, s)
		}
	}
	for i := 0; i < len(spans); i++ {
		for j := i + 1; j < len(spans); j++ {
			overlap := math.Min(spans[i].last, spans[j].last) -
				math.Max(spans[i].first, spans[j].first)
			if overlap >= coexistenceDays {
				return true
			}
		}
	}
	return false
}

// bucketChurning reports whether a (build id, IP /24) pair is one person
// reinstalling rather than several people who happen to share a phone model
// and a network.
//
// Empty components never churn — an unknown IP must not group strangers by ROM
// build alone, which is the whole reason the build id cannot carry identity:
// in production a single build id covers 324 unrelated accounts.
func bucketChurning(hw, ipb string) bool {
	ids := bucketInstalls(hw, ipb)
	if len(ids) < identityChurnMin {
		return false
	}
	if installsCoexist(ids) {
		return false // separate people sharing a model and a router
	}
	return true
}

// grantTrialIfEligible gives an identity its one and only 7-day trial.
//
// It is withheld when the identity already had one (whether or not it is still
// running) or when its bucket is churning. A withheld trial is not a ban: the
// install still works, on the free tier.
func grantTrialIfEligible(di deviceIdentity, deviceID string) {
	if di.key == "" || db == nil {
		return
	}
	var existing int
	if err := db.QueryRow(`SELECT COUNT(*) FROM trial_grants WHERE identity_key = ?`, di.key).
		Scan(&existing); err != nil {
		log.Printf("⚠️ trial grant lookup for %s: %v", di.key, err)
		return
	}
	if existing > 0 {
		return
	}
	if bucketChurning(di.hwPrefix, di.ipBucket) {
		log.Printf("🔁 Trial withheld (install churn): device=%s identity=%s bucket=%s|%s",
			deviceID, di.key, di.hwPrefix, di.ipBucket)
		return
	}
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO trial_grants (identity_key, bucket, note) VALUES (?, ?, ?)`,
		di.key, di.hwPrefix+"|"+di.ipBucket, di.kind); err != nil {
		log.Printf("⚠️ trial grant insert for %s: %v", di.key, err)
		return
	}
	log.Printf("🎁 Trial granted: device=%s identity=%s kind=%s", deviceID, di.key, di.kind)
}

// identityTrialState reports the trial for a device. known is false when the
// device has no identity row at all, which tells callers to fall back to the
// pre-identity rule instead of silently denying a trial.
func identityTrialState(deviceID string) (active bool, known bool) {
	di, ok := lookupIdentity(deviceID)
	if !ok {
		return false, false
	}
	var ageDays sql.NullFloat64
	err := db.QueryRow(`
		SELECT julianday('now') - julianday(granted_at)
		FROM trial_grants WHERE identity_key = ? AND revoked = 0`, di.key).Scan(&ageDays)
	if err == sql.ErrNoRows {
		return false, true // identity exists and was denied (or never granted) a trial
	}
	if err != nil {
		log.Printf("⚠️ identityTrialState(%s): %v", deviceID, err)
		return false, false
	}
	return ageDays.Valid && ageDays.Float64 < trialWindowDays, true
}

// quotaDeviceIDs returns every install whose AI calls count against the same
// daily allowance as deviceID: itself, plus the other installs of the same
// physical device (strong identity), plus the rest of its bucket when that
// bucket is churning. The bucket clause is applied regardless of kind, so
// rotating a spoofed fingerprint does not escape the group.
func quotaDeviceIDs(deviceID string) []string {
	ids := []string{deviceID}
	seen := map[string]bool{deviceID: true}
	di, ok := lookupIdentity(deviceID)
	if !ok || db == nil {
		return ids
	}

	add := func(query string, args ...interface{}) {
		rows, err := db.Query(query, args...)
		if err != nil {
			log.Printf("⚠️ quotaDeviceIDs(%s): %v", deviceID, err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}

	if di.kind == identityStrong {
		add(`SELECT device_id FROM device_identity WHERE identity_key = ?`, di.key)
	}
	if bucketChurning(di.hwPrefix, di.ipBucket) {
		add(fmt.Sprintf(`SELECT device_id FROM device_identity
			WHERE hw_prefix = ? AND ip_bucket = ?
			  AND created_at >= datetime('now', '-%d day')`, identityChurnWindowDays),
			di.hwPrefix, di.ipBucket)
	}
	return ids
}

// dailyChatGPTCount counts today's AI calls across every install that shares
// this device's allowance, so a reinstall no longer resets the counter.
func dailyChatGPTCount(deviceID string) int {
	if analyticsDB == nil {
		return 0
	}
	ids := quotaDeviceIDs(deviceID)
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	var used int
	if err := analyticsDB.QueryRow(
		`SELECT count(*) FROM api_calls
		 WHERE device_id IN (`+placeholders+`)
		   AND call_type = 'chatgpt' AND created_at >= date('now')`, args...).Scan(&used); err != nil {
		log.Printf("⚠️ dailyChatGPTCount(%s): %v", deviceID, err)
		return 0
	}
	return used
}

// dailyAICallCount counts today's OpenAI-proxy calls of ANY call_type across
// the same identity group — the basis of the secondary (anti-spoof) ceiling.
// Chart work ('astrolog', 'transit-year', 'transit-multi-year') is deliberately
// excluded: it is local CPU-bound computation with its own limiter, and a
// single transit-year request logs hundreds of rows that would otherwise
// swallow the AI allowance.
func dailyAICallCount(deviceID string) int {
	if analyticsDB == nil {
		return 0
	}
	ids := quotaDeviceIDs(deviceID)
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids)+len(aiOverheadCallTypes)+1)
	for _, id := range ids {
		args = append(args, id)
	}
	typePlaceholders := "?"
	args = append(args, "chatgpt")
	for ct := range aiOverheadCallTypes {
		typePlaceholders += ",?"
		args = append(args, ct)
	}
	var used int
	if err := analyticsDB.QueryRow(
		`SELECT count(*) FROM api_calls
		 WHERE device_id IN (`+placeholders+`)
		   AND call_type IN (`+typePlaceholders+`) AND created_at >= date('now')`, args...).Scan(&used); err != nil {
		log.Printf("⚠️ dailyAICallCount(%s): %v", deviceID, err)
		return 0
	}
	return used
}

// revokeTrialForDevice withdraws the trial of the identity behind a device —
// the targeted lever for a proven abuser, used instead of a ban. The install
// keeps working on the free tier. Returns the identity it acted on.
func revokeTrialForDevice(deviceID, note string) (string, error) {
	di, ok := lookupIdentity(deviceID)
	if !ok {
		return "", fmt.Errorf("no identity for device %s", deviceID)
	}
	if _, err := db.Exec(
		`UPDATE trial_grants SET revoked = 1, note = ? WHERE identity_key = ?`, note, di.key); err != nil {
		return di.key, err
	}
	log.Printf("🚫 Trial revoked: device=%s identity=%s note=%s", deviceID, di.key, note)
	return di.key, nil
}
