package main

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// setupIdentityTestDBs builds in-memory users/analytics DBs plus the identity
// tables, mirroring what initIdentityTables creates in production.
func setupIdentityTestDBs(t *testing.T) {
	t.Helper()
	setupQuotaTestDBs(t)
	// The real users table carries current_device_id; the quota fixture does not.
	if _, err := db.Exec(`ALTER TABLE users ADD COLUMN current_device_id TEXT`); err != nil {
		t.Fatalf("add current_device_id: %v", err)
	}
	if _, err := db.Exec(`
	CREATE TABLE device_identity (
		device_id    TEXT PRIMARY KEY,
		identity_key TEXT NOT NULL,
		kind         TEXT NOT NULL,
		hw_prefix    TEXT NOT NULL DEFAULT '',
		ip_bucket    TEXT NOT NULL DEFAULT '',
		created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE trial_grants (
		identity_key TEXT PRIMARY KEY,
		granted_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		bucket       TEXT NOT NULL DEFAULT '',
		revoked      INTEGER NOT NULL DEFAULT 0,
		note         TEXT NOT NULL DEFAULT ''
	);`); err != nil {
		t.Fatalf("create identity tables: %v", err)
	}
}

// register simulates one app install calling /user/register.
func register(t *testing.T, deviceID, fingerprint, ip string) deviceIdentity {
	t.Helper()
	di := resolveDeviceIdentity(deviceID, fingerprint, ip)
	grantTrialIfEligible(di, deviceID)
	addUser(t, deviceID+"@device.astrolytix.app", "free", sql.NullString{}, 0, 0)
	if _, err := db.Exec(`UPDATE users SET current_device_id = ? WHERE email = ?`,
		deviceID, deviceID+"@device.astrolytix.app"); err != nil {
		t.Fatalf("set current_device_id: %v", err)
	}
	return di
}

func addChatCalls(t *testing.T, deviceID string, n int) {
	t.Helper()
	today := time.Now().UTC().Format("2006-01-02 15:04:05")
	for i := 0; i < n; i++ {
		if _, err := analyticsDB.Exec(
			`INSERT INTO api_calls (device_id, call_type, created_at) VALUES (?, 'chatgpt', ?)`,
			deviceID, today); err != nil {
			t.Fatalf("insert call: %v", err)
		}
	}
}

func TestIPBucket(t *testing.T) {
	cases := map[string]string{
		"91.98.77.205":     "91.98.77.0/24",
		"91.98.77.9:51314": "91.98.77.0/24",
		"":                 "",
		"not-an-ip":        "not-an-ip",
	}
	for in, want := range cases {
		if got := ipBucket(in); got != want {
			t.Errorf("ipBucket(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHwPrefix(t *testing.T) {
	if got := hwPrefix("V1UGS35H.75-14-9-3-1-2|86f680cb-a56c"); got != "V1UGS35H.75-14-9-3-1-2" {
		t.Errorf("hwPrefix = %q", got)
	}
	if got := hwPrefix("no-pipe"); got != "no-pipe" {
		t.Errorf("hwPrefix without pipe = %q", got)
	}
}

// TestReinstallFarmLosesTrial is the regression test for the actual incident:
// one physical device wiping the app over and over to keep landing on the
// 80-call trial tier. The first installs still get their trial; once the
// churn threshold is crossed, further reinstalls come up free.
func TestReinstallFarmLosesTrial(t *testing.T) {
	setupIdentityTestDBs(t)
	const hw = "V1UGS35H.75-14-9-3-1-2"
	const ip = "203.0.113.42"

	// Early installs are indistinguishable from an honest user reinstalling
	// once, so they still get a trial. That is the intended cost of not
	// punishing legitimate wipes.
	for i := 0; i < identityChurnMin-1; i++ {
		dev := fmt.Sprintf("%s|install-%d", hw, i)
		register(t, dev, "", ip)
		if active, known := identityTrialState(dev); !known || !active {
			t.Fatalf("install %d should be inside its trial (known=%v active=%v)", i, known, active)
		}
	}

	// The install that crosses the churn threshold is where it stops: no new
	// trial, but the app keeps working on free.
	farmed := fmt.Sprintf("%s|install-farmed", hw)
	register(t, farmed, "", ip)
	active, known := identityTrialState(farmed)
	if !known {
		t.Fatal("farmed install must have an identity row")
	}
	if active {
		t.Error("reinstall past the churn threshold must NOT get a fresh trial")
	}
	if limit, tier := aiDailyLimitForUser(farmed+"@device.astrolytix.app", farmed); limit != aiLimitFree || tier != "free" {
		t.Errorf("farmed install: got (%d,%q), want (%d,free)", limit, tier, aiLimitFree)
	}
}

// TestReinstallDoesNotResetDailyQuota covers the second half of the hole: even
// with no trial, a wipe used to hand out a brand-new 15-call bucket because
// the counter was keyed on the install UUID.
func TestReinstallDoesNotResetDailyQuota(t *testing.T) {
	setupIdentityTestDBs(t)
	const hw = "V1UGS35H.75-14-9-3-1-2"
	const ip = "203.0.113.42"

	var devices []string
	for i := 0; i < identityChurnMin; i++ {
		dev := fmt.Sprintf("%s|install-%d", hw, i)
		register(t, dev, "", ip)
		devices = append(devices, dev)
		addChatCalls(t, dev, 5)
	}

	fresh := fmt.Sprintf("%s|install-fresh", hw)
	register(t, fresh, "", ip)
	if got := dailyChatGPTCount(fresh); got != len(devices)*5 {
		t.Errorf("fresh install sees %d calls, want %d (the farm's calls must follow it)", got, len(devices)*5)
	}
}

// TestHouseholdNotThrottled is the collateral-damage guard: two phones of the
// same model behind one router must stay independent. Grouping strangers by
// ROM build was never acceptable — Build.ID is shared by hundreds of accounts.
func TestHouseholdNotThrottled(t *testing.T) {
	setupIdentityTestDBs(t)
	const hw = "QKR1.191246.002" // 324 unrelated accounts share this in production
	const ip = "198.51.100.7"

	a := register(t, hw+"|phone-a", "", ip)
	addChatCalls(t, hw+"|phone-a", 12)
	register(t, hw+"|phone-b", "", ip)

	if bucketChurning(a.hwPrefix, a.ipBucket) {
		t.Fatal("two installs must not look like a farm")
	}
	if got := dailyChatGPTCount(hw + "|phone-b"); got != 0 {
		t.Errorf("second phone sees %d calls from the first; want 0", got)
	}
	if active, known := identityTrialState(hw + "|phone-b"); !known || !active {
		t.Error("second phone in a household deserves its own trial")
	}
}

// addChatCallsOn writes calls for a device on a specific day, so a test can
// lay out who was using the app when.
func addChatCallsOn(t *testing.T, deviceID string, daysAgo int, n int) {
	t.Helper()
	when := time.Now().UTC().AddDate(0, 0, -daysAgo).Format("2006-01-02 15:04:05")
	for i := 0; i < n; i++ {
		if _, err := analyticsDB.Exec(
			`INSERT INTO api_calls (device_id, call_type, created_at) VALUES (?, 'chatgpt', ?)`,
			deviceID, when); err != nil {
			t.Fatalf("insert call: %v", err)
		}
	}
}

// TestCoexistingUsersNeverTreatedAsFarm is the collateral-damage guard that
// matters most: three people with the same phone model behind one router
// (three installs — past the churn threshold) must keep their own trials and
// their own quotas, because they use the app side by side.
//
// The distinction is drawn on real behaviour, not on the model: a farm's
// installs replace one another and never overlap; these do.
func TestCoexistingUsersNeverTreatedAsFarm(t *testing.T) {
	setupIdentityTestDBs(t)
	const hw = "QKR1.191246.002"
	const ip = "198.51.100.7"

	for i, dev := range []string{hw + "|user-a", hw + "|user-b", hw + "|user-c"} {
		register(t, dev, "", ip)
		// Everyone has been using the app for the last three weeks.
		for _, daysAgo := range []int{20, 14, 7, 1} {
			addChatCallsOn(t, dev, daysAgo, 2+i)
		}
	}

	if bucketChurning(hw, ipBucket(ip)) {
		t.Error("three people using the app in parallel must not be read as a reinstall farm")
	}
	for _, dev := range []string{hw + "|user-a", hw + "|user-b", hw + "|user-c"} {
		if active, known := identityTrialState(dev); !known || !active {
			t.Errorf("%s: coexisting user lost their trial", dev)
		}
		if got := dailyChatGPTCount(dev); got != 0 {
			t.Errorf("%s: sees %d calls from other people's installs, want 0", dev, got)
		}
	}
}

// TestSerialReinstallsStillCaught: the same three installs, but used one after
// another the way the observed farm behaved (each goes silent when the next
// appears). No overlap → still churn.
func TestSerialReinstallsStillCaught(t *testing.T) {
	setupIdentityTestDBs(t)
	const hw = "V1UGS35H.75-14-9-3-1-2"
	const ip = "203.0.113.42"

	register(t, hw+"|wipe-1", "", ip)
	addChatCallsOn(t, hw+"|wipe-1", 20, 5)
	register(t, hw+"|wipe-2", "", ip)
	addChatCallsOn(t, hw+"|wipe-2", 12, 5)
	register(t, hw+"|wipe-3", "", ip)
	addChatCallsOn(t, hw+"|wipe-3", 2, 5)

	if !bucketChurning(hw, ipBucket(ip)) {
		t.Error("installs that replace one another must be read as churn")
	}
	if active, _ := identityTrialState(hw + "|wipe-3"); active {
		t.Error("third wipe must not receive a fresh trial")
	}
}

// TestStrongIdentitySurvivesReinstall: once the app sends a real hardware
// fingerprint, reinstalls are recognised immediately — no churn threshold, no
// IP involved (the device can move networks).
func TestStrongIdentitySurvivesReinstall(t *testing.T) {
	setupIdentityTestDBs(t)
	const fp = "android-id-abc123"

	first := register(t, "QKR1.x|install-1", fp, "198.51.100.7")
	if first.kind != identityStrong {
		t.Fatalf("kind = %q, want strong", first.kind)
	}
	addChatCalls(t, "QKR1.x|install-1", 9)

	// Age the trial out, then wipe the app and move networks.
	if _, err := db.Exec(`UPDATE trial_grants SET granted_at = datetime('now','-10 day')`); err != nil {
		t.Fatalf("age trial: %v", err)
	}
	second := register(t, "QKR1.x|install-2", fp, "203.0.113.99")
	if second.key != first.key {
		t.Errorf("same fingerprint must resolve to one identity: %q vs %q", second.key, first.key)
	}
	var grants int
	if err := db.QueryRow(`SELECT COUNT(*) FROM trial_grants`).Scan(&grants); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if grants != 1 {
		t.Errorf("reinstall issued a second trial grant (%d rows); the identity gets exactly one", grants)
	}
	if active, _ := identityTrialState("QKR1.x|install-2"); active {
		t.Error("the trial belongs to the identity and was already spent")
	}
	if got := dailyChatGPTCount("QKR1.x|install-2"); got != 9 {
		t.Errorf("reinstall sees %d calls, want 9", got)
	}
}

// TestSpoofedFingerprintCaughtByChurn: a patched build can invent a new
// fingerprint per install. That escapes the strong-identity grouping, so the
// bucket rule has to catch it regardless of kind.
func TestSpoofedFingerprintCaughtByChurn(t *testing.T) {
	setupIdentityTestDBs(t)
	const hw = "V1UGS35H.75-14-9-3-1-2"
	const ip = "203.0.113.42"

	for i := 0; i < identityChurnMin; i++ {
		dev := fmt.Sprintf("%s|spoof-%d", hw, i)
		register(t, dev, fmt.Sprintf("random-fingerprint-%d", i), ip)
		addChatCalls(t, dev, 4)
	}
	next := hw + "|spoof-next"
	register(t, next, "random-fingerprint-next", ip)

	if active, _ := identityTrialState(next); active {
		t.Error("rotating a fake fingerprint must not keep buying trials")
	}
	if got := dailyChatGPTCount(next); got != identityChurnMin*4 {
		t.Errorf("spoofing install sees %d calls, want %d", got, identityChurnMin*4)
	}
}

// TestStrongIdentityNotDowngraded: dropping the header on a later call must
// not detach an install from the identity it already joined.
func TestStrongIdentityNotDowngraded(t *testing.T) {
	setupIdentityTestDBs(t)
	strong := register(t, "dev|1", "real-hardware-id", "198.51.100.7")
	again := resolveDeviceIdentity("dev|1", "", "198.51.100.7")
	if again.key != strong.key || again.kind != identityStrong {
		t.Errorf("identity downgraded to %q/%q, want %q/strong", again.key, again.kind, strong.key)
	}
}

// TestLegacyBackfillPreservesTrial: users who existed before this layer keep
// exactly the trial they had, so the rollout cuts nobody off mid-trial.
func TestLegacyBackfillPreservesTrial(t *testing.T) {
	setupIdentityTestDBs(t)
	addUser(t, "old|dev@device.astrolytix.app", "free", sql.NullString{}, 0, 2) // 2 days in
	addUser(t, "gone|dev@device.astrolytix.app", "free", sql.NullString{}, 0, 40)
	if _, err := db.Exec(`UPDATE users SET current_device_id = replace(email, '@device.astrolytix.app', '')`); err != nil {
		t.Fatalf("set device ids: %v", err)
	}

	backfillIdentities()

	if active, known := identityTrialState("old|dev"); !known || !active {
		t.Error("account 2 days old must still be in trial after backfill")
	}
	if active, known := identityTrialState("gone|dev"); !known || active {
		t.Error("account 40 days old must be out of trial after backfill")
	}
}

// TestUnknownDeviceFallsBackToOldRule: a device with no identity row (a request
// that beats its own registration) must not silently lose its trial.
func TestUnknownDeviceFallsBackToOldRule(t *testing.T) {
	setupIdentityTestDBs(t)
	addUser(t, "ghost@device.astrolytix.app", "free", sql.NullString{}, 0, 1)
	if !withinTrialWindow("ghost@device.astrolytix.app", "ghost") {
		t.Error("unknown device should fall back to the created_at rule")
	}
}

// TestRevokeTrialForDevice: the targeted lever for a proven abuser — the
// install keeps working, it just drops to the free allowance.
func TestRevokeTrialForDevice(t *testing.T) {
	setupIdentityTestDBs(t)
	register(t, "abuser|1", "", "203.0.113.42")
	if active, _ := identityTrialState("abuser|1"); !active {
		t.Fatal("precondition: trial active")
	}
	if _, err := revokeTrialForDevice("abuser|1", "confirmed fake purchases"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if active, known := identityTrialState("abuser|1"); !known || active {
		t.Error("revoked trial must be inactive")
	}
	if limit, tier := aiDailyLimitForUser("abuser|1@device.astrolytix.app", "abuser|1"); limit != aiLimitFree || tier != "free" {
		t.Errorf("revoked device: got (%d,%q), want (%d,free) — not a ban", limit, tier, aiLimitFree)
	}
}
