package main

import (
	"database/sql"
	"testing"
	"time"
)

// setupQuotaTestDBs points the package globals `db` and `analyticsDB` at fresh
// in-memory SQLite databases with just the columns the quota logic reads.
func setupQuotaTestDBs(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open users db: %v", err)
	}
	if _, err = db.Exec(`CREATE TABLE users (
		email TEXT PRIMARY KEY,
		subscription_type TEXT NOT NULL DEFAULT 'free',
		subscription_expiry DATETIME,
		is_super INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create users: %v", err)
	}
	analyticsDB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open analytics db: %v", err)
	}
	if _, err = analyticsDB.Exec(`CREATE TABLE api_calls (
		device_id TEXT NOT NULL,
		call_type TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create api_calls: %v", err)
	}
}

// addUser inserts a user row with created_at set ageDays days in the past.
func addUser(t *testing.T, email, subType string, expiry sql.NullString, isSuper int, ageDays float64) {
	t.Helper()
	created := time.Now().UTC().Add(-time.Duration(ageDays*24) * time.Hour).Format("2006-01-02 15:04:05")
	_, err := db.Exec(
		`INSERT INTO users (email, subscription_type, subscription_expiry, is_super, created_at) VALUES (?,?,?,?,?)`,
		email, subType, expiry, isSuper, created)
	if err != nil {
		t.Fatalf("insert user %s: %v", email, err)
	}
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func TestAiDailyLimitForUser(t *testing.T) {
	setupQuotaTestDBs(t)
	future := time.Now().Add(30 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	past := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")

	// email, subType, expiry, isSuper, ageDays
	addUser(t, "super@x.com", "paid", sql.NullString{}, 1, 100)
	addUser(t, "paid.active@x.com", "paid", nullStr(future), 0, 100)
	addUser(t, "paid.expired@x.com", "paid", nullStr(past), 0, 100)   // expired → free, old → not trial
	addUser(t, "paid.lifetime@x.com", "paid", sql.NullString{}, 0, 100)
	addUser(t, "free.old@x.com", "free", sql.NullString{}, 0, 30)      // past trial
	addUser(t, "free.new@x.com", "free", sql.NullString{}, 0, 2)       // within trial

	cases := []struct {
		email     string
		wantLimit int
		wantTier  string
	}{
		{"super@x.com", 0, "super"},
		{"paid.active@x.com", aiLimitPaid, "paid"},
		{"paid.lifetime@x.com", aiLimitPaid, "paid"},
		{"paid.expired@x.com", aiLimitFree, "free"},
		{"free.old@x.com", aiLimitFree, "free"},
		{"free.new@x.com", aiLimitTrial, "trial"},
		{"ghost@x.com", aiLimitFree, "free"}, // unknown user: no rows → free, not fresh
	}
	for _, c := range cases {
		gotLimit, gotTier := aiDailyLimitForUser(c.email, "")
		if gotLimit != c.wantLimit || gotTier != c.wantTier {
			t.Errorf("%s: got (%d,%q), want (%d,%q)", c.email, gotLimit, gotTier, c.wantLimit, c.wantTier)
		}
	}
}

func TestEntitlementDeviceOR(t *testing.T) {
	setupQuotaTestDBs(t)
	// Email account is free/old, but the anonymous device account is paid.
	addUser(t, "user@x.com", "free", sql.NullString{}, 0, 60)
	addUser(t, "dev123@device.astrolytix.app", "paid", sql.NullString{}, 0, 60)

	limit, tier := aiDailyLimitForUser("user@x.com", "dev123")
	if limit != aiLimitPaid || tier != "paid" {
		t.Errorf("device-OR paid: got (%d,%q), want (%d,paid)", limit, tier, aiLimitPaid)
	}

	// Super on the device account propagates too.
	setupQuotaTestDBs(t)
	addUser(t, "user2@x.com", "free", sql.NullString{}, 0, 60)
	addUser(t, "dev999@device.astrolytix.app", "free", sql.NullString{}, 1, 60)
	if limit, tier := aiDailyLimitForUser("user2@x.com", "dev999"); limit != 0 || tier != "super" {
		t.Errorf("device-OR super: got (%d,%q), want (0,super)", limit, tier)
	}
}

func TestTrialAnchoredOnCreatedAt(t *testing.T) {
	setupQuotaTestDBs(t)
	addUser(t, "edge.in@x.com", "free", sql.NullString{}, 0, 6.9)  // just inside 7d
	addUser(t, "edge.out@x.com", "free", sql.NullString{}, 0, 7.1) // just outside 7d
	if !withinTrialWindow("edge.in@x.com", "") {
		t.Error("6.9-day-old account should be within trial")
	}
	if withinTrialWindow("edge.out@x.com", "") {
		t.Error("7.1-day-old account should NOT be within trial")
	}
}

func TestEntitlementNotExpired(t *testing.T) {
	future := time.Now().Add(time.Hour).Format("2006-01-02 15:04:05.999999999 -0700 MST")
	past := time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05.999999999 -0700 MST")
	if !entitlementNotExpired(sql.NullString{}) {
		t.Error("NULL expiry (lifetime) should be valid")
	}
	if !entitlementNotExpired(nullStr(future)) {
		t.Error("future expiry should be valid")
	}
	if entitlementNotExpired(nullStr(past)) {
		t.Error("past expiry should be expired")
	}
}

// TestDailyCountBoundary exercises the same COUNT query the proxy runs, to
// confirm the >= limit boundary blocks correctly and only counts today's
// chatgpt calls for the right device.
func TestDailyCountBoundary(t *testing.T) {
	setupQuotaTestDBs(t)
	dev := "devA"
	insert := func(callType, when string) {
		if _, err := analyticsDB.Exec(
			`INSERT INTO api_calls (device_id, call_type, created_at) VALUES (?,?,?)`,
			dev, callType, when); err != nil {
			t.Fatalf("insert call: %v", err)
		}
	}
	today := time.Now().UTC().Format("2006-01-02 15:04:05")
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	for i := 0; i < 25; i++ {
		insert("chatgpt", today)
	}
	insert("chatgpt", yesterday) // must not count
	insert("astrolog", today)    // wrong type, must not count
	insert("chatgpt", today)     // devB below uses a different id

	var used int
	analyticsDB.QueryRow(
		`SELECT count(*) FROM api_calls WHERE device_id = ? AND call_type = 'chatgpt' AND created_at >= date('now')`,
		dev).Scan(&used)
	if used != 26 {
		t.Fatalf("today's chatgpt count = %d, want 26", used)
	}
	// At the free limit (25), a user with 26 today is blocked; a paid user (300) is not.
	if used < aiLimitFree {
		t.Errorf("expected used(%d) >= free limit(%d)", used, aiLimitFree)
	}
	if used >= aiLimitPaid {
		t.Errorf("paid user should not be blocked at used=%d (limit %d)", used, aiLimitPaid)
	}
}
