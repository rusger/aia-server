package main

import (
	"database/sql"
	"testing"
	"time"
)

func TestGoogleReverifyDueWindow(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{"ends in 1h", now.Add(time.Hour), true},
		{"ends exactly +48h", now.Add(48 * time.Hour), true},
		{"ends +49h", now.Add(49 * time.Hour), false},
		{"ends in a month", now.Add(30 * 24 * time.Hour), false},
		{"ended 1h ago", now.Add(-time.Hour), true},
		{"ended 6d23h ago", now.Add(-7*24*time.Hour + time.Hour), true},
		{"ended exactly 7d ago", now.Add(-7 * 24 * time.Hour), false},
		{"ended 30d ago", now.Add(-30 * 24 * time.Hour), false},
	}
	for _, c := range cases {
		if got := googleReverifyDue(c.expiry, now); got != c.want {
			t.Errorf("%s: googleReverifyDue=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestGooglePlayStateActive(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	past := now.Add(-time.Hour)
	if !googlePlayStateActive(1, &future, now) {
		t.Error("paid + future expiry must be active")
	}
	if !googlePlayStateActive(2, &future, now) {
		t.Error("trial + future expiry must be active")
	}
	if googlePlayStateActive(0, &future, now) || googlePlayStateActive(3, &future, now) {
		t.Error("pending/deferred must not be active")
	}
	if googlePlayStateActive(1, &past, now) {
		t.Error("expired must not be active")
	}
	if googlePlayStateActive(1, nil, now) {
		t.Error("unknown expiry must not be active")
	}
}

func TestRTDNSilent(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	since := now.Add(-rtdnSilenceWindow)
	if rtdnSilent(0, time.Time{}, since) {
		t.Error("no signals → never silent")
	}
	if !rtdnSilent(1, time.Time{}, since) {
		t.Error("signals and no notification ever → silent")
	}
	if !rtdnSilent(2, now.Add(-4*24*time.Hour), since) {
		t.Error("signals and last notification 4d ago → silent")
	}
	if rtdnSilent(2, now.Add(-time.Hour), since) {
		t.Error("recent notification → not silent")
	}
}

func TestMaskToken(t *testing.T) {
	tok := "abcdefghijklmnopqrstuvwxyz0123456789"
	m := maskToken(tok)
	if m != "abcdef…6789" {
		t.Errorf("maskToken=%q", m)
	}
	if maskToken("short") != "***" {
		t.Error("short token must be fully masked")
	}
}

func setupGoogleReverifyDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err = db.Exec(`
	CREATE TABLE users (
		email TEXT PRIMARY KEY,
		subscription_type TEXT NOT NULL DEFAULT 'free',
		subscription_length TEXT,
		subscription_expiry DATETIME,
		last_payment_method TEXT,
		updated_at DATETIME);
	CREATE TABLE purchase_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT, product_id TEXT, store TEXT, purchase_token TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

func readExpiry(t *testing.T, email string) (string, time.Time) {
	t.Helper()
	var typ string
	var exp sql.NullString
	if err := db.QueryRow(`SELECT subscription_type, subscription_expiry FROM users WHERE email = ?`, email).Scan(&typ, &exp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !exp.Valid {
		return typ, time.Time{}
	}
	tm, err := parseDBTime(exp.String)
	if err != nil {
		t.Fatalf("parse %q: %v", exp.String, err)
	}
	return typ, tm
}

func TestApplyGoogleVerifiedExpiryForwardOnly(t *testing.T) {
	setupGoogleReverifyDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	cur := now.Add(time.Hour)
	later := now.Add(30 * 24 * time.Hour)
	if _, err := db.Exec(`INSERT INTO users (email, subscription_type, subscription_length, subscription_expiry) VALUES
		('renew@test', 'paid', 'monthly', ?),
		('lapsed@test', 'free', 'monthly', ?),
		('ahead@test', 'paid', 'yearly', ?),
		('life@test', 'paid', 'lifetime', NULL)`, cur, now.Add(-2*24*time.Hour), now.Add(200*24*time.Hour)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Renewal moves the window forward.
	adv, err := applyGoogleVerifiedExpiry("renew@test", "astrolytix_monthly", &later, now)
	if err != nil || !adv {
		t.Fatalf("renewal: adv=%v err=%v", adv, err)
	}
	if typ, e := readExpiry(t, "renew@test"); typ != "paid" || !e.Equal(later) {
		t.Errorf("renew: type=%s expiry=%v want paid %v", typ, e, later)
	}
	// Idempotent: the same verified expiry again changes nothing.
	if adv, _ := applyGoogleVerifiedExpiry("renew@test", "astrolytix_monthly", &later, now); adv {
		t.Error("same expiry re-applied must not advance")
	}

	// Lapsed (expiry-sync downgraded to free) but renewed in Play → paid again.
	if adv, err := applyGoogleVerifiedExpiry("lapsed@test", "astrolytix_monthly", &later, now); err != nil || !adv {
		t.Fatalf("lapsed: adv=%v err=%v", adv, err)
	}
	if typ, e := readExpiry(t, "lapsed@test"); typ != "paid" || !e.Equal(later) {
		t.Errorf("lapsed: type=%s expiry=%v", typ, e)
	}

	// A later existing window is never shortened.
	if adv, _ := applyGoogleVerifiedExpiry("ahead@test", "astrolytix_monthly", &later, now); adv {
		t.Error("earlier Play expiry must not shorten a later window")
	}
	if _, e := readExpiry(t, "ahead@test"); !e.Equal(now.Add(200 * 24 * time.Hour)) {
		t.Errorf("ahead: expiry changed to %v", e)
	}

	// Lifetime untouched.
	if adv, _ := applyGoogleVerifiedExpiry("life@test", "astrolytix_monthly", &later, now); adv {
		t.Error("lifetime account must not be touched")
	}
	// Unknown user / nil expiry → no-op, no error.
	if adv, err := applyGoogleVerifiedExpiry("nobody@test", "astrolytix_monthly", &later, now); adv || err != nil {
		t.Errorf("unknown user: adv=%v err=%v", adv, err)
	}
	if adv, err := applyGoogleVerifiedExpiry("renew@test", "astrolytix_monthly", nil, now); adv || err != nil {
		t.Errorf("nil expiry: adv=%v err=%v", adv, err)
	}
}

func TestGoogleReverifyCandidatesSelection(t *testing.T) {
	setupGoogleReverifyDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := db.Exec(`INSERT INTO users (email, subscription_type, subscription_length, subscription_expiry) VALUES
		('soon@test', 'paid', 'monthly', ?),
		('far@test', 'paid', 'monthly', ?),
		('old@test', 'free', 'monthly', ?),
		('life@test', 'paid', 'lifetime', NULL),
		('apple@test', 'paid', 'monthly', ?)`,
		now.Add(10*time.Hour), now.Add(20*24*time.Hour), now.Add(-30*24*time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO purchase_history (email, product_id, store, purchase_token) VALUES
		('soon@test', 'astrolytix_monthly', 'google', 'tok-soon-old-000000'),
		('soon@test', 'astrolytix_monthly', 'google', 'tok-soon-new-000000'),
		('far@test', 'astrolytix_monthly', 'google', 'tok-far-0000000000'),
		('old@test', 'astrolytix_monthly', 'google', 'tok-old-0000000000'),
		('life@test', 'astrolytix_lifetime', 'google', 'tok-life-000000000'),
		('apple@test', 'astrolytix_monthly', 'apple', 'jws')`); err != nil {
		t.Fatalf("seed purchases: %v", err)
	}
	cands, err := googleReverifyCandidates(now, "")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(cands) != 1 || cands[0].email != "soon@test" || cands[0].token != "tok-soon-new-000000" {
		t.Fatalf("want only soon@test with newest token, got %+v", cands)
	}
	// Token-targeted (RTDN) path ignores the window but still only the newest token.
	cands, err = googleReverifyCandidates(now, "tok-far-0000000000")
	if err != nil || len(cands) != 1 || cands[0].email != "far@test" {
		t.Fatalf("token path: %+v err=%v", cands, err)
	}
	cands, err = googleReverifyCandidates(now, "tok-soon-old-000000")
	if err != nil || len(cands) != 0 {
		t.Fatalf("superseded token must not be selected: %+v err=%v", cands, err)
	}
}
