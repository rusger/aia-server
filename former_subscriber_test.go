package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"testing"
	"time"
)

func setupFormerSubscriberDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		CREATE TABLE users (email TEXT PRIMARY KEY, subscription_type TEXT NOT NULL DEFAULT 'free',
			subscription_expiry DATETIME, is_super INTEGER DEFAULT 0, current_device_id TEXT,
			referral_premium_until TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE devices (email TEXT, device_id TEXT, revoked INTEGER DEFAULT 0);
		CREATE TABLE purchase_history (email TEXT, device_id TEXT, product_id TEXT, transaction_id TEXT,
			original_transaction_id TEXT, purchase_token TEXT, store TEXT, is_trial INTEGER DEFAULT 0);
		CREATE TABLE apple_notifications (notification_type TEXT, environment TEXT,
			transaction_id TEXT, original_transaction_id TEXT);
		CREATE TABLE device_identity (device_id TEXT PRIMARY KEY, identity_key TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT 'strong', hw_prefix TEXT DEFAULT '', ip_bucket TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP);
	`); err != nil {
		t.Fatal(err)
	}
	formerSubscriberCacheMu.Lock()
	formerSubscriberCache = map[string]formerSubscriberCacheEntry{}
	formerSubscriberCacheMu.Unlock()
	formerSubscriberNow = time.Now
}

func fsExec(t *testing.T, q string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func anon(dev string) string { return dev + "@device.astrolytix.app" }

func fakeJWS(env string) string {
	payload, _ := json.Marshal(map[string]string{"environment": env, "transactionId": "1"})
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// anonDevice: an install with its anonymous account and identity row.
func anonDevice(t *testing.T, dev, identity, subType, expiry string) {
	t.Helper()
	fsExec(t, `INSERT INTO users (email, subscription_type, subscription_expiry, current_device_id) VALUES (?,?,?,?)`,
		anon(dev), subType, nullStr(expiry), dev)
	fsExec(t, `INSERT INTO devices (email, device_id) VALUES (?,?)`, anon(dev), dev)
	if identity != "" {
		fsExec(t, `INSERT INTO device_identity (device_id, identity_key) VALUES (?,?)`, dev, identity)
	}
}

func storePurchase(t *testing.T, email, dev, store, txn, token string, trial int) {
	t.Helper()
	fsExec(t, `INSERT INTO purchase_history (email, device_id, product_id, transaction_id,
		original_transaction_id, purchase_token, store, is_trial) VALUES (?,?,?,?,?,?,?,?)`,
		email, dev, "astrolytix_pro_yearly_v2", txn, txn, token, store, trial)
}

func TestFormerSubscriberCriterion(t *testing.T) {
	setupFormerSubscriberDB(t)
	past := time.Now().UTC().Add(-48 * time.Hour).Format("2006-01-02 15:04:05")
	future := time.Now().UTC().Add(5 * 24 * time.Hour).Format("2006-01-02 15:04:05")

	// Trial ended unpaid (Apple production, JWS says Production).
	anonDevice(t, "TRIAL", "fp:trial", "paid", past)
	storePurchase(t, anon("TRIAL"), "TRIAL", "apple", "t1", fakeJWS("Production"), 1)
	// Refunded: the server set type=free and left the 2027 expiry behind.
	anonDevice(t, "REFUND", "fp:refund", "free", "2027-11-04 10:40:58 +0000 UTC")
	storePurchase(t, anon("REFUND"), "apple_s2s", "apple", "r1", "", 0)
	fsExec(t, `INSERT INTO apple_notifications VALUES ('REFUND','Production','r1','r1')`)
	// Never subscribed.
	anonDevice(t, "NEVER", "fp:never", "free", "")
	// Active trial with auto-renew off: access until expiry.
	anonDevice(t, "ACTIVE", "fp:active", "paid", future)
	storePurchase(t, anon("ACTIVE"), "ACTIVE", "apple", "a1", fakeJWS("Production"), 1)
	// Sandbox only (App Review / TestFlight): by JWS, and by notifications only.
	anonDevice(t, "SANDBOX", "fp:sandbox", "paid", past)
	storePurchase(t, anon("SANDBOX"), "SANDBOX", "apple", "s1", fakeJWS("Sandbox"), 0)
	anonDevice(t, "SANDBOX2", "fp:sandbox2", "free", "")
	storePurchase(t, anon("SANDBOX2"), "apple_s2s", "apple", "s2", "", 0)
	fsExec(t, `INSERT INTO apple_notifications VALUES ('EXPIRED','Sandbox','s2','s2')`)
	// Expired admin gift.
	anonDevice(t, "GIFT", "fp:gift", "paid", past)
	storePurchase(t, anon("GIFT"), "GIFT", "admin", "", "", 0)
	// Owner.
	anonDevice(t, "OWNER", "fp:owner", "free", "")
	fsExec(t, `UPDATE users SET is_super = 1 WHERE email = ?`, anon("OWNER"))
	storePurchase(t, anon("OWNER"), "OWNER", "google", "g1", "tok", 0)
	// Lapsed Google subscriber on an email account; reinstalled (new install,
	// same identity_key) and still signed in to nothing paid.
	fsExec(t, `INSERT INTO users (email, subscription_type, subscription_expiry) VALUES ('g@x.com','paid',?)`, past)
	anonDevice(t, "OLD", "fp:google", "free", "")
	fsExec(t, `INSERT INTO devices (email, device_id) VALUES ('g@x.com','OLD')`)
	storePurchase(t, "g@x.com", "OLD", "google", "gp", "tok.a.b.c", 0)
	anonDevice(t, "NEW", "fp:google", "free", "")
	// Same physical device signs in to a fresh free email account.
	fsExec(t, `INSERT INTO users (email, subscription_type) VALUES ('fresh@x.com','free')`)
	// Referral premium keeps access.
	anonDevice(t, "REF", "fp:ref", "free", "")
	fsExec(t, `UPDATE users SET referral_premium_until = ? WHERE email = ?`, future, anon("REF"))
	storePurchase(t, anon("REF"), "REF", "apple", "f1", fakeJWS("Production"), 1)
	// No identity row: the install stands alone; yookassa counts as payment.
	anonDevice(t, "LONE", "", "paid", past)
	storePurchase(t, "", "LONE", "yookassa", "y1", "", 0)

	cases := []struct {
		name, email, dev string
		want             bool
	}{
		{"trial ended unpaid", anon("TRIAL"), "TRIAL", true},
		{"refund", anon("REFUND"), "REFUND", true},
		{"never subscribed", anon("NEVER"), "NEVER", false},
		{"active trial, auto-renew off", anon("ACTIVE"), "ACTIVE", false},
		{"sandbox by JWS", anon("SANDBOX"), "SANDBOX", false},
		{"sandbox by notifications", anon("SANDBOX2"), "SANDBOX2", false},
		{"expired admin gift", anon("GIFT"), "GIFT", false},
		{"is_super", anon("OWNER"), "OWNER", false},
		{"reinstall keeps the cut", anon("NEW"), "NEW", true},
		{"other free account, same device", "fresh@x.com", "NEW", true},
		{"referral premium", anon("REF"), "REF", false},
		{"no identity row, yookassa", anon("LONE"), "LONE", true},
		{"unknown caller", "ghost@x.com", "GHOST", false},
	}
	for _, c := range cases {
		if got := isFormerSubscriber(c.email, c.dev); got != c.want {
			t.Errorf("%s: isFormerSubscriber=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestFormerSubscriberPurchaseLiftsBlockDespiteCache(t *testing.T) {
	setupFormerSubscriberDB(t)
	past := time.Now().UTC().Add(-48 * time.Hour).Format("2006-01-02 15:04:05")
	anonDevice(t, "D", "fp:d", "paid", past)
	storePurchase(t, anon("D"), "D", "apple", "t1", fakeJWS("Production"), 1)
	if !isFormerSubscriber(anon("D"), "D") {
		t.Fatal("expected blocked before purchase")
	}
	future := time.Now().UTC().Add(365 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	fsExec(t, `UPDATE users SET subscription_type='paid', subscription_expiry=? WHERE email=?`, future, anon("D"))
	if isFormerSubscriber(anon("D"), "D") {
		t.Fatal("a purchase must lift the block on the next request, not after the cache TTL")
	}
}

func TestFormerSubscriberCacheExpires(t *testing.T) {
	setupFormerSubscriberDB(t)
	now := time.Now()
	formerSubscriberNow = func() time.Time { return now }
	anonDevice(t, "C", "fp:c", "free", "")
	if isFormerSubscriber(anon("C"), "C") {
		t.Fatal("never subscribed must pass")
	}
	storePurchase(t, anon("C"), "C", "google", "g", "tok", 0) // subscribed elsewhere, now lapsed
	if isFormerSubscriber(anon("C"), "C") {
		t.Fatal("within TTL the cached verdict stands")
	}
	now = now.Add(formerSubscriberCacheTTL + time.Second)
	if !isFormerSubscriber(anon("C"), "C") {
		t.Fatal("after TTL the new purchase history must count")
	}
}

func TestFormerSubscriberGateResponse(t *testing.T) {
	setupFormerSubscriberDB(t)
	past := time.Now().UTC().Add(-48 * time.Hour).Format("2006-01-02 15:04:05")
	anonDevice(t, "X", "fp:x", "free", "")
	storePurchase(t, anon("X"), "X", "apple", "t", fakeJWS("Production"), 1)
	anonDevice(t, "Y", "fp:y", "paid", past) // never a store purchase → free tier
	called := 0
	h := formerSubscriberGate(func(w http.ResponseWriter, r *http.Request) { called++ })

	call := func(email, dev string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/chatgpt", nil)
		req = req.WithContext(context.WithValue(req.Context(), "claims",
			&JWTClaims{Email: email, DeviceID: dev}))
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	rec := call(anon("X"), "X")
	if rec.Code != http.StatusPaymentRequired || called != 0 {
		t.Fatalf("former subscriber: code=%d called=%d", rec.Code, called)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != "former_subscriber" || body["reason"] != "former_subscriber" ||
		body["tier"] != "former" || body["success"] != false {
		t.Fatalf("body = %v", body)
	}
	if _, has := body["reset_at"]; has {
		t.Fatal("no reset_at: old clients would show a reset countdown")
	}
	if rec := call(anon("Y"), "Y"); rec.Code != 200 || called != 1 {
		t.Fatalf("free tier must pass: code=%d called=%d", rec.Code, called)
	}
}

// Every route whose handler reaches a paid model is gated, and nothing else.
func TestFormerSubscriberGateOnExactlyTheModelRoutes(t *testing.T) {
	src, err := os.ReadFile("astrolog_api.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`HandleFunc\("([^"]+)",\s*jwtAuthMiddleware\(formerSubscriberGate\(`)
	var got []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		got = append(got, m[1])
	}
	want := append([]string{}, formerSubscriberRoutes...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("gated routes %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("gated routes %v, want %v", got, want)
		}
	}
}
