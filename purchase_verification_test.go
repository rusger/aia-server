package main

// Tests for the purchase-verification hardening (2026-09-01): recordPurchase
// used to grant entitlement on the client's word for Apple (and on ANY store
// string), and the S2S webhook accepted Apple-signed notifications from other
// apps. These tests pin the new fail-closed rules.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsCompactJWS(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.c2ln", true},
		{"MIIT4gYJKoZIhvcNAQcCoIIT0zCCE=", false}, // SK1 base64 receipt: no dots
		{"", false},
		{"a.b", false},
		{"a.b.c.d", false},
		{"a. b.c", false}, // whitespace never appears in a compact JWS
	}
	for _, c := range cases {
		if got := isCompactJWS(c.in); got != c.want {
			t.Errorf("isCompactJWS(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCheckAppleTransactionClaims(t *testing.T) {
	const bundle = "com.astrolytix.app"
	ok := &appleTransactionInfo{
		TransactionID: "1000000123",
		BundleID:      bundle,
		ProductID:     "astrolytix_pro_monthly_v2",
	}
	if err := checkAppleTransactionClaims(ok, "astrolytix_pro_monthly_v2", bundle); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}

	foreign := *ok
	foreign.BundleID = "com.attacker.app"
	if err := checkAppleTransactionClaims(&foreign, "astrolytix_pro_monthly_v2", bundle); err == nil {
		t.Fatal("foreign bundleId accepted — cross-app replay is open")
	}

	empty := *ok
	empty.BundleID = ""
	if err := checkAppleTransactionClaims(&empty, "astrolytix_pro_monthly_v2", bundle); err == nil {
		t.Fatal("empty bundleId accepted in a purchase token")
	}

	wrongProduct := *ok
	wrongProduct.ProductID = "astrolytix_pro_lifetime"
	if err := checkAppleTransactionClaims(&wrongProduct, "astrolytix_pro_monthly_v2", bundle); err == nil {
		t.Fatal("productId mismatch accepted — a cheap product's token could buy an expensive claim")
	}

	noTxn := *ok
	noTxn.TransactionID = ""
	if err := checkAppleTransactionClaims(&noTxn, "astrolytix_pro_monthly_v2", bundle); err == nil {
		t.Fatal("missing transactionId accepted")
	}
}

func TestAppleNotificationBundleOK(t *testing.T) {
	if !appleNotificationBundleOK("com.astrolytix.app") {
		t.Fatal("our own bundleId rejected")
	}
	if !appleNotificationBundleOK("") {
		t.Fatal("empty bundleId must stay allowed (TEST notifications omit it)")
	}
	if appleNotificationBundleOK("com.attacker.app") {
		t.Fatal("foreign bundleId accepted — signed-notification replay is open")
	}
}

// TestVerifyAppleJWSRejectsSelfSignedChain builds a structurally valid ES256
// JWS whose x5c chain is self-signed (not rooted in Apple's CA) and asserts
// verifyAppleJWS rejects it. This is exactly what a forger can produce:
// correct shape, correct algorithm, wrong trust root.
func TestVerifyAppleJWSRejectsSelfSignedChain(t *testing.T) {
	makeCert := func(parentKey *ecdsa.PrivateKey, parent *x509.Certificate, cn string, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         isCA,
			BasicConstraintsValid: true,
		}
		signerKey := key
		signerCert := tmpl
		if parent != nil {
			signerKey = parentKey
			signerCert = parent
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatalf("cert: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return cert, key
	}

	rootCert, rootKey := makeCert(nil, nil, "Fake Apple Root", true)
	leafCert, leafKey := makeCert(rootKey, rootCert, "Fake Apple Leaf", false)

	header, _ := json.Marshal(map[string]interface{}{
		"alg": "ES256",
		"x5c": []string{
			base64.StdEncoding.EncodeToString(leafCert.Raw),
			base64.StdEncoding.EncodeToString(rootCert.Raw),
		},
	})
	payload, _ := json.Marshal(map[string]interface{}{
		"transactionId": "999",
		"bundleId":      "com.astrolytix.app",
		"productId":     "astrolytix_pro_lifetime",
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	forged := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	// With or without the real Apple root pool loaded, a self-signed chain
	// must never verify: no pool → fail closed, pool → chain fails.
	initAppleRootCA()
	if _, err := verifyAppleJWS(forged); err == nil {
		t.Fatal("self-signed x5c chain verified — forged purchase tokens would be accepted")
	}
}

func TestAppleCorroboratedExpiry(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE purchase_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT, store TEXT, transaction_id TEXT,
		original_transaction_id TEXT, expiry_date DATETIME)`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	// Unknown transaction: a legacy receipt with no S2S trace gets nothing.
	if known, _ := appleCorroboratedExpiry("777"); known {
		t.Fatal("unknown transaction corroborated")
	}
	if known, _ := appleCorroboratedExpiry(""); known {
		t.Fatal("empty transaction id corroborated")
	}

	// S2S placeholder row (unattributed) corroborates, with its expiry.
	expiry := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	if _, err = db.Exec(`INSERT INTO purchase_history
		(email, store, transaction_id, original_transaction_id, expiry_date)
		VALUES ('apple:555', 'apple', '555', '555', ?)`, expiry); err != nil {
		t.Fatalf("insert: %v", err)
	}
	known, got := appleCorroboratedExpiry("555")
	if !known {
		t.Fatal("S2S-recorded transaction not corroborated")
	}
	if got == nil || !got.Equal(expiry) {
		t.Fatalf("corroborated expiry = %v, want %v (client expiry must never be used)", got, expiry)
	}

	// Wrong store never corroborates an Apple claim.
	if _, err = db.Exec(`INSERT INTO purchase_history
		(email, store, transaction_id, original_transaction_id) VALUES ('u@x', 'google', '888', '888')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if known, _ := appleCorroboratedExpiry("888"); known {
		t.Fatal("google row corroborated an apple transaction")
	}
}

// ── recordPurchase handler: fail-closed status codes ─────────────────────────

// callRecordPurchase drives the real handler with an authenticated request,
// the way jwtAuthMiddleware would (claims placed in the request context).
func callRecordPurchase(t *testing.T, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/user/purchases", bytes.NewReader(payload))
	claims := &JWTClaims{Email: "buyer@test", DeviceID: "test-device"}
	req = req.WithContext(context.WithValue(req.Context(), "claims", claims))
	rec := httptest.NewRecorder()
	recordPurchase(rec, req)
	return rec
}

func setupPurchaseHandlerDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Exec(`
	CREATE TABLE users (
		email TEXT PRIMARY KEY,
		subscription_type TEXT NOT NULL DEFAULT 'free',
		subscription_length TEXT,
		subscription_expiry DATETIME,
		last_payment_method TEXT,
		app_account_token TEXT,
		updated_at DATETIME);
	CREATE TABLE purchase_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT, device_id TEXT, product_id TEXT, transaction_id TEXT,
		original_transaction_id TEXT, purchase_date DATETIME, expiry_date DATETIME,
		subscription_type TEXT, subscription_length TEXT, store TEXT,
		purchase_token TEXT, is_trial INTEGER);
	INSERT INTO users (email) VALUES ('buyer@test');`); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

func userSubscriptionType(t *testing.T, email string) string {
	t.Helper()
	var typ string
	if err := db.QueryRow(`SELECT subscription_type FROM users WHERE email=?`, email).Scan(&typ); err != nil {
		t.Fatalf("read user: %v", err)
	}
	return typ
}

func TestRecordPurchaseRejectsUnknownStore(t *testing.T) {
	setupPurchaseHandlerDB(t)
	for _, store := range []string{"admin", "yookassa", "steam", ""} {
		rec := callRecordPurchase(t, map[string]interface{}{
			"product_id":        "astrolytix_pro_lifetime",
			"store":             store,
			"subscription_type": "paid",
		})
		if rec.Code != 400 {
			t.Errorf("store %q: status %d, want 400", store, rec.Code)
		}
	}
	if got := userSubscriptionType(t, "buyer@test"); got != "free" {
		t.Fatalf("entitlement granted through store bypass: %s", got)
	}
}

func TestRecordPurchaseAppleInvalidJWSFailsClosed(t *testing.T) {
	setupPurchaseHandlerDB(t)
	// A JWS-shaped token that Apple never signed must be a hard 400.
	rec := callRecordPurchase(t, map[string]interface{}{
		"product_id":     "astrolytix_pro_lifetime",
		"store":          "apple",
		"transaction_id": "123",
		"purchase_token": "eyJhbGciOiJFUzI1NiJ9.eyJmYWtlIjp0cnVlfQ.c2ln",
	})
	if rec.Code != 400 {
		t.Fatalf("forged JWS: status %d, want 400", rec.Code)
	}
	if got := userSubscriptionType(t, "buyer@test"); got != "free" {
		t.Fatalf("forged JWS granted entitlement: %s", got)
	}
}

func TestRecordPurchaseAppleLegacyDefersWithoutS2S(t *testing.T) {
	setupPurchaseHandlerDB(t)
	rec := callRecordPurchase(t, map[string]interface{}{
		"product_id":        "astrolytix_pro_monthly_v2",
		"store":             "apple",
		"transaction_id":    "555",
		"purchase_token":    "MIIT4gYJKoZIhvcNAQcCoIIT0zCC", // SK1-style opaque receipt
		"app_account_token": "tok-abc",
		"expiry_date":       time.Now().Add(24 * time.Hour * 365 * 100).Format(time.RFC3339),
	})
	if rec.Code != 503 {
		t.Fatalf("uncorroborated legacy receipt: status %d, want 503 (retryable)", rec.Code)
	}
	if got := userSubscriptionType(t, "buyer@test"); got != "free" {
		t.Fatalf("uncorroborated legacy receipt granted entitlement: %s", got)
	}
	// The account token must be stored anyway so S2S can attribute and grant.
	var tok string
	if err := db.QueryRow(`SELECT COALESCE(app_account_token,'') FROM users WHERE email='buyer@test'`).Scan(&tok); err != nil || tok != "tok-abc" {
		t.Fatalf("app_account_token not stored on deferral (got %q, err %v)", tok, err)
	}
}

func TestRecordPurchaseGoogleVerificationErrorFailsClosed(t *testing.T) {
	setupPurchaseHandlerDB(t)
	oldFlag, oldFile, oldCreds := GOOGLE_PLAY_VERIFY_PURCHASES, GOOGLE_PLAY_CREDENTIALS_FILE, googlePlayCredentials
	GOOGLE_PLAY_VERIFY_PURCHASES = true
	GOOGLE_PLAY_CREDENTIALS_FILE = "" // access-token fetch errors instantly, no network
	googlePlayCredentials = nil
	t.Cleanup(func() {
		GOOGLE_PLAY_VERIFY_PURCHASES, GOOGLE_PLAY_CREDENTIALS_FILE, googlePlayCredentials = oldFlag, oldFile, oldCreds
	})

	rec := callRecordPurchase(t, map[string]interface{}{
		"product_id":          "astrolytix_pro_monthly_v2",
		"store":               "google",
		"transaction_id":      "g-1",
		"purchase_token":      "some-google-token",
		"subscription_length": "monthly",
	})
	if rec.Code != 503 {
		t.Fatalf("google verification error: status %d, want 503 — an error must never 'continue anyway'", rec.Code)
	}
	if got := userSubscriptionType(t, "buyer@test"); got != "free" {
		t.Fatalf("google verification error granted entitlement: %s", got)
	}
}

func TestProcessAppleNotificationForeignBundleShortCircuits(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE apple_notifications (
		notification_uuid TEXT PRIMARY KEY, notification_type TEXT, subtype TEXT,
		environment TEXT, transaction_id TEXT, original_transaction_id TEXT, product_id TEXT)`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	note := &appleNotificationPayload{NotificationType: "SUBSCRIBED", NotificationUUID: "uuid-1"}
	note.Data.BundleID = "com.attacker.app"
	txn := &appleTransactionInfo{TransactionID: "42", ProductID: "astrolytix_pro_lifetime"}

	if !processAppleNotification(note, txn) {
		t.Fatal("foreign notification should report handled (200 to stop retries)")
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM apple_notifications`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("foreign notification left %d audit rows — it reached processing", rows)
	}
}
