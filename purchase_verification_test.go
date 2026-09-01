package main

// Tests for the purchase-verification hardening (2026-09-01): recordPurchase
// used to grant entitlement on the client's word for Apple (and on ANY store
// string), and the S2S webhook accepted Apple-signed notifications from other
// apps. These tests pin the new fail-closed rules.

import (
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
