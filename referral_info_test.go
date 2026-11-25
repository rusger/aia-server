package main

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"
)

// A201: a valid JWT whose email has no users row (device placeholder account) must get 404, not 500.
func TestReferralInfoMissingUserIs404(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE purchase_history (id INTEGER PRIMARY KEY, email TEXT)`); err != nil {
		t.Fatal(err)
	}
	referralSchemaReady.Store(false)
	defer referralSchemaReady.Store(false)

	call := func(email string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/referral/info", nil)
		req = req.WithContext(context.WithValue(req.Context(), "claims", &JWTClaims{Email: email, DeviceID: "dev-1"}))
		rec := httptest.NewRecorder()
		referralInfo(rec, req)
		return rec
	}

	if rec := call("ghost@device.astrolytix.app"); rec.Code != 404 {
		t.Fatalf("missing user: status %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}

	if _, err = db.Exec(`INSERT INTO users (email) VALUES ('real@test')`); err != nil {
		t.Fatal(err)
	}
	if rec := call("real@test"); rec.Code != 200 {
		t.Fatalf("existing user: status %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}
