package main

import (
    "bytes"
    "database/sql"
    "encoding/json"
    "net/http/httptest"
    "testing"
    "time"
)

func TestAuthLinkToken(t *testing.T) {
    tok, err := newAuthLinkToken()
    if err != nil {
        t.Fatalf("newAuthLinkToken: %v", err)
    }
    if !isAuthLinkToken(tok) {
        t.Fatalf("fresh token rejected: %q", tok)
    }
    tok2, _ := newAuthLinkToken()
    if tok == tok2 {
        t.Fatalf("two tokens identical")
    }
    for _, bad := range []string{"", "abc", tok[:47], tok + "0", "zz" + tok[2:]} {
        if isAuthLinkToken(bad) {
            t.Errorf("accepted bad token %q", bad)
        }
    }
    if got := authLinkURL(tok); got != "https://astrolytix.com/login/?t="+tok {
        t.Errorf("authLinkURL = %q", got)
    }
    if authLinkURL("") != "" {
        t.Errorf("empty token must give no link")
    }
}

// Handler-level coverage of /api/auth/verify-link against an in-memory DB:
// the e-mail login tail (completeEmailLogin) runs for real — users, devices,
// login_history — while the optional helpers (identity, referral) just log
// their missing tables and grant nothing.
func TestVerifyAuthLinkHandler(t *testing.T) {
    var err error
    db, err = sql.Open("sqlite", ":memory:")
    if err != nil {
        t.Fatalf("open db: %v", err)
    }
    defer db.Close()
    if _, err = db.Exec(`
    CREATE TABLE auth_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        device_id TEXT,
        expires_at DATETIME NOT NULL,
        used INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        subscription_type TEXT NOT NULL DEFAULT 'free',
        subscription_length TEXT NOT NULL DEFAULT 'monthly',
        subscription_expiry DATETIME,
        is_super INTEGER DEFAULT 0,
        current_device_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        device_id TEXT,
        logged_in_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        device_id TEXT NOT NULL,
        device_name TEXT,
        platform TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );`); err != nil {
        t.Fatalf("schema: %v", err)
    }
    ensureAuthLinkSchema() // the migration under test adds link_token
    JWT_SECRET_KEY = "test-secret"

    post := func(body map[string]string) EmailAuthResponse {
        raw, _ := json.Marshal(body)
        rec := httptest.NewRecorder()
        verifyAuthLink(rec, httptest.NewRequest("POST", "/api/auth/verify-link", bytes.NewReader(raw)))
        var resp EmailAuthResponse
        if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
            t.Fatalf("bad JSON %q: %v", rec.Body.String(), err)
        }
        return resp
    }
    seed := func(email, code string, expires time.Time) string {
        tok, _ := newAuthLinkToken()
        if _, err := db.Exec(`INSERT INTO auth_codes (email, code, device_id, expires_at, link_token)
                              VALUES (?, ?, '', ?, ?)`, email, code, expires, tok); err != nil {
            t.Fatalf("seed: %v", err)
        }
        return tok
    }
    used := func(tok string) int {
        var u int
        if err := db.QueryRow(`SELECT used FROM auth_codes WHERE link_token = ?`, tok).Scan(&u); err != nil {
            t.Fatalf("used(%s): %v", tok, err)
        }
        return u
    }

    // (a) valid token → tokens + email, row consumed, user + device created.
    tok := seed("link@example.com", "123456", time.Now().Add(AUTH_CODE_EXP))
    resp := post(map[string]string{"token": tok, "device_id": "dev-1", "device_name": "Test", "platform": "iOS"})
    if !resp.Success || resp.AccessToken == "" || resp.RefreshToken == "" {
        t.Fatalf("valid token: %+v", resp)
    }
    if resp.Email != "link@example.com" {
        t.Errorf("email in response = %q", resp.Email)
    }
    if used(tok) != 1 {
        t.Errorf("row not consumed after link login")
    }
    var n int
    db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = 'link@example.com'`).Scan(&n)
    if n != 1 {
        t.Errorf("user rows = %d", n)
    }
    db.QueryRow(`SELECT COUNT(*) FROM devices WHERE email = 'link@example.com' AND device_id = 'dev-1' AND revoked = 0`).Scan(&n)
    if n != 1 {
        t.Errorf("device rows = %d", n)
    }

    // (b) the same token again → link_invalid (single use); the code of
    // that row is dead too (verify-code sees no unused row).
    resp = post(map[string]string{"token": tok, "device_id": "dev-1"})
    if resp.Success || resp.Code != "link_invalid" {
        t.Errorf("reused token: %+v", resp)
    }
    db.QueryRow(`SELECT COUNT(*) FROM auth_codes WHERE email = 'link@example.com' AND used = 0`).Scan(&n)
    if n != 0 {
        t.Errorf("code half still alive after link login: %d unused rows", n)
    }

    // Unknown but well-formed token → link_invalid; malformed → link_invalid.
    other, _ := newAuthLinkToken()
    if resp = post(map[string]string{"token": other, "device_id": "dev-1"}); resp.Success || resp.Code != "link_invalid" {
        t.Errorf("unknown token: %+v", resp)
    }
    if resp = post(map[string]string{"token": "nope", "device_id": "dev-1"}); resp.Success || resp.Code != "link_invalid" {
        t.Errorf("malformed token: %+v", resp)
    }

    // (c) expired → link_expired and the row flips to used.
    tok = seed("late@example.com", "654321", time.Now().Add(-time.Minute))
    if resp = post(map[string]string{"token": tok, "device_id": "dev-2"}); resp.Success || resp.Code != "link_expired" {
        t.Errorf("expired token: %+v", resp)
    }
    if used(tok) != 1 {
        t.Errorf("expired row not consumed")
    }

    // (d) the code half consumes the link half: a code login kills the token.
    tok = seed("code@example.com", "111111", time.Now().Add(AUTH_CODE_EXP))
    db.Exec(`UPDATE auth_codes SET used = 1 WHERE email = 'code@example.com' AND code = '111111'`) // what verifyAuthCode does
    if resp = post(map[string]string{"token": tok, "device_id": "dev-3"}); resp.Success || resp.Code != "link_invalid" {
        t.Errorf("token after code login: %+v", resp)
    }

    // Missing device id is rejected before any lookup.
    tok = seed("nodev@example.com", "222222", time.Now().Add(AUTH_CODE_EXP))
    if resp = post(map[string]string{"token": tok}); resp.Success || used(tok) != 0 {
        t.Errorf("missing device_id: %+v used=%d", resp, used(tok))
    }
}
