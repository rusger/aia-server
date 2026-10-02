package main

import (
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "log"
    "net/http"
    "strings"
    "time"
)

// One-tap sign-in link (owner 2026-10-02).
//
// The verification e-mail carries, next to the 6-digit code, a link
// https://astrolytix.com/login/?t=<token>. On the phone the link opens the
// app (universal / app link, or the astrolytix:// scheme from the site's
// fallback page) and the app posts the token to /api/auth/verify-link. The
// token lives in the SAME auth_codes row as the code — same expiry, same
// single use — so whichever of the two is used first consumes both. Reading
// the mail somewhere else still works through the code.

// Public base of the sign-in link; the token rides in the query so the
// static site serves login/index.html for every token (nginx try_files).
const AUTH_LINK_BASE = "https://astrolytix.com/login/?t="

// authLinkTokenHexLen is the length of a token: 24 random bytes, hex.
const authLinkTokenHexLen = 48

// ensureAuthLinkSchema adds auth_codes.link_token (idempotent).
func ensureAuthLinkSchema() {
    if _, err := db.Exec(`ALTER TABLE auth_codes ADD COLUMN link_token TEXT`); err != nil &&
        !strings.Contains(err.Error(), "duplicate column") {
        log.Printf("⚠️ auth_codes.link_token migration: %v", err)
    }
    if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_auth_codes_link_token ON auth_codes(link_token)`); err != nil {
        log.Printf("⚠️ idx_auth_codes_link_token: %v", err)
    }
}

// newAuthLinkToken returns 24 random bytes as 48 hex characters.
func newAuthLinkToken() (string, error) {
    b := make([]byte, authLinkTokenHexLen/2)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

// authLinkURL builds the mailed link; empty token → empty string (no link
// line in the mail).
func authLinkURL(token string) string {
    if token == "" {
        return ""
    }
    return AUTH_LINK_BASE + token
}

// isAuthLinkToken is the cheap shape check before touching the database.
func isAuthLinkToken(token string) bool {
    if len(token) != authLinkTokenHexLen {
        return false
    }
    _, err := hex.DecodeString(token)
    return err == nil
}

// Request body of POST /api/auth/verify-link.
type EmailAuthVerifyLink struct {
    Token      string `json:"token"`
    DeviceID   string `json:"device_id"`
    DeviceName string `json:"device_name"`
    Platform   string `json:"platform"`
}

// verifyAuthLink completes the e-mail login from the mailed link token:
// the link-side twin of verifyAuthCode (same row, same rules, same
// completeEmailLogin tail). Errors carry a machine-readable code:
// link_invalid (unknown / already used) or link_expired.
func verifyAuthLink(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    log.Println("🔗 [verifyAuthLink] Received request")

    var req EmailAuthVerifyLink
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(EmailAuthResponse{Success: false, Error: "Invalid request format"})
        return
    }
    token := strings.ToLower(strings.TrimSpace(req.Token))
    deviceID := strings.TrimSpace(req.DeviceID)
    if !isAuthLinkToken(token) {
        json.NewEncoder(w).Encode(EmailAuthResponse{Success: false, Error: "Invalid sign-in link", Code: "link_invalid"})
        return
    }
    if deviceID == "" {
        json.NewEncoder(w).Encode(EmailAuthResponse{Success: false, Error: "Device ID is required"})
        return
    }

    var email, storedCode string
    var expiresAt time.Time
    err := db.QueryRow(`SELECT email, code, expires_at FROM auth_codes
                        WHERE link_token = ? AND used = 0
                        ORDER BY created_at DESC LIMIT 1`, token).Scan(&email, &storedCode, &expiresAt)
    if err == sql.ErrNoRows {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "This sign-in link is invalid or was already used. Enter the code from the e-mail or request a new one.",
            Code:    "link_invalid",
        })
        return
    } else if err != nil {
        log.Printf("❌ [verifyAuthLink] database error: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{Success: false, Error: "Verification failed"})
        return
    }
    if time.Now().After(expiresAt) {
        db.Exec(`UPDATE auth_codes SET used = 1 WHERE link_token = ?`, token)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "This sign-in link has expired. Please request a new code.",
            Code:    "link_expired",
        })
        return
    }

    log.Printf("🔗 [verifyAuthLink] token matched for %s (device %s)", email, deviceID)
    completeEmailLogin(w, email, storedCode, deviceID,
        strings.TrimSpace(req.DeviceName), strings.TrimSpace(req.Platform))
}
