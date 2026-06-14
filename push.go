package main

// APNs (Apple Push Notification service) outbound push delivery.
//
// This is SEPARATE from the inbound Apple App Store Server Notifications
// (purchase webhooks) handled in astrolog_api.go. Here we SEND pushes to
// user devices using a token-based (.p8) APNs auth key.
//
// Flow:
//   * The app registers for remote notifications, gets an APNs device token,
//     and POSTs it to /api/user/push-token (JWT-protected). We store it on the
//     devices row keyed by (email, device_id).
//   * An admin (Stellar Vault form) or the local CLI can then send a push to a
//     device by its device_id (the "unique device code") or to all of a user's
//     devices by email, via /api/admin/send-push.
//
// Build: this file is compiled alongside astrolog_api.go (see build.sh).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Config + provider auth token (ES256 JWT signed with the .p8 key)
// ---------------------------------------------------------------------------

type apnsConfig struct {
	keyPath    string
	keyID      string
	teamID     string
	bundleID   string
	production bool
	key        *ecdsa.PrivateKey
}

var (
	apnsCfg     *apnsConfig
	apnsCfgErr  error
	apnsCfgOnce sync.Once

	apnsJWT       string
	apnsJWTIssued time.Time
	apnsJWTMu     sync.Mutex
)

// loadAPNsConfig reads the APNs env vars and parses the .p8 private key once.
func loadAPNsConfig() (*apnsConfig, error) {
	apnsCfgOnce.Do(func() {
		c := &apnsConfig{
			keyPath:    getEnv("APNS_KEY_PATH", ""),
			keyID:      getEnv("APNS_KEY_ID", ""),
			teamID:     getEnv("APNS_TEAM_ID", ""),
			bundleID:   getEnv("APNS_BUNDLE_ID", getEnv("APPLE_BUNDLE_ID", "com.astrolytix.app")),
			production: strings.ToLower(getEnv("APNS_PRODUCTION", "true")) != "false",
		}
		if c.keyPath == "" || c.keyID == "" || c.teamID == "" {
			apnsCfgErr = fmt.Errorf("APNS not configured: set APNS_KEY_PATH, APNS_KEY_ID, APNS_TEAM_ID")
			return
		}
		pemBytes, err := os.ReadFile(c.keyPath)
		if err != nil {
			apnsCfgErr = fmt.Errorf("reading APNs key %s: %w", c.keyPath, err)
			return
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			apnsCfgErr = fmt.Errorf("APNs key %s is not valid PEM", c.keyPath)
			return
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			apnsCfgErr = fmt.Errorf("parsing APNs key: %w", err)
			return
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			apnsCfgErr = fmt.Errorf("APNs key is not an ECDSA key")
			return
		}
		c.key = ecKey
		apnsCfg = c
		log.Printf("✓ APNs configured (keyID=%s teamID=%s bundle=%s production=%v)",
			c.keyID, c.teamID, c.bundleID, c.production)
	})
	return apnsCfg, apnsCfgErr
}

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// apnsProviderToken returns a cached ES256 JWT, regenerating it if older than
// 40 minutes (APNs requires a fresh token between 20 and 60 minutes).
func apnsProviderToken(c *apnsConfig) (string, error) {
	apnsJWTMu.Lock()
	defer apnsJWTMu.Unlock()

	if apnsJWT != "" && time.Since(apnsJWTIssued) < 40*time.Minute {
		return apnsJWT, nil
	}

	header := base64url([]byte(fmt.Sprintf(`{"alg":"ES256","kid":"%s"}`, c.keyID)))
	claims := base64url([]byte(fmt.Sprintf(`{"iss":"%s","iat":%d}`, c.teamID, time.Now().Unix())))
	signingInput := header + "." + claims

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing APNs token: %w", err)
	}
	// ES256 signature = R||S, each left-padded to 32 bytes.
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)

	apnsJWT = signingInput + "." + base64url(sig)
	apnsJWTIssued = time.Now()
	return apnsJWT, nil
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

var apnsHTTPClient = &http.Client{Timeout: 15 * time.Second}

// sendAPNs delivers a single alert push to one APNs device token. Returns nil
// on success (HTTP 200) or an error describing the APNs rejection reason.
func sendAPNs(deviceToken, title, body, payload string) error {
	c, err := loadAPNsConfig()
	if err != nil {
		return err
	}
	jwt, err := apnsProviderToken(c)
	if err != nil {
		return err
	}

	host := "api.push.apple.com"
	if !c.production {
		host = "api.sandbox.push.apple.com"
	}

	aps := map[string]interface{}{
		"alert": map[string]string{"title": title, "body": body},
		"sound": "default",
	}
	payloadMap := map[string]interface{}{"aps": aps}
	if payload != "" {
		// Custom key the app's notification tap handler reads to deep-link.
		payloadMap["payload"] = payload
	}
	jsonBody, err := json.Marshal(payloadMap)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/3/device/%s", host, deviceToken)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", c.bundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")

	resp, err := apnsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("APNs request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	reason := strings.TrimSpace(string(respBody))
	return fmt.Errorf("APNs %d: %s (apns-id=%s)", resp.StatusCode, reason, resp.Header.Get("apns-id"))
}

// pushTarget is one resolved device row eligible to receive a push.
type pushTarget struct {
	deviceID string
	token    string
	platform string
}

// resolvePushTargets returns the eligible (non-revoked, has-token) devices for
// a device_id (exact match) or an email (all the user's devices). iOS only for
// now — Android tokens would need FCM, which we don't send yet.
func resolvePushTargets(deviceID, email string) ([]pushTarget, error) {
	var rows *sql.Rows
	var err error
	switch {
	case strings.TrimSpace(deviceID) != "":
		rows, err = db.Query(`SELECT device_id, push_token, COALESCE(platform,'') FROM devices
			WHERE device_id = ? AND revoked = 0 AND push_token IS NOT NULL AND push_token != ''`, deviceID)
	case strings.TrimSpace(email) != "":
		rows, err = db.Query(`SELECT device_id, push_token, COALESCE(platform,'') FROM devices
			WHERE email = ? AND revoked = 0 AND push_token IS NOT NULL AND push_token != ''`,
			strings.ToLower(strings.TrimSpace(email)))
	default:
		return nil, fmt.Errorf("device_id or email required")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []pushTarget
	for rows.Next() {
		var t pushTarget
		if err := rows.Scan(&t.deviceID, &t.token, &t.platform); err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// HTTP handler: store a device's push token (JWT-protected)
// ---------------------------------------------------------------------------

func registerPushToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok || claims.Email == "" || claims.DeviceID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}

	var req struct {
		PushToken string `json:"push_token"`
		Platform  string `json:"platform"`
		Language  string `json:"language"`
		TZOffset  *int   `json:"tz_offset_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}
	if strings.TrimSpace(req.PushToken) == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "push_token required"})
		return
	}
	tz := 0
	if req.TZOffset != nil {
		tz = *req.TZOffset
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	// Upsert onto the existing (email, device_id) row; create it if the device
	// hasn't been recorded yet (relies on the unique index idx_devices_email_device).
	_, err := db.Exec(`
		INSERT INTO devices (email, device_id, platform, push_token, push_token_updated_at, last_seen, language, tz_offset_minutes)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)
		ON CONFLICT(email, device_id) DO UPDATE SET
			push_token = excluded.push_token,
			push_token_updated_at = CURRENT_TIMESTAMP,
			last_seen = CURRENT_TIMESTAMP,
			platform = CASE WHEN excluded.platform != '' THEN excluded.platform ELSE devices.platform END,
			language = CASE WHEN excluded.language != '' THEN excluded.language ELSE devices.language END,
			tz_offset_minutes = excluded.tz_offset_minutes`,
		email, claims.DeviceID, req.Platform, req.PushToken, req.Language, tz)
	if err != nil {
		log.Printf("⚠️ push-token upsert failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// ---------------------------------------------------------------------------
// HTTP handler: admin sends a push to a device / user (admin secret + 2FA)
// ---------------------------------------------------------------------------

func adminSendPush(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		AdminEmail       string `json:"admin_email"`
		AdminSecret      string `json:"admin_secret"`
		VerificationCode string `json:"verification_code"`
		DeviceCode       string `json:"device_code"` // the device_id to target
		Email            string `json:"email"`       // OR target all of a user's devices
		Title            string `json:"title"`
		Message          string `json:"message"`
		Payload          string `json:"payload"` // optional deep-link, e.g. astro:birthday:...
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}

	// Same admin gate as toggle-super: admin email allowlist + secret + 2FA code.
	if !isAdminEmail(req.AdminEmail) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}
	if ADMIN_SECRET_KEY != "" && req.AdminSecret != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid admin secret"})
		return
	}
	if req.VerificationCode == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Verification code required"})
		return
	}
	var codeID int
	var expiresAt time.Time
	if err := db.QueryRow(`SELECT id, expires_at FROM auth_codes WHERE email = ? AND code = ? AND used = 0`,
		req.AdminEmail, req.VerificationCode).Scan(&codeID, &expiresAt); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid or expired verification code"})
		return
	}
	if time.Now().After(expiresAt) {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Verification code has expired"})
		return
	}
	db.Exec(`UPDATE auth_codes SET used = 1 WHERE id = ?`, codeID)

	if strings.TrimSpace(req.Message) == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "message required"})
		return
	}
	title := req.Title
	if strings.TrimSpace(title) == "" {
		title = "Astrolytix"
	}

	targets, err := resolvePushTargets(req.DeviceCode, req.Email)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	if len(targets) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "No device with a registered push token found for that code/email",
		})
		return
	}

	sent := 0
	var failures []string
	for _, t := range targets {
		if !strings.EqualFold(t.platform, "iOS") && t.platform != "" {
			failures = append(failures, fmt.Sprintf("%s: unsupported platform %q (only iOS/APNs)", t.deviceID, t.platform))
			continue
		}
		if err := sendAPNs(t.token, title, req.Message, req.Payload); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", t.deviceID, err))
			continue
		}
		sent++
	}

	log.Printf("📣 Admin %s sent push (sent=%d, failed=%d, target=%q%s)",
		req.AdminEmail, sent, len(failures), req.DeviceCode, req.Email)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  sent > 0,
		"sent":     sent,
		"failures": failures,
	})
}

// ---------------------------------------------------------------------------
// CLI: ./astrolog_api send-push <device_id> "<message>" ["<title>"]
// Runs locally on the server (where users.db + the .p8 live), bypassing HTTP
// and 2FA. Handy for testing delivery to your own device and as the basis for
// scripted/bulk client messaging.
// ---------------------------------------------------------------------------

func runSendPushCLI(args []string) {
	if len(args) < 2 {
		fmt.Println("usage: astrolog_api send-push <device_id> \"<message>\" [\"<title>\"] [\"<payload>\"]")
		os.Exit(2)
	}
	deviceID := args[0]
	message := args[1]
	title := "Astrolytix"
	if len(args) >= 3 && strings.TrimSpace(args[2]) != "" {
		title = args[2]
	}
	payload := ""
	if len(args) >= 4 {
		payload = args[3]
	}

	if _, err := loadAPNsConfig(); err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	var err error
	db, err = sql.Open("sqlite", getEnv("USERS_DB_PATH", "./users.db"))
	if err != nil {
		fmt.Printf("❌ open users.db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	targets, err := resolvePushTargets(deviceID, "")
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Printf("❌ no device with a registered push token for device_id=%q\n", deviceID)
		fmt.Println("   (the app must run once with push enabled to register its APNs token)")
		os.Exit(1)
	}

	ok := 0
	for _, t := range targets {
		if err := sendAPNs(t.token, title, message, payload); err != nil {
			fmt.Printf("❌ %s: %v\n", t.deviceID, err)
			continue
		}
		fmt.Printf("✅ sent to %s\n", t.deviceID)
		ok++
	}
	if ok == 0 {
		os.Exit(1)
	}
}
