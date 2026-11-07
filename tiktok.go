package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// TikTok "Share your horoscope video" (owner 14.09.2026)
//
// The app renders a presenter video on the device and lets the user post it
// to THEIR OWN TikTok account. TikTok's developer program approves exactly
// this kind of third-party use, not first-party autoposting, so the flow is:
//   app: Login Kit (PKCE) in the system browser → redirect to astrolytix.com
//        → deep link back with `code`
//   server (here): exchange code → tokens (client_secret never leaves the
//        server), keep per-user tokens, refresh them, and proxy the Content
//        Posting API calls that need the token. The video bytes go from the
//        phone straight to TikTok's presigned upload_url (no token needed).
//
// Env: TIKTOK_CLIENT_KEY, TIKTOK_CLIENT_SECRET (same developer app as the
// insta-agent publisher). Missing keys → 503, never a silent no-op.
// ---------------------------------------------------------------------------

const (
	tiktokOAuthURL       = "https://open.tiktokapis.com/v2/oauth/token/"
	tiktokUserInfoURL    = "https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url"
	tiktokCreatorInfoURL = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
	tiktokVideoInitURL   = "https://open.tiktokapis.com/v2/post/publish/video/init/"
	tiktokStatusURL      = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

	tiktokRefreshMargin = 5 * time.Minute
	// avatar_url is a signed CDN link (…?x-expires=<unix>&x-signature=…) that
	// dies after a few days; serving a dead one gave the app HTTP 403 floods
	// (Sentry APP-R, 25.10.2026). GET /account re-reads user/info when the
	// link is about to expire (margin), at most once per tiktokAvatarRetry on
	// failure, and once per tiktokAvatarTTL otherwise — never on every request.
	tiktokAvatarMargin = time.Hour
	tiktokAvatarRetry  = time.Hour
	tiktokAvatarTTL    = 24 * time.Hour
	tiktokMaxSingle    = 64 << 20 // TikTok: one chunk may be up to 64 MB
	tiktokChunk        = 32 << 20 // multi-chunk plan: 32 MB pieces
)

var tiktokReady atomic.Bool

// errTikTokNotConfigured lets handlers answer 503 (not a 401) when the
// server has no client key/secret.
var errTikTokNotConfigured = errors.New("TikTok client key/secret not configured")

// tiktokRefreshMu serialises token refreshes per account: TikTok rotates the
// refresh_token, so two concurrent refreshes would let the loser persist a
// dead token (review r1).
var tiktokRefreshMu sync.Map // email -> *sync.Mutex

// tiktokHTTP is swappable in tests.
var tiktokHTTP = &http.Client{Timeout: 30 * time.Second}

type tiktokAccount struct {
	Email            string
	OpenID           string
	AccessToken      string
	RefreshToken     string
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
	DisplayName      string
	AvatarURL        string
	AvatarCheckedAt  time.Time // last user/info read (zero = never)
}

func ensureTikTokSchema() {
	if tiktokReady.Load() {
		return
	}
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tiktok_accounts (
			email              TEXT PRIMARY KEY,
			open_id            TEXT NOT NULL,
			access_token       TEXT NOT NULL,
			refresh_token      TEXT NOT NULL,
			expires_at         DATETIME NOT NULL,
			refresh_expires_at DATETIME NOT NULL,
			display_name       TEXT,
			avatar_url         TEXT,
			avatar_checked_at  DATETIME,
			updated_at         DATETIME
		)`)
	if err != nil {
		log.Printf("⚠️ tiktok_accounts schema create failed: %v — will retry on next request", err)
		return
	}
	// column added 07.11.2026; tables created before that lack it
	if _, err := db.Exec(`ALTER TABLE tiktok_accounts ADD COLUMN avatar_checked_at DATETIME`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		log.Printf("⚠️ tiktok_accounts avatar_checked_at column: %v — will retry on next request", err)
		return
	}
	tiktokReady.Store(true)
}

func tiktokKeys() (string, string, error) {
	k, s := strings.TrimSpace(getEnv("TIKTOK_CLIENT_KEY", "")), strings.TrimSpace(getEnv("TIKTOK_CLIENT_SECRET", ""))
	if k == "" || s == "" {
		return "", "", errTikTokNotConfigured
	}
	return k, s, nil
}

func tiktokJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("⚠️ tiktok: write response: %v", err)
	}
}

func tiktokFail(w http.ResponseWriter, status int, msg, code string) {
	tiktokJSON(w, status, map[string]interface{}{"success": false, "error": msg, "code": code})
}

func tiktokClaims(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok || claims.Email == "" {
		tiktokFail(w, http.StatusUnauthorized, "Unauthorized", "unauthorized")
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(claims.Email)), true
}

// --- pure helpers (tested) -------------------------------------------------

// tiktokChunkPlan — TikTok FILE_UPLOAD rules: a single chunk may carry the
// whole file up to 64 MB; larger files go in 32 MB chunks with
// total_chunk_count = floor(size / chunk_size) and the LAST chunk absorbing
// the remainder (so every chunk is ≥ 5 MB and the last one < 64 MB).
// The phone uploads chunk i as bytes [i*chunk, min(size, (i+1)*chunk)) and
// the final chunk as [ (total-1)*chunk, size ).
func tiktokChunkPlan(size int64) (chunkSize int64, total int64) {
	if size <= 0 {
		return 0, 0
	}
	if size <= tiktokMaxSingle {
		return size, 1
	}
	chunkSize = tiktokChunk
	total = size / chunkSize // floor; remainder rides in the last chunk
	if total < 1 {
		total = 1
	}
	return chunkSize, total
}

func tiktokNeedsRefresh(expiresAt, now time.Time) bool {
	return !now.Add(tiktokRefreshMargin).Before(expiresAt)
}

// tiktokAPIError extracts TikTok's {"error":{"code","message"}} envelope.
// code "ok" means success.
func tiktokAPIError(body []byte) (code, message string) {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "bad_response", "TikTok returned a non-JSON response"
	}
	if env.Error.Code == "" || env.Error.Code == "ok" {
		return "ok", ""
	}
	return env.Error.Code, env.Error.Message
}

// --- storage ---------------------------------------------------------------

func tiktokLoadAccount(email string) (*tiktokAccount, error) {
	ensureTikTokSchema()
	a := &tiktokAccount{Email: email}
	var exp, rexp, checked string
	err := db.QueryRow(`SELECT open_id, access_token, refresh_token, expires_at, refresh_expires_at,
		COALESCE(display_name,''), COALESCE(avatar_url,''), COALESCE(avatar_checked_at,'') FROM tiktok_accounts WHERE email = ?`, email).
		Scan(&a.OpenID, &a.AccessToken, &a.RefreshToken, &exp, &rexp, &a.DisplayName, &a.AvatarURL, &checked)
	if err != nil {
		return nil, err
	}
	a.ExpiresAt, _ = time.Parse(time.RFC3339, exp)
	a.RefreshExpiresAt, _ = time.Parse(time.RFC3339, rexp)
	a.AvatarCheckedAt, _ = time.Parse(time.RFC3339, checked)
	return a, nil
}

func tiktokSaveAccount(a *tiktokAccount) error {
	ensureTikTokSchema()
	checked := ""
	if !a.AvatarCheckedAt.IsZero() {
		checked = a.AvatarCheckedAt.UTC().Format(time.RFC3339)
	}
	_, err := db.Exec(`INSERT INTO tiktok_accounts (email, open_id, access_token, refresh_token, expires_at, refresh_expires_at, display_name, avatar_url, avatar_checked_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(email) DO UPDATE SET open_id = excluded.open_id, access_token = excluded.access_token,
			refresh_token = excluded.refresh_token, expires_at = excluded.expires_at, refresh_expires_at = excluded.refresh_expires_at,
			display_name = excluded.display_name, avatar_url = excluded.avatar_url, avatar_checked_at = excluded.avatar_checked_at,
			updated_at = CURRENT_TIMESTAMP`,
		a.Email, a.OpenID, a.AccessToken, a.RefreshToken, a.ExpiresAt.UTC().Format(time.RFC3339),
		a.RefreshExpiresAt.UTC().Format(time.RFC3339), a.DisplayName, a.AvatarURL, checked)
	return err
}

// tiktokAvatarExpiry reads the x-expires unix timestamp TikTok's CDN signs
// into avatar_url. ok=false: no/unparseable stamp (treat as "unknown", not dead).
func tiktokAvatarExpiry(avatarURL string) (time.Time, bool) {
	u, err := url.Parse(avatarURL)
	if err != nil {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(u.Query().Get("x-expires"), 10, 64)
	if err != nil || sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// tiktokAvatarDead — the signed link is past (or within margin of) its x-expires.
func tiktokAvatarDead(avatarURL string, now time.Time) bool {
	exp, ok := tiktokAvatarExpiry(avatarURL)
	return ok && !now.Add(tiktokAvatarMargin).Before(exp)
}

// tiktokAvatarStale decides whether GET /account should re-read user/info now.
// Dead or missing link: retry no more often than tiktokAvatarRetry (a broken
// TikTok must not turn every /account into an API call). Live link: once per
// tiktokAvatarTTL so a never-expiring link still tracks name/picture changes.
func tiktokAvatarStale(a *tiktokAccount, now time.Time) bool {
	since := now.Sub(a.AvatarCheckedAt)
	if a.AvatarURL == "" || tiktokAvatarDead(a.AvatarURL, now) {
		return since >= tiktokAvatarRetry
	}
	return since >= tiktokAvatarTTL
}

// tiktokAvatarServable — what /account may hand to the app: never a dead link
// (the client would get HTTP 403 from the CDN); empty means "no avatar".
func tiktokAvatarServable(avatarURL string, now time.Time) string {
	if tiktokAvatarDead(avatarURL, now) {
		return ""
	}
	return avatarURL
}

// --- TikTok calls ----------------------------------------------------------

type tiktokTokenResp struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	OpenID           string `json:"open_id"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func tiktokTokenRequest(form url.Values) (*tiktokTokenResp, error) {
	req, err := http.NewRequest("POST", tiktokOAuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := tiktokHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var t tiktokTokenResp
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	if t.Error != "" || t.AccessToken == "" {
		return nil, fmt.Errorf("tiktok oauth: %s: %s", t.Error, t.ErrorDescription)
	}
	return &t, nil
}

// tiktokBearer does a JSON call with the user's token; returns body and the
// TikTok error code ("ok" on success).
func tiktokBearer(method, endpoint, token string, payload interface{}) ([]byte, string, string, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, "", "", err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp, err := tiktokHTTP.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", "", err
	}
	code, msg := tiktokAPIError(raw)
	return raw, code, msg, nil
}

// tiktokFreshAccount loads the user's account and refreshes the access token
// when it is about to expire. Fail closed: no account or refresh failure is an error.
func tiktokFreshAccount(email string) (*tiktokAccount, error) {
	muAny, _ := tiktokRefreshMu.LoadOrStore(email, &sync.Mutex{})
	mu := muAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	a, err := tiktokLoadAccount(email)
	if err != nil {
		return nil, fmt.Errorf("not connected")
	}
	if !tiktokNeedsRefresh(a.ExpiresAt, time.Now()) {
		return a, nil
	}
	key, secret, err := tiktokKeys()
	if err != nil {
		return nil, err
	}
	t, err := tiktokTokenRequest(url.Values{"client_key": {key}, "client_secret": {secret},
		"grant_type": {"refresh_token"}, "refresh_token": {a.RefreshToken}})
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}
	a.AccessToken, a.RefreshToken = t.AccessToken, t.RefreshToken
	a.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	if t.RefreshExpiresIn > 0 {
		a.RefreshExpiresAt = time.Now().Add(time.Duration(t.RefreshExpiresIn) * time.Second)
	}
	if t.OpenID != "" {
		a.OpenID = t.OpenID
	}
	if err := tiktokSaveAccount(a); err != nil {
		return nil, fmt.Errorf("save refreshed token: %w", err)
	}
	return a, nil
}

// --- handlers --------------------------------------------------------------

// tiktokAccountError — 503 when the server lacks keys, 401 when the user has
// no (valid) connection.
func tiktokAccountError(w http.ResponseWriter, err error) {
	if errors.Is(err, errTikTokNotConfigured) {
		tiktokFail(w, http.StatusServiceUnavailable, err.Error(), "not_configured")
		return
	}
	tiktokFail(w, http.StatusUnauthorized, err.Error(), "not_connected")
}

// POST /api/tiktok/exchange {code, code_verifier, redirect_uri}
func tiktokExchange(w http.ResponseWriter, r *http.Request) {
	email, ok := tiktokClaims(w, r)
	if !ok {
		return
	}
	key, secret, err := tiktokKeys()
	if err != nil {
		tiktokFail(w, http.StatusServiceUnavailable, err.Error(), "not_configured")
		return
	}
	var req struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		RedirectURI  string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" || req.CodeVerifier == "" || req.RedirectURI == "" {
		tiktokFail(w, http.StatusBadRequest, "code, code_verifier and redirect_uri are required", "bad_request")
		return
	}
	t, err := tiktokTokenRequest(url.Values{"client_key": {key}, "client_secret": {secret}, "code": {req.Code},
		"grant_type": {"authorization_code"}, "redirect_uri": {req.RedirectURI}, "code_verifier": {req.CodeVerifier}})
	if err != nil {
		log.Printf("⚠️ tiktok exchange for %s: %v", email, err)
		tiktokFail(w, http.StatusBadGateway, "TikTok did not accept the login code", "exchange_failed")
		return
	}
	a := &tiktokAccount{Email: email, OpenID: t.OpenID, AccessToken: t.AccessToken, RefreshToken: t.RefreshToken,
		ExpiresAt:        time.Now().Add(time.Duration(t.ExpiresIn) * time.Second),
		RefreshExpiresAt: time.Now().Add(time.Duration(t.RefreshExpiresIn) * time.Second)}
	// display name / avatar for the app's "connected as …" line
	tiktokReadUserInfo(a, time.Now())
	if err := tiktokSaveAccount(a); err != nil {
		log.Printf("⚠️ tiktok save account for %s: %v", email, err)
		tiktokFail(w, http.StatusInternalServerError, "Database error", "db")
		return
	}
	tiktokJSON(w, http.StatusOK, map[string]interface{}{"success": true, "open_id": a.OpenID,
		"display_name": a.DisplayName, "avatar_url": a.AvatarURL, "scope": t.Scope})
}

// tiktokReadUserInfo fills display name / avatar from TikTok user/info and
// stamps AvatarCheckedAt whether or not the call worked (that stamp is the
// rate limit). Failure keeps the old values; the caller saves. Returns ok.
func tiktokReadUserInfo(a *tiktokAccount, now time.Time) bool {
	a.AvatarCheckedAt = now
	raw, code, msg, err := tiktokBearer("GET", tiktokUserInfoURL, a.AccessToken, nil)
	if err != nil {
		log.Printf("⚠️ tiktok user/info for %s: %v", a.Email, err)
		return false
	}
	if code != "ok" {
		log.Printf("⚠️ tiktok user/info for %s: %s %s", a.Email, code, msg)
		return false
	}
	var u struct {
		Data struct {
			User struct {
				OpenID      string `json:"open_id"`
				DisplayName string `json:"display_name"`
				AvatarURL   string `json:"avatar_url"`
			} `json:"user"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &u) != nil || (u.Data.User.AvatarURL == "" && u.Data.User.DisplayName == "") {
		log.Printf("⚠️ tiktok user/info for %s: unexpected body", a.Email)
		return false
	}
	a.DisplayName, a.AvatarURL = u.Data.User.DisplayName, u.Data.User.AvatarURL
	if a.OpenID == "" {
		a.OpenID = u.Data.User.OpenID
	}
	return true
}

// GET /api/tiktok/account
func tiktokAccountStatus(w http.ResponseWriter, r *http.Request) {
	email, ok := tiktokClaims(w, r)
	if !ok {
		return
	}
	a, err := tiktokLoadAccount(email)
	if err != nil {
		tiktokJSON(w, http.StatusOK, map[string]interface{}{"success": true, "connected": false})
		return
	}
	now := time.Now()
	if tiktokAvatarStale(a, now) {
		// fresh token first; if the refresh itself fails we keep what we have
		// (AvatarCheckedAt is stamped only when user/info actually ran, so a
		// dead refresh token means one refresh attempt per /account — same as
		// every other TikTok handler, no extra API calls)
		if fa, err := tiktokFreshAccount(email); err != nil {
			log.Printf("⚠️ tiktok avatar refresh for %s: %v", email, err)
		} else {
			a = fa
			tiktokReadUserInfo(a, now)
			if err := tiktokSaveAccount(a); err != nil {
				log.Printf("⚠️ tiktok save account for %s: %v", email, err)
			}
		}
	}
	tiktokJSON(w, http.StatusOK, map[string]interface{}{"success": true, "connected": true, "open_id": a.OpenID,
		"display_name": a.DisplayName, "avatar_url": tiktokAvatarServable(a.AvatarURL, now),
		"refresh_expires_at": a.RefreshExpiresAt.UTC().Format(time.RFC3339)})
}

// DELETE /api/tiktok/account
func tiktokDisconnect(w http.ResponseWriter, r *http.Request) {
	email, ok := tiktokClaims(w, r)
	if !ok {
		return
	}
	ensureTikTokSchema()
	if _, err := db.Exec(`DELETE FROM tiktok_accounts WHERE email = ?`, email); err != nil {
		log.Printf("⚠️ tiktok disconnect for %s: %v", email, err)
		tiktokFail(w, http.StatusInternalServerError, "Database error", "db")
		return
	}
	tiktokJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// GET /api/tiktok/creator-info — privacy options etc. (TikTok UX requirement)
func tiktokCreatorInfo(w http.ResponseWriter, r *http.Request) {
	email, ok := tiktokClaims(w, r)
	if !ok {
		return
	}
	a, err := tiktokFreshAccount(email)
	if err != nil {
		tiktokAccountError(w, err)
		return
	}
	raw, code, msg, err := tiktokBearer("POST", tiktokCreatorInfoURL, a.AccessToken, map[string]interface{}{})
	if err != nil {
		log.Printf("⚠️ tiktok creator_info for %s: %v", email, err)
		tiktokFail(w, http.StatusBadGateway, "TikTok is unreachable", "upstream")
		return
	}
	if code != "ok" {
		tiktokFail(w, http.StatusBadGateway, msg, code)
		return
	}
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		tiktokFail(w, http.StatusBadGateway, "bad creator_info response", "bad_response")
		return
	}
	tiktokJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": out.Data})
}

// tiktokPublishRequest is what the app sends to /api/tiktok/publish/init.
type tiktokPublishRequest struct {
	Title              string `json:"title"`
	PrivacyLevel       string `json:"privacy_level"`
	DisableComment     bool   `json:"disable_comment"`
	DisableDuet        bool   `json:"disable_duet"`
	DisableStitch      bool   `json:"disable_stitch"`
	VideoSize          int64  `json:"video_size"`
	BrandContentToggle bool   `json:"brand_content_toggle"`
	BrandOrganicToggle bool   `json:"brand_organic_toggle"`
	// IsAigc: the user marked the video as AI-generated; TikTok then labels
	// the post "Creator labeled as AI-generated". Older app builds do not
	// send the field — it stays false for them.
	IsAigc bool `json:"is_aigc"`
}

// tiktokInitPayload builds the body of TikTok's video/init call (Direct Post,
// FILE_UPLOAD) from the app's request.
func tiktokInitPayload(req tiktokPublishRequest) map[string]interface{} {
	chunk, total := tiktokChunkPlan(req.VideoSize)
	return map[string]interface{}{
		"post_info": map[string]interface{}{
			"title": req.Title, "privacy_level": req.PrivacyLevel,
			"disable_comment": req.DisableComment, "disable_duet": req.DisableDuet, "disable_stitch": req.DisableStitch,
			"brand_content_toggle": req.BrandContentToggle, "brand_organic_toggle": req.BrandOrganicToggle,
			"is_aigc": req.IsAigc,
		},
		"source_info": map[string]interface{}{
			"source": "FILE_UPLOAD", "video_size": req.VideoSize, "chunk_size": chunk, "total_chunk_count": total,
		},
	}
}

// POST /api/tiktok/publish/init
func tiktokPublishInit(w http.ResponseWriter, r *http.Request) {
	email, ok := tiktokClaims(w, r)
	if !ok {
		return
	}
	var req tiktokPublishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.VideoSize <= 0 || req.PrivacyLevel == "" {
		tiktokFail(w, http.StatusBadRequest, "privacy_level and video_size are required", "bad_request")
		return
	}
	a, err := tiktokFreshAccount(email)
	if err != nil {
		tiktokAccountError(w, err)
		return
	}
	chunk, total := tiktokChunkPlan(req.VideoSize)
	payload := tiktokInitPayload(req)
	raw, code, msg, err := tiktokBearer("POST", tiktokVideoInitURL, a.AccessToken, payload)
	if err != nil {
		log.Printf("⚠️ tiktok video/init for %s: %v", email, err)
		tiktokFail(w, http.StatusBadGateway, "TikTok is unreachable", "upstream")
		return
	}
	if code != "ok" {
		log.Printf("⚠️ tiktok video/init for %s: %s %s", email, code, msg)
		tiktokFail(w, http.StatusBadGateway, msg, code)
		return
	}
	var out struct {
		Data struct {
			PublishID string `json:"publish_id"`
			UploadURL string `json:"upload_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Data.PublishID == "" {
		tiktokFail(w, http.StatusBadGateway, "bad video/init response", "bad_response")
		return
	}
	tiktokJSON(w, http.StatusOK, map[string]interface{}{"success": true, "publish_id": out.Data.PublishID,
		"upload_url": out.Data.UploadURL, "chunk_size": chunk, "total_chunk_count": total})
}

// GET /api/tiktok/publish/status?publish_id=…
func tiktokPublishStatus(w http.ResponseWriter, r *http.Request) {
	email, ok := tiktokClaims(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("publish_id"))
	if id == "" {
		tiktokFail(w, http.StatusBadRequest, "publish_id is required", "bad_request")
		return
	}
	a, err := tiktokFreshAccount(email)
	if err != nil {
		tiktokAccountError(w, err)
		return
	}
	raw, code, msg, err := tiktokBearer("POST", tiktokStatusURL, a.AccessToken, map[string]string{"publish_id": id})
	if err != nil {
		log.Printf("⚠️ tiktok status for %s: %v", email, err)
		tiktokFail(w, http.StatusBadGateway, "TikTok is unreachable", "upstream")
		return
	}
	if code != "ok" {
		tiktokFail(w, http.StatusBadGateway, msg, code)
		return
	}
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		tiktokFail(w, http.StatusBadGateway, "bad status response", "bad_response")
		return
	}
	tiktokJSON(w, http.StatusOK, map[string]interface{}{"success": true, "data": out.Data})
}
