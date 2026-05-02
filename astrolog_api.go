package main

import (
    "bytes"
    "context"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "database/sql"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/big"
    "net/http"
    "net/smtp"
    "os"
    "os/exec"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/gorilla/mux"
    "github.com/rs/cors"
    "golang.org/x/time/rate"
    _ "modernc.org/sqlite"
)

// Configuration
var (
    SECRET_KEY         = getEnv("ASTROLOG_SECRET_KEY", "your-very-secret-key-change-this") // Legacy HMAC key (deprecated)
    JWT_SECRET_KEY     string                                                               // JWT signing key (loaded/generated on startup)
    PORT               = getEnv("PORT", "8080")
    TLS_CERT_FILE      = getEnv("TLS_CERT_FILE", "")
    TLS_KEY_FILE       = getEnv("TLS_KEY_FILE", "")
    OPENAI_API_KEY     = getEnv("OPENAI_API_KEY", "")
    USE_HTTPS          = getEnv("USE_HTTPS", "false")
    ACCESS_TOKEN_EXP   = 24 * time.Hour  // Access tokens expire in 24 hours
    REFRESH_TOKEN_EXP  = 30 * 24 * time.Hour // Refresh tokens expire in 30 days
    JWT_SECRET_FILE    = "jwt_secret.key" // File to persist JWT secret

    // SMTP Configuration for email auth
    SMTP_HOST          = getEnv("SMTP_HOST", "smtp.office365.com")
    SMTP_PORT          = getEnv("SMTP_PORT", "587")
    SMTP_USER          = getEnv("SMTP_USER", "")
    SMTP_PASSWORD      = getEnv("SMTP_PASSWORD", "")
    SMTP_FROM          = getEnv("SMTP_FROM", "Astrolytix <noreply@astrolytix.com>")
    AUTH_CODE_EXP      = 10 * time.Minute // Auth codes expire in 10 minutes

    // AI Model Configuration (server-controlled, changeable without app rebuild)
    MODEL_SUPER   = getEnv("MODEL_SUPER", "gpt-4.1")       // Super tier (was o1)
    MODEL_PREMIUM = getEnv("MODEL_PREMIUM", "gpt-4.1-mini") // Paid/trial tier (was gpt-4o)
    MODEL_ECONOMY = getEnv("MODEL_ECONOMY", "gpt-4o-mini")  // Free tier after trial

    // Google Play In-App Purchase verification
    GOOGLE_PLAY_PACKAGE_NAME     = getEnv("GOOGLE_PLAY_PACKAGE_NAME", "com.astrolytix.app")
    GOOGLE_PLAY_CREDENTIALS_FILE = getEnv("GOOGLE_PLAY_CREDENTIALS_FILE", "") // Path to service account JSON
    GOOGLE_PLAY_VERIFY_PURCHASES = getEnv("GOOGLE_PLAY_VERIFY_PURCHASES", "false") == "true"
)

// JWT Claims structure
type JWTClaims struct {
    Email              string `json:"email"`               // Primary user identity
    DeviceID           string `json:"device_id,omitempty"` // Optional device tracking
    SubscriptionType   string `json:"subscription_type"`
    SubscriptionLength string `json:"subscription_length"`
    TokenType          string `json:"token_type"` // "access" or "refresh"
    jwt.RegisteredClaims
}

// Auth response with tokens
type AuthTokensResponse struct {
    Success      bool   `json:"success"`
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int64  `json:"expires_in"` // seconds until access token expires
    Message      string `json:"message,omitempty"`
    Error        string `json:"error,omitempty"`
}

// Token refresh request
type TokenRefreshRequest struct {
    RefreshToken string `json:"refresh_token"`
}

// Generate a random secret for JWT if not provided
func generateRandomSecret() string {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        log.Fatal("Failed to generate random secret:", err)
    }
    return base64.URLEncoding.EncodeToString(bytes)
}

// Load or generate JWT secret key (persists to file)
func initJWTSecret() error {
    // Check if secret file exists
    if _, err := os.Stat(JWT_SECRET_FILE); err == nil {
        // File exists, read it
        data, err := os.ReadFile(JWT_SECRET_FILE)
        if err != nil {
            return fmt.Errorf("failed to read JWT secret file: %v", err)
        }
        JWT_SECRET_KEY = string(data)
        log.Printf("✅ JWT secret loaded from %s", JWT_SECRET_FILE)
        return nil
    }

    // File doesn't exist, generate new secret
    JWT_SECRET_KEY = generateRandomSecret()

    // Save to file with restricted permissions (0600 = read/write for owner only)
    err := os.WriteFile(JWT_SECRET_FILE, []byte(JWT_SECRET_KEY), 0600)
    if err != nil {
        return fmt.Errorf("failed to save JWT secret to file: %v", err)
    }

    log.Printf("✅ JWT secret generated and saved to %s", JWT_SECRET_FILE)
    log.Printf("   Secret will be reused on server restarts")
    return nil
}

// Request structure
type AstrologRequest struct {
    Date      string `json:"date"`      // "month day year"
    Time      string `json:"time"`      // "HH:MM"
    Timezone  string `json:"timezone"`  // GMT offset
    Longitude string `json:"longitude"`
    Latitude  string `json:"latitude"`
    ChartType string `json:"chart_type,omitempty"` // "natal" or "navamsha"
    DeviceID  string `json:"device_id"`
    Signature string `json:"signature"`
    Timestamp int64  `json:"timestamp"` // Unix timestamp for replay attack prevention
}

// Response structure
type AstrologResponse struct {
    Success bool   `json:"success"`
    Data    string `json:"data,omitempty"`
    Command string `json:"command,omitempty"`
    Error   string `json:"error,omitempty"`
}

// User registration request
type UserRegisterRequest struct {
    DeviceID           string `json:"device_id"`           // STABLE device identifier
    SubscriptionType   string `json:"subscription_type"`   // "free" or "paid"
    SubscriptionLength string `json:"subscription_length"` // "monthly" or "yearly"
    Timestamp          int64  `json:"timestamp"`           // Unix timestamp
    Signature          string `json:"signature"`           // HMAC signature
}

// User registration response
type UserRegisterResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message,omitempty"`
    Error   string `json:"error,omitempty"`
}

// ChatGPT proxy request
type ChatGPTProxyRequest struct {
    Messages   []map[string]string `json:"messages"`
    Model      string              `json:"model"`
    Temperature float64            `json:"temperature,omitempty"`
    MaxTokens   int                `json:"max_tokens,omitempty"`
    DeviceID    string             `json:"device_id"`
    Timestamp   int64              `json:"timestamp"`
    Signature   string             `json:"signature"`
}

// ChatGPT proxy response
type ChatGPTProxyResponse struct {
    Success bool   `json:"success"`
    Content string `json:"content,omitempty"`
    Error   string `json:"error,omitempty"`
}

// Email auth request - request code
type EmailAuthRequestCode struct {
    Email    string `json:"email"`
    DeviceID string `json:"device_id"` // Optional - to link email with device
}

// Email auth request - verify code
type EmailAuthVerifyCode struct {
    Email    string `json:"email"`
    Code     string `json:"code"`
    DeviceID string `json:"device_id"` // Device to associate with this email
}

// Email auth response
type EmailAuthResponse struct {
    Success      bool   `json:"success"`
    Message      string `json:"message,omitempty"`
    Error        string `json:"error,omitempty"`
    AccessToken  string `json:"access_token,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
    ExpiresIn    int64  `json:"expires_in,omitempty"`
}

// Admin subscription grant request
type AdminGrantSubscriptionRequest struct {
    Email              string `json:"email"`
    SubscriptionType   string `json:"subscription_type"`   // "paid" or "free"
    SubscriptionLength string `json:"subscription_length"` // "monthly", "yearly", "lifetime"
    DurationDays       int    `json:"duration_days"`       // Number of days (0 = permanent/lifetime)
    AdminEmail         string `json:"admin_email"`         // Must match hardcoded admin email
    AdminSecret        string `json:"admin_secret"`        // Secret key for admin operations (REQUIRED)
    VerificationCode   string `json:"verification_code"`   // 6-digit code sent to admin email
}

// Bot grant subscription request (no 2FA - authenticated via BOT_API_SECRET)
type BotGrantSubscriptionRequest struct {
    BotSecret          string `json:"bot_secret"`
    Email              string `json:"email"`
    SubscriptionType   string `json:"subscription_type"`   // "paid" or "free"
    SubscriptionLength string `json:"subscription_length"` // "monthly", "yearly", "lifetime"
    DurationDays       int    `json:"duration_days"`
    TransactionID      string `json:"transaction_id"`
    PaymentMethod      string `json:"payment_method"` // "yookassa", "stars", "crypto"
}

// Admin code request (step 1)
type AdminRequestCodeRequest struct {
    AdminEmail  string `json:"admin_email"`
    AdminSecret string `json:"admin_secret"`
}

// Purchase record request
type RecordPurchaseRequest struct {
    ProductID          string `json:"product_id"`
    TransactionID      string `json:"transaction_id"`
    PurchaseToken      string `json:"purchase_token"` // Google Play purchase token for verification
    PurchaseDate       string `json:"purchase_date"`
    ExpiryDate         string `json:"expiry_date"`
    SubscriptionType   string `json:"subscription_type"`
    SubscriptionLength string `json:"subscription_length"`
    Store              string `json:"store"` // "apple" or "google"
}

// Admin hardcoded emails (can grant subscriptions)
var ADMIN_EMAILS = []string{
    "somasuryagnilocana@gmail.com",
    // Add more admin emails here
}

// Admin secret key (REQUIRED - set via environment variable)
// Generate with: openssl rand -hex 32
var ADMIN_SECRET_KEY = getEnv("ADMIN_SECRET_KEY", "")

// Bot API secret key - used by Telegram bot to grant subscriptions without 2FA
// Generate with: openssl rand -hex 32
var BOT_API_SECRET = getEnv("BOT_API_SECRET", "")

// Device rate limiter
type DeviceLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
}

func NewDeviceLimiter() *DeviceLimiter {
    return &DeviceLimiter{
        limiters: make(map[string]*rate.Limiter),
    }
}

func (dl *DeviceLimiter) GetLimiter(deviceID string) *rate.Limiter {
    dl.mu.Lock()
    defer dl.mu.Unlock()

    limiter, exists := dl.limiters[deviceID]
    if !exists {
        // Allow burst of 20 requests for Power Periods feature (needs ~5-10 per batch)
        // Then 10 requests per second for sustained use
        // Still protected by IP limiter (30/sec) against mass-device attacks
        limiter = rate.NewLimiter(rate.Limit(10), 20)
        dl.limiters[deviceID] = limiter
    }

    // Clean old limiters (simple memory management)
    if len(dl.limiters) > 10000 {
        dl.limiters = make(map[string]*rate.Limiter)
    }

    return limiter
}

var deviceLimiter = NewDeviceLimiter()

// IP rate limiter - protects against attackers using many fake device IDs from same IP
type IPLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewIPLimiter() *IPLimiter {
	return &IPLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (il *IPLimiter) GetLimiter(ip string) *rate.Limiter {
	il.mu.Lock()
	defer il.mu.Unlock()

	limiter, exists := il.limiters[ip]
	if !exists {
		// Allow 30 requests per second per IP with burst of 50
		// Legitimate: 1 user = ~5 req/burst, even 5 users on same WiFi = 25 req
		// Attack: 100 fake devices from 1 IP hitting limits quickly
		limiter = rate.NewLimiter(rate.Limit(30), 50)
		il.limiters[ip] = limiter
	}

	// Clean old limiters periodically (simple memory management)
	if len(il.limiters) > 50000 {
		il.limiters = make(map[string]*rate.Limiter)
	}

	return limiter
}

var ipLimiter = NewIPLimiter()

// Registration rate limiter - prevents mass device creation from single IP
type RegistrationLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewRegistrationLimiter() *RegistrationLimiter {
	return &RegistrationLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (rl *RegistrationLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		// Allow 10 device registrations per IP per hour (burst of 10, refill 1 every 6 min)
		// Legitimate: family sharing WiFi might register 3-4 devices
		// Attack: can only create 10 fake devices per hour per IP
		limiter = rate.NewLimiter(rate.Every(6*time.Minute), 10)
		rl.limiters[ip] = limiter
	}

	// Clean old limiters periodically
	if len(rl.limiters) > 50000 {
		rl.limiters = make(map[string]*rate.Limiter)
	}

	return limiter
}

var registrationLimiter = NewRegistrationLimiter()

// Helper to extract client IP from request (handles proxies)
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (set by proxies like Caddy, nginx)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take first IP (original client)
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (may include port)
	ip := r.RemoteAddr
	// Remove port if present
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}

// botRenewalURL returns the external renewal URL (Telegram bot deep link),
// loaded once from env. Empty string disables external renewal entirely —
// in that case the server NEVER returns a renewal_url to clients, regardless
// of payment method. Set BOT_RENEWAL_URL=https://t.me/<botname> to enable.
var botRenewalURL = os.Getenv("BOT_RENEWAL_URL")

// isRURequest is the server-side gate that decides whether a client should
// see hints about external (non-IAP) payment options. Apple/Google policy
// forbids surfacing alternative payment paths inside the app; we only
// surface them to clearly-Russian audiences where IAP is unavailable.
//
// Conservative on purpose: false negatives (real RU users not seeing the
// hint) are acceptable; false positives (App Reviewers seeing it) are NOT.
// Currently uses Accept-Language as the primary signal — real reviewers'
// devices have en-* locale; Russian users have ru-* locale. CF-IPCountry
// is also honoured if Cloudflare is in front. IP CIDR check left as TODO
// for when a vetted RU range list is available.
func isRURequest(r *http.Request) bool {
    if r == nil {
        return false
    }
    if cc := strings.ToUpper(r.Header.Get("CF-IPCountry")); cc == "RU" {
        return true
    }
    al := strings.ToLower(r.Header.Get("Accept-Language"))
    if strings.HasPrefix(al, "ru") || strings.Contains(al, ",ru") || strings.Contains(al, " ru") {
        return true
    }
    return false
}

// computeRenewalChannel decides which renewal flow the client should show.
// "apple_iap" / "google_iap" → native store Manage Subscriptions
// "external"                  → renewal_url (Telegram bot)
// "none"                      → no renewal CTA at all
//
// The result is policy-safe: "external" is only returned when we are
// confident the client should see external options (existing YooKassa
// customers, or RU-locale free users who can't use IAP at all).
func computeRenewalChannel(lastPaymentMethod string, subscriptionType string, isRU bool) string {
    switch lastPaymentMethod {
    case "apple":
        return "apple_iap"
    case "google":
        return "google_iap"
    case "yookassa":
        return "external"
    }
    // No prior paid history (or admin-granted): only show external for free
    // RU-locale users who are deciding how to subscribe in the first place.
    if subscriptionType == "free" && isRU {
        return "external"
    }
    return "none"
}

// computeRenewalBanner returns a banner descriptor for the client to render,
// or nil if no banner should be shown. Only returned for "external" channel
// users approaching expiry — IAP users are auto-renewed by the store and
// don't need server-side reminders.
func computeRenewalBanner(channel string, expiry time.Time, lang string) map[string]interface{} {
    if channel != "external" || expiry.IsZero() {
        return nil
    }
    daysLeft := int(time.Until(expiry).Hours() / 24)
    if daysLeft > 7 || daysLeft < -1 {
        return nil
    }
    if botRenewalURL == "" {
        return nil
    }
    var title, cta string
    if strings.HasPrefix(strings.ToLower(lang), "ru") {
        cta = "Продлить"
        switch {
        case daysLeft < 0:
            title = "Подписка истекла"
        case daysLeft == 0:
            title = "Подписка истекает сегодня"
        case daysLeft == 1:
            title = "Подписка истекает завтра"
        default:
            title = fmt.Sprintf("Подписка истекает через %d дн.", daysLeft)
        }
    } else {
        cta = "Renew"
        switch {
        case daysLeft < 0:
            title = "Subscription expired"
        case daysLeft == 0:
            title = "Subscription expires today"
        case daysLeft == 1:
            title = "Subscription expires tomorrow"
        default:
            title = fmt.Sprintf("Subscription expires in %d days", daysLeft)
        }
    }
    return map[string]interface{}{
        "show":     true,
        "title":    title,
        "cta_text": cta,
        "cta_url":  botRenewalURL,
    }
}

// parseDBTime parses a timestamp string from SQLite that may have been stored
// in any of several formats — Go's default time.String() form (with nanoseconds
// + timezone), RFC3339, or the bare "YYYY-MM-DD HH:MM:SS" form.
func parseDBTime(s string) (time.Time, error) {
    formats := []string{
        "2006-01-02 15:04:05.999999999 -0700 MST",
        "2006-01-02 15:04:05.999999999Z07:00",
        time.RFC3339Nano,
        time.RFC3339,
        "2006-01-02 15:04:05",
    }
    for _, f := range formats {
        if t, err := time.Parse(f, s); err == nil {
            return t, nil
        }
    }
    return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}

// Global database connections
var db *sql.DB
var analyticsDB *sql.DB

// Initialize database
func initDB() error {
    var err error
    db, err = sql.Open("sqlite", "./users.db")
    if err != nil {
        return fmt.Errorf("failed to open database: %v", err)
    }

    // V2 SCHEMA: email as primary identity
    // IMPORTANT: Do NOT drop tables - this would delete all user data on restart!
    // Use CREATE TABLE IF NOT EXISTS to preserve existing data

    // Main users table - email is the identity
    createUsersSQL := `
    CREATE TABLE IF NOT EXISTS users (
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
    CREATE INDEX IF NOT EXISTS idx_users_subscription ON users(subscription_type);
    `
    _, err = db.Exec(createUsersSQL)
    if err != nil {
        return fmt.Errorf("failed to create users table: %v", err)
    }

    // Migration: add last_payment_method column (idempotent — sqlite errors if exists, we ignore)
    if _, mErr := db.Exec(`ALTER TABLE users ADD COLUMN last_payment_method TEXT`); mErr != nil {
        if !strings.Contains(mErr.Error(), "duplicate column") {
            log.Printf("ℹ️ users.last_payment_method migration note: %v", mErr)
        }
    }
    // Backfill last_payment_method from latest purchase_history row per email.
    // Idempotent: only updates rows where the column is still NULL.
    if _, bErr := db.Exec(`
        UPDATE users SET last_payment_method = (
            SELECT store FROM purchase_history
             WHERE purchase_history.email = users.email
             ORDER BY purchase_date DESC LIMIT 1
        )
        WHERE last_payment_method IS NULL`); bErr != nil {
        log.Printf("⚠️ Backfill last_payment_method failed: %v", bErr)
    }
    // Paid users still NULL after the join are by definition admin-granted
    // (no purchase row exists). Tag them so the client knows no self-serve
    // renewal channel applies.
    if _, bErr := db.Exec(`
        UPDATE users SET last_payment_method = 'admin'
         WHERE subscription_type = 'paid' AND last_payment_method IS NULL`); bErr != nil {
        log.Printf("⚠️ Backfill admin-granted users failed: %v", bErr)
    }

    // Auth codes for email verification
    createAuthCodesSQL := `
    CREATE TABLE IF NOT EXISTS auth_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        device_id TEXT,
        expires_at DATETIME NOT NULL,
        used INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_auth_codes_email ON auth_codes(email, used);
    `
    _, err = db.Exec(createAuthCodesSQL)
    if err != nil {
        return fmt.Errorf("failed to create auth_codes table: %v", err)
    }

    // Login history for audit
    createLoginHistorySQL := `
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        device_id TEXT,
        logged_in_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_login_history_email ON login_history(email);
    `
    _, err = db.Exec(createLoginHistorySQL)
    if err != nil {
        return fmt.Errorf("failed to create login_history table: %v", err)
    }

    // Purchase history
    createPurchaseHistorySQL := `
    CREATE TABLE IF NOT EXISTS purchase_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        device_id TEXT,
        product_id TEXT NOT NULL,
        transaction_id TEXT,
        purchase_date DATETIME NOT NULL,
        expiry_date DATETIME,
        subscription_type TEXT NOT NULL,
        subscription_length TEXT NOT NULL,
        store TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_purchase_email ON purchase_history(email);
    `
    _, err = db.Exec(createPurchaseHistorySQL)
    if err != nil {
        return fmt.Errorf("failed to create purchase_history table: %v", err)
    }

    // T2.B partner invite hashes — short codes that map to a snapshot of
    // the inviter's birth data so the recipient app can compute a
    // compatibility chart without ever asking the inviter for the data
    // again. Stored separately from the users table because invites are
    // per-share-link, not per-account, and one user can issue many.
    createInvitesSQL := `
    CREATE TABLE IF NOT EXISTS partner_invites (
        invite_hash TEXT PRIMARY KEY,
        inviter_email TEXT NOT NULL,
        inviter_name TEXT NOT NULL,
        birth_date TEXT NOT NULL,
        birth_time TEXT NOT NULL,
        birth_latitude REAL NOT NULL,
        birth_longitude REAL NOT NULL,
        birth_place TEXT NOT NULL,
        birth_timezone TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        claimed_by_email TEXT,
        claimed_at DATETIME
    );
    CREATE INDEX IF NOT EXISTS idx_invites_inviter ON partner_invites(inviter_email);
    `
    _, err = db.Exec(createInvitesSQL)
    if err != nil {
        return fmt.Errorf("failed to create partner_invites table: %v", err)
    }

    log.Println("✅ Database initialized (email as primary identity)")
    return nil
}

// Initialize analytics database (separate from main db for analytical data)
func initAnalyticsDB() error {
    var err error
    analyticsDB, err = sql.Open("sqlite", "./analytics.db")
    if err != nil {
        return fmt.Errorf("failed to open analytics database: %v", err)
    }

    // Create api_calls table to track all API usage
    createTableSQL := `
    CREATE TABLE IF NOT EXISTS api_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        call_type TEXT NOT NULL,
        model TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_api_calls_device ON api_calls(device_id);
    CREATE INDEX IF NOT EXISTS idx_api_calls_type ON api_calls(call_type);
    CREATE INDEX IF NOT EXISTS idx_api_calls_date ON api_calls(created_at);
    `

    _, err = analyticsDB.Exec(createTableSQL)
    if err != nil {
        return fmt.Errorf("failed to create api_calls table: %v", err)
    }

    // Renewal funnel: track every time the server tells a client to surface
    // an external (non-IAP) renewal CTA. Joined later against purchase_history
    // (store='yookassa') to compute exposure → conversion rate.
    _, err = analyticsDB.Exec(`
        CREATE TABLE IF NOT EXISTS renewal_impressions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            channel TEXT NOT NULL,
            days_left INTEGER,
            had_banner INTEGER DEFAULT 0,
            shown_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_renewal_email ON renewal_impressions(email);
        CREATE INDEX IF NOT EXISTS idx_renewal_shown_at ON renewal_impressions(shown_at);`)
    if err != nil {
        return fmt.Errorf("failed to create renewal_impressions table: %v", err)
    }

    // Add token columns if they don't exist (migration for existing databases)
    tokenColumnSQL := `
    ALTER TABLE api_calls ADD COLUMN prompt_tokens INTEGER DEFAULT 0;
    ALTER TABLE api_calls ADD COLUMN completion_tokens INTEGER DEFAULT 0;
    ALTER TABLE api_calls ADD COLUMN total_tokens INTEGER DEFAULT 0;
    `
    // Ignore errors - columns may already exist
    analyticsDB.Exec(tokenColumnSQL)

    // Create monthly aggregates table for historical data retention
    createMonthlyTableSQL := `
    CREATE TABLE IF NOT EXISTS api_calls_monthly (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        year_month TEXT NOT NULL,
        device_id TEXT NOT NULL,
        call_type TEXT NOT NULL,
        model TEXT,
        total_calls INTEGER DEFAULT 0,
        total_prompt_tokens INTEGER DEFAULT 0,
        total_completion_tokens INTEGER DEFAULT 0,
        total_tokens INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(year_month, device_id, call_type, model)
    );

    CREATE INDEX IF NOT EXISTS idx_monthly_date ON api_calls_monthly(year_month);
    CREATE INDEX IF NOT EXISTS idx_monthly_device ON api_calls_monthly(device_id);
    `
    _, err = analyticsDB.Exec(createMonthlyTableSQL)
    if err != nil {
        return fmt.Errorf("failed to create api_calls_monthly table: %v", err)
    }

    // Run retention cleanup on startup (async)
    go cleanupOldAnalyticsData(12) // Keep 12 months of detailed data

    // Create analytics_events table for flexible event tracking
    createEventsTableSQL := `
    CREATE TABLE IF NOT EXISTS analytics_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        event_name TEXT NOT NULL,
        properties TEXT,
        app_version TEXT,
        platform TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_events_device ON analytics_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_events_type ON analytics_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_name ON analytics_events(event_name);
    CREATE INDEX IF NOT EXISTS idx_events_date ON analytics_events(created_at);
    `

    _, err = analyticsDB.Exec(createEventsTableSQL)
    if err != nil {
        return fmt.Errorf("failed to create analytics_events table: %v", err)
    }

    log.Println("✅ Analytics database initialized successfully")
    return nil
}

// Log an API call to analytics database (without token tracking)
func logAPICall(deviceID, callType, model string) {
    logAPICallWithTokens(deviceID, callType, model, 0, 0, 0)
}

// Log an API call with token usage for cost tracking
func logAPICallWithTokens(deviceID, callType, model string, promptTokens, completionTokens, totalTokens int) {
    if analyticsDB == nil {
        return
    }
    go func() {
        _, err := analyticsDB.Exec(
            `INSERT INTO api_calls (device_id, call_type, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?, ?, ?, ?, ?, ?)`,
            deviceID, callType, model, promptTokens, completionTokens, totalTokens)
        if err != nil {
            log.Printf("⚠️ Failed to log API call: %v", err)
        }
    }()
}

// Cleanup old analytics data by aggregating into monthly summaries
func cleanupOldAnalyticsData(retentionMonths int) {
    if analyticsDB == nil {
        return
    }

    cutoffDate := fmt.Sprintf("-%d months", retentionMonths)

    // First, aggregate old data into monthly table
    aggregateSQL := `
    INSERT OR REPLACE INTO api_calls_monthly (year_month, device_id, call_type, model, total_calls, total_prompt_tokens, total_completion_tokens, total_tokens)
    SELECT
        strftime('%Y-%m', created_at) as year_month,
        device_id,
        call_type,
        model,
        COUNT(*) as total_calls,
        SUM(COALESCE(prompt_tokens, 0)) as total_prompt_tokens,
        SUM(COALESCE(completion_tokens, 0)) as total_completion_tokens,
        SUM(COALESCE(total_tokens, 0)) as total_tokens
    FROM api_calls
    WHERE created_at < date('now', ?)
    GROUP BY strftime('%Y-%m', created_at), device_id, call_type, model
    ON CONFLICT(year_month, device_id, call_type, model) DO UPDATE SET
        total_calls = excluded.total_calls,
        total_prompt_tokens = excluded.total_prompt_tokens,
        total_completion_tokens = excluded.total_completion_tokens,
        total_tokens = excluded.total_tokens;
    `

    _, err := analyticsDB.Exec(aggregateSQL, cutoffDate)
    if err != nil {
        log.Printf("⚠️ Failed to aggregate old analytics data: %v", err)
        return
    }

    // Then delete the old detailed records
    deleteSQL := `DELETE FROM api_calls WHERE created_at < date('now', ?)`
    result, err := analyticsDB.Exec(deleteSQL, cutoffDate)
    if err != nil {
        log.Printf("⚠️ Failed to delete old analytics data: %v", err)
        return
    }

    rowsDeleted, _ := result.RowsAffected()
    if rowsDeleted > 0 {
        log.Printf("🧹 Analytics cleanup: aggregated and removed %d old records (older than %d months)", rowsDeleted, retentionMonths)

        // Vacuum to reclaim space
        analyticsDB.Exec("VACUUM")
    }
}

// ============================================================
// ANALYTICS EVENT TRACKING
// ============================================================

// AnalyticsEvent represents a single analytics event
type AnalyticsEvent struct {
    DeviceID   string            `json:"device_id"`
    EventType  string            `json:"event_type"`   // 'session', 'feature', 'screen', 'error', 'action'
    EventName  string            `json:"event_name"`   // 'app_launched', 'natal_chart_opened', etc.
    Properties map[string]string `json:"properties"`   // Flexible key-value pairs
    AppVersion string            `json:"app_version"`
    Platform   string            `json:"platform"`     // 'android' or 'ios'
}

// AnalyticsEventsRequest for batch event submission
type AnalyticsEventsRequest struct {
    Events []AnalyticsEvent `json:"events"`
}

// POST /api/analytics/event - Track a single analytics event
func trackAnalyticsEvent(w http.ResponseWriter, r *http.Request) {
    if analyticsDB == nil {
        http.Error(w, "Analytics not available", http.StatusServiceUnavailable)
        return
    }

    var event AnalyticsEvent
    if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if event.DeviceID == "" || event.EventType == "" || event.EventName == "" {
        http.Error(w, "Missing required fields: device_id, event_type, event_name", http.StatusBadRequest)
        return
    }

    // Convert properties to JSON string
    propertiesJSON := ""
    if event.Properties != nil {
        if propsBytes, err := json.Marshal(event.Properties); err == nil {
            propertiesJSON = string(propsBytes)
        }
    }

    // Insert event asynchronously
    go func() {
        _, err := analyticsDB.Exec(
            `INSERT INTO analytics_events (device_id, event_type, event_name, properties, app_version, platform)
             VALUES (?, ?, ?, ?, ?, ?)`,
            event.DeviceID, event.EventType, event.EventName, propertiesJSON, event.AppVersion, event.Platform)
        if err != nil {
            log.Printf("⚠️ Failed to log analytics event: %v", err)
        }
    }()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "message": "Event tracked",
    })
}

// POST /api/analytics/events - Track multiple analytics events (batch)
func trackAnalyticsEvents(w http.ResponseWriter, r *http.Request) {
    if analyticsDB == nil {
        http.Error(w, "Analytics not available", http.StatusServiceUnavailable)
        return
    }

    var req AnalyticsEventsRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if len(req.Events) == 0 {
        http.Error(w, "No events provided", http.StatusBadRequest)
        return
    }

    // Limit batch size to prevent abuse
    if len(req.Events) > 100 {
        http.Error(w, "Maximum 100 events per batch", http.StatusBadRequest)
        return
    }

    // Insert events asynchronously
    go func() {
        tx, err := analyticsDB.Begin()
        if err != nil {
            log.Printf("⚠️ Failed to begin transaction for batch events: %v", err)
            return
        }

        stmt, err := tx.Prepare(
            `INSERT INTO analytics_events (device_id, event_type, event_name, properties, app_version, platform)
             VALUES (?, ?, ?, ?, ?, ?)`)
        if err != nil {
            tx.Rollback()
            log.Printf("⚠️ Failed to prepare statement for batch events: %v", err)
            return
        }
        defer stmt.Close()

        inserted := 0
        for _, event := range req.Events {
            if event.DeviceID == "" || event.EventType == "" || event.EventName == "" {
                continue // Skip invalid events
            }

            propertiesJSON := ""
            if event.Properties != nil {
                if propsBytes, err := json.Marshal(event.Properties); err == nil {
                    propertiesJSON = string(propsBytes)
                }
            }

            _, err := stmt.Exec(event.DeviceID, event.EventType, event.EventName, propertiesJSON, event.AppVersion, event.Platform)
            if err != nil {
                log.Printf("⚠️ Failed to insert event: %v", err)
                continue
            }
            inserted++
        }

        if err := tx.Commit(); err != nil {
            log.Printf("⚠️ Failed to commit batch events: %v", err)
            return
        }
        log.Printf("📊 Batch inserted %d analytics events", inserted)
    }()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "message": fmt.Sprintf("Queued %d events for tracking", len(req.Events)),
    })
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

// Generate JWT access token
func generateAccessToken(email, deviceID, subscriptionType, subscriptionLength string) (string, error) {
    now := time.Now()
    claims := JWTClaims{
        Email:              email,
        DeviceID:           deviceID,
        SubscriptionType:   subscriptionType,
        SubscriptionLength: subscriptionLength,
        TokenType:          "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(now.Add(ACCESS_TOKEN_EXP)),
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    "astrolog-api",
            Subject:   email, // Email is now the subject
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(JWT_SECRET_KEY))
}

// Generate JWT refresh token
func generateRefreshToken(email, deviceID, subscriptionType, subscriptionLength string) (string, error) {
    now := time.Now()
    claims := JWTClaims{
        Email:              email,
        DeviceID:           deviceID,
        SubscriptionType:   subscriptionType,
        SubscriptionLength: subscriptionLength,
        TokenType:          "refresh",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(now.Add(REFRESH_TOKEN_EXP)),
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    "astrolog-api",
            Subject:   email, // Email is now the subject
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(JWT_SECRET_KEY))
}

// Validate and parse JWT token
func validateToken(tokenString string, expectedType string) (*JWTClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Validate signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(JWT_SECRET_KEY), nil
    })

    if err != nil {
        return nil, err
    }

    if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
        // Validate token type
        if claims.TokenType != expectedType {
            return nil, fmt.Errorf("invalid token type: expected %s, got %s", expectedType, claims.TokenType)
        }
        return claims, nil
    }

    return nil, fmt.Errorf("invalid token")
}

// Extract JWT token from Authorization header
func extractTokenFromHeader(r *http.Request) (string, error) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return "", fmt.Errorf("missing authorization header")
    }

    // Expected format: "Bearer <token>"
    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        return "", fmt.Errorf("invalid authorization header format")
    }

    return parts[1], nil
}

// JWT validation middleware
func jwtAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        tokenString, err := extractTokenFromHeader(r)
        if err != nil {
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "error":   "Unauthorized: " + err.Error(),
            })
            return
        }

        claims, err := validateToken(tokenString, "access")
        if err != nil {
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "error":   "Invalid or expired token",
            })
            return
        }

        // Add claims to request context for use in handlers
        ctx := context.WithValue(r.Context(), "claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

func generateSignature(data map[string]interface{}) string {
    // Manually build sorted JSON string
    keys := make([]string, 0, len(data))
    for k := range data {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    
    // Build JSON string with sorted keys
    jsonParts := make([]string, 0, len(keys))
    for _, k := range keys {
        var valueStr string
        switch v := data[k].(type) {
        case string:
            valueStr = fmt.Sprintf(`"%s":"%s"`, k, v)
        case int64:
            valueStr = fmt.Sprintf(`"%s":%d`, k, v)
        case int:
            valueStr = fmt.Sprintf(`"%s":%d`, k, v)
        case float64:
            valueStr = fmt.Sprintf(`"%s":"%v"`, k, v)
        default:
            valueStr = fmt.Sprintf(`"%s":"%v"`, k, v)
        }
        jsonParts = append(jsonParts, valueStr)
    }
    jsonStr := "{" + strings.Join(jsonParts, ",") + "}"
    
    fmt.Printf("JSON for signature (Go): %s\n", jsonStr)
    
    h := hmac.New(sha256.New, []byte(SECRET_KEY))
    h.Write([]byte(jsonStr))
    return hex.EncodeToString(h.Sum(nil))
}

func validateSignature(req AstrologRequest) bool {
    currentTime := time.Now().Unix()
    fmt.Printf("Current server time: %d, Request timestamp: %d, Diff: %d\n", 
        currentTime, req.Timestamp, currentTime - req.Timestamp)
    
    if currentTime - req.Timestamp > 300 || req.Timestamp > currentTime + 60 {
        fmt.Printf("Timestamp validation failed\n")
        return false
    }

    // Create data map without signature
    data := map[string]interface{}{
        "date":      req.Date,
        "time":      req.Time,
        "timezone":  req.Timezone,
        "longitude": req.Longitude,
        "latitude":  req.Latitude,
        "device_id": req.DeviceID,
        "timestamp": req.Timestamp,
    }
    
    // Include chart_type in signature validation if present
    if req.ChartType != "" {
        data["chart_type"] = req.ChartType
    }

    expectedSig := generateSignature(data)
    fmt.Printf("Expected sig: %s\nReceived sig: %s\n", expectedSig, req.Signature)
    
    return hmac.Equal([]byte(req.Signature), []byte(expectedSig))
}

func sanitizeDate(date string) (string, error) {
    re := regexp.MustCompile(`^(\d{1,2}) (\d{1,2}) (\d{4})$`)
    if !re.MatchString(date) {
        return "", fmt.Errorf("invalid date format")
    }

    parts := strings.Split(date, " ")
    month, _ := strconv.Atoi(parts[0])
    day, _ := strconv.Atoi(parts[1])
    year, _ := strconv.Atoi(parts[2])

    if month < 1 || month > 12 || day < 1 || day > 31 || year < 1800 || year > 2100 {
        return "", fmt.Errorf("date out of range")
    }

    return date, nil
}

func sanitizeTime(timeStr string) (string, error) {
    re := regexp.MustCompile(`^(\d{1,2}):(\d{2})$`)
    if !re.MatchString(timeStr) {
        return "", fmt.Errorf("invalid time format")
    }

    parts := strings.Split(timeStr, ":")
    hours, _ := strconv.Atoi(parts[0])
    minutes, _ := strconv.Atoi(parts[1])

    if hours < 0 || hours > 23 || minutes < 0 || minutes > 59 {
        return "", fmt.Errorf("time out of range")
    }

    return timeStr, nil
}

func sanitizeTimezone(tz string) (string, error) {
    tzFloat, err := strconv.ParseFloat(tz, 64)
    if err != nil || tzFloat < -12 || tzFloat > 12 {
        return "", fmt.Errorf("invalid timezone")
    }
    return tz, nil
}

func sanitizeCoordinate(coord string, isLatitude bool) (string, error) {
    coordFloat, err := strconv.ParseFloat(coord, 64)
    if err != nil {
        return "", fmt.Errorf("invalid coordinate")
    }

    if isLatitude && (coordFloat < -90 || coordFloat > 90) {
        return "", fmt.Errorf("latitude out of range")
    }
    if !isLatitude && (coordFloat < -180 || coordFloat > 180) {
        return "", fmt.Errorf("longitude out of range")
    }

    return coord, nil
}

func calculateChart(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get claims from JWT middleware
    claims, ok := r.Context().Value("claims").(*JWTClaims)
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Unauthorized",
        })
        return
    }

    // Parse request
    var req AstrologRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Use device_id from JWT claims (more secure than trusting request body)
    deviceID := claims.DeviceID

    // Check IP rate limit first (protects against mass-device attacks)
    clientIP := getClientIP(r)
    ipLim := ipLimiter.GetLimiter(clientIP)
    if !ipLim.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Too many requests from your network. Please wait.",
        })
        return
    }

    // Check device rate limit
    limiter := deviceLimiter.GetLimiter(deviceID)
    if !limiter.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Rate limit exceeded. Please try again.",
        })
        return
    }

    // Sanitize inputs
    date, err := sanitizeDate(req.Date)
    if err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid date: " + err.Error(),
        })
        return
    }

    timeStr, err := sanitizeTime(req.Time)
    if err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid time: " + err.Error(),
        })
        return
    }

    timezone, err := sanitizeTimezone(req.Timezone)
    if err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid timezone: " + err.Error(),
        })
        return
    }

    longitude, err := sanitizeCoordinate(req.Longitude, false)
    if err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid longitude: " + err.Error(),
        })
        return
    }

    latitude, err := sanitizeCoordinate(req.Latitude, true)
    if err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid latitude: " + err.Error(),
        })
        return
    }

    // Build command
    dateParts := strings.Split(date, " ")
    // Invert timezone and longitude for Astrolog
    tzFloat, _ := strconv.ParseFloat(timezone, 64)
    lonFloat, _ := strconv.ParseFloat(longitude, 64)
    invertedTz := -tzFloat
    invertedLon := -lonFloat
    
    // Base arguments
    args := []string{
        "-qa",
        dateParts[0], dateParts[1], dateParts[2],
        timeStr,
        fmt.Sprintf("%g", invertedTz),
        fmt.Sprintf("%g", invertedLon),
        latitude,
    }
    
    // Add chart-specific parameters
    if req.ChartType == "navamsha" {
        // Navamsha divisional chart parameters
        args = append(args, "-s", "0.883208", "-R", "8", "9", "10", "-9", "-c", "14", "-C", "-RC", "22", "31")
        log.Printf("Calculating Navamsha chart")
    } else {
        // Natal chart parameters (default)
        args = append(args, "-s", "0.883208", "-R", "8", "9", "10", "-c", "14", "-C", "-RC", "22", "31")
        log.Printf("Calculating Natal chart")
    }
    
    // Create the full command string
    fullCommand := fmt.Sprintf("./astrolog %s", strings.Join(args, " "))
    log.Printf("Executing command: %s", fullCommand)

    // Execute command with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, "./astrolog", args...)
    cmd.Dir = "/home/ruslan/aia"
    
    output, err := cmd.Output()
    if err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Failed to calculate chart",
        })
        return
    }

    // Process output (apply sed filters)
    // The Midh (Midheaven) line is intentionally KEPT — clients use it as
    // the natal MC longitude for the T2.1 natal-aspect notification
    // detector. Older clients that don't recognise the row simply ignore
    // it (their parser regex enumerates allowed planet keys).
    lines := strings.Split(string(output), "\n")
    var filtered []string
    for _, line := range lines {
        if !strings.HasPrefix(line, "House cusp") {
            filtered = append(filtered, line)
        }
    }

    // Log API call for analytics
    chartType := req.ChartType
    if chartType == "" {
        chartType = "natal"
    }
    logAPICall(deviceID, "astrolog", chartType)

    json.NewEncoder(w).Encode(AstrologResponse{
        Success: true,
        Data:    strings.Join(filtered, "\n"),
        Command: fullCommand,
    })
}

// TransitYearRequest for batch transit calculation
type TransitYearRequest struct {
    Year      int     `json:"year"`
    Timezone  string  `json:"timezone"`
    Longitude string  `json:"longitude"`
    Latitude  string  `json:"latitude"`
    Months    []int   `json:"months,omitempty"` // Optional: specific months (1-12) to calculate
}

// TransitYearResponse contains all transit data for a year
type TransitYearResponse struct {
    Success bool              `json:"success"`
    Year    int               `json:"year"`
    Data    map[string]string `json:"data"` // date -> chart output
    Error   string            `json:"error,omitempty"`
}

// calculateTransitYear generates transit data for all days in a year
// This is much faster than 365 individual API calls
func calculateTransitYear(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get claims from JWT middleware
    claims, ok := r.Context().Value("claims").(*JWTClaims)
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(TransitYearResponse{
            Success: false,
            Error:   "Unauthorized",
        })
        return
    }

    // Parse request
    var req TransitYearRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(TransitYearResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Validate year (same range as individual astrolog endpoint: 1800-2100)
    if req.Year < 1800 || req.Year > 2100 {
        json.NewEncoder(w).Encode(TransitYearResponse{
            Success: false,
            Error:   "Invalid year (must be 1800-2100)",
        })
        return
    }

    // Check IP rate limit (more lenient for batch - only 2 per minute per IP)
    clientIP := getClientIP(r)
    // Use a separate rate limiter for batch requests (stricter)
    // For now, just check IP limiter - batch counts as many requests
    ipLim := ipLimiter.GetLimiter(clientIP)
    if !ipLim.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(TransitYearResponse{
            Success: false,
            Error:   "Too many requests. Please wait.",
        })
        return
    }

    // Sanitize inputs
    timezone, err := sanitizeTimezone(req.Timezone)
    if err != nil {
        json.NewEncoder(w).Encode(TransitYearResponse{
            Success: false,
            Error:   "Invalid timezone: " + err.Error(),
        })
        return
    }

    longitude, err := sanitizeCoordinate(req.Longitude, false)
    if err != nil {
        json.NewEncoder(w).Encode(TransitYearResponse{
            Success: false,
            Error:   "Invalid longitude: " + err.Error(),
        })
        return
    }

    latitude, err := sanitizeCoordinate(req.Latitude, true)
    if err != nil {
        json.NewEncoder(w).Encode(TransitYearResponse{
            Success: false,
            Error:   "Invalid latitude: " + err.Error(),
        })
        return
    }

    // Build set of months to calculate (default: all 12)
    monthsToCalc := make(map[int]bool)
    if len(req.Months) > 0 {
        for _, m := range req.Months {
            if m >= 1 && m <= 12 {
                monthsToCalc[m] = true
            }
        }
        log.Printf("[TransitYear] Starting batch calculation for year %d, months %v (user: %s)", req.Year, req.Months, claims.Email)
    } else {
        for m := 1; m <= 12; m++ {
            monthsToCalc[m] = true
        }
        log.Printf("[TransitYear] Starting batch calculation for year %d (all months) (user: %s)", req.Year, claims.Email)
    }
    startTime := time.Now()

    // Calculate all days in parallel with worker pool
    results := make(map[string]string)
    var resultsMu sync.Mutex
    var wg sync.WaitGroup

    // Determine days in year
    startDate := time.Date(req.Year, 1, 1, 0, 0, 0, 0, time.UTC)
    endDate := time.Date(req.Year, 12, 31, 0, 0, 0, 0, time.UTC)

    // Create job channel
    type job struct {
        date time.Time
    }
    jobs := make(chan job, 366)

    // Invert timezone and longitude for Astrolog
    tzFloat, _ := strconv.ParseFloat(timezone, 64)
    lonFloat, _ := strconv.ParseFloat(longitude, 64)
    invertedTz := -tzFloat
    invertedLon := -lonFloat

    // Start workers (10 parallel workers)
    numWorkers := 10
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := range jobs {
                dateStr := fmt.Sprintf("%d %d %d", j.date.Month(), j.date.Day(), j.date.Year())

                args := []string{
                    "-qa",
                    fmt.Sprintf("%d", j.date.Month()),
                    fmt.Sprintf("%d", j.date.Day()),
                    fmt.Sprintf("%d", j.date.Year()),
                    "12:00", // Noon for transit
                    fmt.Sprintf("%g", invertedTz),
                    fmt.Sprintf("%g", invertedLon),
                    latitude,
                    "-s", "0.883208", "-R", "8", "9", "10", "-c", "14", "-C", "-RC", "22", "31",
                }

                ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                cmd := exec.CommandContext(ctx, "./astrolog", args...)
                cmd.Dir = "/home/ruslan/aia"

                output, err := cmd.Output()
                cancel()

                if err != nil {
                    resultsMu.Lock()
                    results[dateStr] = "" // Empty string for failed dates
                    resultsMu.Unlock()
                    continue
                }

                // Filter output (mirrors the single-chart endpoint — Midh
                // is kept for parity, House cusp lines are still dropped).
                lines := strings.Split(string(output), "\n")
                var filtered []string
                for _, line := range lines {
                    if !strings.HasPrefix(line, "House cusp") {
                        filtered = append(filtered, line)
                    }
                }

                resultsMu.Lock()
                results[dateStr] = strings.Join(filtered, "\n")
                resultsMu.Unlock()
            }
        }()
    }

    // Send jobs (only for selected months)
    jobCount := 0
    for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
        if monthsToCalc[int(d.Month())] {
            jobs <- job{date: d}
            jobCount++
        }
    }
    close(jobs)

    // Wait for completion
    wg.Wait()

    elapsed := time.Since(startTime)
    log.Printf("[TransitYear] Completed year %d: %d days (requested %d) in %v (user: %s)",
        req.Year, len(results), jobCount, elapsed, claims.Email)

    // Log API call
    logAPICall(claims.DeviceID, "transit-year", fmt.Sprintf("%d", req.Year))

    json.NewEncoder(w).Encode(TransitYearResponse{
        Success: true,
        Year:    req.Year,
        Data:    results,
    })
}

// Validate signature for user registration requests
func validateUserRegisterSignature(req UserRegisterRequest) bool {
    currentTime := time.Now().Unix()

    // Check timestamp (5 min window)
    if currentTime - req.Timestamp > 300 || req.Timestamp > currentTime + 60 {
        log.Printf("User registration timestamp validation failed")
        return false
    }

    // Create data map without signature
    data := map[string]interface{}{
        "device_id":           req.DeviceID,
        "subscription_type":   req.SubscriptionType,
        "subscription_length": req.SubscriptionLength,
        "timestamp":           req.Timestamp,
    }

    expectedSig := generateSignature(data)
    return hmac.Equal([]byte(req.Signature), []byte(expectedSig))
}

// Register or update user by device ID
// Creates an anonymous user account that can be upgraded to email auth later
func registerOrUpdateUser(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Check IP rate limit for registrations (prevents mass device creation attacks)
    clientIP := getClientIP(r)
    regLim := registrationLimiter.GetLimiter(clientIP)
    if !regLim.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Too many registration attempts. Please try again later.",
        })
        return
    }

    // Parse request
    var req struct {
        DeviceID           string `json:"device_id"`
        SubscriptionType   string `json:"subscription_type"`
        SubscriptionLength string `json:"subscription_length"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("❌ [registerOrUpdateUser] Invalid request: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid request format",
        })
        return
    }

    if req.DeviceID == "" {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Device ID is required",
        })
        return
    }

    // Default subscription values
    subscriptionType := req.SubscriptionType
    if subscriptionType == "" {
        subscriptionType = "free"
    }
    subscriptionLength := req.SubscriptionLength
    if subscriptionLength == "" {
        subscriptionLength = "monthly"
    }

    // Create anonymous email from device ID
    anonymousEmail := fmt.Sprintf("%s@device.astrolytix.app", req.DeviceID)
    log.Printf("📱 [registerOrUpdateUser] Device registration: %s", req.DeviceID)

    // Check if user already exists
    var existingType, existingLength string
    var subscriptionExpiry sql.NullString
    err := db.QueryRow(`SELECT subscription_type, subscription_length, subscription_expiry FROM users WHERE email = ?`, anonymousEmail).
        Scan(&existingType, &existingLength, &subscriptionExpiry)

    if err == sql.ErrNoRows {
        // New device - create anonymous user
        _, err = db.Exec(`INSERT INTO users (email, subscription_type, subscription_length, current_device_id)
                          VALUES (?, ?, ?, ?)`,
            anonymousEmail, subscriptionType, subscriptionLength, req.DeviceID)
        if err != nil {
            log.Printf("❌ Failed to create anonymous user: %v", err)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "error":   "Failed to register device",
            })
            return
        }
        log.Printf("✅ New anonymous user created for device: %s", req.DeviceID)
    } else if err != nil {
        log.Printf("❌ Database error: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database error",
        })
        return
    } else {
        // Existing device - use stored subscription values
        subscriptionType = existingType
        subscriptionLength = existingLength

        // Check if subscription is expired
        if subscriptionExpiry.Valid && subscriptionExpiry.String != "" {
            expiryTime, err := time.Parse("2006-01-02 15:04:05", subscriptionExpiry.String)
            if err == nil && time.Now().After(expiryTime) {
                subscriptionType = "free"
                log.Printf("⚠️ Subscription expired for device: %s", req.DeviceID)
            }
        }

        log.Printf("✅ Existing device logged in: %s (plan: %s)", req.DeviceID, subscriptionType)
    }

    // Generate JWT tokens
    accessToken, err := generateAccessToken(anonymousEmail, req.DeviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("❌ Failed to generate access token: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to generate token",
        })
        return
    }

    refreshToken, err := generateRefreshToken(anonymousEmail, req.DeviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("❌ Failed to generate refresh token: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to generate token",
        })
        return
    }

    log.Printf("✅ Device auth successful: %s, tokens generated", req.DeviceID)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":       true,
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "expires_in":    int64(ACCESS_TOKEN_EXP.Seconds()),
    })
}

// Legacy endpoint - redirects to registerOrUpdateUser
func registerUser(w http.ResponseWriter, r *http.Request) {
    registerOrUpdateUser(w, r)
}

// Refresh access token using refresh token
func refreshAccessToken(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Parse request
    var req TokenRefreshRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Validate refresh token
    claims, err := validateToken(req.RefreshToken, "refresh")
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Invalid or expired refresh token",
        })
        return
    }

    // V2 SCHEMA: Verify user exists by EMAIL and get current subscription status
    email := claims.Email
    if email == "" {
        // Old token without email - require re-login
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Please login again to refresh your session",
        })
        return
    }

    var subscriptionType, subscriptionLength string
    var subscriptionExpiry sql.NullString
    query := `SELECT subscription_type, subscription_length, subscription_expiry FROM users WHERE email = ?`
    err = db.QueryRow(query, email).Scan(&subscriptionType, &subscriptionLength, &subscriptionExpiry)
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "User not found",
        })
        return
    } else if err != nil {
        log.Printf("Database error: %v", err)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Database error",
        })
        return
    }

    // Check if subscription is expired
    if subscriptionExpiry.Valid && subscriptionExpiry.String != "" {
        expiryTime, perr := parseDBTime(subscriptionExpiry.String)
        if perr != nil {
            log.Printf("⚠️ Could not parse subscription_expiry for %s: %v (raw=%q)", email, perr, subscriptionExpiry.String)
        } else if time.Now().After(expiryTime) {
            log.Printf("⚠️ Subscription expired for %s on %s — downgrading to free", email, expiryTime.Format(time.RFC3339))
            subscriptionType = "free"
        }
    }

    // Generate new access token with current subscription status
    accessToken, err := generateAccessToken(email, claims.DeviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("Failed to generate access token: %v", err)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    // Optionally generate new refresh token (token rotation for better security)
    newRefreshToken, err := generateRefreshToken(email, claims.DeviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("Failed to generate refresh token: %v", err)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    log.Printf("🔄 Token refreshed for user: %s", email)

    // Return new tokens
    json.NewEncoder(w).Encode(AuthTokensResponse{
        Success:      true,
        AccessToken:  accessToken,
        RefreshToken: newRefreshToken,
        ExpiresIn:    int64(ACCESS_TOKEN_EXP.Seconds()),
        Message:      "Token refreshed successfully",
    })
}


// Validate signature for ChatGPT proxy requests
func validateChatGPTSignature(req ChatGPTProxyRequest) bool {
    currentTime := time.Now().Unix()

    // Check timestamp (5 min window)
    if currentTime - req.Timestamp > 300 || req.Timestamp > currentTime + 60 {
        log.Printf("ChatGPT request timestamp validation failed")
        return false
    }

    // Create data map without signature
    data := map[string]interface{}{
        "device_id": req.DeviceID,
        "timestamp": req.Timestamp,
        "model":     req.Model,
    }

    expectedSig := generateSignature(data)
    return hmac.Equal([]byte(req.Signature), []byte(expectedSig))
}

// Proxy ChatGPT requests (keeps API key on server)
func chatGPTProxy(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get claims from JWT middleware
    claims, ok := r.Context().Value("claims").(*JWTClaims)
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Unauthorized",
        })
        return
    }

    // Check if OpenAI API key is configured
    if OPENAI_API_KEY == "" {
        log.Printf("❌ OpenAI API key not configured")
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "ChatGPT service not configured on server",
        })
        return
    }

    // Parse request
    var req ChatGPTProxyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Use device_id from JWT claims (more secure than trusting request body)
    deviceID := claims.DeviceID

    // Check IP rate limit first (protects against mass-device attacks)
    clientIP := getClientIP(r)
    ipLim := ipLimiter.GetLimiter(clientIP)
    if !ipLim.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Too many requests from your network. Please wait.",
        })
        return
    }

    // Rate limiting for ChatGPT requests per device
    limiter := deviceLimiter.GetLimiter(deviceID)
    if !limiter.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Rate limit exceeded. Please try again.",
        })
        return
    }

    log.Printf("🤖 Proxying ChatGPT request for device: %s, model: %s", deviceID, req.Model)

    // Check if this is an o1 model (has different API requirements)
    isO1Model := req.Model == "o1" || strings.HasPrefix(req.Model, "o1-")

    // Process messages for o1 model (convert system messages to user messages)
    messages := req.Messages
    if isO1Model {
        processedMessages := make([]map[string]string, 0, len(req.Messages))
        for _, msg := range req.Messages {
            if msg["role"] == "system" {
                // o1 doesn't support system role - convert to user
                processedMessages = append(processedMessages, map[string]string{
                    "role":    "user",
                    "content": msg["content"],
                })
            } else {
                processedMessages = append(processedMessages, msg)
            }
        }
        messages = processedMessages
        log.Printf("🤖 o1 model detected - converted %d messages (system→user)", len(messages))
    }

    // Prepare OpenAI API request
    openAIRequest := map[string]interface{}{
        "model":    req.Model,
        "messages": messages,
    }

    // o1 models don't support temperature parameter
    if req.Temperature > 0 && !isO1Model {
        openAIRequest["temperature"] = req.Temperature
    }

    // o1 models use max_completion_tokens instead of max_tokens
    if req.MaxTokens > 0 {
        if isO1Model {
            openAIRequest["max_completion_tokens"] = req.MaxTokens
        } else {
            openAIRequest["max_tokens"] = req.MaxTokens
        }
    }

    requestBody, err := json.Marshal(openAIRequest)
    if err != nil {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Failed to prepare request",
        })
        return
    }

    // Call OpenAI API (o1 models are slower, need longer timeout)
    timeout := 120 * time.Second
    if isO1Model {
        timeout = 180 * time.Second
    }
    client := &http.Client{Timeout: timeout}
    openAIReq, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(requestBody))
    if err != nil {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Failed to create request",
        })
        return
    }

    openAIReq.Header.Set("Content-Type", "application/json")
    openAIReq.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)

    resp, err := client.Do(openAIReq)
    if err != nil {
        log.Printf("❌ OpenAI API error: %v", err)
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Failed to connect to ChatGPT",
        })
        return
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Failed to read response",
        })
        return
    }

    if resp.StatusCode != 200 {
        log.Printf("❌ OpenAI API error status %d: %s", resp.StatusCode, string(body))
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   fmt.Sprintf("ChatGPT API error: %d", resp.StatusCode),
        })
        return
    }

    // Parse OpenAI response
    var openAIResp map[string]interface{}
    if err := json.Unmarshal(body, &openAIResp); err != nil {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Failed to parse response",
        })
        return
    }

    // Extract content from response
    choices, ok := openAIResp["choices"].([]interface{})
    if !ok || len(choices) == 0 {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Invalid response format",
        })
        return
    }

    firstChoice, ok := choices[0].(map[string]interface{})
    if !ok {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Invalid choice format",
        })
        return
    }

    message, ok := firstChoice["message"].(map[string]interface{})
    if !ok {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Invalid message format",
        })
        return
    }

    content, ok := message["content"].(string)
    if !ok {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Invalid content format",
        })
        return
    }

    // Extract token usage from response
    var promptTokens, completionTokens, totalTokens int
    if usage, ok := openAIResp["usage"].(map[string]interface{}); ok {
        if pt, ok := usage["prompt_tokens"].(float64); ok {
            promptTokens = int(pt)
        }
        if ct, ok := usage["completion_tokens"].(float64); ok {
            completionTokens = int(ct)
        }
        if tt, ok := usage["total_tokens"].(float64); ok {
            totalTokens = int(tt)
        }
    }

    log.Printf("✅ ChatGPT request successful, response length: %d, tokens: %d prompt + %d completion = %d total",
        len(content), promptTokens, completionTokens, totalTokens)

    // Log API call with token usage for analytics
    logAPICallWithTokens(deviceID, "chatgpt", req.Model, promptTokens, completionTokens, totalTokens)

    // Return success response
    json.NewEncoder(w).Encode(ChatGPTProxyResponse{
        Success: true,
        Content: content,
    })
}

// Get user subscription info by EMAIL (v2 schema)
func getUserInfo(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get claims from JWT middleware
    claims, ok := r.Context().Value("claims").(*JWTClaims)
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    // Use EMAIL from JWT claims as primary identity (v2 schema)
    email := claims.Email
    if email == "" {
        // Fallback for old tokens that might not have email
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Please login again to refresh your session",
        })
        return
    }

    var subscriptionType, subscriptionLength string
    var createdAt, updatedAt string
    var subscriptionExpiry sql.NullString
    var isSuper int
    var currentDeviceID sql.NullString
    var lastPaymentMethod sql.NullString

    query := `SELECT subscription_type, subscription_length, subscription_expiry, created_at, updated_at, COALESCE(is_super, 0), current_device_id, last_payment_method
              FROM users WHERE email = ?`

    err := db.QueryRow(query, email).Scan(&subscriptionType, &subscriptionLength, &subscriptionExpiry, &createdAt, &updatedAt, &isSuper, &currentDeviceID, &lastPaymentMethod)
    if err == sql.ErrNoRows {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "User not found",
        })
        return
    } else if err != nil {
        log.Printf("Database error: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database error",
        })
        return
    }

    // Check if subscription is expired
    effectiveSubType := subscriptionType
    if subscriptionExpiry.Valid && subscriptionExpiry.String != "" {
        // Try multiple date formats (Go stores with timezone info)
        var expiryTime time.Time
        var err error
        formats := []string{
            "2006-01-02 15:04:05.999999999 -0700 MST",
            "2006-01-02 15:04:05.999999999 +0000 UTC",
            "2006-01-02 15:04:05",
            time.RFC3339,
        }
        for _, format := range formats {
            expiryTime, err = time.Parse(format, subscriptionExpiry.String)
            if err == nil {
                break
            }
        }
        if err == nil && time.Now().After(expiryTime) {
            effectiveSubType = "free" // Subscription expired
        }
    }

    log.Printf("📊 [getUserInfo] email=%s, db_type=%s, effective_type=%s, expiry=%s",
        email, subscriptionType, effectiveSubType, subscriptionExpiry.String)

    // Renewal channel & external-payment surfacing.
    // The client must NOT decide whether to show external (non-IAP) renewal —
    // the server is the only authority. Apple/Google policy violation risk.
    isRU := isRURequest(r)
    renewalChannel := computeRenewalChannel(lastPaymentMethod.String, effectiveSubType, isRU)
    var renewalURL interface{} = nil
    if renewalChannel == "external" && botRenewalURL != "" {
        renewalURL = botRenewalURL
    }
    var renewalBanner interface{} = nil
    var bannerDaysLeft int = -999
    if renewalChannel == "external" && subscriptionExpiry.Valid {
        if expT, perr := parseDBTime(subscriptionExpiry.String); perr == nil {
            if b := computeRenewalBanner(renewalChannel, expT, r.Header.Get("Accept-Language")); b != nil {
                renewalBanner = b
                bannerDaysLeft = int(time.Until(expT).Hours() / 24)
            }
        }
    }

    // Log every external impression once per day per email (funnel analytics).
    // Idempotent-ish via the WHERE NOT EXISTS guard. Apple/Google channels
    // are not logged (no funnel to analyze — store handles renewal).
    if renewalChannel == "external" && analyticsDB != nil {
        had := 0
        if renewalBanner != nil {
            had = 1
        }
        analyticsDB.Exec(`
            INSERT INTO renewal_impressions (email, channel, days_left, had_banner)
            SELECT ?, ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM renewal_impressions
                 WHERE email = ?
                   AND date(shown_at) = date('now')
            )`, email, renewalChannel, bannerDaysLeft, had, email)
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":              true,
        "email":                email,
        "device_id":            currentDeviceID.String, // For backward compatibility
        "subscription_type":    effectiveSubType,
        "subscription_length":  subscriptionLength,
        "subscription_expiry":  subscriptionExpiry.String,
        "is_super":             isSuper == 1,
        "created_at":           createdAt,
        "updated_at":           updatedAt,
        "model_super":          MODEL_SUPER,
        "model_premium":        MODEL_PREMIUM,
        "model_economy":        MODEL_ECONOMY,
        "last_payment_method":  lastPaymentMethod.String,
        "renewal_channel":      renewalChannel,
        "renewal_url":          renewalURL,
        "renewal_banner":       renewalBanner,
    })
}

// ============================================
// GOOGLE PLAY IN-APP PURCHASE VERIFICATION
// ============================================

// GooglePlayCredentials holds service account credentials
type GooglePlayCredentials struct {
    Type                    string `json:"type"`
    ProjectID               string `json:"project_id"`
    PrivateKeyID            string `json:"private_key_id"`
    PrivateKey              string `json:"private_key"`
    ClientEmail             string `json:"client_email"`
    ClientID                string `json:"client_id"`
    AuthURI                 string `json:"auth_uri"`
    TokenURI                string `json:"token_uri"`
    AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
    ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// GooglePlayPurchaseResponse is the response from Google Play API
type GooglePlayPurchaseResponse struct {
    // For subscriptions
    Kind                        string `json:"kind"`
    StartTimeMillis             string `json:"startTimeMillis"`
    ExpiryTimeMillis            string `json:"expiryTimeMillis"`
    AutoRenewing                bool   `json:"autoRenewing"`
    PriceCurrencyCode           string `json:"priceCurrencyCode"`
    PriceAmountMicros           string `json:"priceAmountMicros"`
    PaymentState                int    `json:"paymentState"` // 0=pending, 1=received, 2=free trial, 3=deferred
    CancelReason                int    `json:"cancelReason"`
    OrderID                     string `json:"orderId"`
    AcknowledgementState        int    `json:"acknowledgementState"` // 0=not acknowledged, 1=acknowledged
    // For one-time products
    PurchaseState               int    `json:"purchaseState"` // 0=purchased, 1=canceled, 2=pending
    ConsumptionState            int    `json:"consumptionState"` // 0=not consumed, 1=consumed
    PurchaseTimeMillis          string `json:"purchaseTimeMillis"`
    // Error fields
    Error                       *GooglePlayError `json:"error,omitempty"`
}

type GooglePlayError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Status  string `json:"status"`
}

var googlePlayAccessToken string
var googlePlayTokenExpiry time.Time
var googlePlayCredentials *GooglePlayCredentials
var googlePlayTokenMutex sync.Mutex

// loadGooglePlayCredentials loads the service account credentials from file
func loadGooglePlayCredentials() error {
    if GOOGLE_PLAY_CREDENTIALS_FILE == "" {
        return fmt.Errorf("GOOGLE_PLAY_CREDENTIALS_FILE not set")
    }

    data, err := os.ReadFile(GOOGLE_PLAY_CREDENTIALS_FILE)
    if err != nil {
        return fmt.Errorf("failed to read credentials file: %v", err)
    }

    googlePlayCredentials = &GooglePlayCredentials{}
    if err := json.Unmarshal(data, googlePlayCredentials); err != nil {
        return fmt.Errorf("failed to parse credentials: %v", err)
    }

    log.Println("✅ Google Play credentials loaded")
    return nil
}

// getGooglePlayAccessToken gets a valid OAuth2 access token for Google Play API
func getGooglePlayAccessToken() (string, error) {
    googlePlayTokenMutex.Lock()
    defer googlePlayTokenMutex.Unlock()

    // Return cached token if still valid
    if googlePlayAccessToken != "" && time.Now().Before(googlePlayTokenExpiry.Add(-5*time.Minute)) {
        return googlePlayAccessToken, nil
    }

    if googlePlayCredentials == nil {
        if err := loadGooglePlayCredentials(); err != nil {
            return "", err
        }
    }

    // Create JWT for service account
    now := time.Now()
    claims := jwt.MapClaims{
        "iss":   googlePlayCredentials.ClientEmail,
        "scope": "https://www.googleapis.com/auth/androidpublisher",
        "aud":   "https://oauth2.googleapis.com/token",
        "iat":   now.Unix(),
        "exp":   now.Add(time.Hour).Unix(),
    }

    // Parse private key
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

    // Parse PEM private key
    privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(googlePlayCredentials.PrivateKey))
    if err != nil {
        return "", fmt.Errorf("failed to parse private key: %v", err)
    }

    signedJWT, err := token.SignedString(privateKey)
    if err != nil {
        return "", fmt.Errorf("failed to sign JWT: %v", err)
    }

    // Exchange JWT for access token
    resp, err := http.PostForm("https://oauth2.googleapis.com/token", map[string][]string{
        "grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
        "assertion":  {signedJWT},
    })
    if err != nil {
        return "", fmt.Errorf("token exchange failed: %v", err)
    }
    defer resp.Body.Close()

    var tokenResp struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
        TokenType   string `json:"token_type"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return "", fmt.Errorf("failed to decode token response: %v", err)
    }

    if tokenResp.AccessToken == "" {
        body, _ := io.ReadAll(resp.Body)
        return "", fmt.Errorf("no access token in response: %s", string(body))
    }

    googlePlayAccessToken = tokenResp.AccessToken
    googlePlayTokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

    log.Println("✅ Google Play access token refreshed")
    return googlePlayAccessToken, nil
}

// verifyGooglePlayPurchase verifies a purchase with Google Play API
// Returns (isValid, expiryTime, error)
func verifyGooglePlayPurchase(productID, purchaseToken string, isSubscription bool) (bool, *time.Time, error) {
    if !GOOGLE_PLAY_VERIFY_PURCHASES {
        log.Println("⚠️ Google Play verification disabled, skipping verification")
        return true, nil, nil
    }

    accessToken, err := getGooglePlayAccessToken()
    if err != nil {
        return false, nil, fmt.Errorf("failed to get access token: %v", err)
    }

    var apiURL string
    if isSubscription {
        apiURL = fmt.Sprintf(
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/subscriptions/%s/tokens/%s",
            GOOGLE_PLAY_PACKAGE_NAME, productID, purchaseToken,
        )
    } else {
        // One-time purchase (lifetime)
        apiURL = fmt.Sprintf(
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/products/%s/tokens/%s",
            GOOGLE_PLAY_PACKAGE_NAME, productID, purchaseToken,
        )
    }

    req, err := http.NewRequest("GET", apiURL, nil)
    if err != nil {
        return false, nil, err
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return false, nil, fmt.Errorf("API request failed: %v", err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    log.Printf("🔍 Google Play API response (%d): %s", resp.StatusCode, string(body))

    if resp.StatusCode != 200 {
        return false, nil, fmt.Errorf("Google Play API error: %s", string(body))
    }

    var purchaseResp GooglePlayPurchaseResponse
    if err := json.Unmarshal(body, &purchaseResp); err != nil {
        return false, nil, fmt.Errorf("failed to parse response: %v", err)
    }

    if isSubscription {
        // For subscriptions, check payment state
        // PaymentState: 0=pending, 1=received, 2=free trial, 3=deferred
        if purchaseResp.PaymentState != 1 && purchaseResp.PaymentState != 2 {
            log.Printf("⚠️ Subscription payment not received, state: %d", purchaseResp.PaymentState)
            return false, nil, nil
        }

        // Parse expiry time
        if purchaseResp.ExpiryTimeMillis != "" {
            expiryMillis, _ := strconv.ParseInt(purchaseResp.ExpiryTimeMillis, 10, 64)
            expiryTime := time.Unix(0, expiryMillis*int64(time.Millisecond))
            if time.Now().After(expiryTime) {
                log.Printf("⚠️ Subscription expired at %v", expiryTime)
                return false, &expiryTime, nil
            }
            log.Printf("✅ Subscription valid until %v", expiryTime)
            return true, &expiryTime, nil
        }
    } else {
        // For one-time products, check purchase state
        // PurchaseState: 0=purchased, 1=canceled, 2=pending
        if purchaseResp.PurchaseState != 0 {
            log.Printf("⚠️ One-time purchase not valid, state: %d", purchaseResp.PurchaseState)
            return false, nil, nil
        }
        log.Println("✅ One-time purchase verified")
        return true, nil, nil
    }

    return true, nil, nil
}

// Record a purchase in the purchase history
func recordPurchase(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get claims from JWT middleware
    claims, ok := r.Context().Value("claims").(*JWTClaims)
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    deviceID := claims.DeviceID
    email := claims.Email // Get email from JWT (includes anonymous device emails)

    var req RecordPurchaseRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid request body",
        })
        return
    }

    // Validate required fields
    if req.ProductID == "" || req.Store == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "product_id and store are required",
        })
        return
    }

    // Parse purchase date (use current time if not provided)
    purchaseDate := time.Now()
    if req.PurchaseDate != "" {
        parsed, err := time.Parse(time.RFC3339, req.PurchaseDate)
        if err == nil {
            purchaseDate = parsed
        }
    }

    // Parse expiry date (optional)
    var expiryDate *time.Time
    if req.ExpiryDate != "" {
        parsed, err := time.Parse(time.RFC3339, req.ExpiryDate)
        if err == nil {
            expiryDate = &parsed
        }
    }

    // Verify Google Play purchase if enabled and it's a Google purchase
    if req.Store == "google" && req.PurchaseToken != "" {
        // Determine if it's a subscription or one-time purchase
        isSubscription := req.SubscriptionLength == "monthly" || req.SubscriptionLength == "yearly"

        isValid, verifiedExpiry, err := verifyGooglePlayPurchase(req.ProductID, req.PurchaseToken, isSubscription)
        if err != nil {
            log.Printf("⚠️ Google Play verification error (continuing anyway): %v", err)
            // Don't fail the purchase if verification has issues - log and continue
            // This allows purchases to work even if Google API is temporarily unavailable
        } else if !isValid {
            log.Printf("❌ Google Play purchase verification failed for product %s", req.ProductID)
            w.WriteHeader(http.StatusBadRequest)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "error":   "Purchase verification failed",
            })
            return
        } else if verifiedExpiry != nil {
            // Use the verified expiry time from Google
            log.Printf("✅ Using verified expiry from Google: %v", verifiedExpiry)
            expiryDate = verifiedExpiry
        }
    } else if req.Store == "google" && req.PurchaseToken == "" && GOOGLE_PLAY_VERIFY_PURCHASES {
        log.Printf("⚠️ Google purchase without token, verification enabled - this may indicate an issue")
    }

    // Use transaction to ensure atomicity
    tx, err := db.Begin()
    if err != nil {
        log.Printf("Error starting transaction: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database error",
        })
        return
    }
    defer tx.Rollback()

    // Insert purchase record
    query := `INSERT INTO purchase_history
              (email, device_id, product_id, transaction_id, purchase_date, expiry_date, subscription_type, subscription_length, store)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

    _, err = tx.Exec(query, email, deviceID, req.ProductID, req.TransactionID, purchaseDate, expiryDate, req.SubscriptionType, req.SubscriptionLength, req.Store)
    if err != nil {
        log.Printf("Error recording purchase: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to record purchase",
        })
        return
    }

    // Also update user's subscription status in the users table
    if req.SubscriptionType != "" {
        updateQuery := `UPDATE users SET
                        subscription_type = ?,
                        subscription_length = ?,
                        subscription_expiry = ?,
                        last_payment_method = ?,
                        updated_at = CURRENT_TIMESTAMP
                        WHERE email = ?`
        _, err = tx.Exec(updateQuery, req.SubscriptionType, req.SubscriptionLength, expiryDate, req.Store, email)
        if err != nil {
            log.Printf("Error updating user subscription: %v", err)
            // Continue anyway - purchase record is more important
        } else {
            log.Printf("✅ User subscription updated: email=%s, type=%s, length=%s, method=%s", email, req.SubscriptionType, req.SubscriptionLength, req.Store)
        }
    }

    // Commit transaction
    if err = tx.Commit(); err != nil {
        log.Printf("Error committing transaction: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to save purchase",
        })
        return
    }

    log.Printf("✅ Purchase recorded: device=%s, product=%s, store=%s", deviceID, req.ProductID, req.Store)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "message": "Purchase recorded successfully",
    })
}

// Get purchase history for a user
func getPurchaseHistory(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get claims from JWT middleware
    claims, ok := r.Context().Value("claims").(*JWTClaims)
    if !ok {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    deviceID := claims.DeviceID

    query := `SELECT product_id, transaction_id, purchase_date, expiry_date, subscription_type, subscription_length, store, created_at
              FROM purchase_history WHERE device_id = ? ORDER BY purchase_date DESC`

    rows, err := db.Query(query, deviceID)
    if err != nil {
        log.Printf("Error fetching purchase history: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to fetch purchase history",
        })
        return
    }
    defer rows.Close()

    var purchases []map[string]interface{}
    for rows.Next() {
        var productID, transactionID, subscriptionType, subscriptionLength, store string
        var purchaseDate, createdAt time.Time
        var expiryDate sql.NullTime

        if err := rows.Scan(&productID, &transactionID, &purchaseDate, &expiryDate, &subscriptionType, &subscriptionLength, &store, &createdAt); err != nil {
            log.Printf("Error scanning purchase row: %v", err)
            continue
        }

        purchase := map[string]interface{}{
            "product_id":          productID,
            "transaction_id":      transactionID,
            "purchase_date":       purchaseDate.Format(time.RFC3339),
            "subscription_type":   subscriptionType,
            "subscription_length": subscriptionLength,
            "store":               store,
            "created_at":          createdAt.Format(time.RFC3339),
        }
        if expiryDate.Valid {
            purchase["expiry_date"] = expiryDate.Time.Format(time.RFC3339)
        }
        purchases = append(purchases, purchase)
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":   true,
        "purchases": purchases,
    })
}

// ============================================================================
// GDPR: DELETE USER DATA
// ============================================================================

// Delete all user data (GDPR Right to Erasure)
func deleteUserData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get claims from JWT middleware
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Unauthorized",
		})
		return
	}

	email := claims.Email
	deviceID := claims.DeviceID

	log.Printf("[GDPR] Data deletion requested for email=%s, device_id=%s", email, deviceID)

	// Delete from main database (keep purchase_history for tax/legal compliance)
	deletions := []struct {
		table string
		query string
		args  []interface{}
	}{
		{"auth_codes", "DELETE FROM auth_codes WHERE email = ?", []interface{}{email}},
		{"login_history", "DELETE FROM login_history WHERE email = ?", []interface{}{email}},
		{"users", "DELETE FROM users WHERE email = ?", []interface{}{email}},
	}

	deletedTables := []string{}
	for _, d := range deletions {
		result, err := db.Exec(d.query, d.args...)
		if err != nil {
			log.Printf("[GDPR] Error deleting from %s: %v", d.table, err)
			continue
		}
		rows, _ := result.RowsAffected()
		if rows > 0 {
			deletedTables = append(deletedTables, d.table)
		}
		log.Printf("[GDPR] Deleted %d rows from %s", rows, d.table)
	}

	// Delete from analytics database
	analyticsDeletions := []struct {
		table string
		query string
		args  []interface{}
	}{
		{"api_calls", "DELETE FROM api_calls WHERE device_id = ?", []interface{}{deviceID}},
		{"api_calls_monthly", "DELETE FROM api_calls_monthly WHERE device_id = ?", []interface{}{deviceID}},
		{"analytics_events", "DELETE FROM analytics_events WHERE device_id = ?", []interface{}{deviceID}},
	}

	for _, d := range analyticsDeletions {
		result, err := analyticsDB.Exec(d.query, d.args...)
		if err != nil {
			log.Printf("[GDPR] Error deleting from analytics.%s: %v", d.table, err)
			continue
		}
		rows, _ := result.RowsAffected()
		if rows > 0 {
			deletedTables = append(deletedTables, "analytics."+d.table)
		}
		log.Printf("[GDPR] Deleted %d rows from analytics.%s", rows, d.table)
	}

	log.Printf("[GDPR] Data deletion complete for %s. Affected tables: %v", email, deletedTables)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"message":        "All personal data has been deleted",
		"deleted_tables": deletedTables,
	})
}

// ============================================================================
// T2.B PARTNER INVITES
// ============================================================================
//
// Two endpoints back the invite-partner deep-link feature in the Flutter
// client. The flow is:
//
//   1. User A taps "Invite partner" → client POSTs /api/invites/create
//      with their birth data (the same fields the chart API takes).
//   2. Server stores it under a short random hash and returns the hash
//      plus a public share URL of the form
//      https://astrolytix.com/i/{hash} (universal/app-link entry point).
//   3. User A shares the URL via the system share sheet.
//   4. User B opens the URL → iOS Universal Link / Android App Link
//      routes them straight into the Astrolytix app, which calls
//      GET /api/invites/{hash} to retrieve User A's birth data and
//      compute the compatibility chart locally.
//   5. The first claim records claimed_by_email + claimed_at; subsequent
//      reads still succeed (one invite hash can be opened multiple times,
//      e.g. on a re-install) but only the first claimer counts for
//      attribution.
//
// Privacy: hashes are non-guessable (10 chars base32 = 50 bits). The
// payload is birth data — not credentials — and is only meaningful when
// combined with the recipient's own chart. Inviters can revoke (not yet
// implemented; left for a follow-up if abuse appears).

type CreateInviteRequest struct {
	InviterName string  `json:"inviter_name"`
	BirthDate   string  `json:"birth_date"`
	BirthTime   string  `json:"birth_time"`
	BirthLat    float64 `json:"birth_latitude"`
	BirthLon    float64 `json:"birth_longitude"`
	BirthPlace  string  `json:"birth_place"`
	BirthTZ     string  `json:"birth_timezone"`
}

type CreateInviteResponse struct {
	Success  bool   `json:"success"`
	Hash     string `json:"hash,omitempty"`
	ShareURL string `json:"share_url,omitempty"`
	Error    string `json:"error,omitempty"`
}

type GetInviteResponse struct {
	Success     bool    `json:"success"`
	Hash        string  `json:"hash,omitempty"`
	InviterName string  `json:"inviter_name,omitempty"`
	BirthDate   string  `json:"birth_date,omitempty"`
	BirthTime   string  `json:"birth_time,omitempty"`
	BirthLat    float64 `json:"birth_latitude,omitempty"`
	BirthLon    float64 `json:"birth_longitude,omitempty"`
	BirthPlace  string  `json:"birth_place,omitempty"`
	BirthTZ     string  `json:"birth_timezone,omitempty"`
	CreatedAt   string  `json:"created_at,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// generateInviteHash returns a 10-character URL-safe base32 hash drawn
// from crypto/rand. 50 bits of entropy is well clear of brute-force
// attacks against /api/invites/{hash}.
func generateInviteHash() (string, error) {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // 31 chars, ambiguous chars dropped
	const length = 10
	hash := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		hash[i] = alphabet[n.Int64()]
	}
	return string(hash), nil
}

// POST /api/invites/create — JWT required.
// Stores the inviter's birth data under a fresh hash and returns the
// hash + canonical share URL the client can drop into the system share
// sheet.
func createInvite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(CreateInviteResponse{
			Success: false,
			Error:   "Unauthorized",
		})
		return
	}

	var req CreateInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CreateInviteResponse{
			Success: false,
			Error:   "Invalid JSON: " + err.Error(),
		})
		return
	}

	if req.BirthDate == "" || req.BirthTime == "" || req.BirthPlace == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CreateInviteResponse{
			Success: false,
			Error:   "birth_date, birth_time and birth_place are required",
		})
		return
	}

	// Generate a unique hash, retrying on the (extremely unlikely) collision.
	var hash string
	for attempt := 0; attempt < 5; attempt++ {
		h, err := generateInviteHash()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(CreateInviteResponse{
				Success: false,
				Error:   "Failed to generate hash: " + err.Error(),
			})
			return
		}
		var existing string
		row := db.QueryRow(`SELECT invite_hash FROM partner_invites WHERE invite_hash = ?`, h)
		if err := row.Scan(&existing); err == sql.ErrNoRows {
			hash = h
			break
		}
	}
	if hash == "" {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CreateInviteResponse{
			Success: false,
			Error:   "Could not allocate invite hash",
		})
		return
	}

	_, err := db.Exec(`
        INSERT INTO partner_invites (
            invite_hash, inviter_email, inviter_name,
            birth_date, birth_time, birth_latitude, birth_longitude,
            birth_place, birth_timezone
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hash, claims.Email, req.InviterName,
		req.BirthDate, req.BirthTime, req.BirthLat, req.BirthLon,
		req.BirthPlace, req.BirthTZ,
	)
	if err != nil {
		log.Printf("[invites] insert failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CreateInviteResponse{
			Success: false,
			Error:   "Failed to store invite",
		})
		return
	}

	shareURL := fmt.Sprintf("https://astrolytix.com/i/%s", hash)
	log.Printf("[invites] created %s for %s", hash, claims.Email)

	json.NewEncoder(w).Encode(CreateInviteResponse{
		Success:  true,
		Hash:     hash,
		ShareURL: shareURL,
	})
}

// GET /api/invites/{hash} — public, no JWT required.
// Returns the inviter's birth data so the recipient app can compute a
// compatibility chart. Also marks the invite as claimed on first read
// (purely informational — the endpoint stays readable afterwards so the
// recipient can re-open the same link from another device).
func getInvite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	hash := vars["hash"]
	if hash == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(GetInviteResponse{
			Success: false,
			Error:   "Missing invite hash",
		})
		return
	}

	var (
		inviterEmail string
		inviterName  string
		birthDate    string
		birthTime    string
		birthLat     float64
		birthLon     float64
		birthPlace   string
		birthTZ      string
		createdAt    string
		claimedBy    sql.NullString
	)
	row := db.QueryRow(`
        SELECT inviter_email, inviter_name, birth_date, birth_time,
               birth_latitude, birth_longitude, birth_place, birth_timezone,
               created_at, claimed_by_email
        FROM partner_invites WHERE invite_hash = ?`, hash)
	err := row.Scan(
		&inviterEmail, &inviterName, &birthDate, &birthTime,
		&birthLat, &birthLon, &birthPlace, &birthTZ,
		&createdAt, &claimedBy,
	)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(GetInviteResponse{
			Success: false,
			Error:   "Invite not found",
		})
		return
	}
	if err != nil {
		log.Printf("[invites] lookup failed for %s: %v", hash, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(GetInviteResponse{
			Success: false,
			Error:   "Lookup failed",
		})
		return
	}

	// Best-effort first-claim record. We don't fail the read if it errors.
	if !claimedBy.Valid {
		_, _ = db.Exec(`
            UPDATE partner_invites
               SET claimed_at = CURRENT_TIMESTAMP
             WHERE invite_hash = ? AND claimed_at IS NULL`, hash)
	}

	json.NewEncoder(w).Encode(GetInviteResponse{
		Success:     true,
		Hash:        hash,
		InviterName: inviterName,
		BirthDate:   birthDate,
		BirthTime:   birthTime,
		BirthLat:    birthLat,
		BirthLon:    birthLon,
		BirthPlace:  birthPlace,
		BirthTZ:     birthTZ,
		CreatedAt:   createdAt,
	})
}

// ============================================================================
// EMAIL AUTHENTICATION
// ============================================================================

// Generate a 6-digit numeric code
func generateAuthCode() string {
    max := big.NewInt(1000000)
    n, err := rand.Int(rand.Reader, max)
    if err != nil {
        // Fallback to less secure random if crypto/rand fails
        return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
    }
    return fmt.Sprintf("%06d", n.Int64())
}

// Validate email format
func isValidEmail(email string) bool {
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
    return emailRegex.MatchString(email)
}

// Send email using SMTP (Office 365 / GoDaddy M365)
func sendAuthCodeEmail(toEmail, code string) error {
    if SMTP_USER == "" || SMTP_PASSWORD == "" {
        return fmt.Errorf("SMTP credentials not configured")
    }

    // Parse the From address to get just the email part
    fromEmail := SMTP_USER
    fromName := "Astrolytix"
    if strings.Contains(SMTP_FROM, "<") && strings.Contains(SMTP_FROM, ">") {
        parts := strings.Split(SMTP_FROM, "<")
        fromName = strings.TrimSpace(parts[0])
        fromEmail = strings.TrimSuffix(parts[1], ">")
    }

    // Build the email message
    subject := "Your Astrolytix verification code"
    body := fmt.Sprintf(`Hello,

Your verification code is: %s

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
Astrolytix Team`, code)

    // Build MIME message
    msg := fmt.Sprintf("From: %s <%s>\r\n"+
        "To: %s\r\n"+
        "Subject: %s\r\n"+
        "MIME-Version: 1.0\r\n"+
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n"+
        "\r\n"+
        "%s", fromName, fromEmail, toEmail, subject, body)

    // Connect to SMTP server with TLS
    addr := fmt.Sprintf("%s:%s", SMTP_HOST, SMTP_PORT)

    // Create TLS config
    tlsConfig := &tls.Config{
        ServerName: SMTP_HOST,
    }

    // Connect to server
    conn, err := tls.Dial("tcp", addr, tlsConfig)
    if err != nil {
        // Try STARTTLS instead (for port 587)
        log.Printf("Direct TLS failed, trying STARTTLS: %v", err)
        return sendAuthCodeEmailSTARTTLS(toEmail, fromEmail, fromName, subject, body)
    }
    defer conn.Close()

    // Create SMTP client
    client, err := smtp.NewClient(conn, SMTP_HOST)
    if err != nil {
        return fmt.Errorf("failed to create SMTP client: %v", err)
    }
    defer client.Close()

    // Authenticate
    auth := smtp.PlainAuth("", SMTP_USER, SMTP_PASSWORD, SMTP_HOST)
    if err = client.Auth(auth); err != nil {
        return fmt.Errorf("SMTP auth failed: %v", err)
    }

    // Set sender and recipient
    if err = client.Mail(fromEmail); err != nil {
        return fmt.Errorf("SMTP MAIL failed: %v", err)
    }
    if err = client.Rcpt(toEmail); err != nil {
        return fmt.Errorf("SMTP RCPT failed: %v", err)
    }

    // Send the email body
    w, err := client.Data()
    if err != nil {
        return fmt.Errorf("SMTP DATA failed: %v", err)
    }
    _, err = w.Write([]byte(msg))
    if err != nil {
        return fmt.Errorf("SMTP write failed: %v", err)
    }
    err = w.Close()
    if err != nil {
        return fmt.Errorf("SMTP close failed: %v", err)
    }

    return client.Quit()
}

// loginAuth implements LOGIN authentication for SMTP (required by Office 365)
type loginAuth struct {
    username, password string
}

func LoginAuth(username, password string) smtp.Auth {
    return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
    return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
    if more {
        switch string(fromServer) {
        case "Username:":
            return []byte(a.username), nil
        case "Password:":
            return []byte(a.password), nil
        default:
            return nil, fmt.Errorf("unknown server response: %s", fromServer)
        }
    }
    return nil, nil
}

// Send email using STARTTLS (for port 587)
func sendAuthCodeEmailSTARTTLS(toEmail, fromEmail, fromName, subject, body string) error {
    addr := fmt.Sprintf("%s:%s", SMTP_HOST, SMTP_PORT)

    // Build MIME message
    msg := fmt.Sprintf("From: %s <%s>\r\n"+
        "To: %s\r\n"+
        "Subject: %s\r\n"+
        "MIME-Version: 1.0\r\n"+
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n"+
        "\r\n"+
        "%s", fromName, fromEmail, toEmail, subject, body)

    // Connect to server
    conn, err := smtp.Dial(addr)
    if err != nil {
        return fmt.Errorf("failed to connect to SMTP server: %v", err)
    }
    defer conn.Close()

    // Send EHLO
    if err = conn.Hello("localhost"); err != nil {
        return fmt.Errorf("SMTP EHLO failed: %v", err)
    }

    // Start TLS
    tlsConfig := &tls.Config{
        ServerName: SMTP_HOST,
    }
    if err = conn.StartTLS(tlsConfig); err != nil {
        return fmt.Errorf("SMTP STARTTLS failed: %v", err)
    }

    // Authenticate using LOGIN auth (required by Office 365)
    auth := LoginAuth(SMTP_USER, SMTP_PASSWORD)
    if err = conn.Auth(auth); err != nil {
        return fmt.Errorf("SMTP auth failed: %v", err)
    }

    // Set sender and recipient
    if err = conn.Mail(fromEmail); err != nil {
        return fmt.Errorf("SMTP MAIL failed: %v", err)
    }
    if err = conn.Rcpt(toEmail); err != nil {
        return fmt.Errorf("SMTP RCPT failed: %v", err)
    }

    // Send the email body
    w, err := conn.Data()
    if err != nil {
        return fmt.Errorf("SMTP DATA failed: %v", err)
    }
    _, err = w.Write([]byte(msg))
    if err != nil {
        return fmt.Errorf("SMTP write failed: %v", err)
    }
    err = w.Close()
    if err != nil {
        return fmt.Errorf("SMTP close failed: %v", err)
    }

    return conn.Quit()
}

// Rate limiter for email requests (prevent abuse)
var emailRateLimiter = NewDeviceLimiter()

// Request auth code - sends 6-digit code to email
func requestAuthCode(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    log.Println("📧 [requestAuthCode] Received request")

    // Parse request
    var req EmailAuthRequestCode
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Validate email
    email := strings.ToLower(strings.TrimSpace(req.Email))
    if email == "" || !isValidEmail(email) {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Invalid email address",
        })
        return
    }

    // Rate limit by email (1 request per minute)
    limiter := emailRateLimiter.GetLimiter(email)
    if !limiter.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Please wait before requesting another code",
        })
        return
    }

    // Apple Review test account — fixed code, no email sent
    if email == "astrolytix.tester2@gmail.com" {
        code := "000000"
        expiresAt := time.Now().Add(AUTH_CODE_EXP)
        db.Exec(`UPDATE auth_codes SET used = 1 WHERE email = ? AND used = 0`, email)
        db.Exec(`INSERT INTO auth_codes (email, code, device_id, expires_at) VALUES (?, ?, ?, ?)`,
            email, code, req.DeviceID, expiresAt)
        log.Printf("✅ Apple Review test account — code %s stored for %s", code, email)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: true,
            Message: "Verification code sent to your email",
        })
        return
    }

    // Generate 6-digit code
    code := generateAuthCode()
    expiresAt := time.Now().Add(AUTH_CODE_EXP)

    // Invalidate any existing unused codes for this email
    _, err := db.Exec(`UPDATE auth_codes SET used = 1 WHERE email = ? AND used = 0`, email)
    if err != nil {
        log.Printf("❌ Failed to invalidate old codes: %v", err)
    }

    // Store the code in database
    _, err = db.Exec(`INSERT INTO auth_codes (email, code, device_id, expires_at) VALUES (?, ?, ?, ?)`,
        email, code, req.DeviceID, expiresAt)
    if err != nil {
        log.Printf("❌ Failed to store auth code: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Failed to generate code",
        })
        return
    }

    // Send email
    log.Printf("📧 Sending auth code to %s", email)
    if err := sendAuthCodeEmail(email, code); err != nil {
        log.Printf("❌ Failed to send email: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Failed to send email. Please try again.",
        })
        return
    }

    log.Printf("✅ Auth code sent to %s (expires: %v)", email, expiresAt)
    json.NewEncoder(w).Encode(EmailAuthResponse{
        Success: true,
        Message: "Verification code sent to your email",
    })
}

// Verify auth code - validates code and returns JWT tokens
func verifyAuthCode(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    log.Println("🔐 [verifyAuthCode] Received request")

    // Parse request
    var req EmailAuthVerifyCode
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Validate input
    email := strings.ToLower(strings.TrimSpace(req.Email))
    code := strings.TrimSpace(req.Code)
    deviceID := strings.TrimSpace(req.DeviceID)

    if email == "" || !isValidEmail(email) {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Invalid email address",
        })
        return
    }

    if code == "" || len(code) != 6 {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Invalid verification code",
        })
        return
    }

    if deviceID == "" {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Device ID is required",
        })
        return
    }

    // Look up the code in database
    var storedCode string
    var expiresAt time.Time
    var used int

    err := db.QueryRow(`SELECT code, expires_at, used FROM auth_codes
                        WHERE email = ? AND used = 0
                        ORDER BY created_at DESC LIMIT 1`, email).Scan(&storedCode, &expiresAt, &used)

    if err == sql.ErrNoRows {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "No verification code found. Please request a new one.",
        })
        return
    } else if err != nil {
        log.Printf("❌ Database error: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Verification failed",
        })
        return
    }

    // Check if code is expired
    if time.Now().After(expiresAt) {
        // Mark as used
        db.Exec(`UPDATE auth_codes SET used = 1 WHERE email = ? AND code = ?`, email, storedCode)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Verification code has expired. Please request a new one.",
        })
        return
    }

    // Verify the code
    if code != storedCode {
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Invalid verification code",
        })
        return
    }

    // Mark code as used
    _, err = db.Exec(`UPDATE auth_codes SET used = 1 WHERE email = ? AND code = ?`, email, storedCode)
    if err != nil {
        log.Printf("❌ Failed to mark code as used: %v", err)
    }

    // NEW V2 SCHEMA: Check if user exists by email in users
    var subscriptionType, subscriptionLength string
    var subscriptionExpiry sql.NullString

    err = db.QueryRow(`SELECT subscription_type, subscription_length, subscription_expiry FROM users WHERE email = ?`, email).
        Scan(&subscriptionType, &subscriptionLength, &subscriptionExpiry)

    if err == sql.ErrNoRows {
        // New user - create account with email
        subscriptionType = "free"
        subscriptionLength = "monthly"

        _, err = db.Exec(`INSERT INTO users (email, subscription_type, subscription_length, current_device_id)
                          VALUES (?, ?, ?, ?)`,
            email, subscriptionType, subscriptionLength, deviceID)
        if err != nil {
            log.Printf("❌ Failed to create user: %v", err)
            json.NewEncoder(w).Encode(EmailAuthResponse{
                Success: false,
                Error:   "Failed to create account",
            })
            return
        }
        log.Printf("✅ New user created: %s (device: %s)", email, deviceID)
    } else if err != nil {
        log.Printf("❌ Database error: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Verification failed",
        })
        return
    } else {
        // Existing user - update current_device_id (for tracking)
        _, err = db.Exec(`UPDATE users SET current_device_id = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`,
            deviceID, email)
        if err != nil {
            log.Printf("⚠️ Failed to update device: %v", err)
        }

        // Check if subscription is expired
        if subscriptionExpiry.Valid && subscriptionExpiry.String != "" {
            expiryTime, perr := parseDBTime(subscriptionExpiry.String)
            if perr != nil {
                log.Printf("⚠️ Could not parse subscription_expiry for %s: %v (raw=%q)", email, perr, subscriptionExpiry.String)
            } else if time.Now().After(expiryTime) {
                log.Printf("⚠️ Subscription expired for %s on %s — downgrading to free", email, expiryTime.Format(time.RFC3339))
                subscriptionType = "free"
            }
        }

        log.Printf("✅ Existing user logged in: %s (device: %s, plan: %s)", email, deviceID, subscriptionType)
    }

    // Record login in history
    db.Exec(`INSERT INTO login_history (email, device_id) VALUES (?, ?)`, email, deviceID)

    // Generate JWT tokens with EMAIL as primary identity
    accessToken, err := generateAccessToken(email, deviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("❌ Failed to generate access token: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    refreshToken, err := generateRefreshToken(email, deviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("❌ Failed to generate refresh token: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    log.Printf("✅ Auth successful for %s, tokens generated", email)

    json.NewEncoder(w).Encode(EmailAuthResponse{
        Success:      true,
        Message:      "Email verified successfully",
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    int64(ACCESS_TOKEN_EXP.Seconds()),
    })
}

// ============================================================================
// ADMIN ENDPOINTS
// ============================================================================

// Check if email is in admin list
func isAdminEmail(email string) bool {
    email = strings.ToLower(strings.TrimSpace(email))
    for _, adminEmail := range ADMIN_EMAILS {
        if strings.ToLower(adminEmail) == email {
            return true
        }
    }
    return false
}

// Admin endpoint to request verification code (Step 1)
// This sends a 6-digit code to the admin's email
func adminRequestCode(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    log.Println("🔐 [adminRequestCode] Received request")

    var req AdminRequestCodeRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid request format",
        })
        return
    }

    // Validate admin email is in allowed list
    if !isAdminEmail(req.AdminEmail) {
        log.Printf("❌ [adminRequestCode] Unauthorized email: %s", req.AdminEmail)
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    // Validate admin secret (REQUIRED for admin operations)
    if ADMIN_SECRET_KEY == "" {
        log.Println("❌ [adminRequestCode] ADMIN_SECRET_KEY not configured on server")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Admin secret not configured on server",
        })
        return
    }

    if req.AdminSecret != ADMIN_SECRET_KEY {
        log.Printf("❌ [adminRequestCode] Invalid admin secret")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    // Generate 6-digit code using crypto/rand
    code := generateAuthCode()
    expiresAt := time.Now().Add(10 * time.Minute)

    // Store code in database (reuse auth_codes table)
    _, err := db.Exec(`INSERT INTO auth_codes (email, code, device_id, expires_at) VALUES (?, ?, ?, ?)`,
        strings.ToLower(req.AdminEmail), code, "admin-action", expiresAt)
    if err != nil {
        log.Printf("❌ [adminRequestCode] Failed to store code: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to generate code",
        })
        return
    }

    // Send email with code
    subject := "🔐 Admin Verification Code - Astrolytix"
    body := fmt.Sprintf(`
Your admin verification code is:

%s

This code expires in 10 minutes.

If you did not request this code, please ignore this email and check your server security.

⚠️ Never share this code with anyone.
`, code)

    // Get from email info
    fromEmail := SMTP_USER
    fromName := "Astrolytix"
    if strings.Contains(SMTP_FROM, "<") && strings.Contains(SMTP_FROM, ">") {
        parts := strings.Split(SMTP_FROM, "<")
        fromName = strings.TrimSpace(parts[0])
        fromEmail = strings.TrimSuffix(parts[1], ">")
    }

    if err := sendAuthCodeEmailSTARTTLS(req.AdminEmail, fromEmail, fromName, subject, body); err != nil {
        log.Printf("❌ [adminRequestCode] Failed to send email: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to send verification email",
        })
        return
    }

    log.Printf("✅ [adminRequestCode] Verification code sent to %s", req.AdminEmail)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "message": "Verification code sent to your email",
    })
}

// Admin endpoint to grant subscription to any user by email (Step 2)
// Requires: admin email + admin secret + verification code
func adminGrantSubscription(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    log.Println("🔐 [adminGrantSubscription] Received request")

    // Parse request
    var req AdminGrantSubscriptionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid request format",
        })
        return
    }

    // Step 1: Validate admin email is in allowed list
    if !isAdminEmail(req.AdminEmail) {
        log.Printf("❌ [adminGrantSubscription] Unauthorized admin email: %s", req.AdminEmail)
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized: Not an admin email",
        })
        return
    }

    // Step 2: Validate admin secret (REQUIRED)
    if ADMIN_SECRET_KEY == "" {
        log.Println("❌ [adminGrantSubscription] ADMIN_SECRET_KEY not configured")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Admin secret not configured on server",
        })
        return
    }

    if req.AdminSecret != ADMIN_SECRET_KEY {
        log.Printf("❌ [adminGrantSubscription] Invalid admin secret")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized: Invalid admin secret",
        })
        return
    }

    // Step 3: Validate verification code
    if req.VerificationCode == "" {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Verification code required. Call /api/admin/request-code first.",
        })
        return
    }

    // Check code in database
    var codeID int
    var expiresAt time.Time
    err := db.QueryRow(`SELECT id, expires_at FROM auth_codes
                        WHERE email = ? AND code = ? AND used = 0 AND device_id = 'admin-action'
                        ORDER BY created_at DESC LIMIT 1`,
        strings.ToLower(req.AdminEmail), req.VerificationCode).Scan(&codeID, &expiresAt)

    if err == sql.ErrNoRows {
        log.Printf("❌ [adminGrantSubscription] Invalid verification code")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid or expired verification code",
        })
        return
    } else if err != nil {
        log.Printf("❌ [adminGrantSubscription] Database error: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database error",
        })
        return
    }

    // Check if code expired
    if time.Now().After(expiresAt) {
        log.Printf("❌ [adminGrantSubscription] Verification code expired")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Verification code expired. Request a new one.",
        })
        return
    }

    // Mark code as used
    db.Exec(`UPDATE auth_codes SET used = 1 WHERE id = ?`, codeID)

    // Validate target email
    targetEmail := strings.ToLower(strings.TrimSpace(req.Email))
    if targetEmail == "" || !isValidEmail(targetEmail) {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid target email address",
        })
        return
    }

    // Validate subscription type
    if req.SubscriptionType != "free" && req.SubscriptionType != "paid" {
        req.SubscriptionType = "paid" // Default to paid for grants
    }

    // Validate subscription length
    if req.SubscriptionLength != "monthly" && req.SubscriptionLength != "yearly" && req.SubscriptionLength != "lifetime" {
        req.SubscriptionLength = "yearly" // Default to yearly
    }

    // Calculate expiry date
    var subscriptionExpiry *time.Time
    if req.DurationDays > 0 {
        expiry := time.Now().AddDate(0, 0, req.DurationDays)
        subscriptionExpiry = &expiry
    } else if req.SubscriptionLength == "lifetime" {
        // Lifetime = 100 years from now (effectively permanent)
        expiry := time.Now().AddDate(100, 0, 0)
        subscriptionExpiry = &expiry
    } else if req.SubscriptionLength == "yearly" {
        expiry := time.Now().AddDate(1, 0, 0)
        subscriptionExpiry = &expiry
    } else {
        // Monthly
        expiry := time.Now().AddDate(0, 1, 0)
        subscriptionExpiry = &expiry
    }

    // V2 SCHEMA: Check if user exists by email in users
    var existingID int
    err = db.QueryRow(`SELECT id FROM users WHERE email = ?`, targetEmail).Scan(&existingID)

    if err == sql.ErrNoRows {
        // User doesn't exist - create record (they will get tokens when they sign in)
        log.Printf("🔵 [adminGrantSubscription] Creating new user record for %s", targetEmail)

        _, err = db.Exec(`INSERT INTO users (email, subscription_type, subscription_length, subscription_expiry)
                          VALUES (?, ?, ?, ?)`,
            targetEmail,
            req.SubscriptionType,
            req.SubscriptionLength,
            subscriptionExpiry)

        if err != nil {
            log.Printf("❌ [adminGrantSubscription] Failed to create user: %v", err)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "error":   "Failed to create user record",
            })
            return
        }
    } else if err != nil {
        log.Printf("❌ [adminGrantSubscription] Database error: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database error",
        })
        return
    } else {
        // User exists - update their subscription
        log.Printf("🔵 [adminGrantSubscription] Updating existing user %s", targetEmail)

        _, err = db.Exec(`UPDATE users SET
                          subscription_type = ?,
                          subscription_length = ?,
                          subscription_expiry = ?,
                          updated_at = CURRENT_TIMESTAMP
                          WHERE email = ?`,
            req.SubscriptionType,
            req.SubscriptionLength,
            subscriptionExpiry,
            targetEmail)

        if err != nil {
            log.Printf("❌ [adminGrantSubscription] Failed to update user: %v", err)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "error":   "Failed to update subscription",
            })
            return
        }
    }

    expiryStr := "never"
    if subscriptionExpiry != nil {
        expiryStr = subscriptionExpiry.Format("2006-01-02")
    }

    log.Printf("✅ [adminGrantSubscription] Granted %s %s subscription to %s (expires: %s)",
        req.SubscriptionLength, req.SubscriptionType, targetEmail, expiryStr)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":              true,
        "message":              fmt.Sprintf("Subscription granted to %s", targetEmail),
        "email":                targetEmail,
        "subscription_type":    req.SubscriptionType,
        "subscription_length":  req.SubscriptionLength,
        "subscription_expiry":  expiryStr,
    })
}

// Bot endpoint: check if email exists in users table (no 2FA, uses BOT_API_SECRET)
func botCheckEmail(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    botSecret := r.URL.Query().Get("bot_secret")
    email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))

    if BOT_API_SECRET == "" || botSecret != BOT_API_SECRET {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
        return
    }

    if email == "" || !isValidEmail(email) {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid email"})
        return
    }

    var id int
    err := db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&id)
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Email not found"})
        return
    } else if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
        return
    }

    log.Printf("✅ [botCheckEmail] Email found: %s", email)
    json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "email": email})
}

// Bot endpoint: grant subscription (no 2FA, authenticated via BOT_API_SECRET)
func botGrantSubscription(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    log.Println("🤖 [botGrantSubscription] Received request")

    var req BotGrantSubscriptionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request format"})
        return
    }

    if BOT_API_SECRET == "" || req.BotSecret != BOT_API_SECRET {
        log.Println("❌ [botGrantSubscription] Invalid bot secret")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
        return
    }

    targetEmail := strings.ToLower(strings.TrimSpace(req.Email))
    if targetEmail == "" || !isValidEmail(targetEmail) {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid email"})
        return
    }

    if req.SubscriptionType != "free" && req.SubscriptionType != "paid" {
        req.SubscriptionType = "paid"
    }
    if req.SubscriptionLength != "monthly" && req.SubscriptionLength != "yearly" && req.SubscriptionLength != "lifetime" {
        req.SubscriptionLength = "monthly"
    }

    var subscriptionExpiry *time.Time
    if req.DurationDays > 0 {
        expiry := time.Now().AddDate(0, 0, req.DurationDays)
        subscriptionExpiry = &expiry
    } else if req.SubscriptionLength == "lifetime" {
        expiry := time.Now().AddDate(100, 0, 0)
        subscriptionExpiry = &expiry
    } else if req.SubscriptionLength == "yearly" {
        expiry := time.Now().AddDate(1, 0, 0)
        subscriptionExpiry = &expiry
    } else {
        expiry := time.Now().AddDate(0, 1, 0)
        subscriptionExpiry = &expiry
    }

    var existingID int
    err := db.QueryRow(`SELECT id FROM users WHERE email = ?`, targetEmail).Scan(&existingID)
    if err == sql.ErrNoRows {
        log.Printf("🔵 [botGrantSubscription] Creating new user record for %s", targetEmail)
        _, err = db.Exec(`INSERT INTO users (email, subscription_type, subscription_length, subscription_expiry, last_payment_method) VALUES (?, ?, ?, ?, ?)`,
            targetEmail, req.SubscriptionType, req.SubscriptionLength, subscriptionExpiry, req.PaymentMethod)
        if err != nil {
            log.Printf("❌ [botGrantSubscription] Failed to create user: %v", err)
            w.WriteHeader(http.StatusInternalServerError)
            json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Failed to create user record"})
            return
        }
    } else if err != nil {
        log.Printf("❌ [botGrantSubscription] Database error: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
        return
    } else {
        log.Printf("🔵 [botGrantSubscription] Updating existing user %s", targetEmail)
        _, err = db.Exec(`UPDATE users SET subscription_type = ?, subscription_length = ?, subscription_expiry = ?, last_payment_method = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`,
            req.SubscriptionType, req.SubscriptionLength, subscriptionExpiry, req.PaymentMethod, targetEmail)
        if err != nil {
            log.Printf("❌ [botGrantSubscription] Failed to update user: %v", err)
            w.WriteHeader(http.StatusInternalServerError)
            json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Failed to update subscription"})
            return
        }
    }

    expiryStr := "never"
    if subscriptionExpiry != nil {
        expiryStr = subscriptionExpiry.Format("2006-01-02")
    }

    if req.SubscriptionType == "paid" && req.PaymentMethod != "" {
        var deviceID sql.NullString
        _ = db.QueryRow(`SELECT current_device_id FROM users WHERE email = ?`, targetEmail).Scan(&deviceID)
        productID := fmt.Sprintf("bot_%s_%s", req.PaymentMethod, req.SubscriptionLength)
        _, phErr := db.Exec(`INSERT INTO purchase_history
            (email, device_id, product_id, transaction_id, purchase_date, expiry_date, subscription_type, subscription_length, store)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            targetEmail, deviceID.String, productID, req.TransactionID, time.Now(), subscriptionExpiry,
            req.SubscriptionType, req.SubscriptionLength, req.PaymentMethod)
        if phErr != nil {
            log.Printf("⚠️ [botGrantSubscription] purchase_history insert failed: %v", phErr)
        }
    }

    log.Printf("✅ [botGrantSubscription] Granted %s %s to %s via %s (expires: %s, txn: %s)",
        req.SubscriptionLength, req.SubscriptionType, targetEmail, req.PaymentMethod, expiryStr, req.TransactionID)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":             true,
        "message":             fmt.Sprintf("Subscription granted to %s", targetEmail),
        "email":               targetEmail,
        "subscription_type":   req.SubscriptionType,
        "subscription_length": req.SubscriptionLength,
        "subscription_expiry": expiryStr,
    })
}

// Admin endpoint to list all users with subscriptions
func adminListUsers(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get admin email and secret from query params or headers
    adminEmail := r.URL.Query().Get("admin_email")
    adminSecret := r.URL.Query().Get("admin_secret")

    if !isAdminEmail(adminEmail) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    // V2 SCHEMA: Query all users from users
    rows, err := db.Query(`SELECT id, email, subscription_type, subscription_length,
                           subscription_expiry, COALESCE(is_super, 0), current_device_id, created_at, updated_at
                           FROM users ORDER BY updated_at DESC LIMIT 100`)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database error",
        })
        return
    }
    defer rows.Close()

    var users []map[string]interface{}
    for rows.Next() {
        var id int
        var email, subType, subLength string
        var subExpiry, currentDeviceID, createdAt, updatedAt sql.NullString
        var isSuper int

        err := rows.Scan(&id, &email, &subType, &subLength, &subExpiry, &isSuper, &currentDeviceID, &createdAt, &updatedAt)
        if err != nil {
            continue
        }

        user := map[string]interface{}{
            "id":                  id,
            "email":               email,
            "subscription_type":   subType,
            "subscription_length": subLength,
            "subscription_expiry": subExpiry.String,
            "is_super":            isSuper == 1,
            "current_device_id":   currentDeviceID.String,
            "created_at":          createdAt.String,
            "updated_at":          updatedAt.String,
        }
        users = append(users, user)
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "users":   users,
        "count":   len(users),
    })
}

// Admin endpoint to toggle super status for a user (requires 2FA verification code)
func adminToggleSuper(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    var req struct {
        AdminEmail       string `json:"admin_email"`
        AdminSecret      string `json:"admin_secret"`
        VerificationCode string `json:"verification_code"`
        DeviceID         string `json:"device_id"`
        Email            string `json:"email"`
        IsSuper          bool   `json:"is_super"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid request",
        })
        return
    }

    // Validate admin credentials
    if !isAdminEmail(req.AdminEmail) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    if ADMIN_SECRET_KEY != "" && req.AdminSecret != ADMIN_SECRET_KEY {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    // Verify the email code (2FA required for super toggle)
    if req.VerificationCode == "" {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Verification code required",
        })
        return
    }

    var codeID int
    var expiresAt time.Time
    err := db.QueryRow(`SELECT id, expires_at FROM auth_codes WHERE email = ? AND code = ? AND used = 0`,
        req.AdminEmail, req.VerificationCode).Scan(&codeID, &expiresAt)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid or expired verification code",
        })
        return
    }

    if time.Now().After(expiresAt) {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Verification code has expired",
        })
        return
    }

    // Mark code as used
    db.Exec(`UPDATE auth_codes SET used = 1 WHERE id = ?`, codeID)

    // V2 SCHEMA: Find user by email (email is now required)
    targetEmail := strings.ToLower(strings.TrimSpace(req.Email))
    if targetEmail == "" {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Email is required",
        })
        return
    }

    // Update is_super flag
    superValue := 0
    if req.IsSuper {
        superValue = 1
    }

    result, err := db.Exec(`UPDATE users SET is_super = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`,
        superValue, targetEmail)
    if err != nil {
        log.Printf("Error updating super status: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database error",
        })
        return
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "User not found",
        })
        return
    }

    log.Printf("✅ Admin %s toggled super status for %s to %v", req.AdminEmail, targetEmail, req.IsSuper)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":  true,
        "email":    targetEmail,
        "is_super": req.IsSuper,
        "message":  "Super status updated successfully",
    })
}

// Admin endpoint to get analytics data
func adminGetAnalytics(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get admin credentials from query params
    adminEmail := r.URL.Query().Get("admin_email")
    adminSecret := r.URL.Query().Get("admin_secret")

    if !isAdminEmail(adminEmail) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    if analyticsDB == nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Analytics database not initialized",
        })
        return
    }

    // Get current month and year
    now := time.Now()
    currentMonth := now.Format("2006-01")
    currentYear := now.Format("2006")

    // Total calls this month (astrolog)
    var astrologMonthly int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE call_type = 'astrolog' AND strftime('%Y-%m', created_at) = ?`, currentMonth).Scan(&astrologMonthly)

    // Total calls this year (astrolog)
    var astrologYearly int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE call_type = 'astrolog' AND strftime('%Y', created_at) = ?`, currentYear).Scan(&astrologYearly)

    // Total calls this month (chatgpt)
    var chatgptMonthly int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE call_type = 'chatgpt' AND strftime('%Y-%m', created_at) = ?`, currentMonth).Scan(&chatgptMonthly)

    // Total calls this year (chatgpt)
    var chatgptYearly int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE call_type = 'chatgpt' AND strftime('%Y', created_at) = ?`, currentYear).Scan(&chatgptYearly)

    // Unique users this month
    var uniqueUsersMonthly int
    analyticsDB.QueryRow(`SELECT COUNT(DISTINCT device_id) FROM api_calls WHERE strftime('%Y-%m', created_at) = ?`, currentMonth).Scan(&uniqueUsersMonthly)

    // Unique users this year
    var uniqueUsersYearly int
    analyticsDB.QueryRow(`SELECT COUNT(DISTINCT device_id) FROM api_calls WHERE strftime('%Y', created_at) = ?`, currentYear).Scan(&uniqueUsersYearly)

    // Average astrolog calls per user this month
    var avgAstrologMonthly float64
    if uniqueUsersMonthly > 0 {
        avgAstrologMonthly = float64(astrologMonthly) / float64(uniqueUsersMonthly)
    }

    // Average chatgpt calls per user this month
    var avgChatgptMonthly float64
    if uniqueUsersMonthly > 0 {
        avgChatgptMonthly = float64(chatgptMonthly) / float64(uniqueUsersMonthly)
    }

    // Average astrolog calls per user this year
    var avgAstrologYearly float64
    if uniqueUsersYearly > 0 {
        avgAstrologYearly = float64(astrologYearly) / float64(uniqueUsersYearly)
    }

    // Average chatgpt calls per user this year
    var avgChatgptYearly float64
    if uniqueUsersYearly > 0 {
        avgChatgptYearly = float64(chatgptYearly) / float64(uniqueUsersYearly)
    }

    // Max astrolog calls by a single user (all time)
    var maxAstrologUser string
    var maxAstrologCalls int
    analyticsDB.QueryRow(`SELECT device_id, COUNT(*) as cnt FROM api_calls WHERE call_type = 'astrolog' GROUP BY device_id ORDER BY cnt DESC LIMIT 1`).Scan(&maxAstrologUser, &maxAstrologCalls)

    // Max chatgpt calls by a single user (all time)
    var maxChatgptUser string
    var maxChatgptCalls int
    analyticsDB.QueryRow(`SELECT device_id, COUNT(*) as cnt FROM api_calls WHERE call_type = 'chatgpt' GROUP BY device_id ORDER BY cnt DESC LIMIT 1`).Scan(&maxChatgptUser, &maxChatgptCalls)

    // Monthly breakdown for last 12 months
    rows, err := analyticsDB.Query(`
        SELECT strftime('%Y-%m', created_at) as month,
               SUM(CASE WHEN call_type = 'astrolog' THEN 1 ELSE 0 END) as astrolog_calls,
               SUM(CASE WHEN call_type = 'chatgpt' THEN 1 ELSE 0 END) as chatgpt_calls,
               COUNT(DISTINCT device_id) as unique_users
        FROM api_calls
        WHERE created_at >= date('now', '-12 months')
        GROUP BY month
        ORDER BY month DESC
    `)

    var monthlyData []map[string]interface{}
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var month string
            var astrologCalls, chatgptCalls, users int
            if err := rows.Scan(&month, &astrologCalls, &chatgptCalls, &users); err == nil {
                monthlyData = append(monthlyData, map[string]interface{}{
                    "month":          month,
                    "astrolog_calls": astrologCalls,
                    "chatgpt_calls":  chatgptCalls,
                    "unique_users":   users,
                })
            }
        }
    }

    // Model usage breakdown (for ChatGPT)
    modelRows, err := analyticsDB.Query(`
        SELECT model, COUNT(*) as cnt
        FROM api_calls
        WHERE call_type = 'chatgpt' AND model IS NOT NULL AND model != ''
        GROUP BY model
        ORDER BY cnt DESC
    `)

    var modelUsage []map[string]interface{}
    if err == nil {
        defer modelRows.Close()
        for modelRows.Next() {
            var model string
            var cnt int
            if err := modelRows.Scan(&model, &cnt); err == nil {
                modelUsage = append(modelUsage, map[string]interface{}{
                    "model": model,
                    "count": cnt,
                })
            }
        }
    }

    // Total all-time stats
    var totalAstrolog, totalChatgpt, totalUniqueUsers int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE call_type = 'astrolog'`).Scan(&totalAstrolog)
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE call_type = 'chatgpt'`).Scan(&totalChatgpt)
    analyticsDB.QueryRow(`SELECT COUNT(DISTINCT device_id) FROM api_calls`).Scan(&totalUniqueUsers)

    // ============================================================
    // EVENT ANALYTICS (from analytics_events table)
    // ============================================================

    // Total events this month
    var eventsMonthly int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM analytics_events WHERE strftime('%Y-%m', created_at) = ?`, currentMonth).Scan(&eventsMonthly)

    // Total events this year
    var eventsYearly int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM analytics_events WHERE strftime('%Y', created_at) = ?`, currentYear).Scan(&eventsYearly)

    // Unique users from events this month
    var eventUsersMonthly int
    analyticsDB.QueryRow(`SELECT COUNT(DISTINCT device_id) FROM analytics_events WHERE strftime('%Y-%m', created_at) = ?`, currentMonth).Scan(&eventUsersMonthly)

    // Event type breakdown (this month)
    eventTypeRows, err := analyticsDB.Query(`
        SELECT event_type, COUNT(*) as cnt
        FROM analytics_events
        WHERE strftime('%Y-%m', created_at) = ?
        GROUP BY event_type
        ORDER BY cnt DESC
    `, currentMonth)

    var eventTypes []map[string]interface{}
    if err == nil {
        defer eventTypeRows.Close()
        for eventTypeRows.Next() {
            var eventType string
            var cnt int
            if err := eventTypeRows.Scan(&eventType, &cnt); err == nil {
                eventTypes = append(eventTypes, map[string]interface{}{
                    "event_type": eventType,
                    "count":      cnt,
                })
            }
        }
    }

    // Top event names (this month)
    eventNameRows, err := analyticsDB.Query(`
        SELECT event_name, COUNT(*) as cnt
        FROM analytics_events
        WHERE strftime('%Y-%m', created_at) = ?
        GROUP BY event_name
        ORDER BY cnt DESC
        LIMIT 20
    `, currentMonth)

    var topEvents []map[string]interface{}
    if err == nil {
        defer eventNameRows.Close()
        for eventNameRows.Next() {
            var eventName string
            var cnt int
            if err := eventNameRows.Scan(&eventName, &cnt); err == nil {
                topEvents = append(topEvents, map[string]interface{}{
                    "event_name": eventName,
                    "count":      cnt,
                })
            }
        }
    }

    // Platform breakdown (this month)
    platformRows, err := analyticsDB.Query(`
        SELECT COALESCE(platform, 'unknown') as platform, COUNT(*) as cnt
        FROM analytics_events
        WHERE strftime('%Y-%m', created_at) = ?
        GROUP BY platform
        ORDER BY cnt DESC
    `, currentMonth)

    var platforms []map[string]interface{}
    if err == nil {
        defer platformRows.Close()
        for platformRows.Next() {
            var platform string
            var cnt int
            if err := platformRows.Scan(&platform, &cnt); err == nil {
                platforms = append(platforms, map[string]interface{}{
                    "platform": platform,
                    "count":    cnt,
                })
            }
        }
    }

    // Total all-time events
    var totalEvents int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM analytics_events`).Scan(&totalEvents)

    // ============================================================
    // TOKEN USAGE STATISTICS (for cost analysis)
    // ============================================================

    // Token totals this month
    var monthlyPromptTokens, monthlyCompletionTokens, monthlyTotalTokens int64
    analyticsDB.QueryRow(`
        SELECT COALESCE(SUM(prompt_tokens), 0), COALESCE(SUM(completion_tokens), 0), COALESCE(SUM(total_tokens), 0)
        FROM api_calls WHERE call_type = 'chatgpt' AND strftime('%Y-%m', created_at) = ?
    `, currentMonth).Scan(&monthlyPromptTokens, &monthlyCompletionTokens, &monthlyTotalTokens)

    // Token totals this year
    var yearlyPromptTokens, yearlyCompletionTokens, yearlyTotalTokens int64
    analyticsDB.QueryRow(`
        SELECT COALESCE(SUM(prompt_tokens), 0), COALESCE(SUM(completion_tokens), 0), COALESCE(SUM(total_tokens), 0)
        FROM api_calls WHERE call_type = 'chatgpt' AND strftime('%Y', created_at) = ?
    `, currentYear).Scan(&yearlyPromptTokens, &yearlyCompletionTokens, &yearlyTotalTokens)

    // Token usage by model (this month)
    tokenModelRows, err := analyticsDB.Query(`
        SELECT model,
               COUNT(*) as calls,
               COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
               COALESCE(SUM(completion_tokens), 0) as completion_tokens,
               COALESCE(SUM(total_tokens), 0) as total_tokens
        FROM api_calls
        WHERE call_type = 'chatgpt' AND model IS NOT NULL AND model != ''
          AND strftime('%Y-%m', created_at) = ?
        GROUP BY model
        ORDER BY total_tokens DESC
    `, currentMonth)

    var tokenByModel []map[string]interface{}
    if err == nil {
        defer tokenModelRows.Close()
        for tokenModelRows.Next() {
            var model string
            var calls int
            var promptToks, completionToks, totalToks int64
            if err := tokenModelRows.Scan(&model, &calls, &promptToks, &completionToks, &totalToks); err == nil {
                // Calculate estimated cost based on model pricing (as of 2024)
                var estimatedCost float64
                switch model {
                case "gpt-4o":
                    estimatedCost = (float64(promptToks) * 2.50 / 1000000) + (float64(completionToks) * 10.00 / 1000000)
                case "gpt-4o-mini":
                    estimatedCost = (float64(promptToks) * 0.15 / 1000000) + (float64(completionToks) * 0.60 / 1000000)
                case "o1":
                    estimatedCost = (float64(promptToks) * 15.00 / 1000000) + (float64(completionToks) * 60.00 / 1000000)
                case "o1-mini":
                    estimatedCost = (float64(promptToks) * 1.10 / 1000000) + (float64(completionToks) * 4.40 / 1000000)
                default:
                    // Default to gpt-4o pricing
                    estimatedCost = (float64(promptToks) * 2.50 / 1000000) + (float64(completionToks) * 10.00 / 1000000)
                }

                tokenByModel = append(tokenByModel, map[string]interface{}{
                    "model":             model,
                    "calls":             calls,
                    "prompt_tokens":     promptToks,
                    "completion_tokens": completionToks,
                    "total_tokens":      totalToks,
                    "estimated_cost":    fmt.Sprintf("$%.4f", estimatedCost),
                })
            }
        }
    }

    // Daily token usage for last 7 days
    dailyTokenRows, err := analyticsDB.Query(`
        SELECT date(created_at) as day,
               COUNT(*) as calls,
               COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
               COALESCE(SUM(completion_tokens), 0) as completion_tokens,
               COALESCE(SUM(total_tokens), 0) as total_tokens
        FROM api_calls
        WHERE call_type = 'chatgpt' AND created_at >= date('now', '-7 days')
        GROUP BY day
        ORDER BY day DESC
    `)

    var dailyTokens []map[string]interface{}
    if err == nil {
        defer dailyTokenRows.Close()
        for dailyTokenRows.Next() {
            var day string
            var calls int
            var promptToks, completionToks, totalToks int64
            if err := dailyTokenRows.Scan(&day, &calls, &promptToks, &completionToks, &totalToks); err == nil {
                dailyTokens = append(dailyTokens, map[string]interface{}{
                    "date":              day,
                    "calls":             calls,
                    "prompt_tokens":     promptToks,
                    "completion_tokens": completionToks,
                    "total_tokens":      totalToks,
                })
            }
        }
    }

    // Database size info
    var dbPageCount, dbPageSize int
    analyticsDB.QueryRow(`SELECT page_count, page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&dbPageCount, &dbPageSize)
    dbSizeBytes := dbPageCount * dbPageSize

    // Count of aggregated monthly records
    var monthlyAggregateCount int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls_monthly`).Scan(&monthlyAggregateCount)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "current_period": map[string]interface{}{
            "month": currentMonth,
            "year":  currentYear,
        },
        "monthly": map[string]interface{}{
            "astrolog_calls":     astrologMonthly,
            "chatgpt_calls":      chatgptMonthly,
            "unique_users":       uniqueUsersMonthly,
            "avg_astrolog_per_user": fmt.Sprintf("%.2f", avgAstrologMonthly),
            "avg_chatgpt_per_user":  fmt.Sprintf("%.2f", avgChatgptMonthly),
        },
        "yearly": map[string]interface{}{
            "astrolog_calls":     astrologYearly,
            "chatgpt_calls":      chatgptYearly,
            "unique_users":       uniqueUsersYearly,
            "avg_astrolog_per_user": fmt.Sprintf("%.2f", avgAstrologYearly),
            "avg_chatgpt_per_user":  fmt.Sprintf("%.2f", avgChatgptYearly),
        },
        "all_time": map[string]interface{}{
            "total_astrolog_calls": totalAstrolog,
            "total_chatgpt_calls":  totalChatgpt,
            "total_unique_users":   totalUniqueUsers,
        },
        "max_usage": map[string]interface{}{
            "astrolog": map[string]interface{}{
                "device_id": maxAstrologUser,
                "calls":     maxAstrologCalls,
            },
            "chatgpt": map[string]interface{}{
                "device_id": maxChatgptUser,
                "calls":     maxChatgptCalls,
            },
        },
        "monthly_breakdown": monthlyData,
        "model_usage":       modelUsage,
        "events": map[string]interface{}{
            "monthly": map[string]interface{}{
                "total_events":  eventsMonthly,
                "unique_users":  eventUsersMonthly,
            },
            "yearly": map[string]interface{}{
                "total_events": eventsYearly,
            },
            "all_time": map[string]interface{}{
                "total_events": totalEvents,
            },
            "event_types":    eventTypes,
            "top_events":     topEvents,
            "platforms":      platforms,
        },
        "token_usage": map[string]interface{}{
            "monthly": map[string]interface{}{
                "prompt_tokens":     monthlyPromptTokens,
                "completion_tokens": monthlyCompletionTokens,
                "total_tokens":      monthlyTotalTokens,
            },
            "yearly": map[string]interface{}{
                "prompt_tokens":     yearlyPromptTokens,
                "completion_tokens": yearlyCompletionTokens,
                "total_tokens":      yearlyTotalTokens,
            },
            "by_model":    tokenByModel,
            "daily_usage": dailyTokens,
        },
        "database": map[string]interface{}{
            "size_bytes":              dbSizeBytes,
            "size_mb":                 fmt.Sprintf("%.2f", float64(dbSizeBytes)/1024/1024),
            "monthly_aggregate_count": monthlyAggregateCount,
            "retention_months":        12,
        },
    })
}

// Admin endpoint to get API calls for a specific user/device
func adminGetUserCalls(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Get admin credentials from query params
    adminEmail := r.URL.Query().Get("admin_email")
    adminSecret := r.URL.Query().Get("admin_secret")
    deviceId := r.URL.Query().Get("device_id")
    userEmail := r.URL.Query().Get("user_email") // Email of the user to look up

    if !isAdminEmail(adminEmail) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    // Get login history from main database (by email)
    var loginHistory []map[string]interface{}
    if userEmail != "" {
        loginRows, err := db.Query(`
            SELECT device_id, device_info, logged_in_at
            FROM login_history
            WHERE email = ?
            ORDER BY logged_in_at DESC
            LIMIT 50
        `, userEmail)
        if err == nil {
            defer loginRows.Close()
            for loginRows.Next() {
                var loginDeviceId sql.NullString
                var deviceInfo sql.NullString
                var loggedInAt string
                if err := loginRows.Scan(&loginDeviceId, &deviceInfo, &loggedInAt); err == nil {
                    loginHistory = append(loginHistory, map[string]interface{}{
                        "device_id":    loginDeviceId.String,
                        "device_info":  deviceInfo.String,
                        "logged_in_at": loggedInAt,
                    })
                }
            }
        }
    }

    // If no device_id provided but we have login history, return just that
    if deviceId == "" {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":       true,
            "calls":         []interface{}{},
            "login_history": loginHistory,
            "summary": map[string]interface{}{
                "total_astrolog": 0,
                "total_chatgpt":  0,
                "total_calls":    0,
                "login_count":    len(loginHistory),
            },
        })
        return
    }

    if analyticsDB == nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":       false,
            "error":         "Analytics database not initialized",
            "login_history": loginHistory,
        })
        return
    }

    // Get the last 100 API calls for this device
    rows, err := analyticsDB.Query(`
        SELECT call_type, model, created_at
        FROM api_calls
        WHERE device_id = ?
        ORDER BY created_at DESC
        LIMIT 100
    `, deviceId)

    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":       false,
            "error":         "Database query error",
            "login_history": loginHistory,
        })
        return
    }
    defer rows.Close()

    var calls []map[string]interface{}
    for rows.Next() {
        var callType string
        var model sql.NullString
        var createdAt string
        if err := rows.Scan(&callType, &model, &createdAt); err == nil {
            call := map[string]interface{}{
                "call_type": callType,
                "timestamp": createdAt,
            }
            if model.Valid {
                call["model"] = model.String
            } else {
                call["model"] = ""
            }
            calls = append(calls, call)
        }
    }

    // Get summary stats for this user
    var totalAstrolog, totalChatgpt int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE device_id = ? AND call_type = 'astrolog'`, deviceId).Scan(&totalAstrolog)
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE device_id = ? AND call_type = 'chatgpt'`, deviceId).Scan(&totalChatgpt)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":       true,
        "calls":         calls,
        "login_history": loginHistory,
        "summary": map[string]interface{}{
            "total_astrolog": totalAstrolog,
            "total_chatgpt":  totalChatgpt,
            "total_calls":    totalAstrolog + totalChatgpt,
            "login_count":    len(loginHistory),
        },
    })
}

// Admin endpoint to get aggregated model usage per user
func adminModelUsageByUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	adminEmail := r.URL.Query().Get("admin_email")
	adminSecret := r.URL.Query().Get("admin_secret")

	if !isAdminEmail(adminEmail) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Unauthorized",
		})
		return
	}

	if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid admin secret",
		})
		return
	}

	if analyticsDB == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Analytics database not initialized",
		})
		return
	}

	// Step 1: Build email -> set of device_ids mapping from both users table and login_history
	emailDevices := make(map[string]map[string]bool)
	emailInfo := make(map[string]map[string]interface{})

	userRows, err := db.Query(`SELECT email, subscription_type, is_super, current_device_id FROM users`)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to query users",
		})
		return
	}
	defer userRows.Close()

	for userRows.Next() {
		var email, subType string
		var isSuper int
		var deviceId sql.NullString
		if err := userRows.Scan(&email, &subType, &isSuper, &deviceId); err == nil {
			if _, ok := emailDevices[email]; !ok {
				emailDevices[email] = make(map[string]bool)
			}
			if deviceId.Valid && deviceId.String != "" {
				emailDevices[email][deviceId.String] = true
			}
			emailInfo[email] = map[string]interface{}{
				"subscription_type": subType,
				"is_super":          isSuper == 1,
			}
		}
	}

	// Also gather device_ids from login_history
	loginRows, err := db.Query(`SELECT DISTINCT email, device_id FROM login_history WHERE device_id IS NOT NULL AND device_id != ''`)
	if err == nil {
		defer loginRows.Close()
		for loginRows.Next() {
			var email, deviceId string
			if err := loginRows.Scan(&email, &deviceId); err == nil {
				if _, ok := emailDevices[email]; !ok {
					emailDevices[email] = make(map[string]bool)
				}
				emailDevices[email][deviceId] = true
			}
		}
	}

	// Build reverse mapping: device_id -> emails
	deviceToEmails := make(map[string][]string)
	for email, devices := range emailDevices {
		for deviceId := range devices {
			deviceToEmails[deviceId] = append(deviceToEmails[deviceId], email)
		}
	}

	// Step 2: Get all api_calls grouped by device_id and model
	allModels := make(map[string]bool)
	modelCategories := make(map[string]string) // model -> category (call_type)
	emailModelCounts := make(map[string]map[string]int)
	emailTotals := make(map[string]int)
	globalModelTotals := make(map[string]int)

	callRows, err := analyticsDB.Query(`
		SELECT device_id, call_type, COALESCE(model, 'unknown') as model, COUNT(*) as cnt
		FROM api_calls
		GROUP BY device_id, call_type, model
	`)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to query api calls",
		})
		return
	}
	defer callRows.Close()

	for callRows.Next() {
		var deviceId, callType, model string
		var cnt int
		if err := callRows.Scan(&deviceId, &callType, &model, &cnt); err == nil {
			allModels[model] = true
			modelCategories[model] = callType
			globalModelTotals[model] += cnt

			// Attribute to all emails associated with this device
			emails := deviceToEmails[deviceId]
			for _, email := range emails {
				if _, ok := emailModelCounts[email]; !ok {
					emailModelCounts[email] = make(map[string]int)
				}
				emailModelCounts[email][model] += cnt
				emailTotals[email] += cnt
			}
		}
	}

	// Step 3: Build sorted result
	type userUsage struct {
		Email   string
		Type    string
		IsSuper bool
		Models  map[string]int
		Total   int
	}

	var userUsages []userUsage
	for email, models := range emailModelCounts {
		subType := "free"
		isSuper := false
		if info, ok := emailInfo[email]; ok {
			if st, ok := info["subscription_type"].(string); ok {
				subType = st
			}
			if is, ok := info["is_super"].(bool); ok {
				isSuper = is
			}
		}
		userUsages = append(userUsages, userUsage{
			Email:   email,
			Type:    subType,
			IsSuper: isSuper,
			Models:  models,
			Total:   emailTotals[email],
		})
	}

	sort.Slice(userUsages, func(i, j int) bool {
		return userUsages[i].Total > userUsages[j].Total
	})

	// Build model list sorted by global usage descending
	modelList := make([]string, 0, len(allModels))
	for m := range allModels {
		modelList = append(modelList, m)
	}
	sort.Slice(modelList, func(i, j int) bool {
		return globalModelTotals[modelList[i]] > globalModelTotals[modelList[j]]
	})

	// Build response
	usersResult := make([]map[string]interface{}, len(userUsages))
	for i, u := range userUsages {
		usersResult[i] = map[string]interface{}{
			"email":    u.Email,
			"type":     u.Type,
			"is_super": u.IsSuper,
			"models":   u.Models,
			"total":    u.Total,
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"users":            usersResult,
		"models":           modelList,
		"model_totals":     globalModelTotals,
		"model_categories": modelCategories,
		"total_users":      len(userUsages),
	})
}

// Admin endpoint to run analytics cleanup/aggregation manually
func adminAnalyticsCleanup(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    adminEmail := r.URL.Query().Get("admin_email")
    adminSecret := r.URL.Query().Get("admin_secret")
    retentionStr := r.URL.Query().Get("retention_months")

    if !isAdminEmail(adminEmail) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    if analyticsDB == nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Analytics database not initialized",
        })
        return
    }

    // Default to 12 months retention
    retentionMonths := 12
    if retentionStr != "" {
        if months, err := strconv.Atoi(retentionStr); err == nil && months > 0 {
            retentionMonths = months
        }
    }

    // Get stats before cleanup
    var beforeCount int
    var beforeSizeBytes int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls`).Scan(&beforeCount)
    analyticsDB.QueryRow(`SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&beforeSizeBytes)

    // Run cleanup
    cleanupOldAnalyticsData(retentionMonths)

    // Get stats after cleanup
    var afterCount int
    var afterSizeBytes int
    var aggregateCount int
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls`).Scan(&afterCount)
    analyticsDB.QueryRow(`SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&afterSizeBytes)
    analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls_monthly`).Scan(&aggregateCount)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":          true,
        "retention_months": retentionMonths,
        "before": map[string]interface{}{
            "record_count": beforeCount,
            "size_mb":      fmt.Sprintf("%.2f", float64(beforeSizeBytes)/1024/1024),
        },
        "after": map[string]interface{}{
            "record_count":    afterCount,
            "size_mb":         fmt.Sprintf("%.2f", float64(afterSizeBytes)/1024/1024),
            "aggregate_count": aggregateCount,
        },
        "records_removed": beforeCount - afterCount,
    })
}

// Admin endpoint to view historical aggregated data
func adminGetHistoricalData(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    adminEmail := r.URL.Query().Get("admin_email")
    adminSecret := r.URL.Query().Get("admin_secret")

    if !isAdminEmail(adminEmail) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    if analyticsDB == nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Analytics database not initialized",
        })
        return
    }

    // Get aggregated historical data
    rows, err := analyticsDB.Query(`
        SELECT year_month, call_type, model,
               SUM(total_calls) as calls,
               SUM(total_prompt_tokens) as prompt_tokens,
               SUM(total_completion_tokens) as completion_tokens,
               SUM(total_tokens) as total_tokens
        FROM api_calls_monthly
        GROUP BY year_month, call_type, model
        ORDER BY year_month DESC, call_type, model
    `)

    if err != nil {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Database query error",
        })
        return
    }
    defer rows.Close()

    var data []map[string]interface{}
    for rows.Next() {
        var yearMonth, callType string
        var model sql.NullString
        var calls int
        var promptTokens, completionTokens, totalTokens int64

        if err := rows.Scan(&yearMonth, &callType, &model, &calls, &promptTokens, &completionTokens, &totalTokens); err == nil {
            entry := map[string]interface{}{
                "year_month":        yearMonth,
                "call_type":         callType,
                "calls":             calls,
                "prompt_tokens":     promptTokens,
                "completion_tokens": completionTokens,
                "total_tokens":      totalTokens,
            }
            if model.Valid {
                entry["model"] = model.String
            } else {
                entry["model"] = ""
            }
            data = append(data, entry)
        }
    }

    // Summary by month
    summaryRows, err := analyticsDB.Query(`
        SELECT year_month,
               SUM(total_calls) as calls,
               SUM(total_prompt_tokens) as prompt_tokens,
               SUM(total_completion_tokens) as completion_tokens,
               SUM(total_tokens) as total_tokens,
               COUNT(DISTINCT device_id) as unique_users
        FROM api_calls_monthly
        GROUP BY year_month
        ORDER BY year_month DESC
    `)

    var monthlySummary []map[string]interface{}
    if err == nil {
        defer summaryRows.Close()
        for summaryRows.Next() {
            var yearMonth string
            var calls, uniqueUsers int
            var promptTokens, completionTokens, totalTokens int64

            if err := summaryRows.Scan(&yearMonth, &calls, &promptTokens, &completionTokens, &totalTokens, &uniqueUsers); err == nil {
                monthlySummary = append(monthlySummary, map[string]interface{}{
                    "year_month":        yearMonth,
                    "total_calls":       calls,
                    "unique_users":      uniqueUsers,
                    "prompt_tokens":     promptTokens,
                    "completion_tokens": completionTokens,
                    "total_tokens":      totalTokens,
                })
            }
        }
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":         true,
        "data":            data,
        "monthly_summary": monthlySummary,
    })
}

// Admin endpoint: YooKassa renewal funnel.
// Counts impressions (server told a client to surface external renewal),
// unique exposed users, and conversions (purchase_history rows with
// store='yookassa') over a time window. Conversion rate is paid_users
// over exposed_users.
func adminRenewalFunnel(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    adminEmail := r.URL.Query().Get("admin_email")
    adminSecret := r.URL.Query().Get("admin_secret")
    if !isAdminEmail(adminEmail) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
        return
    }
    if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid admin secret"})
        return
    }

    days := r.URL.Query().Get("days")
    if days == "" {
        days = "30"
    }
    daysInt, err := strconv.Atoi(days)
    if err != nil || daysInt < 1 || daysInt > 3650 {
        daysInt = 30
    }
    since := time.Now().AddDate(0, 0, -daysInt)

    var impressions, exposedUsers int
    if analyticsDB != nil {
        analyticsDB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT email) FROM renewal_impressions WHERE shown_at >= ?`,
            since.Format("2006-01-02 15:04:05")).Scan(&impressions, &exposedUsers)
    }

    var paidUsers int
    db.QueryRow(`SELECT COUNT(DISTINCT email) FROM purchase_history WHERE store = 'yookassa' AND purchase_date >= ?`,
        since.Format("2006-01-02 15:04:05")).Scan(&paidUsers)

    var conversionRate float64
    if exposedUsers > 0 {
        conversionRate = float64(paidUsers) / float64(exposedUsers)
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":          true,
        "window_days":      daysInt,
        "since":            since.Format(time.RFC3339),
        "impressions":      impressions,
        "exposed_users":    exposedUsers,
        "paid_users":       paidUsers,
        "conversion_rate":  conversionRate,
        "note":             "exposed_users = distinct emails that saw external renewal CTA. paid_users = distinct emails that purchased via YooKassa. conversion_rate = paid_users / exposed_users.",
    })
}

// Admin endpoint to download the main database (requires 2FA verification code)
func adminDownloadDB(w http.ResponseWriter, r *http.Request) {
    // Get admin credentials from query params
    adminEmail := r.URL.Query().Get("admin_email")
    adminSecret := r.URL.Query().Get("admin_secret")
    verificationCode := r.URL.Query().Get("verification_code")

    if !isAdminEmail(adminEmail) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Unauthorized",
        })
        return
    }

    if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid admin secret",
        })
        return
    }

    // Verify the email code (2FA required)
    if verificationCode == "" {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Verification code required",
        })
        return
    }

    var codeID int
    var expiresAt time.Time
    err := db.QueryRow(`SELECT id, expires_at FROM auth_codes WHERE email = ? AND code = ? AND used = 0`,
        adminEmail, verificationCode).Scan(&codeID, &expiresAt)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Invalid or expired verification code",
        })
        return
    }

    if time.Now().After(expiresAt) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Verification code has expired",
        })
        return
    }

    // Mark code as used
    db.Exec(`UPDATE auth_codes SET used = 1 WHERE id = ?`, codeID)

    // Read database file
    dbPath := "./users.db"
    data, err := os.ReadFile(dbPath)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        log.Printf("Error reading database file: %v", err)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Failed to read database file",
        })
        return
    }

    // Generate filename with timestamp
    timestamp := time.Now().Format("2006-01-02_15-04-05")
    filename := fmt.Sprintf("astrolytix_backup_%s.db", timestamp)

    log.Printf("✅ Admin %s downloaded database backup", adminEmail)

    // Send file as download
    w.Header().Set("Content-Type", "application/x-sqlite3")
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
    w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
    w.Write(data)
}

// Admin endpoint to get detailed usage report by email and date (requires 2FA verification code)
func adminUsageReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	adminEmail := r.URL.Query().Get("admin_email")
	adminSecret := r.URL.Query().Get("admin_secret")
	verificationCode := r.URL.Query().Get("verification_code")

	if !isAdminEmail(adminEmail) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Unauthorized",
		})
		return
	}

	if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid admin secret",
		})
		return
	}

	// Verify the email code (2FA required)
	if verificationCode == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Verification code required",
		})
		return
	}

	var codeID int
	var expiresAt time.Time
	err := db.QueryRow(`SELECT id, expires_at FROM auth_codes WHERE email = ? AND code = ? AND used = 0`,
		adminEmail, verificationCode).Scan(&codeID, &expiresAt)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid or expired verification code",
		})
		return
	}

	if time.Now().After(expiresAt) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Verification code has expired",
		})
		return
	}

	// Mark code as used
	db.Exec(`UPDATE auth_codes SET used = 1 WHERE id = ?`, codeID)

	if analyticsDB == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Analytics database not initialized",
		})
		return
	}

	// Parse query params
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "daily"
	}

	// Step 1: Build email -> set of device_ids mapping
	emailDevices := make(map[string]map[string]bool)
	emailInfo := make(map[string]map[string]interface{})

	userRows, err := db.Query(`SELECT email, subscription_type, is_super, current_device_id FROM users`)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to query users",
		})
		return
	}
	defer userRows.Close()

	for userRows.Next() {
		var email, subType string
		var isSuper int
		var deviceId sql.NullString
		if err := userRows.Scan(&email, &subType, &isSuper, &deviceId); err == nil {
			if _, ok := emailDevices[email]; !ok {
				emailDevices[email] = make(map[string]bool)
			}
			if deviceId.Valid && deviceId.String != "" {
				emailDevices[email][deviceId.String] = true
			}
			emailInfo[email] = map[string]interface{}{
				"subscription_type": subType,
				"is_super":          isSuper == 1,
			}
		}
	}

	// Also gather device_ids from login_history
	loginRows, err := db.Query(`SELECT DISTINCT email, device_id FROM login_history WHERE device_id IS NOT NULL AND device_id != ''`)
	if err == nil {
		defer loginRows.Close()
		for loginRows.Next() {
			var email, deviceId string
			if err := loginRows.Scan(&email, &deviceId); err == nil {
				if _, ok := emailDevices[email]; !ok {
					emailDevices[email] = make(map[string]bool)
				}
				emailDevices[email][deviceId] = true
			}
		}
	}

	// Build reverse mapping: device_id -> emails
	deviceToEmails := make(map[string][]string)
	for email, devices := range emailDevices {
		for deviceId := range devices {
			deviceToEmails[deviceId] = append(deviceToEmails[deviceId], email)
		}
	}

	// Step 2: Query api_calls grouped by device_id, date, call_type, model with token sums
	dateFormat := "date(created_at)"
	if period == "monthly" {
		dateFormat = "strftime('%Y-%m', created_at)"
	}

	query := fmt.Sprintf(`
		SELECT device_id, %s as period_date, call_type, COALESCE(model, 'unknown') as model,
		       COUNT(*) as cnt,
		       SUM(COALESCE(prompt_tokens, 0)) as prompt_toks,
		       SUM(COALESCE(completion_tokens, 0)) as completion_toks,
		       SUM(COALESCE(total_tokens, 0)) as total_toks
		FROM api_calls
		WHERE 1=1
	`, dateFormat)

	var args []interface{}
	if startDate != "" {
		query += " AND date(created_at) >= ?"
		args = append(args, startDate)
	}
	if endDate != "" {
		query += " AND date(created_at) <= ?"
		args = append(args, endDate)
	}
	query += fmt.Sprintf(" GROUP BY device_id, %s, call_type, model ORDER BY period_date", dateFormat)

	callRows, err := analyticsDB.Query(query, args...)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to query api calls: " + err.Error(),
		})
		return
	}
	defer callRows.Close()

	// Step 3: Aggregate data per email per date
	type dailyEntry struct {
		Calls           int
		AstrologCalls   int
		ChatgptCalls    int
		PromptTokens    int64
		CompletionTokens int64
		TotalTokens     int64
		Models          map[string]int
	}

	type emailData struct {
		TotalCalls       int
		AstrologCalls    int
		ChatgptCalls     int
		PromptTokens     int64
		CompletionTokens int64
		TotalTokens      int64
		ModelsUsed       map[string]int
		Daily            map[string]*dailyEntry
	}

	emailStats := make(map[string]*emailData)

	// Also track by-date aggregates
	type dateAggregate struct {
		TotalCalls       int
		UniqueUsers      map[string]bool
		PromptTokens     int64
		CompletionTokens int64
		TotalTokens      int64
	}
	dateStats := make(map[string]*dateAggregate)

	for callRows.Next() {
		var deviceId, periodDate, callType, model string
		var cnt int
		var promptToks, completionToks, totalToks int64
		if err := callRows.Scan(&deviceId, &periodDate, &callType, &model, &cnt, &promptToks, &completionToks, &totalToks); err != nil {
			continue
		}

		emails := deviceToEmails[deviceId]
		for _, email := range emails {
			if _, ok := emailStats[email]; !ok {
				emailStats[email] = &emailData{
					ModelsUsed: make(map[string]int),
					Daily:      make(map[string]*dailyEntry),
				}
			}
			ed := emailStats[email]
			ed.TotalCalls += cnt
			ed.PromptTokens += promptToks
			ed.CompletionTokens += completionToks
			ed.TotalTokens += totalToks
			ed.ModelsUsed[model] += cnt

			if callType == "astrolog" {
				ed.AstrologCalls += cnt
			} else {
				ed.ChatgptCalls += cnt
			}

			if _, ok := ed.Daily[periodDate]; !ok {
				ed.Daily[periodDate] = &dailyEntry{Models: make(map[string]int)}
			}
			day := ed.Daily[periodDate]
			day.Calls += cnt
			day.PromptTokens += promptToks
			day.CompletionTokens += completionToks
			day.TotalTokens += totalToks
			day.Models[model] += cnt
			if callType == "astrolog" {
				day.AstrologCalls += cnt
			} else {
				day.ChatgptCalls += cnt
			}

			// Track date aggregates
			if _, ok := dateStats[periodDate]; !ok {
				dateStats[periodDate] = &dateAggregate{UniqueUsers: make(map[string]bool)}
			}
			dateStats[periodDate].UniqueUsers[email] = true
		}

		// Date aggregates (count once per device, not per email)
		if _, ok := dateStats[periodDate]; !ok {
			dateStats[periodDate] = &dateAggregate{UniqueUsers: make(map[string]bool)}
		}
		dateStats[periodDate].TotalCalls += cnt
		dateStats[periodDate].PromptTokens += promptToks
		dateStats[periodDate].CompletionTokens += completionToks
		dateStats[periodDate].TotalTokens += totalToks
	}

	// Helper: estimate cost based on model pricing
	estimateCost := func(model string, promptToks, completionToks int64) float64 {
		switch model {
		case "gpt-4o":
			return (float64(promptToks) * 2.50 / 1000000) + (float64(completionToks) * 10.00 / 1000000)
		case "gpt-4o-mini":
			return (float64(promptToks) * 0.15 / 1000000) + (float64(completionToks) * 0.60 / 1000000)
		case "o1":
			return (float64(promptToks) * 15.00 / 1000000) + (float64(completionToks) * 60.00 / 1000000)
		case "o1-mini":
			return (float64(promptToks) * 1.10 / 1000000) + (float64(completionToks) * 4.40 / 1000000)
		default:
			return (float64(promptToks) * 2.50 / 1000000) + (float64(completionToks) * 10.00 / 1000000)
		}
	}

	// Step 4: We need per-model token breakdown for cost. Re-query per email won't work since we aggregated.
	// Instead, query model-level token breakdown per device per date for cost estimation.
	costQuery := fmt.Sprintf(`
		SELECT device_id, %s as period_date, COALESCE(model, 'unknown') as model,
		       SUM(COALESCE(prompt_tokens, 0)) as prompt_toks,
		       SUM(COALESCE(completion_tokens, 0)) as completion_toks
		FROM api_calls
		WHERE 1=1
	`, dateFormat)

	var costArgs []interface{}
	if startDate != "" {
		costQuery += " AND date(created_at) >= ?"
		costArgs = append(costArgs, startDate)
	}
	if endDate != "" {
		costQuery += " AND date(created_at) <= ?"
		costArgs = append(costArgs, endDate)
	}
	costQuery += fmt.Sprintf(" GROUP BY device_id, %s, model", dateFormat)

	costRows, err := analyticsDB.Query(costQuery, costArgs...)

	// email -> total cost, email -> date -> cost
	emailCost := make(map[string]float64)
	emailDailyCost := make(map[string]map[string]float64)
	dateCost := make(map[string]float64)

	if err == nil {
		defer costRows.Close()
		for costRows.Next() {
			var deviceId, periodDate, model string
			var promptToks, completionToks int64
			if err := costRows.Scan(&deviceId, &periodDate, &model, &promptToks, &completionToks); err != nil {
				continue
			}
			cost := estimateCost(model, promptToks, completionToks)

			emails := deviceToEmails[deviceId]
			for _, email := range emails {
				emailCost[email] += cost
				if _, ok := emailDailyCost[email]; !ok {
					emailDailyCost[email] = make(map[string]float64)
				}
				emailDailyCost[email][periodDate] += cost
			}
			dateCost[periodDate] += cost
		}
	}

	// Step 5: Build response
	// by_user array
	type userResult struct {
		Email string
		Total int
	}
	var userOrder []userResult
	for email, ed := range emailStats {
		userOrder = append(userOrder, userResult{Email: email, Total: ed.TotalCalls})
	}
	sort.Slice(userOrder, func(i, j int) bool {
		return userOrder[i].Total > userOrder[j].Total
	})

	var byUser []map[string]interface{}
	var grandTotalCalls int
	var grandTotalTokens int64
	var grandTotalCost float64
	uniqueEmails := make(map[string]bool)

	for _, ur := range userOrder {
		email := ur.Email
		ed := emailStats[email]
		uniqueEmails[email] = true
		grandTotalCalls += ed.TotalCalls
		grandTotalTokens += ed.TotalTokens
		grandTotalCost += emailCost[email]

		subType := "free"
		isSuper := false
		if info, ok := emailInfo[email]; ok {
			if st, ok := info["subscription_type"].(string); ok {
				subType = st
			}
			if is, ok := info["is_super"].(bool); ok {
				isSuper = is
			}
		}

		// Build daily breakdown sorted by date
		var dates []string
		for d := range ed.Daily {
			dates = append(dates, d)
		}
		sort.Strings(dates)

		var dailyArr []map[string]interface{}
		for _, d := range dates {
			day := ed.Daily[d]
			dayCost := float64(0)
			if dc, ok := emailDailyCost[email]; ok {
				dayCost = dc[d]
			}
			dailyArr = append(dailyArr, map[string]interface{}{
				"date":             d,
				"calls":            day.Calls,
				"astrolog_calls":   day.AstrologCalls,
				"chatgpt_calls":    day.ChatgptCalls,
				"prompt_tokens":    day.PromptTokens,
				"completion_tokens": day.CompletionTokens,
				"tokens":           day.TotalTokens,
				"cost":             fmt.Sprintf("$%.4f", dayCost),
			})
		}

		byUser = append(byUser, map[string]interface{}{
			"email":             email,
			"type":              subType,
			"is_super":          isSuper,
			"total_calls":       ed.TotalCalls,
			"astrolog_calls":    ed.AstrologCalls,
			"chatgpt_calls":     ed.ChatgptCalls,
			"prompt_tokens":     ed.PromptTokens,
			"completion_tokens": ed.CompletionTokens,
			"total_tokens":      ed.TotalTokens,
			"estimated_cost":    fmt.Sprintf("$%.4f", emailCost[email]),
			"models_used":       ed.ModelsUsed,
			"daily":             dailyArr,
		})
	}

	// by_date array
	var dateKeys []string
	for d := range dateStats {
		dateKeys = append(dateKeys, d)
	}
	sort.Strings(dateKeys)

	var byDate []map[string]interface{}
	for _, d := range dateKeys {
		ds := dateStats[d]
		byDate = append(byDate, map[string]interface{}{
			"date":         d,
			"total_calls":  ds.TotalCalls,
			"unique_users": len(ds.UniqueUsers),
			"tokens":       ds.TotalTokens,
			"cost":         fmt.Sprintf("$%.4f", dateCost[d]),
		})
	}

	log.Printf("✅ Admin %s generated usage report (%d users, %d dates)", adminEmail, len(byUser), len(byDate))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"report": map[string]interface{}{
			"by_user": byUser,
			"by_date": byDate,
			"totals": map[string]interface{}{
				"calls":  grandTotalCalls,
				"users":  len(uniqueEmails),
				"tokens": grandTotalTokens,
				"cost":   fmt.Sprintf("$%.4f", grandTotalCost),
			},
			"period":     period,
			"start_date": startDate,
			"end_date":   endDate,
		},
	})
}

// Admin endpoint to proxy OpenAI Costs & Usage APIs (key is never stored)
func adminOpenAICosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var reqBody struct {
		AdminEmail    string `json:"admin_email"`
		AdminSecret   string `json:"admin_secret"`
		OpenAIKey     string `json:"openai_admin_key"`
		StartDate     string `json:"start_date"`
		EndDate       string `json:"end_date"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	if !isAdminEmail(reqBody.AdminEmail) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Unauthorized",
		})
		return
	}

	if ADMIN_SECRET_KEY != "" && reqBody.AdminSecret != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid admin secret",
		})
		return
	}

	if reqBody.OpenAIKey == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "OpenAI admin API key is required",
		})
		return
	}

	// Parse date range (default: last 30 days)
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -30)

	if reqBody.StartDate != "" {
		if t, err := time.Parse("2006-01-02", reqBody.StartDate); err == nil {
			startTime = t
		}
	}
	if reqBody.EndDate != "" {
		if t, err := time.Parse("2006-01-02", reqBody.EndDate); err == nil {
			endTime = t.Add(24 * time.Hour) // include the end date
		}
	}

	startUnix := startTime.Unix()
	endUnix := endTime.Unix()

	client := &http.Client{Timeout: 30 * time.Second}

	// Helper to fetch paginated OpenAI API data
	fetchOpenAI := func(baseURL string, extraParams string) ([]json.RawMessage, error) {
		var allBuckets []json.RawMessage
		nextPage := ""

		for {
			url := fmt.Sprintf("%s?start_time=%d&end_time=%d&bucket_width=1d&limit=30",
				baseURL, startUnix, endUnix)
			if extraParams != "" {
				url += "&" + extraParams
			}
			if nextPage != "" {
				url += "&page=" + nextPage
			}

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+reqBody.OpenAIKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("request failed: %v", err)
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read response: %v", err)
			}

			if resp.StatusCode != 200 {
				// Parse and sanitize error — never leak API key in response
				var errObj struct {
					Error interface{} `json:"error"`
				}
				errMsg := ""
				if json.Unmarshal(body, &errObj) == nil {
					switch e := errObj.Error.(type) {
					case string:
						errMsg = e
					case map[string]interface{}:
						if msg, ok := e["message"].(string); ok {
							errMsg = msg
						}
					}
				}
				switch resp.StatusCode {
				case 401:
					return nil, fmt.Errorf("Invalid API key. Use an Admin key (sk-admin-...) from platform.openai.com > API Keys")
				case 403:
					if strings.Contains(errMsg, "api.usage.read") {
						return nil, fmt.Errorf("Key missing 'api.usage.read' scope. Edit your key at platform.openai.com > API Keys and enable Usage read permission (or use a key with All permissions)")
					}
					return nil, fmt.Errorf("Access denied (403). Your key needs admin/usage permissions")
				default:
					if errMsg != "" {
						return nil, fmt.Errorf("OpenAI error (%d): %s", resp.StatusCode, errMsg)
					}
					return nil, fmt.Errorf("OpenAI error (HTTP %d)", resp.StatusCode)
				}
			}

			var page struct {
				Data     []json.RawMessage `json:"data"`
				HasMore  bool              `json:"has_more"`
				NextPage string            `json:"next_page"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				return nil, fmt.Errorf("failed to parse response: %v", err)
			}

			allBuckets = append(allBuckets, page.Data...)
			if !page.HasMore || page.NextPage == "" {
				break
			}
			nextPage = page.NextPage
		}
		return allBuckets, nil
	}

	// Fetch Costs API
	costsBuckets, costsErr := fetchOpenAI("https://api.openai.com/v1/organization/costs", "")

	// Fetch Usage API (completions, grouped by model)
	usageBuckets, usageErr := fetchOpenAI("https://api.openai.com/v1/organization/usage/completions", "group_by[]=model")

	if costsErr != nil && usageErr != nil {
		// Both failed — show the more useful error (they're usually the same)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   costsErr.Error(),
		})
		return
	}

	// Parse costs data into daily breakdown
	type dailyCost struct {
		Date      string             `json:"date"`
		Total     float64            `json:"total"`
		ByModel   map[string]float64 `json:"by_model"`
	}

	costsByDate := make(map[string]*dailyCost)
	var totalActualCost float64

	if costsErr == nil {
		log.Printf("📊 Costs API returned %d buckets", len(costsBuckets))
		for i, raw := range costsBuckets {
			if i == 0 {
				// Log first bucket raw for debugging
				log.Printf("📊 Costs bucket[0] raw: %s", string(raw))
			}
			// Try flexible parsing — amount could be struct or number
			var bucket map[string]interface{}
			if err := json.Unmarshal(raw, &bucket); err != nil {
				log.Printf("📊 Costs bucket parse error: %v", err)
				continue
			}
			startTimeVal, _ := bucket["start_time"].(float64)
			date := time.Unix(int64(startTimeVal), 0).UTC().Format("2006-01-02")
			if _, ok := costsByDate[date]; !ok {
				costsByDate[date] = &dailyCost{Date: date, ByModel: make(map[string]float64)}
			}

			results, ok := bucket["results"].([]interface{})
			if !ok {
				log.Printf("📊 Costs bucket has no results array, keys: %v", func() []string {
					keys := make([]string, 0, len(bucket))
					for k := range bucket { keys = append(keys, k) }
					return keys
				}())
				continue
			}
			for _, r := range results {
				result, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				lineItem, _ := result["line_item"].(string)
				var costValue float64
				// Handle amount as struct {value, currency} or as direct number
				switch amt := result["amount"].(type) {
				case map[string]interface{}:
					costValue, _ = amt["value"].(float64)
				case float64:
					costValue = amt
				}
				costsByDate[date].Total += costValue
				costsByDate[date].ByModel[lineItem] += costValue
				totalActualCost += costValue
			}
		}
		log.Printf("📊 Costs parsed: %d dates, total=$%.4f", len(costsByDate), totalActualCost)
	}

	// Parse usage data into daily + model breakdown
	type dailyUsage struct {
		Date          string         `json:"date"`
		InputTokens   int64          `json:"input_tokens"`
		OutputTokens  int64          `json:"output_tokens"`
		Requests      int64          `json:"requests"`
		ByModel       map[string]map[string]int64 `json:"by_model"`
	}

	usageByDate := make(map[string]*dailyUsage)
	modelTotals := make(map[string]map[string]int64) // model -> {input_tokens, output_tokens, requests}
	var totalInputTokens, totalOutputTokens, totalRequests int64

	if usageErr == nil {
		for _, raw := range usageBuckets {
			var bucket struct {
				StartTime int64 `json:"start_time"`
				Results   []struct {
					InputTokens      int64  `json:"input_tokens"`
					OutputTokens     int64  `json:"output_tokens"`
					NumModelRequests int64  `json:"num_model_requests"`
					Model            string `json:"model"`
				} `json:"results"`
			}
			if err := json.Unmarshal(raw, &bucket); err != nil {
				continue
			}
			date := time.Unix(bucket.StartTime, 0).UTC().Format("2006-01-02")
			if _, ok := usageByDate[date]; !ok {
				usageByDate[date] = &dailyUsage{Date: date, ByModel: make(map[string]map[string]int64)}
			}
			for _, r := range bucket.Results {
				usageByDate[date].InputTokens += r.InputTokens
				usageByDate[date].OutputTokens += r.OutputTokens
				usageByDate[date].Requests += r.NumModelRequests
				totalInputTokens += r.InputTokens
				totalOutputTokens += r.OutputTokens
				totalRequests += r.NumModelRequests

				if _, ok := usageByDate[date].ByModel[r.Model]; !ok {
					usageByDate[date].ByModel[r.Model] = make(map[string]int64)
				}
				usageByDate[date].ByModel[r.Model]["input_tokens"] += r.InputTokens
				usageByDate[date].ByModel[r.Model]["output_tokens"] += r.OutputTokens
				usageByDate[date].ByModel[r.Model]["requests"] += r.NumModelRequests

				if _, ok := modelTotals[r.Model]; !ok {
					modelTotals[r.Model] = make(map[string]int64)
				}
				modelTotals[r.Model]["input_tokens"] += r.InputTokens
				modelTotals[r.Model]["output_tokens"] += r.OutputTokens
				modelTotals[r.Model]["requests"] += r.NumModelRequests
			}
		}
	}

	// Calculate cost from Usage API tokens using per-model pricing
	estimateModelCost := func(model string, inputToks, outputToks int64) float64 {
		inF := float64(inputToks) / 1000000.0
		outF := float64(outputToks) / 1000000.0
		// Pricing per 1M tokens (input / output)
		switch {
		case strings.Contains(model, "gpt-4o-mini"):
			return inF*0.15 + outF*0.60
		case strings.Contains(model, "gpt-4o"):
			return inF*2.50 + outF*10.00
		case strings.Contains(model, "gpt-4-turbo"):
			return inF*10.00 + outF*30.00
		case strings.Contains(model, "gpt-4"):
			return inF*30.00 + outF*60.00
		case strings.Contains(model, "gpt-3.5-turbo"):
			return inF*0.50 + outF*1.50
		case strings.Contains(model, "o1-mini"):
			return inF*1.10 + outF*4.40
		case strings.Contains(model, "o1"):
			return inF*15.00 + outF*60.00
		default:
			return inF*2.50 + outF*10.00 // default to gpt-4o pricing
		}
	}

	var totalCalculatedCost float64
	dailyCalculatedCost := make(map[string]float64)

	// Build model summary with calculated costs
	var modelSummary []map[string]interface{}
	for model, totals := range modelTotals {
		modelCost := estimateModelCost(model, totals["input_tokens"], totals["output_tokens"])
		totalCalculatedCost += modelCost
		ms := map[string]interface{}{
			"model":          model,
			"input_tokens":   totals["input_tokens"],
			"output_tokens":  totals["output_tokens"],
			"requests":       totals["requests"],
			"calculated_cost": fmt.Sprintf("$%.4f", modelCost),
		}
		modelSummary = append(modelSummary, ms)
	}

	// Calculate per-day costs from usage data
	for d, u := range usageByDate {
		for model, toks := range u.ByModel {
			dailyCalculatedCost[d] += estimateModelCost(model, toks["input_tokens"], toks["output_tokens"])
		}
	}

	sort.Slice(modelSummary, func(i, j int) bool {
		ri := modelSummary[i]["requests"].(int64)
		rj := modelSummary[j]["requests"].(int64)
		return ri > rj
	})

	// Build combined daily array
	allDates := make(map[string]bool)
	for d := range costsByDate {
		allDates[d] = true
	}
	for d := range usageByDate {
		allDates[d] = true
	}

	var dateKeys []string
	for d := range allDates {
		dateKeys = append(dateKeys, d)
	}
	sort.Strings(dateKeys)

	var dailyData []map[string]interface{}
	for _, d := range dateKeys {
		entry := map[string]interface{}{"date": d}
		if c, ok := costsByDate[d]; ok {
			entry["actual_cost"] = fmt.Sprintf("$%.4f", c.Total)
			entry["actual_cost_raw"] = c.Total
			entry["cost_by_model"] = c.ByModel
		}
		if u, ok := usageByDate[d]; ok {
			entry["input_tokens"] = u.InputTokens
			entry["output_tokens"] = u.OutputTokens
			entry["requests"] = u.Requests
			entry["usage_by_model"] = u.ByModel
		}
		if cc, ok := dailyCalculatedCost[d]; ok {
			entry["calculated_cost"] = fmt.Sprintf("$%.4f", cc)
			entry["calculated_cost_raw"] = cc
		}
		dailyData = append(dailyData, entry)
	}

	log.Printf("✅ Admin %s fetched OpenAI costs (%d days, $%.4f total)", reqBody.AdminEmail, len(dailyData), totalActualCost)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"costs": map[string]interface{}{
			"daily":        dailyData,
			"models":       modelSummary,
			"totals": map[string]interface{}{
				"actual_cost":      fmt.Sprintf("$%.4f", totalActualCost),
				"calculated_cost":  fmt.Sprintf("$%.4f", totalCalculatedCost),
				"input_tokens":     totalInputTokens,
				"output_tokens":    totalOutputTokens,
				"requests":         totalRequests,
			},
			"start_date": startTime.Format("2006-01-02"),
			"end_date":   endTime.Add(-1 * time.Second).Format("2006-01-02"),
		},
		"errors": map[string]interface{}{
			"costs_error": func() string { if costsErr != nil { return costsErr.Error() }; return "" }(),
			"usage_error": func() string { if usageErr != nil { return usageErr.Error() }; return "" }(),
		},
	})
}

func main() {
    // Initialize JWT secret (load or generate)
    if err := initJWTSecret(); err != nil {
        log.Fatalf("Failed to initialize JWT secret: %v", err)
    }

    // Initialize database
    if err := initDB(); err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }
    defer db.Close()

    // Initialize analytics database
    if err := initAnalyticsDB(); err != nil {
        log.Printf("⚠️ Warning: Analytics database failed to initialize: %v", err)
        // Continue anyway - analytics is optional
    } else {
        defer analyticsDB.Close()
    }

    router := mux.NewRouter()

    // Public endpoints (no JWT required)
    router.HandleFunc("/api/user/register", registerOrUpdateUser).Methods("POST")
    router.HandleFunc("/api/auth/refresh", refreshAccessToken).Methods("POST")
    router.HandleFunc("/api/auth/request-code", requestAuthCode).Methods("POST")
    router.HandleFunc("/api/auth/verify-code", verifyAuthCode).Methods("POST")

    // Analytics endpoints (public - no JWT required for event tracking)
    router.HandleFunc("/api/analytics/event", trackAnalyticsEvent).Methods("POST")
    router.HandleFunc("/api/analytics/events", trackAnalyticsEvents).Methods("POST")

    // Protected endpoints (JWT required)
    router.HandleFunc("/api/astrolog", jwtAuthMiddleware(calculateChart)).Methods("POST")
    router.HandleFunc("/api/transit-year", jwtAuthMiddleware(calculateTransitYear)).Methods("POST")
    router.HandleFunc("/api/chatgpt", jwtAuthMiddleware(chatGPTProxy)).Methods("POST")
    router.HandleFunc("/api/user/info", jwtAuthMiddleware(getUserInfo)).Methods("GET")
    router.HandleFunc("/api/user/purchases", jwtAuthMiddleware(recordPurchase)).Methods("POST")
    router.HandleFunc("/api/user/purchases", jwtAuthMiddleware(getPurchaseHistory)).Methods("GET")
    router.HandleFunc("/api/user/data", jwtAuthMiddleware(deleteUserData)).Methods("DELETE")

    // T2.B partner invite endpoints
    router.HandleFunc("/api/invites/create", jwtAuthMiddleware(createInvite)).Methods("POST")
    router.HandleFunc("/api/invites/{hash}", getInvite).Methods("GET")

    // Bot endpoints (BOT_API_SECRET required - no 2FA)
    router.HandleFunc("/api/bot/check-email", botCheckEmail).Methods("GET")
    router.HandleFunc("/api/bot/grant-subscription", botGrantSubscription).Methods("POST")

    // Admin endpoints (admin email + secret + verification code required)
    router.HandleFunc("/api/admin/request-code", adminRequestCode).Methods("POST")
    router.HandleFunc("/api/admin/grant-subscription", adminGrantSubscription).Methods("POST")
    router.HandleFunc("/api/admin/users", adminListUsers).Methods("GET")
    router.HandleFunc("/api/admin/toggle-super", adminToggleSuper).Methods("POST")
    router.HandleFunc("/api/admin/analytics", adminGetAnalytics).Methods("GET")
    router.HandleFunc("/api/admin/user-calls", adminGetUserCalls).Methods("GET")
    router.HandleFunc("/api/admin/analytics-cleanup", adminAnalyticsCleanup).Methods("POST")
    router.HandleFunc("/api/admin/historical-data", adminGetHistoricalData).Methods("GET")
    router.HandleFunc("/api/admin/download-db", adminDownloadDB).Methods("GET")
    router.HandleFunc("/api/admin/model-usage-by-user", adminModelUsageByUser).Methods("GET")
    router.HandleFunc("/api/admin/usage-report", adminUsageReport).Methods("GET")
    router.HandleFunc("/api/admin/openai-costs", adminOpenAICosts).Methods("POST")
    router.HandleFunc("/api/admin/renewal-funnel", adminRenewalFunnel).Methods("GET")

    log.Println("✓ Registered routes:")
    log.Println("  [PUBLIC]    POST /api/user/register - Register device and get tokens")
    log.Println("  [PUBLIC]    POST /api/auth/refresh - Refresh access token")
    log.Println("  [PUBLIC]    POST /api/auth/request-code - Request email verification code")
    log.Println("  [PUBLIC]    POST /api/auth/verify-code - Verify code and get tokens")
    log.Println("  [ANALYTICS] POST /api/analytics/event - Track single analytics event")
    log.Println("  [ANALYTICS] POST /api/analytics/events - Track batch analytics events")
    log.Println("  [BOT]       GET  /api/bot/check-email - Check if email exists (BOT_API_SECRET)")
    log.Println("  [BOT]       POST /api/bot/grant-subscription - Grant subscription from bot (BOT_API_SECRET)")
    log.Println("  [ADMIN]     POST /api/admin/request-code - Request admin verification code")
    log.Println("  [ADMIN]     POST /api/admin/grant-subscription - Grant subscription (2FA required)")
    log.Println("  [ADMIN]     GET  /api/admin/users - List users (admin only)")
    log.Println("  [ADMIN]     POST /api/admin/toggle-super - Toggle super tier (admin only)")
    log.Println("  [ADMIN]     GET  /api/admin/analytics - Get usage analytics with token stats (admin only)")
    log.Println("  [ADMIN]     GET  /api/admin/user-calls - Get user API call history (admin only)")
    log.Println("  [ADMIN]     POST /api/admin/analytics-cleanup - Run retention cleanup (admin only)")
    log.Println("  [ADMIN]     GET  /api/admin/historical-data - Get aggregated historical data (admin only)")
    log.Println("  [ADMIN]     GET  /api/admin/download-db - Download database backup (2FA required)")
    log.Println("  [ADMIN]     GET  /api/admin/usage-report - Detailed usage report by email & date (2FA required)")
    log.Println("  [ADMIN]     POST /api/admin/openai-costs - Proxy OpenAI Costs & Usage APIs (key not stored)")
    log.Println("  [PROTECTED] POST /api/astrolog - Calculate chart (JWT required)")
    log.Println("  [PROTECTED] POST /api/transit-year - Batch transit data for year (JWT required)")
    log.Println("  [PROTECTED] POST /api/chatgpt - ChatGPT proxy (JWT required)")
    log.Println("  [PROTECTED] GET  /api/user/info - Get user info (JWT required)")
    log.Println("  [PROTECTED] POST /api/user/purchases - Record purchase (JWT required)")
    log.Println("  [PROTECTED] GET  /api/user/purchases - Get purchase history (JWT required)")
    log.Println("  [PROTECTED] POST /api/invites/create - Create partner invite hash (JWT required)")
    log.Println("  [PUBLIC]    GET  /api/invites/{hash} - Resolve partner invite to birth data")
    log.Println("")
    log.Println("⚠️  JWT Authentication is ENABLED")
    log.Println("   Protected endpoints require 'Authorization: Bearer <token>' header")

    // CORS configuration
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"*"}, // Configure this for your app
        AllowedMethods: []string{"GET", "POST"},
        AllowedHeaders: []string{"Content-Type", "Authorization"}, // Added Authorization header
    })

    handler := c.Handler(router)

    // Start server with HTTPS if configured
    if USE_HTTPS == "true" && TLS_CERT_FILE != "" && TLS_KEY_FILE != "" {
        log.Printf("🔒 Astrolog API server starting with HTTPS on port %s", PORT)
        log.Printf("   Certificate: %s", TLS_CERT_FILE)
        log.Printf("   Private Key: %s", TLS_KEY_FILE)
        log.Fatal(http.ListenAndServeTLS(":"+PORT, TLS_CERT_FILE, TLS_KEY_FILE, handler))
    } else {
        log.Printf("⚠️  Astrolog API server starting with HTTP (insecure) on port %s", PORT)
        log.Printf("   Set USE_HTTPS=true, TLS_CERT_FILE, and TLS_KEY_FILE for secure HTTPS")
        log.Fatal(http.ListenAndServe(":"+PORT, handler))
    }
}