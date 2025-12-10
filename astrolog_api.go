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
)

// JWT Claims structure
type JWTClaims struct {
    DeviceID           string `json:"device_id"`
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

// Admin code request (step 1)
type AdminRequestCodeRequest struct {
    AdminEmail  string `json:"admin_email"`
    AdminSecret string `json:"admin_secret"`
}

// Purchase record request
type RecordPurchaseRequest struct {
    ProductID          string `json:"product_id"`
    TransactionID      string `json:"transaction_id"`
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
        // Allow burst of 5 requests (natal + navamsha + transit + tithi + chatgpt), then 2 requests per second
        limiter = rate.NewLimiter(rate.Every(500*time.Millisecond), 5)
        dl.limiters[deviceID] = limiter
    }

    // Clean old limiters (simple memory management)
    if len(dl.limiters) > 10000 {
        dl.limiters = make(map[string]*rate.Limiter)
    }

    return limiter
}

var deviceLimiter = NewDeviceLimiter()

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

    // Create users table with device_id as primary key (basic structure)
    createTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        device_id TEXT PRIMARY KEY,
        subscription_type TEXT NOT NULL DEFAULT 'free',
        subscription_length TEXT NOT NULL DEFAULT 'monthly',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_subscription ON users(subscription_type, subscription_length);
    `

    _, err = db.Exec(createTableSQL)
    if err != nil {
        return fmt.Errorf("failed to create users table: %v", err)
    }

    // Add email column to existing users table if it doesn't exist
    // SQLite doesn't support IF NOT EXISTS for ALTER TABLE, so we check first
    var count int
    err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='email'`).Scan(&count)
    if err == nil && count == 0 {
        _, err = db.Exec(`ALTER TABLE users ADD COLUMN email TEXT`)
        if err != nil {
            log.Printf("Warning: Could not add email column: %v", err)
        } else {
            log.Println("✅ Added email column to users table")
        }
    }

    // Create email index (only if email column exists now)
    _, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_email ON users(email) WHERE email IS NOT NULL`)
    if err != nil {
        log.Printf("Note: email index may already exist or email column missing: %v", err)
    }

    // Add subscription_expiry column if it doesn't exist
    err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='subscription_expiry'`).Scan(&count)
    if err == nil && count == 0 {
        _, err = db.Exec(`ALTER TABLE users ADD COLUMN subscription_expiry DATETIME`)
        if err != nil {
            log.Printf("Warning: Could not add subscription_expiry column: %v", err)
        } else {
            log.Println("✅ Added subscription_expiry column to users table")
        }
    }

    // Add is_super column for super tier access (more powerful AI model)
    err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='is_super'`).Scan(&count)
    if err == nil && count == 0 {
        _, err = db.Exec(`ALTER TABLE users ADD COLUMN is_super INTEGER DEFAULT 0`)
        if err != nil {
            log.Printf("Warning: Could not add is_super column: %v", err)
        } else {
            log.Println("✅ Added is_super column to users table")
        }
    }

    // Create auth_codes table for email verification
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

    // Create purchase_history table for tracking subscription purchases
    createPurchaseHistorySQL := `
    CREATE TABLE IF NOT EXISTS purchase_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        product_id TEXT NOT NULL,
        transaction_id TEXT,
        purchase_date DATETIME NOT NULL,
        expiry_date DATETIME,
        subscription_type TEXT NOT NULL,
        subscription_length TEXT NOT NULL,
        store TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES users(device_id)
    );

    CREATE INDEX IF NOT EXISTS idx_purchase_device ON purchase_history(device_id);
    CREATE INDEX IF NOT EXISTS idx_purchase_date ON purchase_history(purchase_date);
    `

    _, err = db.Exec(createPurchaseHistorySQL)
    if err != nil {
        return fmt.Errorf("failed to create purchase_history table: %v", err)
    }

    log.Println("✅ Database initialized successfully")
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

    log.Println("✅ Analytics database initialized successfully")
    return nil
}

// Log an API call to analytics database
func logAPICall(deviceID, callType, model string) {
    if analyticsDB == nil {
        return
    }
    go func() {
        _, err := analyticsDB.Exec(`INSERT INTO api_calls (device_id, call_type, model) VALUES (?, ?, ?)`,
            deviceID, callType, model)
        if err != nil {
            log.Printf("⚠️ Failed to log API call: %v", err)
        }
    }()
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

// Generate JWT access token
func generateAccessToken(deviceID, subscriptionType, subscriptionLength string) (string, error) {
    now := time.Now()
    claims := JWTClaims{
        DeviceID:           deviceID,
        SubscriptionType:   subscriptionType,
        SubscriptionLength: subscriptionLength,
        TokenType:          "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(now.Add(ACCESS_TOKEN_EXP)),
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    "astrolog-api",
            Subject:   deviceID,
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(JWT_SECRET_KEY))
}

// Generate JWT refresh token
func generateRefreshToken(deviceID, subscriptionType, subscriptionLength string) (string, error) {
    now := time.Now()
    claims := JWTClaims{
        DeviceID:           deviceID,
        SubscriptionType:   subscriptionType,
        SubscriptionLength: subscriptionLength,
        TokenType:          "refresh",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(now.Add(REFRESH_TOKEN_EXP)),
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    "astrolog-api",
            Subject:   deviceID,
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

    if month < 1 || month > 12 || day < 1 || day > 31 || year < 1900 || year > 2100 {
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

    // Check device rate limit
    limiter := deviceLimiter.GetLimiter(deviceID)
    if !limiter.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Rate limit exceeded. Please wait 1 second.",
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
    lines := strings.Split(string(output), "\n")
    var filtered []string
    for _, line := range lines {
        if !strings.Contains(line, "Midh") && !strings.HasPrefix(line, "House cusp") {
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

// Register or update user by device ID (IDEMPOTENT - safe to call multiple times)
func registerOrUpdateUser(w http.ResponseWriter, r *http.Request) {
    log.Println("🔵 [registerOrUpdateUser] Received request")
    w.Header().Set("Content-Type", "application/json")

    // Parse request
    var req UserRegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("❌ [registerOrUpdateUser] Failed to parse request: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Validate device_id
    if req.DeviceID == "" {
        log.Printf("❌ [registerOrUpdateUser] Missing device_id")
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "device_id is required",
        })
        return
    }

    // Validate signature
    if !validateUserRegisterSignature(req) {
        log.Printf("❌ [registerOrUpdateUser] Invalid signature")
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Invalid signature or expired timestamp",
        })
        return
    }

    log.Printf("🔵 [registerOrUpdateUser] Device ID: %s, type=%s, length=%s",
        req.DeviceID, req.SubscriptionType, req.SubscriptionLength)

    // Validate subscription_type
    if req.SubscriptionType != "free" && req.SubscriptionType != "paid" {
        req.SubscriptionType = "free" // Default to free
    }

    // Validate subscription_length
    if req.SubscriptionLength != "monthly" && req.SubscriptionLength != "yearly" {
        req.SubscriptionLength = "monthly" // Default to monthly
    }

    // Use transaction to ensure atomicity
    tx, err := db.Begin()
    if err != nil {
        log.Printf("❌ [registerOrUpdateUser] Transaction error: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Database error",
        })
        return
    }
    defer tx.Rollback()

    // INSERT OR REPLACE - this is idempotent and safe
    // If device_id exists, it updates. If not, it inserts.
    query := `INSERT INTO users (device_id, subscription_type, subscription_length, updated_at)
              VALUES (?, ?, ?, CURRENT_TIMESTAMP)
              ON CONFLICT(device_id) DO UPDATE SET
                  subscription_type = excluded.subscription_type,
                  subscription_length = excluded.subscription_length,
                  updated_at = CURRENT_TIMESTAMP`

    log.Printf("🔵 [registerOrUpdateUser] Upserting into database...")

    _, err = tx.Exec(query, req.DeviceID, req.SubscriptionType, req.SubscriptionLength)
    if err != nil {
        log.Printf("❌ [registerOrUpdateUser] Database error: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Failed to register user",
        })
        return
    }

    // Commit transaction
    log.Printf("🔵 [registerOrUpdateUser] Committing transaction...")
    if err = tx.Commit(); err != nil {
        log.Printf("❌ [registerOrUpdateUser] Transaction commit error: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Failed to register user",
        })
        return
    }

    log.Printf("✅ [registerOrUpdateUser] User registered/updated: device=%s (type: %s, length: %s)",
        req.DeviceID, req.SubscriptionType, req.SubscriptionLength)

    // Generate JWT tokens
    accessToken, err := generateAccessToken(req.DeviceID, req.SubscriptionType, req.SubscriptionLength)
    if err != nil {
        log.Printf("❌ [registerOrUpdateUser] Failed to generate access token: %v", err)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    refreshToken, err := generateRefreshToken(req.DeviceID, req.SubscriptionType, req.SubscriptionLength)
    if err != nil {
        log.Printf("❌ [registerOrUpdateUser] Failed to generate refresh token: %v", err)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    // Return tokens
    json.NewEncoder(w).Encode(AuthTokensResponse{
        Success:      true,
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    int64(ACCESS_TOKEN_EXP.Seconds()),
        Message:      "User registered successfully",
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

    // Verify device still exists in database and get current subscription status
    var subscriptionType, subscriptionLength string
    query := `SELECT subscription_type, subscription_length FROM users WHERE device_id = ?`
    err = db.QueryRow(query, claims.DeviceID).Scan(&subscriptionType, &subscriptionLength)
    if err == sql.ErrNoRows {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Device not registered",
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

    // Generate new access token with current subscription status
    accessToken, err := generateAccessToken(claims.DeviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("Failed to generate access token: %v", err)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    // Optionally generate new refresh token (token rotation for better security)
    newRefreshToken, err := generateRefreshToken(claims.DeviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("Failed to generate refresh token: %v", err)
        json.NewEncoder(w).Encode(AuthTokensResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    log.Printf("🔄 Token refreshed for device: %s", claims.DeviceID)

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

    // Rate limiting for ChatGPT requests (more restrictive)
    limiter := deviceLimiter.GetLimiter(deviceID)
    if !limiter.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Rate limit exceeded. Please wait 1 second.",
        })
        return
    }

    log.Printf("🤖 Proxying ChatGPT request for device: %s, model: %s", deviceID, req.Model)

    // Prepare OpenAI API request
    openAIRequest := map[string]interface{}{
        "model":       req.Model,
        "messages":    req.Messages,
    }

    if req.Temperature > 0 {
        openAIRequest["temperature"] = req.Temperature
    }
    if req.MaxTokens > 0 {
        openAIRequest["max_tokens"] = req.MaxTokens
    }

    requestBody, err := json.Marshal(openAIRequest)
    if err != nil {
        json.NewEncoder(w).Encode(ChatGPTProxyResponse{
            Success: false,
            Error:   "Failed to prepare request",
        })
        return
    }

    // Call OpenAI API
    client := &http.Client{Timeout: 120 * time.Second}
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

    log.Printf("✅ ChatGPT request successful, response length: %d", len(content))

    // Log API call for analytics
    logAPICall(deviceID, "chatgpt", req.Model)

    // Return success response
    json.NewEncoder(w).Encode(ChatGPTProxyResponse{
        Success: true,
        Content: content,
    })
}

// Get user subscription info by device_id
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

    // Use device_id from JWT claims (more secure than trusting query params)
    deviceID := claims.DeviceID

    var subscriptionType, subscriptionLength string
    var createdAt, updatedAt string
    var subscriptionExpiry sql.NullString
    var isSuper int

    query := `SELECT subscription_type, subscription_length, subscription_expiry, created_at, updated_at, COALESCE(is_super, 0)
              FROM users WHERE device_id = ?`

    err := db.QueryRow(query, deviceID).Scan(&subscriptionType, &subscriptionLength, &subscriptionExpiry, &createdAt, &updatedAt, &isSuper)
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
        expiryTime, err := time.Parse("2006-01-02 15:04:05", subscriptionExpiry.String)
        if err == nil && time.Now().After(expiryTime) {
            effectiveSubType = "free" // Subscription expired
        }
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":              true,
        "device_id":            deviceID,
        "subscription_type":    effectiveSubType,
        "subscription_length":  subscriptionLength,
        "subscription_expiry":  subscriptionExpiry.String,
        "is_super":             isSuper == 1,
        "created_at":           createdAt,
        "updated_at":           updatedAt,
    })
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
              (device_id, product_id, transaction_id, purchase_date, expiry_date, subscription_type, subscription_length, store)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

    _, err = tx.Exec(query, deviceID, req.ProductID, req.TransactionID, purchaseDate, expiryDate, req.SubscriptionType, req.SubscriptionLength, req.Store)
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
                        updated_at = CURRENT_TIMESTAMP
                        WHERE device_id = ?`
        _, err = tx.Exec(updateQuery, req.SubscriptionType, req.SubscriptionLength, expiryDate, deviceID)
        if err != nil {
            log.Printf("Error updating user subscription: %v", err)
            // Continue anyway - purchase record is more important
        } else {
            log.Printf("✅ User subscription updated: device=%s, type=%s, length=%s", deviceID, req.SubscriptionType, req.SubscriptionLength)
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

    // Check if user with this email already exists
    var existingDeviceID string
    var subscriptionType, subscriptionLength string

    err = db.QueryRow(`SELECT device_id, subscription_type, subscription_length FROM users WHERE email = ?`, email).
        Scan(&existingDeviceID, &subscriptionType, &subscriptionLength)

    if err == sql.ErrNoRows {
        // New user - create account with email
        subscriptionType = "free"
        subscriptionLength = "monthly"

        _, err = db.Exec(`INSERT INTO users (device_id, email, subscription_type, subscription_length)
                          VALUES (?, ?, ?, ?)
                          ON CONFLICT(device_id) DO UPDATE SET
                              email = excluded.email,
                              updated_at = CURRENT_TIMESTAMP`,
            deviceID, email, subscriptionType, subscriptionLength)
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
        // Existing user - update device_id if different (user logging in on new device)
        if existingDeviceID != deviceID {
            _, err = db.Exec(`UPDATE users SET device_id = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`,
                deviceID, email)
            if err != nil {
                log.Printf("❌ Failed to update device: %v", err)
            } else {
                log.Printf("✅ User %s switched from device %s to %s", email, existingDeviceID, deviceID)
            }
        }
        log.Printf("✅ Existing user logged in: %s (device: %s)", email, deviceID)
    }

    // Generate JWT tokens
    accessToken, err := generateAccessToken(deviceID, subscriptionType, subscriptionLength)
    if err != nil {
        log.Printf("❌ Failed to generate access token: %v", err)
        json.NewEncoder(w).Encode(EmailAuthResponse{
            Success: false,
            Error:   "Failed to generate token",
        })
        return
    }

    refreshToken, err := generateRefreshToken(deviceID, subscriptionType, subscriptionLength)
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

    // Check if user exists by email
    var existingDeviceID string
    err = db.QueryRow(`SELECT device_id FROM users WHERE email = ?`, targetEmail).Scan(&existingDeviceID)

    if err == sql.ErrNoRows {
        // User doesn't exist - create a placeholder record
        // They will be properly registered when they sign in
        log.Printf("🔵 [adminGrantSubscription] Creating new user record for %s", targetEmail)

        _, err = db.Exec(`INSERT INTO users (device_id, email, subscription_type, subscription_length, subscription_expiry, updated_at)
                          VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
            "pending-"+targetEmail, // Placeholder device ID until user registers
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

    // Query all users
    rows, err := db.Query(`SELECT device_id, email, subscription_type, subscription_length,
                           subscription_expiry, COALESCE(is_super, 0), created_at, updated_at
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
        var deviceID, subType, subLength string
        var email, subExpiry, createdAt, updatedAt sql.NullString
        var isSuper int

        err := rows.Scan(&deviceID, &email, &subType, &subLength, &subExpiry, &isSuper, &createdAt, &updatedAt)
        if err != nil {
            continue
        }

        user := map[string]interface{}{
            "device_id":           deviceID,
            "email":               email.String,
            "subscription_type":   subType,
            "subscription_length": subLength,
            "subscription_expiry": subExpiry.String,
            "is_super":            isSuper == 1,
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

    // Find user by device_id or email
    var deviceID string
    if req.DeviceID != "" {
        deviceID = req.DeviceID
    } else if req.Email != "" {
        err := db.QueryRow(`SELECT device_id FROM users WHERE email = ?`, req.Email).Scan(&deviceID)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "error":   "User not found by email",
            })
            return
        }
    } else {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "Must provide device_id or email",
        })
        return
    }

    // Update is_super flag
    superValue := 0
    if req.IsSuper {
        superValue = 1
    }

    result, err := db.Exec(`UPDATE users SET is_super = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?`,
        superValue, deviceID)
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

    log.Printf("✅ Admin %s toggled super status for device %s to %v", req.AdminEmail, deviceID, req.IsSuper)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":   true,
        "device_id": deviceID,
        "is_super":  req.IsSuper,
        "message":   "Super status updated successfully",
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

    // Protected endpoints (JWT required)
    router.HandleFunc("/api/astrolog", jwtAuthMiddleware(calculateChart)).Methods("POST")
    router.HandleFunc("/api/chatgpt", jwtAuthMiddleware(chatGPTProxy)).Methods("POST")
    router.HandleFunc("/api/user/info", jwtAuthMiddleware(getUserInfo)).Methods("GET")
    router.HandleFunc("/api/user/purchases", jwtAuthMiddleware(recordPurchase)).Methods("POST")
    router.HandleFunc("/api/user/purchases", jwtAuthMiddleware(getPurchaseHistory)).Methods("GET")

    // Admin endpoints (admin email + secret + verification code required)
    router.HandleFunc("/api/admin/request-code", adminRequestCode).Methods("POST")
    router.HandleFunc("/api/admin/grant-subscription", adminGrantSubscription).Methods("POST")
    router.HandleFunc("/api/admin/users", adminListUsers).Methods("GET")
    router.HandleFunc("/api/admin/toggle-super", adminToggleSuper).Methods("POST")
    router.HandleFunc("/api/admin/analytics", adminGetAnalytics).Methods("GET")
    router.HandleFunc("/api/admin/download-db", adminDownloadDB).Methods("GET")

    log.Println("✓ Registered routes:")
    log.Println("  [PUBLIC]    POST /api/user/register - Register device and get tokens")
    log.Println("  [PUBLIC]    POST /api/auth/refresh - Refresh access token")
    log.Println("  [PUBLIC]    POST /api/auth/request-code - Request email verification code")
    log.Println("  [PUBLIC]    POST /api/auth/verify-code - Verify code and get tokens")
    log.Println("  [ADMIN]     POST /api/admin/request-code - Request admin verification code")
    log.Println("  [ADMIN]     POST /api/admin/grant-subscription - Grant subscription (2FA required)")
    log.Println("  [ADMIN]     GET  /api/admin/users - List users (admin only)")
    log.Println("  [ADMIN]     POST /api/admin/toggle-super - Toggle super tier (admin only)")
    log.Println("  [ADMIN]     GET  /api/admin/analytics - Get usage analytics (admin only)")
    log.Println("  [ADMIN]     GET  /api/admin/download-db - Download database backup (2FA required)")
    log.Println("  [PROTECTED] POST /api/astrolog - Calculate chart (JWT required)")
    log.Println("  [PROTECTED] POST /api/chatgpt - ChatGPT proxy (JWT required)")
    log.Println("  [PROTECTED] GET  /api/user/info - Get user info (JWT required)")
    log.Println("  [PROTECTED] POST /api/user/purchases - Record purchase (JWT required)")
    log.Println("  [PROTECTED] GET  /api/user/purchases - Get purchase history (JWT required)")
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