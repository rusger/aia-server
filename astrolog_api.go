package main

import (
    "bytes"
    "context"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
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

// Global database connection
var db *sql.DB

// Initialize database
func initDB() error {
    var err error
    db, err = sql.Open("sqlite", "./users.db")
    if err != nil {
        return fmt.Errorf("failed to open database: %v", err)
    }

    // Create users table with device_id as primary key
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
        return fmt.Errorf("failed to create table: %v", err)
    }

    log.Println("Database initialized successfully")
    return nil
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

    query := `SELECT subscription_type, subscription_length, created_at, updated_at
              FROM users WHERE device_id = ?`

    err := db.QueryRow(query, deviceID).Scan(&subscriptionType, &subscriptionLength, &createdAt, &updatedAt)
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

    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":             true,
        "device_id":           deviceID,
        "subscription_type":   subscriptionType,
        "subscription_length": subscriptionLength,
        "created_at":          createdAt,
        "updated_at":          updatedAt,
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

    router := mux.NewRouter()

    // Public endpoints (no JWT required)
    router.HandleFunc("/api/user/register", registerOrUpdateUser).Methods("POST")
    router.HandleFunc("/api/auth/refresh", refreshAccessToken).Methods("POST")

    // Protected endpoints (JWT required)
    router.HandleFunc("/api/astrolog", jwtAuthMiddleware(calculateChart)).Methods("POST")
    router.HandleFunc("/api/chatgpt", jwtAuthMiddleware(chatGPTProxy)).Methods("POST")
    router.HandleFunc("/api/user/info", jwtAuthMiddleware(getUserInfo)).Methods("GET")

    log.Println("✓ Registered routes:")
    log.Println("  [PUBLIC]    POST /api/user/register - Register device and get tokens")
    log.Println("  [PUBLIC]    POST /api/auth/refresh - Refresh access token")
    log.Println("  [PROTECTED] POST /api/astrolog - Calculate chart (JWT required)")
    log.Println("  [PROTECTED] POST /api/chatgpt - ChatGPT proxy (JWT required)")
    log.Println("  [PROTECTED] GET  /api/user/info - Get user info (JWT required)")
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