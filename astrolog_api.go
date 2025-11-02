package main

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/exec"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"
    "sort"

    "github.com/google/uuid"
    "github.com/gorilla/mux"
    "github.com/rs/cors"
    "golang.org/x/time/rate"
    _ "modernc.org/sqlite"
)

// Configuration
var (
    SECRET_KEY = getEnv("ASTROLOG_SECRET_KEY", "your-very-secret-key-change-this")
    PORT       = getEnv("PORT", "8080")
)

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
    UserID             string `json:"user_id"`
    SubscriptionType   string `json:"subscription_type"`   // "free" or "paid"
    SubscriptionLength string `json:"subscription_length"` // "monthly" or "yearly"
}

// User registration response
type UserRegisterResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message,omitempty"`
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
        // Allow burst of 2 requests (natal + navamsha), then 1 request per 10 seconds
        limiter = rate.NewLimiter(rate.Every(10*time.Second), 2)
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

    // Create users table
    createTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
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

    // Parse request
    var req AstrologRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Validate signature
    if !validateSignature(req) {
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Invalid signature or expired timestamp",
        })
        return
    }

    // Check device rate limit
    limiter := deviceLimiter.GetLimiter(req.DeviceID)
    if !limiter.Allow() {
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(AstrologResponse{
            Success: false,
            Error:   "Rate limit exceeded. Please wait 10 seconds.",
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

// Create new user with server-generated ID (atomic operation)
func createUser(w http.ResponseWriter, r *http.Request) {
    log.Println("🔵 [createUser] Received request to create new user")
    w.Header().Set("Content-Type", "application/json")

    // Parse request
    var req UserRegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("❌ [createUser] Failed to parse request: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    log.Printf("🔵 [createUser] Request params: type=%s, length=%s", req.SubscriptionType, req.SubscriptionLength)

    // Validate subscription_type
    if req.SubscriptionType != "free" && req.SubscriptionType != "paid" {
        req.SubscriptionType = "free" // Default to free
    }

    // Validate subscription_length
    if req.SubscriptionLength != "monthly" && req.SubscriptionLength != "yearly" {
        req.SubscriptionLength = "monthly" // Default to monthly
    }

    // Generate UUID on server side
    userID := uuid.New().String()
    log.Printf("🔵 [createUser] Generated UUID: %s", userID)

    // Use transaction to ensure atomicity
    tx, err := db.Begin()
    if err != nil {
        log.Printf("❌ [createUser] Transaction error: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Database error",
        })
        return
    }
    defer tx.Rollback()

    // Insert new user
    query := `INSERT INTO users (user_id, subscription_type, subscription_length)
              VALUES (?, ?, ?)`
    log.Printf("🔵 [createUser] Inserting into database...")

    _, err = tx.Exec(query, userID, req.SubscriptionType, req.SubscriptionLength)
    if err != nil {
        log.Printf("❌ [createUser] Database insert error: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Failed to create user",
        })
        return
    }

    // Commit transaction
    log.Printf("🔵 [createUser] Committing transaction...")
    if err = tx.Commit(); err != nil {
        log.Printf("❌ [createUser] Transaction commit error: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Failed to create user",
        })
        return
    }

    log.Printf("✅ [createUser] User created successfully: %s (type: %s, length: %s)",
        userID, req.SubscriptionType, req.SubscriptionLength)

    // Return the generated user_id
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":             true,
        "message":             "User created successfully",
        "user_id":             userID,
        "subscription_type":   req.SubscriptionType,
        "subscription_length": req.SubscriptionLength,
    })
}

// Register or update user
func registerUser(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // Parse request
    var req UserRegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Invalid request format",
        })
        return
    }

    // Validate user_id (should be UUID format)
    if req.UserID == "" {
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "user_id is required",
        })
        return
    }

    // Validate subscription_type
    if req.SubscriptionType != "free" && req.SubscriptionType != "paid" {
        req.SubscriptionType = "free" // Default to free
    }

    // Validate subscription_length
    if req.SubscriptionLength != "monthly" && req.SubscriptionLength != "yearly" {
        req.SubscriptionLength = "monthly" // Default to monthly
    }

    // Insert or update user in database
    query := `
    INSERT INTO users (user_id, subscription_type, subscription_length)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
        subscription_type = excluded.subscription_type,
        subscription_length = excluded.subscription_length,
        updated_at = CURRENT_TIMESTAMP
    `

    _, err := db.Exec(query, req.UserID, req.SubscriptionType, req.SubscriptionLength)
    if err != nil {
        log.Printf("Database error: %v", err)
        json.NewEncoder(w).Encode(UserRegisterResponse{
            Success: false,
            Error:   "Failed to register user",
        })
        return
    }

    log.Printf("User registered/updated: %s (type: %s, length: %s)",
        req.UserID, req.SubscriptionType, req.SubscriptionLength)

    json.NewEncoder(w).Encode(UserRegisterResponse{
        Success: true,
        Message: "User registered successfully",
    })
}

// Get user subscription info
func getUserInfo(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    userID := r.URL.Query().Get("user_id")
    if userID == "" {
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error":   "user_id parameter is required",
        })
        return
    }

    var subscriptionType, subscriptionLength string
    var createdAt, updatedAt string

    query := `SELECT subscription_type, subscription_length, created_at, updated_at
              FROM users WHERE user_id = ?`

    err := db.QueryRow(query, userID).Scan(&subscriptionType, &subscriptionLength, &createdAt, &updatedAt)
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
        "user_id":             userID,
        "subscription_type":   subscriptionType,
        "subscription_length": subscriptionLength,
        "created_at":          createdAt,
        "updated_at":          updatedAt,
    })
}

func main() {
    // Initialize database
    if err := initDB(); err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }
    defer db.Close()

    router := mux.NewRouter()
    router.HandleFunc("/api/astrolog", calculateChart).Methods("POST")
    router.HandleFunc("/api/user/create", createUser).Methods("POST")
    router.HandleFunc("/api/user/register", registerUser).Methods("POST")
    router.HandleFunc("/api/user/info", getUserInfo).Methods("GET")

    log.Println("✓ Registered routes:")
    log.Println("  POST /api/astrolog")
    log.Println("  POST /api/user/create")
    log.Println("  POST /api/user/register")
    log.Println("  GET  /api/user/info")

    // CORS configuration
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"*"}, // Configure this for your app
        AllowedMethods: []string{"GET", "POST"},
        AllowedHeaders: []string{"Content-Type"},
    })

    handler := c.Handler(router)

    log.Printf("Astrolog API server starting on port %s", PORT)
    log.Fatal(http.ListenAndServe(":"+PORT, handler))
}