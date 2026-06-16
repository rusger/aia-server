package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// Screen-time tracking (the "Экраны" Stellar Vault tab)
//
// The mobile app accumulates, per screen / sub-tab, how many seconds the user
// spends looking at it, and POSTs the *deltas* here periodically (and on
// background). We keep a running total per (email, device_id, screen_key) so
// the admin dashboard can show:
//   • aggregate — where the whole user base spends its time, by section, as a
//     share of total app time plus an average per-user absolute (h/m/s);
//   • per-user — the exact same breakdown for one user.
//
// Storage is its own table in users.db (keyed by email, like appearance) so the
// per-user view — which Stellar Vault drives by email — is a trivial lookup,
// no cross-database join into analytics.db.
//
// screen_key is an opaque string chosen by the app, e.g. "Forecast" or
// "Forecast / Calendar" (sub-tab after a " / "). The dashboard maps keys to
// human sections/labels; unknown keys still show up under "Other".
// ---------------------------------------------------------------------------

var screenTimeReady atomic.Bool

// ensureScreenTimeSchema creates the screen_time table if missing. Like
// ensureAppearanceSchema it self-heals: any error (e.g. a transient locked DB)
// leaves the ready flag false so the next request retries.
func ensureScreenTimeSchema() {
	if screenTimeReady.Load() {
		return
	}
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS screen_time (
			email         TEXT    NOT NULL,
			device_id     TEXT    NOT NULL,
			screen_key    TEXT    NOT NULL,
			total_seconds INTEGER NOT NULL DEFAULT 0,
			updated_at    DATETIME,
			PRIMARY KEY (email, device_id, screen_key)
		)`)
	if err != nil {
		log.Printf("⚠️ screen_time schema create failed: %v — will retry on next request", err)
		return
	}
	// Index for the per-user lookup (all devices for an email).
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_screen_time_email ON screen_time(email)`); err != nil {
		log.Printf("⚠️ screen_time index create failed: %v — will retry on next request", err)
		return
	}
	screenTimeReady.Store(true)
}

// setScreenTime — POST /api/user/screen-time (JWT-protected).
// Body: { "platform": "iOS", "screens": { "<screen_key>": <delta_seconds>, ... } }
// Each value is the number of seconds spent on that screen SINCE the last
// successful upload, so we add it onto the running total.
func setScreenTime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ensureScreenTimeSchema()

	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok || claims.Email == "" || claims.DeviceID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}

	var req struct {
		Platform string         `json:"platform"`
		Screens  map[string]int `json:"screens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}
	if len(req.Screens) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "updated": 0})
		return
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))

	tx, err := db.Begin()
	if err != nil {
		log.Printf("⚠️ screen_time begin failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	stmt, err := tx.Prepare(`
		INSERT INTO screen_time (email, device_id, screen_key, total_seconds, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(email, device_id, screen_key) DO UPDATE SET
			total_seconds = total_seconds + excluded.total_seconds,
			updated_at = CURRENT_TIMESTAMP`)
	if err != nil {
		tx.Rollback()
		log.Printf("⚠️ screen_time prepare failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	defer stmt.Close()

	updated := 0
	for rawKey, secs := range req.Screens {
		key := strings.TrimSpace(rawKey)
		// Ignore empty keys and non-positive deltas (nothing to add, and we
		// never want a client bug to drive a total negative).
		if key == "" || secs <= 0 {
			continue
		}
		// Defensive cap: a single reasonable upload interval can't legitimately
		// hold more than a day of seconds on one screen.
		if secs > 86400 {
			secs = 86400
		}
		if len(key) > 120 {
			key = key[:120]
		}
		if _, err := stmt.Exec(email, claims.DeviceID, key, secs); err != nil {
			tx.Rollback()
			log.Printf("⚠️ screen_time upsert failed: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
			return
		}
		updated++
	}
	if err := tx.Commit(); err != nil {
		log.Printf("⚠️ screen_time commit failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "updated": updated})
}

// adminGetScreenTime — GET /api/admin/screen-time (admin-protected).
//
//	?user_email=<email>  → that user's per-screen totals (summed over devices)
//	(no user_email)      → aggregate across all users
func adminGetScreenTime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ensureScreenTimeSchema()

	if !isAdminEmail(r.URL.Query().Get("admin_email")) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}
	if ADMIN_SECRET_KEY != "" && r.URL.Query().Get("admin_secret") != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid admin secret"})
		return
	}

	userEmail := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user_email")))

	// ── Per-user: totals per screen, summed across the user's devices ────────
	if userEmail != "" {
		rows, err := db.Query(`
			SELECT screen_key, SUM(total_seconds)
			FROM screen_time
			WHERE email = ?
			GROUP BY screen_key
			ORDER BY SUM(total_seconds) DESC`, userEmail)
		if err != nil {
			log.Printf("⚠️ screen_time per-user query failed: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error: " + err.Error()})
			return
		}
		defer rows.Close()

		screens := []map[string]interface{}{}
		var totalSeconds int64
		for rows.Next() {
			var key string
			var secs int64
			if err := rows.Scan(&key, &secs); err != nil {
				continue
			}
			screens = append(screens, map[string]interface{}{
				"screen_key": key,
				"seconds":    secs,
			})
			totalSeconds += secs
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"email":         userEmail,
			"screens":       screens,
			"total_seconds": totalSeconds,
		})
		return
	}

	// ── Aggregate: per screen across all users ───────────────────────────────
	// sum_seconds = total time the whole base spent on that screen,
	// users      = distinct users who spent any time there.
	// We also count the distinct users overall so the dashboard can show an
	// average-per-user absolute alongside the share-of-total percentage.
	rows, err := db.Query(`
		SELECT screen_key, SUM(total_seconds), COUNT(DISTINCT email)
		FROM screen_time
		GROUP BY screen_key
		ORDER BY SUM(total_seconds) DESC`)
	if err != nil {
		log.Printf("⚠️ screen_time aggregate query failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error: " + err.Error()})
		return
	}
	defer rows.Close()

	screens := []map[string]interface{}{}
	var totalSeconds int64
	for rows.Next() {
		var key string
		var secs, users int64
		if err := rows.Scan(&key, &secs, &users); err != nil {
			continue
		}
		screens = append(screens, map[string]interface{}{
			"screen_key": key,
			"seconds":    secs,
			"users":      users,
		})
		totalSeconds += secs
	}

	// Total distinct users with any screen-time data (denominator for the
	// average-per-user absolute).
	var totalUsers int64
	if err := db.QueryRow(`SELECT COUNT(DISTINCT email) FROM screen_time`).Scan(&totalUsers); err != nil {
		totalUsers = 0
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"total_users":   totalUsers,
		"total_seconds": totalSeconds,
		"screens":       screens,
	})
}
