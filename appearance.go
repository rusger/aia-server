package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// Appearance preferences (the four "Внешний вид" settings)
//
// The mobile app lets the user pick four visual preferences — theme, colour
// scheme, background and horoscope icon set. This file records the last value
// each device reported so the Stellar Vault admin dashboard can show, per
// user, which appearance parameters they have set.
//
// Storage lives on the existing `devices` row (keyed by email + device_id),
// alongside the push-token / language / platform per-device metadata, so a
// user with several devices keeps a value per device. All columns are added
// as nullable migrations — existing rows and old clients are unaffected.
// ---------------------------------------------------------------------------

// migrateAppearance adds the appearance columns to the devices table.
// Idempotent: duplicate-column errors on a second run are ignored.
func migrateAppearance() {
	cols := []string{
		"appearance_theme TEXT",
		"appearance_color TEXT",
		"appearance_background TEXT",
		"appearance_icon_set TEXT",
		"appearance_platform TEXT",
		"appearance_updated_at DATETIME",
	}
	for _, c := range cols {
		if _, err := db.Exec("ALTER TABLE devices ADD COLUMN " + c); err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				log.Printf("ℹ️ devices appearance migration note (%s): %v", c, err)
			}
		}
	}
}

// setAppearanceParams — POST /api/user/appearance (JWT-protected).
// Records the four appearance preferences for the calling device. Called by
// the app (debounced) whenever a preference changes and on launch.
func setAppearanceParams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok || claims.Email == "" || claims.DeviceID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}

	var req struct {
		Theme       string `json:"theme"`
		ColorScheme string `json:"color_scheme"`
		Background  string `json:"background"`
		IconSet     string `json:"icon_set"`
		Platform    string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	// Upsert onto the existing (email, device_id) row; create it if the device
	// hasn't been recorded yet (relies on idx_devices_email_device).
	_, err := db.Exec(`
		INSERT INTO devices (email, device_id, last_seen,
			appearance_theme, appearance_color, appearance_background, appearance_icon_set,
			appearance_platform, appearance_updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(email, device_id) DO UPDATE SET
			last_seen = CURRENT_TIMESTAMP,
			appearance_theme = excluded.appearance_theme,
			appearance_color = excluded.appearance_color,
			appearance_background = excluded.appearance_background,
			appearance_icon_set = excluded.appearance_icon_set,
			appearance_platform = CASE WHEN excluded.appearance_platform != '' THEN excluded.appearance_platform ELSE devices.appearance_platform END,
			appearance_updated_at = CURRENT_TIMESTAMP`,
		email, claims.DeviceID,
		req.Theme, req.ColorScheme, req.Background, req.IconSet, req.Platform)
	if err != nil {
		log.Printf("⚠️ appearance upsert failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// adminGetUserAppearance — GET /api/admin/user-appearance (admin-protected).
//
//	?user_email=<email>  → the appearance per device for that user
//	(no user_email)      → an aggregate distribution across all users,
//	                       counting the most-recent device per user
func adminGetUserAppearance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

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

	// ── Per-user: one entry per device that has reported appearance ──────────
	if userEmail != "" {
		rows, err := db.Query(`
			SELECT device_id,
			       COALESCE(NULLIF(appearance_platform, ''), platform, ''),
			       COALESCE(appearance_theme, ''), COALESCE(appearance_color, ''),
			       COALESCE(appearance_background, ''), COALESCE(appearance_icon_set, ''),
			       COALESCE(appearance_updated_at, '')
			FROM devices
			WHERE email = ? AND appearance_updated_at IS NOT NULL
			ORDER BY appearance_updated_at DESC`, userEmail)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
			return
		}
		defer rows.Close()

		out := []map[string]interface{}{}
		for rows.Next() {
			var deviceID, platform, theme, color, background, iconSet, updatedAt string
			if err := rows.Scan(&deviceID, &platform, &theme, &color, &background, &iconSet, &updatedAt); err != nil {
				continue
			}
			out = append(out, map[string]interface{}{
				"device_id":    deviceID,
				"platform":     platform,
				"theme":        theme,
				"color_scheme": color,
				"background":   background,
				"icon_set":     iconSet,
				"updated_at":   updatedAt,
			})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"email":   userEmail,
			"devices": out,
			"count":   len(out),
		})
		return
	}

	// ── Aggregate: distribution over the most-recent device per user ─────────
	rows, err := db.Query(`
		SELECT appearance_theme, appearance_color, appearance_background, appearance_icon_set
		FROM (
			SELECT appearance_theme, appearance_color, appearance_background, appearance_icon_set,
			       ROW_NUMBER() OVER (PARTITION BY email ORDER BY appearance_updated_at DESC) AS rn
			FROM devices
			WHERE appearance_updated_at IS NOT NULL
		)
		WHERE rn = 1`)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	defer rows.Close()

	theme := map[string]int{}
	color := map[string]int{}
	background := map[string]int{}
	iconSet := map[string]int{}
	type comboKey struct{ t, c, b, i string }
	combos := map[comboKey]int{}
	total := 0
	norm := func(v string) string {
		if v == "" {
			return "(unset)"
		}
		return v
	}
	for rows.Next() {
		var t, c, b, i string
		if err := rows.Scan(&t, &c, &b, &i); err != nil {
			continue
		}
		t, c, b, i = norm(t), norm(c), norm(b), norm(i)
		total++
		theme[t]++
		color[c]++
		background[b]++
		iconSet[i]++
		combos[comboKey{t, c, b, i}]++
	}

	// Every distinct full combination of the four settings, with its user count.
	// The client sorts these and computes percentages against total_users.
	comboList := make([]map[string]interface{}, 0, len(combos))
	for k, n := range combos {
		comboList = append(comboList, map[string]interface{}{
			"theme":        k.t,
			"color_scheme": k.c,
			"background":   k.b,
			"icon_set":     k.i,
			"count":        n,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"total_users":  total,
		"theme":        theme,
		"color_scheme": color,
		"background":   background,
		"icon_set":     iconSet,
		"combinations": comboList,
	})
}
