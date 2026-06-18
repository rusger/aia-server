package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

// languageCols are the columns added to the devices table for the in-app
// language preference (+ country + platform + timestamp). Stored next to the
// appearance columns (see appearance.go) on the same per-device `devices` row.
var languageCols = []string{
	"app_language TEXT",
	"app_country TEXT",
	"language_platform TEXT",
	"language_updated_at DATETIME",
}

// languageReady flips to true only once every column is confirmed present,
// after which ensureLanguageSchema is a cheap atomic load.
var languageReady atomic.Bool

// ensureLanguageSchema makes sure the language columns exist on the devices
// table. Mirrors ensureAppearanceSchema: called at startup AND at the top of
// every language handler, and RETRIES until it fully succeeds so a migration
// that failed once (e.g. a transient "database is locked") self-heals on the
// next request instead of giving up permanently.
func ensureLanguageSchema() {
	if languageReady.Load() {
		return
	}
	allGood := true
	added := 0
	for _, c := range languageCols {
		if _, err := db.Exec("ALTER TABLE devices ADD COLUMN " + c); err != nil {
			if strings.Contains(err.Error(), "duplicate column") {
				continue // already present — good
			}
			log.Printf("⚠️ language ALTER failed (%s): %v — will retry on next request", c, err)
			allGood = false
			continue
		}
		added++
	}
	if allGood {
		languageReady.Store(true)
		if added > 0 {
			log.Printf("✓ language migration: added %d column(s); schema ready", added)
		}
	}
}

// ---------------------------------------------------------------------------
// In-app language preference ("Языки")
//
// The mobile app lets the user pick the interface language. This file records
// the last language each device reported so the Stellar Vault admin dashboard
// can show, per user, which language they use in the app — and an aggregate
// distribution across all users.
//
// Storage lives on the existing `devices` row (keyed by email + device_id),
// alongside the appearance / push-token / platform per-device metadata, so a
// user with several devices keeps a value per device. All columns are added as
// nullable migrations — existing rows and old clients are unaffected.
// ---------------------------------------------------------------------------

// setLanguage — POST /api/user/language (JWT-protected).
// Records the in-app language for the calling device. Called by the app
// (debounced) whenever the language changes and on launch.
func setLanguage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ensureLanguageSchema()

	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok || claims.Email == "" || claims.DeviceID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}

	var req struct {
		Language string `json:"language"`
		Country  string `json:"country"`
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	language := strings.ToLower(strings.TrimSpace(req.Language))
	country := strings.ToUpper(strings.TrimSpace(req.Country))

	// Upsert onto the existing (email, device_id) row; create it if the device
	// hasn't been recorded yet (relies on idx_devices_email_device).
	_, err := db.Exec(`
		INSERT INTO devices (email, device_id, last_seen,
			app_language, app_country, language_platform, language_updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(email, device_id) DO UPDATE SET
			last_seen = CURRENT_TIMESTAMP,
			app_language = excluded.app_language,
			app_country = excluded.app_country,
			language_platform = CASE WHEN excluded.language_platform != '' THEN excluded.language_platform ELSE devices.language_platform END,
			language_updated_at = CURRENT_TIMESTAMP`,
		email, claims.DeviceID, language, country, req.Platform)
	if err != nil {
		log.Printf("⚠️ language upsert failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// adminGetUserLanguages — GET /api/admin/user-languages (admin-protected).
//
//	?user_email=<email>  → the language per device for that user
//	(no user_email)      → an aggregate distribution across all users,
//	                       counting the most-recent device per user
func adminGetUserLanguages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ensureLanguageSchema()

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

	// ── Per-user: one entry per device that has reported a language ──────────
	if userEmail != "" {
		rows, err := db.Query(`
			SELECT device_id,
			       COALESCE(NULLIF(language_platform, ''), platform, ''),
			       COALESCE(app_language, ''), COALESCE(app_country, ''),
			       COALESCE(language_updated_at, '')
			FROM devices
			WHERE email = ? AND language_updated_at IS NOT NULL
			ORDER BY language_updated_at DESC`, userEmail)
		if err != nil {
			log.Printf("⚠️ language per-user query failed: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error: " + err.Error()})
			return
		}
		defer rows.Close()

		out := []map[string]interface{}{}
		for rows.Next() {
			var deviceID, platform, language, country, updatedAt string
			if err := rows.Scan(&deviceID, &platform, &language, &country, &updatedAt); err != nil {
				continue
			}
			out = append(out, map[string]interface{}{
				"device_id":  deviceID,
				"platform":   platform,
				"language":   language,
				"country":    country,
				"updated_at": updatedAt,
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
		SELECT app_language
		FROM (
			SELECT app_language,
			       ROW_NUMBER() OVER (PARTITION BY email ORDER BY language_updated_at DESC) AS rn
			FROM devices
			WHERE language_updated_at IS NOT NULL
		)
		WHERE rn = 1`)
	if err != nil {
		log.Printf("⚠️ language aggregate query failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error: " + err.Error()})
		return
	}
	defer rows.Close()

	counts := map[string]int{}
	total := 0
	for rows.Next() {
		var lang string
		if err := rows.Scan(&lang); err != nil {
			continue
		}
		lang = strings.ToLower(strings.TrimSpace(lang))
		if lang == "" {
			lang = "(unset)"
		}
		counts[lang]++
		total++
	}

	// Flatten to a sortable list of {language, count}.
	langList := make([]map[string]interface{}, 0, len(counts))
	for lang, n := range counts {
		langList = append(langList, map[string]interface{}{
			"language": lang,
			"count":    n,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"total_users": total,
		"languages":   langList,
	})
}
