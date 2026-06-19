package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

// appearanceCols are the columns added to the devices table for the four
// appearance preferences (+ platform + timestamp).
var appearanceCols = []string{
	"appearance_theme TEXT",
	"appearance_color TEXT",
	"appearance_background TEXT",
	"appearance_icon_set TEXT",
	"appearance_spinner TEXT",
	// Per-element "randomize on each launch" flags. When a flag is 1, the value
	// stored alongside it is a momentary shuffle pick, not a deliberate choice —
	// so the dashboard can split "set by user" from "kept random". 0 = the user
	// fixed this element (also the default for old clients that don't report it).
	"appearance_theme_random INTEGER DEFAULT 0",
	"appearance_color_random INTEGER DEFAULT 0",
	"appearance_background_random INTEGER DEFAULT 0",
	"appearance_icon_random INTEGER DEFAULT 0",
	"appearance_spinner_random INTEGER DEFAULT 0",
	"appearance_platform TEXT",
	"appearance_updated_at DATETIME",
}

// appearanceReady flips to true only once every column is confirmed present,
// after which ensureAppearanceSchema is a cheap atomic load.
var appearanceReady atomic.Bool

// ensureAppearanceSchema makes sure the appearance columns exist on the devices
// table. It is called at startup AND at the top of every appearance handler.
//
// Crucially it RETRIES until it fully succeeds: a "duplicate column" error
// means the column is already there (fine), while any other error (e.g. a
// transient "database is locked" from the concurrent push-event loop at
// startup) leaves appearanceReady false so the next request tries again. This
// self-heals a migration that failed once, instead of giving up permanently.
func ensureAppearanceSchema() {
	if appearanceReady.Load() {
		return
	}
	allGood := true
	added := 0
	for _, c := range appearanceCols {
		if _, err := db.Exec("ALTER TABLE devices ADD COLUMN " + c); err != nil {
			if strings.Contains(err.Error(), "duplicate column") {
				continue // already present — good
			}
			log.Printf("⚠️ appearance ALTER failed (%s): %v — will retry on next request", c, err)
			allGood = false
			continue
		}
		added++
	}
	if allGood {
		appearanceReady.Store(true)
		if added > 0 {
			log.Printf("✓ appearance migration: added %d column(s); schema ready", added)
		}
	}
}

// ---------------------------------------------------------------------------
// Appearance preferences (the four "Внешний вид" settings)
//
// The mobile app lets the user pick five visual preferences — theme, colour
// scheme, background, horoscope icon set and loading spinner. This file records the last value
// each device reported so the Stellar Vault admin dashboard can show, per
// user, which appearance parameters they have set.
//
// Storage lives on the existing `devices` row (keyed by email + device_id),
// alongside the push-token / language / platform per-device metadata, so a
// user with several devices keeps a value per device. All columns are added
// as nullable migrations — existing rows and old clients are unaffected.
// ---------------------------------------------------------------------------

// setAppearanceParams — POST /api/user/appearance (JWT-protected).
// Records the four appearance preferences for the calling device. Called by
// the app (debounced) whenever a preference changes and on launch.
func setAppearanceParams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ensureAppearanceSchema()

	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok || claims.Email == "" || claims.DeviceID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}

	var req struct {
		Theme            string `json:"theme"`
		ColorScheme      string `json:"color_scheme"`
		Background       string `json:"background"`
		IconSet          string `json:"icon_set"`
		Spinner          string `json:"spinner"`
		ThemeRandom      bool   `json:"theme_random"`
		ColorRandom      bool   `json:"color_random"`
		BackgroundRandom bool   `json:"background_random"`
		IconRandom       bool   `json:"icon_random"`
		SpinnerRandom    bool   `json:"spinner_random"`
		Platform         string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	// Upsert onto the existing (email, device_id) row; create it if the device
	// hasn't been recorded yet (relies on idx_devices_email_device).
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	_, err := db.Exec(`
		INSERT INTO devices (email, device_id, last_seen,
			appearance_theme, appearance_color, appearance_background, appearance_icon_set, appearance_spinner,
			appearance_theme_random, appearance_color_random, appearance_background_random, appearance_icon_random, appearance_spinner_random,
			appearance_platform, appearance_updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(email, device_id) DO UPDATE SET
			last_seen = CURRENT_TIMESTAMP,
			appearance_theme = excluded.appearance_theme,
			appearance_color = excluded.appearance_color,
			appearance_background = excluded.appearance_background,
			appearance_icon_set = excluded.appearance_icon_set,
			appearance_spinner = excluded.appearance_spinner,
			appearance_theme_random = excluded.appearance_theme_random,
			appearance_color_random = excluded.appearance_color_random,
			appearance_background_random = excluded.appearance_background_random,
			appearance_icon_random = excluded.appearance_icon_random,
			appearance_spinner_random = excluded.appearance_spinner_random,
			appearance_platform = CASE WHEN excluded.appearance_platform != '' THEN excluded.appearance_platform ELSE devices.appearance_platform END,
			appearance_updated_at = CURRENT_TIMESTAMP`,
		email, claims.DeviceID,
		req.Theme, req.ColorScheme, req.Background, req.IconSet, req.Spinner,
		b2i(req.ThemeRandom), b2i(req.ColorRandom), b2i(req.BackgroundRandom), b2i(req.IconRandom), b2i(req.SpinnerRandom),
		req.Platform)
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
	ensureAppearanceSchema()

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
			       COALESCE(appearance_spinner, ''),
			       COALESCE(appearance_theme_random, 0), COALESCE(appearance_color_random, 0),
			       COALESCE(appearance_background_random, 0), COALESCE(appearance_icon_random, 0),
			       COALESCE(appearance_spinner_random, 0),
			       COALESCE(appearance_updated_at, '')
			FROM devices
			WHERE email = ? AND appearance_updated_at IS NOT NULL
			ORDER BY appearance_updated_at DESC`, userEmail)
		if err != nil {
			log.Printf("⚠️ appearance per-user query failed: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error: " + err.Error()})
			return
		}
		defer rows.Close()

		out := []map[string]interface{}{}
		for rows.Next() {
			var deviceID, platform, theme, color, background, iconSet, spinner, updatedAt string
			var themeRnd, colorRnd, bgRnd, iconRnd, spinnerRnd int
			if err := rows.Scan(&deviceID, &platform, &theme, &color, &background, &iconSet, &spinner,
				&themeRnd, &colorRnd, &bgRnd, &iconRnd, &spinnerRnd, &updatedAt); err != nil {
				continue
			}
			out = append(out, map[string]interface{}{
				"device_id":         deviceID,
				"platform":          platform,
				"theme":             theme,
				"color_scheme":      color,
				"background":        background,
				"icon_set":          iconSet,
				"spinner":           spinner,
				"theme_random":      themeRnd == 1,
				"color_random":      colorRnd == 1,
				"background_random": bgRnd == 1,
				"icon_random":       iconRnd == 1,
				"spinner_random":    spinnerRnd == 1,
				"updated_at":        updatedAt,
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

	// ── Drill-down: the users behind a single count ──────────────────────────
	//
	// The dashboard makes every "Users" number clickable. A click sends either:
	//   list=param&param=<key>&value=<displayed value>   (one parameter table)
	//   list=combo&theme=&color_scheme=&background=&icon_set=&spinner=  (a row of
	//                                                       the full-combination table)
	// where each value is exactly what the dashboard shows — a fixed value, the
	// literal "(unset)", or the literal "(random)". We reproduce the same
	// most-recent-device-per-user snapshot the aggregate uses, label every user's
	// values identically, then return the users whose label(s) match so the count
	// and the listed users always agree.
	if listMode := r.URL.Query().Get("list"); listMode == "param" || listMode == "combo" {
		users, err := appearanceUsersMatching(listMode, r.URL.Query())
		if err != nil {
			log.Printf("⚠️ appearance list query failed: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error: " + err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"users":   users,
			"count":   len(users),
		})
		return
	}

	// ── Aggregate: distribution over the most-recent device per user ─────────
	//
	// For each of the four parameters we report a "momentary snapshot" that
	// separates two kinds of users:
	//   • fixed  — the user deliberately chose this value (random flag off);
	//   • random — the user keeps this element shuffling on every launch, so the
	//              stored value is just whatever the last launch happened to pick.
	// Counting a random user's momentary value as a real preference would skew
	// the distribution, so random users are tallied separately (a single
	// "random" bucket per parameter) instead of by their throwaway value.
	rows, err := db.Query(`
		SELECT appearance_theme, appearance_color, appearance_background, appearance_icon_set, appearance_spinner,
		       COALESCE(appearance_theme_random, 0), COALESCE(appearance_color_random, 0),
		       COALESCE(appearance_background_random, 0), COALESCE(appearance_icon_random, 0),
		       COALESCE(appearance_spinner_random, 0)
		FROM (
			SELECT appearance_theme, appearance_color, appearance_background, appearance_icon_set, appearance_spinner,
			       appearance_theme_random, appearance_color_random,
			       appearance_background_random, appearance_icon_random, appearance_spinner_random,
			       ROW_NUMBER() OVER (PARTITION BY email ORDER BY appearance_updated_at DESC) AS rn
			FROM devices
			WHERE appearance_updated_at IS NOT NULL
		)
		WHERE rn = 1`)
	if err != nil {
		log.Printf("⚠️ appearance aggregate query failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error: " + err.Error()})
		return
	}
	defer rows.Close()

	// Per-parameter accumulator: fixed values → user count, plus how many users
	// keep that parameter on random vs. fixed.
	type paramAgg struct {
		fixed       map[string]int
		fixedCount  int
		randomCount int
	}
	newParam := func() *paramAgg { return &paramAgg{fixed: map[string]int{}} }
	theme, color, background, iconSet, spinner := newParam(), newParam(), newParam(), newParam(), newParam()

	type comboKey struct{ t, c, b, i, s string }
	combos := map[comboKey]int{}
	total := 0
	norm := func(v string) string {
		if v == "" {
			return "(unset)"
		}
		return v
	}
	// add tallies one user's value into a parameter; random users go to the
	// random bucket and contribute "(random)" to the combination key.
	add := func(p *paramAgg, v string, isRandom bool) string {
		if isRandom {
			p.randomCount++
			return "(random)"
		}
		v = norm(v)
		p.fixed[v]++
		p.fixedCount++
		return v
	}
	for rows.Next() {
		var t, c, b, i, s string
		var tr, cr, br, ir, sr int
		if err := rows.Scan(&t, &c, &b, &i, &s, &tr, &cr, &br, &ir, &sr); err != nil {
			continue
		}
		total++
		ck := comboKey{
			add(theme, t, tr == 1),
			add(color, c, cr == 1),
			add(background, b, br == 1),
			add(iconSet, i, ir == 1),
			add(spinner, s, sr == 1),
		}
		combos[ck]++
	}

	// Every distinct full combination of the four settings, with its user count.
	// Random elements appear as "(random)" so combinations reflect the stable
	// choices rather than each launch's throwaway shuffle pick.
	comboList := make([]map[string]interface{}, 0, len(combos))
	for k, n := range combos {
		comboList = append(comboList, map[string]interface{}{
			"theme":        k.t,
			"color_scheme": k.c,
			"background":   k.b,
			"icon_set":     k.i,
			"spinner":      k.s,
			"count":        n,
		})
	}

	// Serialise a parameter as {fixed:{value:count}, fixed_count, random_count}.
	paramJSON := func(p *paramAgg) map[string]interface{} {
		return map[string]interface{}{
			"fixed":        p.fixed,
			"fixed_count":  p.fixedCount,
			"random_count": p.randomCount,
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"total_users":  total,
		"theme":        paramJSON(theme),
		"color_scheme": paramJSON(color),
		"background":   paramJSON(background),
		"icon_set":     paramJSON(iconSet),
		"spinner":      paramJSON(spinner),
		"combinations": comboList,
	})
}

// appearanceUsersMatching returns the users (one most-recent device per user)
// whose appearance values match the requested filter, in the same way the
// aggregate counts them. `mode` is "param" or "combo"; `q` carries the filter
// values (each the literal label the dashboard displays: a fixed value,
// "(unset)" or "(random)").
//
// The display label for one element is derived exactly as the aggregate does:
// a random element is labelled "(random)" regardless of its stored value, an
// empty fixed value is "(unset)", otherwise the stored value itself. We compare
// labels — never raw columns — so a listed user set always matches its count.
func appearanceUsersMatching(mode string, q interface {
	Get(string) string
}) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT email, device_id,
		       COALESCE(NULLIF(appearance_platform, ''), platform, ''),
		       appearance_theme, appearance_color, appearance_background, appearance_icon_set, appearance_spinner,
		       COALESCE(appearance_theme_random, 0), COALESCE(appearance_color_random, 0),
		       COALESCE(appearance_background_random, 0), COALESCE(appearance_icon_random, 0),
		       COALESCE(appearance_spinner_random, 0),
		       COALESCE(appearance_updated_at, '')
		FROM (
			SELECT email, device_id, platform,
			       appearance_theme, appearance_color, appearance_background, appearance_icon_set, appearance_spinner,
			       appearance_platform,
			       appearance_theme_random, appearance_color_random,
			       appearance_background_random, appearance_icon_random, appearance_spinner_random,
			       appearance_updated_at,
			       ROW_NUMBER() OVER (PARTITION BY email ORDER BY appearance_updated_at DESC) AS rn
			FROM devices
			WHERE appearance_updated_at IS NOT NULL
		)
		WHERE rn = 1
		ORDER BY appearance_updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// label reproduces the aggregate's per-element display value.
	label := func(v string, isRandom bool) string {
		if isRandom {
			return "(random)"
		}
		if v == "" {
			return "(unset)"
		}
		return v
	}

	// What we're matching against.
	wantParam := q.Get("param")  // mode == "param": which element
	wantValue := q.Get("value")  // mode == "param": its label
	wantCombo := map[string]string{
		"theme":        q.Get("theme"),
		"color_scheme": q.Get("color_scheme"),
		"background":   q.Get("background"),
		"icon_set":     q.Get("icon_set"),
		"spinner":      q.Get("spinner"),
	}

	users := []map[string]interface{}{}
	for rows.Next() {
		var email, deviceID, platform, theme, color, background, iconSet, spinner, updatedAt string
		var tr, cr, br, ir, sr int
		if err := rows.Scan(&email, &deviceID, &platform, &theme, &color, &background, &iconSet, &spinner,
			&tr, &cr, &br, &ir, &sr, &updatedAt); err != nil {
			continue
		}
		labels := map[string]string{
			"theme":        label(theme, tr == 1),
			"color_scheme": label(color, cr == 1),
			"background":   label(background, br == 1),
			"icon_set":     label(iconSet, ir == 1),
			"spinner":      label(spinner, sr == 1),
		}

		match := false
		if mode == "param" {
			if l, ok := labels[wantParam]; ok && l == wantValue {
				match = true
			}
		} else { // combo
			match = labels["theme"] == wantCombo["theme"] &&
				labels["color_scheme"] == wantCombo["color_scheme"] &&
				labels["background"] == wantCombo["background"] &&
				labels["icon_set"] == wantCombo["icon_set"] &&
				labels["spinner"] == wantCombo["spinner"]
		}
		if !match {
			continue
		}

		users = append(users, map[string]interface{}{
			"email":        email,
			"device_id":    deviceID,
			"platform":     platform,
			"theme":        labels["theme"],
			"color_scheme": labels["color_scheme"],
			"background":   labels["background"],
			"icon_set":     labels["icon_set"],
			"spinner":      labels["spinner"],
			"updated_at":   updatedAt,
		})
	}
	return users, nil
}
