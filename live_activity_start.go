package main

// iOS Live Activity lifecycle, part 2: STARTING the marathon Lock-Screen
// countdown while the app is closed (ActivityKit push-to-start, iOS 17.2+).
//
// Owner 2026-09-04: the banner (planned for 21:45 → local midnight) never
// appeared on the Lock Screen unless the app was opened and backgrounded —
// the bridge could only request the activity from a running app. Apple's
// route for exactly this case is a push with `"event":"start"` to the app's
// push-to-start token: the system renders the activity itself, wakes the
// app in the background and hands it the activity's update token, which the
// app registers here for the midnight end push (live_activity.go).
//
// Flow:
//   * The app observes Activity.pushToStartTokenUpdates and POSTs its
//     schedule for the days ahead — one row per day with the exact start
//     moment, the deadline and the PRE-LOCALIZED attributes the widget
//     renders (/api/user/live-activity/schedule, JWT). Every POST replaces
//     the device's unsent rows (an empty list cancels everything); the app
//     re-posts on launch/foreground, so a logged day or a finished marathon
//     drops out within one app session.
//   * liveActivityEndLoop's 30 s tick also drains due start rows: a row whose
//     window has (almost) closed is skipped, never sent late.
//
// Build: this file is compiled alongside astrolog_api.go (see build.sh).

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

// liveActivityStartRetention: rows older than this are pruned.
const liveActivityStartRetention = 40 * 24 * time.Hour

// liveActivityStartMinRemaining: a start push is pointless when the window
// closes sooner than this — the banner would appear and vanish.
const liveActivityStartMinRemaining = 5 * time.Minute

// liveActivityScheduleMaxEntries bounds one schedule POST (the app plans a
// week ahead; 14 leaves room for a two-week horizon).
const liveActivityScheduleMaxEntries = 14

// liveActivityAttributesType is the Swift ActivityAttributes type name the
// widget extension is compiled with.
const liveActivityAttributesType = "MarathonActivityAttributes"

func migrateLiveActivityStarts() {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS live_activity_starts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id TEXT NOT NULL,
			email TEXT NOT NULL,
			push_to_start_token TEXT NOT NULL,  -- ActivityKit push-to-start token (hex)
			start_at INTEGER NOT NULL,          -- unix seconds: when the banner appears
			end_at INTEGER NOT NULL,            -- unix seconds: local midnight of the step
			attributes TEXT NOT NULL,           -- JSON, keys = Swift MarathonActivityAttributes
			alert_title TEXT NOT NULL DEFAULT '',
			alert_body TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			sent_at INTEGER                     -- unix seconds; NULL until sent or skipped
		);`); err != nil {
		log.Printf("⚠️ live_activity_starts table: %v", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_live_activity_starts_due
		ON live_activity_starts (sent_at, start_at)`); err != nil {
		log.Printf("⚠️ live_activity_starts index: %v", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_live_activity_starts_device
		ON live_activity_starts (device_id)`); err != nil {
		log.Printf("⚠️ live_activity_starts device index: %v", err)
	}
}

// liveActivityAttributes mirrors the Swift struct field for field; every
// string arrives pre-localized from the app.
type liveActivityAttributes struct {
	Title        string `json:"title"`
	Subtitle     string `json:"subtitle"`
	DayLabel     string `json:"dayLabel"`
	LeftLabel    string `json:"leftLabel"`
	Closing      bool   `json:"closing"`
	ClosingLabel string `json:"closingLabel"`
}

type liveActivityScheduleEntry struct {
	StartMillis int64                  `json:"start_millis"`
	EndMillis   int64                  `json:"end_millis"`
	Attributes  liveActivityAttributes `json:"attributes"`
	AlertTitle  string                 `json:"alert_title"`
	AlertBody   string                 `json:"alert_body"`
}

type liveActivityScheduleRequest struct {
	PushToStartToken string                      `json:"push_to_start_token"`
	Entries          []liveActivityScheduleEntry `json:"entries"`
}

// liveActivityStartRow is one planned banner as stored / as due for sending.
type liveActivityStartRow struct {
	id         int64
	token      string
	startAt    time.Time
	endAt      time.Time
	attributes liveActivityAttributes
	alertTitle string
	alertBody  string
}

// validateLiveActivitySchedule checks one schedule POST. Entries whose
// window already closed are dropped silently (the app posts on every
// foreground and may include today after midnight-crossing races); every
// other defect is a client bug and rejects the whole request.
func validateLiveActivitySchedule(req liveActivityScheduleRequest, now time.Time) ([]liveActivityScheduleEntry, error) {
	token := strings.TrimSpace(req.PushToStartToken)
	if token == "" {
		return nil, errors.New("push_to_start_token required")
	}
	if len(token) > 512 {
		return nil, errors.New("push_to_start_token too long")
	}
	if len(req.Entries) > liveActivityScheduleMaxEntries {
		return nil, errors.New("too many entries")
	}
	kept := make([]liveActivityScheduleEntry, 0, len(req.Entries))
	for _, e := range req.Entries {
		start := time.UnixMilli(e.StartMillis)
		end := time.UnixMilli(e.EndMillis)
		if e.StartMillis <= 0 || e.EndMillis <= 0 || !end.After(start) {
			return nil, errors.New("entry window invalid")
		}
		if end.Sub(start) > 26*time.Hour {
			return nil, errors.New("entry window too long")
		}
		if start.After(now.Add(31 * 24 * time.Hour)) {
			return nil, errors.New("entry too far ahead")
		}
		if strings.TrimSpace(e.Attributes.Title) == "" ||
			strings.TrimSpace(e.Attributes.Subtitle) == "" ||
			strings.TrimSpace(e.Attributes.DayLabel) == "" {
			return nil, errors.New("attributes title/subtitle/dayLabel required")
		}
		if !end.After(now) {
			continue
		}
		kept = append(kept, e)
	}
	return kept, nil
}

// replaceLiveActivitySchedule swaps the device's unsent rows for [entries]
// (already validated). Sent rows stay for the audit trail / prune.
func replaceLiveActivitySchedule(email, deviceID, token string, entries []liveActivityScheduleEntry, now time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM live_activity_starts WHERE device_id = ? AND sent_at IS NULL`, deviceID); err != nil {
		return err
	}
	for _, e := range entries {
		attrs, err := json.Marshal(e.Attributes)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO live_activity_starts
			(device_id, email, push_to_start_token, start_at, end_at, attributes, alert_title, alert_body, created_at, sent_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			deviceID, email, token, time.UnixMilli(e.StartMillis).Unix(), time.UnixMilli(e.EndMillis).Unix(),
			string(attrs), e.AlertTitle, e.AlertBody, now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// dueLiveActivityStarts lists the unsent rows whose start moment has passed.
func dueLiveActivityStarts(now time.Time) ([]liveActivityStartRow, error) {
	rows, err := db.Query(`SELECT id, push_to_start_token, start_at, end_at, attributes, alert_title, alert_body
		FROM live_activity_starts WHERE sent_at IS NULL AND start_at <= ? ORDER BY start_at`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []liveActivityStartRow
	for rows.Next() {
		var r liveActivityStartRow
		var startAt, endAt int64
		var attrs string
		if err := rows.Scan(&r.id, &r.token, &startAt, &endAt, &attrs, &r.alertTitle, &r.alertBody); err != nil {
			return nil, err
		}
		r.startAt = time.Unix(startAt, 0)
		r.endAt = time.Unix(endAt, 0)
		if err := json.Unmarshal([]byte(attrs), &r.attributes); err != nil {
			log.Printf("⚠️ live-activity start row %d: bad attributes: %v", r.id, err)
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func markLiveActivityStartSent(id int64, now time.Time) error {
	_, err := db.Exec(`UPDATE live_activity_starts SET sent_at = ? WHERE id = ?`, now.Unix(), id)
	return err
}

// liveActivityStartWorthSending: a banner whose window closes in under
// [liveActivityStartMinRemaining] is not started (pure, unit-tested).
func liveActivityStartWorthSending(now, endAt time.Time) bool {
	return endAt.Sub(now) >= liveActivityStartMinRemaining
}

// liveActivityStartBody builds the ActivityKit push-to-start payload.
// content-state carries the window as unix seconds (the Swift ContentState
// stores plain integers — Date would need the 2001 reference epoch);
// input-push-token asks iOS 18 to hand the app the update token right away.
func liveActivityStartBody(now time.Time, r liveActivityStartRow) ([]byte, error) {
	aps := map[string]interface{}{
		"timestamp": now.Unix(),
		"event":     "start",
		"content-state": map[string]interface{}{
			"startUnix": r.startAt.Unix(),
			"endUnix":   r.endAt.Unix(),
		},
		"attributes-type":  liveActivityAttributesType,
		"attributes":       r.attributes,
		"input-push-token": 1,
	}
	if r.alertTitle != "" || r.alertBody != "" {
		aps["alert"] = map[string]interface{}{"title": r.alertTitle, "body": r.alertBody}
	}
	return json.Marshal(map[string]interface{}{"aps": aps})
}

// sendLiveActivityStart delivers the start push; APNs drops it at the
// deadline (a banner that arrives after midnight is worse than none).
func sendLiveActivityStart(r liveActivityStartRow) error {
	c, err := loadAPNsConfig()
	if err != nil {
		return err
	}
	jwt, err := apnsProviderToken(c)
	if err != nil {
		return err
	}
	body, err := liveActivityStartBody(time.Now(), r)
	if err != nil {
		return err
	}
	return sendAPNsWithFallback(c, jwt, liveActivityTopic(c.bundleID), liveActivityPushType, r.token, body, r.endAt.Unix())
}

// processDueLiveActivityStarts sends every due start push (one-shot, like
// the end push) and skips the ones whose window is about to close. Returns
// the number of rows processed.
func processDueLiveActivityStarts(now time.Time, send func(r liveActivityStartRow) error) int {
	due, err := dueLiveActivityStarts(now)
	if err != nil {
		log.Printf("⚠️ live-activity start due query: %v", err)
		return 0
	}
	for _, r := range due {
		if !liveActivityStartWorthSending(now, r.endAt) {
			log.Printf("⏭ live-activity start %s… skipped: window ends %s", shortToken(r.token), r.endAt.UTC().Format(time.RFC3339))
		} else if err := send(r); err != nil {
			log.Printf("⚠️ live-activity start push %s…: %v", shortToken(r.token), err)
		} else {
			log.Printf("🟢 live-activity start push %s… sent (window %s → %s)", shortToken(r.token),
				r.startAt.UTC().Format(time.RFC3339), r.endAt.UTC().Format(time.RFC3339))
		}
		if err := markLiveActivityStartSent(r.id, now); err != nil {
			log.Printf("⚠️ live-activity start mark sent: %v", err)
		}
	}
	return len(due)
}

func pruneLiveActivityStarts(now time.Time) {
	if _, err := db.Exec(`DELETE FROM live_activity_starts WHERE created_at < ?`,
		now.Add(-liveActivityStartRetention).Unix()); err != nil {
		log.Printf("⚠️ live-activity start prune: %v", err)
	}
}

// scheduleLiveActivity: POST /api/user/live-activity/schedule
func scheduleLiveActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims, ok := liveActivityClaims(w, r)
	if !ok {
		return
	}
	var req liveActivityScheduleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}
	now := time.Now()
	entries, err := validateLiveActivitySchedule(req, now)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if err := replaceLiveActivitySchedule(email, claims.DeviceID, strings.TrimSpace(req.PushToStartToken), entries, now); err != nil {
		log.Printf("⚠️ live-activity schedule replace failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "scheduled": len(entries)})
}
