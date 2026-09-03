package main

// iOS Live Activity lifecycle: ending the marathon Lock-Screen countdown.
//
// The app shows a Duolingo-style countdown (Live Activity) from 16:00 local
// to local midnight while the day's marathon step is unlogged. iOS offers no
// scheduled end for an activity: without help it keeps the frozen "0:00"
// banner for up to 8 h after start + 4 h of dismissal grace (owner's
// screenshot 2026-09-03, 08:23 — banner still up). The Apple-sanctioned fix is
// an ActivityKit push with `"event":"end"` sent at the deadline.
//
// Flow:
//   * The app requests the activity with pushType .token, receives the
//     activity's APNs token and POSTs {push_token, end_millis} here
//     (/api/user/live-activity, JWT-protected — same auth as /user/push-token).
//   * liveActivityEndLoop wakes every 30 s and sends the end push for every
//     row whose end_at has passed, marking sent_at (once — dead tokens are
//     not retried; the activity is gone anyway).
//   * When the user logs the day, the app ends the activity itself and
//     DELETEs the row so no push is sent to a dead token.
//
// Build: this file is compiled alongside astrolog_api.go (see build.sh).

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// liveActivityPollInterval bounds how late the end push can be after end_at.
const liveActivityPollInterval = 30 * time.Second

// liveActivityRetention: rows (sent or not) older than this are pruned.
const liveActivityRetention = 3 * 24 * time.Hour

func migrateLiveActivities() {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS live_activity_ends (
			push_token TEXT PRIMARY KEY,    -- ActivityKit push token (hex)
			email TEXT NOT NULL,
			device_id TEXT NOT NULL,
			end_at INTEGER NOT NULL,        -- unix seconds: local midnight of the step
			created_at INTEGER NOT NULL,    -- unix seconds
			sent_at INTEGER                 -- unix seconds; NULL until the end push went out
		);`); err != nil {
		log.Printf("⚠️ live_activity_ends table: %v", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_live_activity_ends_due
		ON live_activity_ends (sent_at, end_at)`); err != nil {
		log.Printf("⚠️ live_activity_ends index: %v", err)
	}
}

// liveActivityTopic is the APNs topic for Live Activity control pushes:
// the app's bundle id with the ActivityKit suffix.
func liveActivityTopic(bundleID string) string {
	return bundleID + ".push-type.liveactivity"
}

// liveActivityEndBody builds the ActivityKit "end" payload. No content-state
// is sent on purpose: the widget keeps its last state (ContentState.endTime
// is a Swift Date whose JSON encoding is easy to get wrong), and for "end"
// ActivityKit treats content-state as optional. dismissal-date tells iOS to
// remove the banner at the deadline instead of keeping it up to 4 h.
func liveActivityEndBody(now, dismissAt time.Time) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"aps": map[string]interface{}{
			"timestamp":      now.Unix(),
			"event":          "end",
			"dismissal-date": dismissAt.Unix(),
		},
	})
}

// sendLiveActivityEnd delivers the "end" push to one activity token.
func sendLiveActivityEnd(token string, dismissAt time.Time) error {
	c, err := loadAPNsConfig()
	if err != nil {
		return err
	}
	jwt, err := apnsProviderToken(c)
	if err != nil {
		return err
	}
	body, err := liveActivityEndBody(time.Now(), dismissAt)
	if err != nil {
		return err
	}
	// A late end push is still useful (it removes the banner), so no expiry.
	return sendAPNsWithFallback(c, jwt, liveActivityTopic(c.bundleID), "liveactivity", token, body, 0)
}

// upsertLiveActivityEnd records the deadline for one activity token. A
// device runs one countdown at a time, so any other pending row of the same
// device is dropped (a new day's activity replaced the previous one on the
// phone — its old token must not receive a stray end push later).
func upsertLiveActivityEnd(email, deviceID, token string, endAt, now time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM live_activity_ends
		WHERE device_id = ? AND push_token != ? AND sent_at IS NULL`, deviceID, token); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO live_activity_ends (push_token, email, device_id, end_at, created_at, sent_at)
		VALUES (?, ?, ?, ?, ?, NULL)
		ON CONFLICT(push_token) DO UPDATE SET
			email = excluded.email,
			device_id = excluded.device_id,
			end_at = excluded.end_at,
			created_at = excluded.created_at,
			sent_at = NULL`,
		token, email, deviceID, endAt.Unix(), now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func deleteLiveActivityEnd(deviceID, token string) error {
	// device_id in the WHERE clause: a token can only be cancelled by the
	// device that registered it.
	_, err := db.Exec(`DELETE FROM live_activity_ends WHERE push_token = ? AND device_id = ?`, token, deviceID)
	return err
}

type liveActivityDue struct {
	token string
	endAt time.Time
}

// dueLiveActivityEnds lists the unsent rows whose deadline has passed.
func dueLiveActivityEnds(now time.Time) ([]liveActivityDue, error) {
	rows, err := db.Query(`SELECT push_token, end_at FROM live_activity_ends
		WHERE sent_at IS NULL AND end_at <= ? ORDER BY end_at`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []liveActivityDue
	for rows.Next() {
		var d liveActivityDue
		var endAt int64
		if err := rows.Scan(&d.token, &endAt); err != nil {
			return nil, err
		}
		d.endAt = time.Unix(endAt, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

func markLiveActivityEndSent(token string, now time.Time) error {
	_, err := db.Exec(`UPDATE live_activity_ends SET sent_at = ? WHERE push_token = ?`, now.Unix(), token)
	return err
}

// processDueLiveActivityEnds sends the end push for every due row and marks
// it sent — also on failure: the push is a one-shot (a retry storm against a
// dead or expired token helps nobody; the 8 h system cap still applies).
// Returns the number of rows processed.
func processDueLiveActivityEnds(now time.Time, send func(token string, dismissAt time.Time) error) int {
	due, err := dueLiveActivityEnds(now)
	if err != nil {
		log.Printf("⚠️ live-activity due query: %v", err)
		return 0
	}
	for _, d := range due {
		if err := send(d.token, d.endAt); err != nil {
			log.Printf("⚠️ live-activity end push %s…: %v", shortToken(d.token), err)
		}
		if err := markLiveActivityEndSent(d.token, now); err != nil {
			log.Printf("⚠️ live-activity mark sent: %v", err)
		}
	}
	return len(due)
}

func pruneLiveActivityEnds(now time.Time) {
	if _, err := db.Exec(`DELETE FROM live_activity_ends WHERE created_at < ?`,
		now.Add(-liveActivityRetention).Unix()); err != nil {
		log.Printf("⚠️ live-activity prune: %v", err)
	}
}

func shortToken(t string) string {
	if len(t) > 8 {
		return t[:8]
	}
	return t
}

func liveActivityEndLoop() {
	tick := time.NewTicker(liveActivityPollInterval)
	prune := time.NewTicker(6 * time.Hour)
	pruneLiveActivityEnds(time.Now())
	for {
		select {
		case <-tick.C:
			processDueLiveActivityEnds(time.Now(), sendLiveActivityEnd)
		case <-prune.C:
			pruneLiveActivityEnds(time.Now())
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers (JWT-protected)
// ---------------------------------------------------------------------------

func liveActivityClaims(w http.ResponseWriter, r *http.Request) (*JWTClaims, bool) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok || claims.Email == "" || claims.DeviceID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return nil, false
	}
	return claims, true
}

// registerLiveActivity: POST /api/user/live-activity {push_token, end_millis}
func registerLiveActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims, ok := liveActivityClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		PushToken string `json:"push_token"`
		EndMillis int64  `json:"end_millis"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}
	token := strings.TrimSpace(req.PushToken)
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "push_token required"})
		return
	}
	now := time.Now()
	endAt := time.UnixMilli(req.EndMillis)
	// A deadline in the past or more than 2 days ahead is a client bug (the
	// activity lives at most until the next local midnight).
	if req.EndMillis <= 0 || endAt.Before(now.Add(-time.Minute)) || endAt.After(now.Add(48*time.Hour)) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "end_millis out of range"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if err := upsertLiveActivityEnd(email, claims.DeviceID, token, endAt, now); err != nil {
		log.Printf("⚠️ live-activity upsert failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// cancelLiveActivity: DELETE /api/user/live-activity {push_token}
func cancelLiveActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims, ok := liveActivityClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		PushToken string `json:"push_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request"})
		return
	}
	token := strings.TrimSpace(req.PushToken)
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "push_token required"})
		return
	}
	if err := deleteLiveActivityEnd(claims.DeviceID, token); err != nil {
		log.Printf("⚠️ live-activity delete failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}
