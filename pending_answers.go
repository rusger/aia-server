package main

// Answers that must reach the phone (A45, owner 09.11.2026): «уже оплачено …
// глупо терять … хранить на сервере … до того момента как точно убедимся что
// доставлено на телефон … хеш или контрольную сумму … сервер тоже не
// захламлять».
//
// The in-memory stream buffers (chatgpt_resume.go) live 20 minutes and die
// with the process. A finished user-facing answer that carries a stream_id is
// therefore also written to pending_answers (its SSE events, so a resume
// keeps the client's event indices) and stays there until the app confirms
// it got exactly that text (POST /api/chatgpt-stream/ack with its sha256) —
// or 48 h pass, or the device has more than 20 waiting. Any lookup that
// misses the memory registry falls back to this table, so a repeat POST, a
// resume, and the buffered fallback all survive a restart without a second
// model call. The app lists what is waiting with GET /api/chatgpt-stream/pending.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const (
	pendingAnswerRetention  = 48 * time.Hour
	pendingAnswersPerDevice = 20
	pendingAnswerPruneEvery = time.Hour
)

func migratePendingAnswers() {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS pending_answers (
			device_id TEXT NOT NULL,
			stream_id TEXT NOT NULL,
			call_type TEXT NOT NULL,
			created_at INTEGER NOT NULL,   -- unix seconds, when the answer finished
			events TEXT NOT NULL,          -- JSON array of the SSE payloads, index == "i"
			sha256 TEXT NOT NULL,          -- hex sha256 of the answer text (the "c" events joined)
			PRIMARY KEY (device_id, stream_id)
		);`); err != nil {
		log.Printf("⚠️ pending_answers table: %v", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_pending_answers_created
		ON pending_answers (created_at)`); err != nil {
		log.Printf("⚠️ pending_answers index: %v", err)
	}
}

// answerText joins the "c" events: what the user reads, crisis block included.
func answerText(events [][]byte) string {
	var out []byte
	for _, raw := range events {
		var ev struct {
			C string `json:"c"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			out = append(out, ev.C...)
		}
	}
	return string(out)
}

func answerSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// savePendingAnswer stores a finished answer until the app acknowledges it.
// Only complete answers (last event "done") with text are kept.
func savePendingAnswer(deviceID, streamID, callType string, events [][]byte, now time.Time) {
	if db == nil || len(events) == 0 {
		return
	}
	var last map[string]interface{}
	if json.Unmarshal(events[len(events)-1], &last) != nil || last["done"] != true {
		return
	}
	text := answerText(events)
	if text == "" {
		return
	}
	strs := make([]string, len(events))
	for i, raw := range events {
		strs[i] = string(raw)
	}
	blob, err := json.Marshal(strs)
	if err != nil {
		return
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO pending_answers
		(device_id, stream_id, call_type, created_at, events, sha256) VALUES (?, ?, ?, ?, ?, ?)`,
		deviceID, streamID, callType, now.Unix(), string(blob), answerSHA256(text)); err != nil {
		log.Printf("⚠️ pending answer save: %v", err)
		return
	}
	// Per-device cap: the oldest beyond pendingAnswersPerDevice go.
	if _, err := db.Exec(`DELETE FROM pending_answers WHERE device_id = ? AND stream_id NOT IN (
		SELECT stream_id FROM pending_answers WHERE device_id = ?
		ORDER BY created_at DESC, rowid DESC LIMIT ?)`,
		deviceID, deviceID, pendingAnswersPerDevice); err != nil {
		log.Printf("⚠️ pending answer cap: %v", err)
	}
}

// loadPendingAnswer → the stored events, or nil (none, expired, unreadable).
func loadPendingAnswer(deviceID, streamID string, now time.Time) [][]byte {
	if db == nil {
		return nil
	}
	var blob string
	err := db.QueryRow(`SELECT events FROM pending_answers
		WHERE device_id = ? AND stream_id = ? AND created_at >= ?`,
		deviceID, streamID, now.Add(-pendingAnswerRetention).Unix()).Scan(&blob)
	if err != nil {
		return nil
	}
	var strs []string
	if json.Unmarshal([]byte(blob), &strs) != nil || len(strs) == 0 {
		return nil
	}
	events := make([][]byte, len(strs))
	for i, s := range strs {
		events[i] = []byte(s)
	}
	return events
}

func prunePendingAnswers(now time.Time) {
	if db == nil {
		return
	}
	if _, err := db.Exec(`DELETE FROM pending_answers WHERE created_at < ?`,
		now.Add(-pendingAnswerRetention).Unix()); err != nil {
		log.Printf("⚠️ pending answers prune: %v", err)
	}
}

func pendingAnswersLoop() {
	prunePendingAnswers(time.Now())
	for range time.NewTicker(pendingAnswerPruneEvery).C {
		prunePendingAnswers(time.Now())
	}
}

// lookupOrRestore is streams.lookup with the table behind it: a stored answer
// comes back as a finished buffer with its original event indices.
func (r *streamRegistry) lookupOrRestore(deviceID, streamID string, now time.Time) *streamBuf {
	key := streamKey(deviceID, streamID)
	if b := r.lookup(key, now); b != nil {
		return b
	}
	events := loadPendingAnswer(deviceID, streamID, now)
	if events == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.m[key]; ok && !b.expired(now) && b.resumable() {
		return b // restored or registered meanwhile
	}
	r.sweepLocked(now, streamRegistryMax-1)
	b := newStreamBuf(now)
	b.events, b.done, b.finished = events, true, now
	for _, e := range events {
		b.size += len(e)
	}
	r.m[key] = b
	log.Printf("↩️ ChatGPT answer restored from pending_answers: device=%s", deviceID)
	return b
}

type pendingAnswerItem struct {
	StreamID  string `json:"stream_id"`
	CallType  string `json:"call_type"`
	CreatedAt int64  `json:"created_at"` // unix seconds
	SHA256    string `json:"sha256"`
}

// GET /api/chatgpt-stream/pending → this device's answers not yet confirmed.
// The text itself is fetched with /api/chatgpt-stream/resume?stream_id=…&after=-1.
func chatGPTPendingAnswers(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		streamJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	if !ipLimiter.GetLimiter(getClientIP(r)).Allow() || !deviceLimiter.GetLimiter(claims.DeviceID).Allow() {
		streamJSONError(w, http.StatusTooManyRequests, "Rate limit exceeded. Please try again.", "")
		return
	}
	rows, err := db.Query(`SELECT stream_id, call_type, created_at, sha256 FROM pending_answers
		WHERE device_id = ? AND created_at >= ? ORDER BY created_at`,
		claims.DeviceID, time.Now().Add(-pendingAnswerRetention).Unix())
	if err != nil {
		streamJSONError(w, http.StatusInternalServerError, "Database error", "")
		return
	}
	defer rows.Close()
	items := []pendingAnswerItem{}
	for rows.Next() {
		var it pendingAnswerItem
		if err := rows.Scan(&it.StreamID, &it.CallType, &it.CreatedAt, &it.SHA256); err != nil {
			streamJSONError(w, http.StatusInternalServerError, "Database error", "")
			return
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil { // a partial list must not pass as complete
		streamJSONError(w, http.StatusInternalServerError, "Database error", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "answers": items})
}

// POST /api/chatgpt-stream/ack {stream_id, sha256} → the phone has this exact
// text; the stored copy is deleted. A different hash leaves it (409): the app
// got something else and may fetch it again.
func chatGPTAckAnswer(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		streamJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	var req struct {
		StreamID string `json:"stream_id"`
		SHA256   string `json:"sha256"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		!streamIDRe.MatchString(req.StreamID) || len(req.SHA256) != 64 {
		streamJSONError(w, http.StatusBadRequest, "stream_id and sha256 required", "")
		return
	}
	var stored string
	err := db.QueryRow(`SELECT sha256 FROM pending_answers WHERE device_id = ? AND stream_id = ?`,
		claims.DeviceID, req.StreamID).Scan(&stored)
	if err == sql.ErrNoRows { // nothing stored (already acked, pruned): fine
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true}`))
		return
	}
	if err != nil {
		streamJSONError(w, http.StatusInternalServerError, "Database error", "")
		return
	}
	if stored != req.SHA256 {
		streamJSONError(w, http.StatusConflict, "checksum mismatch", "checksum_mismatch")
		return
	}
	if _, err := db.Exec(`DELETE FROM pending_answers WHERE device_id = ? AND stream_id = ?`,
		claims.DeviceID, req.StreamID); err != nil {
		streamJSONError(w, http.StatusInternalServerError, "Database error", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}
