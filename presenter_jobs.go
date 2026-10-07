package main

// presenter_jobs.go — presenter videos on request (owner 05.10.2026).
//
// The videos are rendered by the owner's Mac, which is always on and runs the
// app's own renderer (5–8 s per video); this server keeps the queue, stores
// the result and serves it (presenter_video.go). The Mac pulls its work from
// here — nothing connects to the Mac.
//
// The protocol lets the app see whether the Mac has STARTED: an iPhone that
// sees no start renders by itself, an Android phone — which cannot — tells
// the user the service is temporarily unavailable.
//
// App (JWT):
//   POST /api/presenter/jobs {text, gender, lang, version, presenter}
//        → {success, status, key, id?, node_online}
//        ready        the video already exists — download it
//        unavailable  the Mac is not polling: no job, no voice is ordered
//        voicing      a job exists; the server is getting its voice (same cache,
//                     limits and accounting as /api/tts)
//        queued       waiting for the Mac
//        rendering    the Mac has taken it
//        failed       see "error"
//   GET  /api/presenter/jobs/{id}         → {success, status, key, error, node_online}
//   POST /api/presenter/jobs/{id}/cancel  the creator, before the Mac took it
//
// Node (X-Presenter-Node-Token = PRESENTER_NODE_TOKEN):
//   POST /api/presenter/node/claim        heartbeat + the oldest queued job
//   GET  /api/presenter/node/audio?key=   the voice mp3
//   PUT  /api/presenter/node/result?id=   the mp4 of a job → ready
//   POST /api/presenter/node/fail {id, error}
//   PUT  /api/presenter/node/video?key=&v=  a catalog video without a job

import (
	"bytes"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

const (
	presenterNodeOnlineSec   = 15   // the node polls every couple of seconds
	presenterRenderStaleSec  = 1500 // a claimed job with no result goes back to the queue once (Ditto on the Mac: 10–15 min a reading, owner 07.10.2026)
	presenterQueuedExpireSec = 3600 // behind two Ditto jobs a third waits up to half an hour; an hour is the ceiling
	presenterJobKeepSec      = 24 * 3600
	presenterMaxAttempts     = 2
	presenterMaxActivePerDev = 2
	presenterVideoMaxBytes   = 80 << 20
)

var (
	presenterIDRe       = regexp.MustCompile(`^[a-z]-[a-z]$`)
	presenterNodeSeenAt atomic.Int64 // unix seconds of the node's last claim
	// presenterNow is the clock; tests move it.
	presenterNow = func() int64 { return time.Now().Unix() }
)

func migratePresenterJobs() {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS presenter_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL,                 -- voice cache key = name of the video
			version TEXT NOT NULL,             -- render version (v17)
			text TEXT NOT NULL,                -- what she reads; wiped when the job ends
			gender TEXT NOT NULL,
			lang TEXT NOT NULL,
			presenter TEXT NOT NULL,           -- pool id, e.g. j-b
			device_id TEXT NOT NULL,
			client_ip TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,              -- voicing | queued | rendering | ready | failed | cancelled
			error TEXT NOT NULL DEFAULT '',
			attempts INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			claimed_at INTEGER,
			done_at INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_presenter_jobs_status ON presenter_jobs(status, created_at);
		CREATE INDEX IF NOT EXISTS idx_presenter_jobs_key ON presenter_jobs(version, key);
		-- one active job per video, whoever asks and however many times at once
		CREATE UNIQUE INDEX IF NOT EXISTS idx_presenter_jobs_active ON presenter_jobs(version, key)
			WHERE status IN ('voicing','queued','rendering');`); err != nil {
		log.Printf("⚠️ presenter_jobs migration: %v", err)
	}
}

func presenterNodeOnline() bool {
	seen := presenterNodeSeenAt.Load()
	return seen > 0 && presenterNow()-seen <= presenterNodeOnlineSec
}

func presenterJSON(w http.ResponseWriter, code int, v map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// presenterFinish ends a job: its text is no longer needed and is wiped.
func presenterFinish(id int64, status, errMsg string) {
	if _, err := db.Exec(`UPDATE presenter_jobs SET status = ?, error = ?, text = '', done_at = ? WHERE id = ?`,
		status, errMsg, presenterNow(), id); err != nil {
		log.Printf("⚠️ presenter job %d → %s: %v", id, status, err)
	}
}

type presenterJobRequest struct {
	Text      string `json:"text"`
	Gender    string `json:"gender"`
	Lang      string `json:"lang"`
	Version   string `json:"version"`
	Presenter string `json:"presenter"`
}

// presenterJobCreateHandler: POST /api/presenter/jobs
func presenterJobCreateHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		presenterVideoError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req presenterJobRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		presenterVideoError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" || len([]rune(text)) > ttsMaxChars {
		presenterVideoError(w, http.StatusBadRequest, "text is required and must fit the voice limit")
		return
	}
	if !presenterIDRe.MatchString(req.Presenter) {
		presenterVideoError(w, http.StatusBadRequest, "presenter must look like j-b")
		return
	}
	key := ttsCacheKey(ttsModel, ttsVoiceFor(req.Gender, req.Lang), req.Lang, text)
	path, ok := presenterVideoPath(req.Version, key)
	if !ok {
		presenterVideoError(w, http.StatusBadRequest, "version must look like v17")
		return
	}
	online := presenterNodeOnline()
	if presenterVideoSize(path) > 0 {
		presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": "ready", "key": key, "node_online": online})
		return
	}
	if !online {
		presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": "unavailable", "key": key, "node_online": false})
		return
	}
	// One job per video, whoever asks: an existing active job is answered as is.
	if id, status, found, err := presenterActiveJob(req.Version, key); err != nil {
		presenterVideoError(w, http.StatusInternalServerError, "queue unavailable")
		return
	} else if found {
		presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": status, "key": key, "id": id, "node_online": true})
		return
	}
	var active int
	if err := db.QueryRow(`SELECT COUNT(*) FROM presenter_jobs WHERE device_id = ? AND status IN ('voicing','queued','rendering')`, claims.DeviceID).Scan(&active); err != nil {
		log.Printf("⚠️ presenter jobs: active count for %s: %v", claims.DeviceID, err)
		presenterVideoError(w, http.StatusInternalServerError, "queue unavailable")
		return
	}
	if active >= presenterMaxActivePerDev {
		presenterVideoError(w, http.StatusTooManyRequests, "too many videos in progress")
		return
	}
	ip := getClientIP(r)
	res, err := db.Exec(`INSERT INTO presenter_jobs (key, version, text, gender, lang, presenter, device_id, client_ip, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'voicing', ?)`, key, req.Version, text, req.Gender, req.Lang, req.Presenter, claims.DeviceID, ip, presenterNow())
	if err != nil {
		// Two identical requests at once: the unique index let only one in —
		// the other gets that job (review r1: no second paid voice).
		if id, status, found, err2 := presenterActiveJob(req.Version, key); err2 == nil && found {
			presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": status, "key": key, "id": id, "node_online": true})
			return
		}
		log.Printf("⚠️ presenter jobs: insert: %v", err)
		presenterVideoError(w, http.StatusInternalServerError, "queue unavailable")
		return
	}
	id, _ := res.LastInsertId()
	go presenterVoiceJob(id, claims.DeviceID, ip, text, req.Gender, req.Lang)
	presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "status": "voicing", "key": key, "id": id, "node_online": true})
}

// presenterActiveJob: the active job of a video, if any.
func presenterActiveJob(version, key string) (id int64, status string, found bool, err error) {
	err = db.QueryRow(`SELECT id, status FROM presenter_jobs WHERE version = ? AND key = ? AND status IN ('voicing','queued','rendering') ORDER BY id LIMIT 1`,
		version, key).Scan(&id, &status)
	if err == sql.ErrNoRows {
		return 0, "", false, nil
	}
	return id, status, err == nil, err
}

// presenterVoiceJob gets the voice of a new job and hands it to the queue.
func presenterVoiceJob(id int64, deviceID, ip, text, gender, lang string) {
	_, _, _, status, msg := ttsEnsure(deviceID, ip, text, gender, lang)
	if status != http.StatusOK {
		reason := "voice_failed"
		if status == http.StatusTooManyRequests {
			reason = "voice_limit"
		}
		log.Printf("🎬 presenter job %d: no voice (%d %s)", id, status, msg)
		presenterFinish(id, "failed", reason)
		return
	}
	// A job cancelled meanwhile stays cancelled.
	if _, err := db.Exec(`UPDATE presenter_jobs SET status = 'queued' WHERE id = ? AND status = 'voicing'`, id); err != nil {
		log.Printf("⚠️ presenter job %d → queued: %v", id, err)
	}
}

// presenterJobStatusHandler: GET /api/presenter/jobs/{id}
func presenterJobStatusHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value("claims").(*JWTClaims); !ok {
		presenterVideoError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		presenterVideoError(w, http.StatusBadRequest, "bad id")
		return
	}
	var status, key, errMsg string
	if err := db.QueryRow(`SELECT status, key, error FROM presenter_jobs WHERE id = ?`, id).Scan(&status, &key, &errMsg); err != nil {
		presenterVideoError(w, http.StatusNotFound, "no such job")
		return
	}
	presenterJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "id": id, "status": status, "key": key, "error": errMsg, "node_online": presenterNodeOnline(),
	})
}

// presenterJobCancelHandler: POST /api/presenter/jobs/{id}/cancel
func presenterJobCancelHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		presenterVideoError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		presenterVideoError(w, http.StatusBadRequest, "bad id")
		return
	}
	res, err := db.Exec(`UPDATE presenter_jobs SET status = 'cancelled', text = '', done_at = ? WHERE id = ? AND device_id = ? AND status IN ('voicing','queued')`,
		presenterNow(), id, claims.DeviceID)
	if err != nil {
		presenterVideoError(w, http.StatusInternalServerError, "queue unavailable")
		return
	}
	n, _ := res.RowsAffected()
	presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "cancelled": n > 0})
}

// presenterNodeAuth lets only the render node in.
func presenterNodeAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := os.Getenv("PRESENTER_NODE_TOKEN")
		if want == "" {
			presenterVideoError(w, http.StatusServiceUnavailable, "render node is not configured")
			return
		}
		got := r.Header.Get("X-Presenter-Node-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			presenterVideoError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		next(w, r)
	}
}

// presenterSweep: stale claims go back once, forgotten jobs fail, old rows go.
func presenterSweep() {
	now := presenterNow()
	for _, step := range []struct {
		what string
		sql  string
		args []interface{}
	}{
		{"requeue stale", `UPDATE presenter_jobs SET status = 'queued', claimed_at = NULL WHERE status = 'rendering' AND claimed_at < ? AND attempts < ?`,
			[]interface{}{now - presenterRenderStaleSec, presenterMaxAttempts}},
		{"fail stale", `UPDATE presenter_jobs SET status = 'failed', error = 'render_timeout', text = '', done_at = ? WHERE status = 'rendering' AND claimed_at < ?`,
			[]interface{}{now, now - presenterRenderStaleSec}},
		{"expire", `UPDATE presenter_jobs SET status = 'failed', error = 'expired', text = '', done_at = ? WHERE status IN ('voicing','queued') AND created_at < ?`,
			[]interface{}{now, now - presenterQueuedExpireSec}},
		{"delete old", `DELETE FROM presenter_jobs WHERE status IN ('ready','failed','cancelled') AND created_at < ?`,
			[]interface{}{now - presenterJobKeepSec}},
	} {
		if _, err := db.Exec(step.sql, step.args...); err != nil {
			log.Printf("⚠️ presenter sweep (%s): %v", step.what, err)
		}
	}
}

// presenterNodeClaimHandler: POST /api/presenter/node/claim
func presenterNodeClaimHandler(w http.ResponseWriter, r *http.Request) {
	presenterNodeSeenAt.Store(presenterNow())
	presenterSweep()
	for tries := 0; tries < 3; tries++ {
		var id int64
		var key, version, text, gender, lang, presenter string
		err := db.QueryRow(`SELECT id, key, version, text, gender, lang, presenter FROM presenter_jobs WHERE status = 'queued' ORDER BY id LIMIT 1`).
			Scan(&id, &key, &version, &text, &gender, &lang, &presenter)
		if err != nil {
			break
		}
		res, err := db.Exec(`UPDATE presenter_jobs SET status = 'rendering', claimed_at = ?, attempts = attempts + 1 WHERE id = ? AND status = 'queued'`,
			presenterNow(), id)
		if err != nil {
			break
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // cancelled between the two statements
		}
		presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "job": map[string]interface{}{
			"id": id, "key": key, "version": version, "text": text, "gender": gender, "lang": lang, "presenter": presenter,
		}})
		return
	}
	presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "job": nil})
}

// presenterNodeAudioHandler: GET /api/presenter/node/audio?key=
func presenterNodeAudioHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if !presenterKeyRe.MatchString(key) {
		presenterVideoError(w, http.StatusBadRequest, "key must be 40 hex characters")
		return
	}
	data, err := os.ReadFile(filepath.Join(ttsCacheDir(), key+".mp3"))
	if err != nil || len(data) <= 200 {
		presenterVideoError(w, http.StatusNotFound, "no voice for this key")
		return
	}
	w.Header().Set("Content-Type", "audio/mpeg")
	w.Write(data)
}

// presenterReadVideo reads an uploaded mp4 (bounded) and checks it is one.
func presenterReadVideo(r *http.Request) ([]byte, string) {
	data, err := io.ReadAll(io.LimitReader(r.Body, presenterVideoMaxBytes+1))
	if err != nil {
		return nil, "upload failed"
	}
	if len(data) > presenterVideoMaxBytes {
		return nil, "video is too large"
	}
	if len(data) < presenterVideoMinBytes || !bytes.Equal(data[4:8], []byte("ftyp")) {
		return nil, "not an mp4"
	}
	return data, ""
}

// presenterStoreVideo writes a video under its final name atomically.
func presenterStoreVideo(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+"-*.part")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		if werr != nil {
			return werr
		}
		return cerr
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// presenterNodeResultHandler: PUT /api/presenter/node/result?id=
func presenterNodeResultHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		presenterVideoError(w, http.StatusBadRequest, "bad id")
		return
	}
	var status, key, version string
	if err := db.QueryRow(`SELECT status, key, version FROM presenter_jobs WHERE id = ?`, id).Scan(&status, &key, &version); err != nil {
		presenterVideoError(w, http.StatusNotFound, "no such job")
		return
	}
	if status != "rendering" {
		presenterVideoError(w, http.StatusConflict, "job is not being rendered")
		return
	}
	path, ok := presenterVideoPath(version, key)
	if !ok {
		presenterVideoError(w, http.StatusInternalServerError, "bad job")
		return
	}
	data, problem := presenterReadVideo(r)
	if problem != "" {
		presenterVideoError(w, http.StatusBadRequest, problem)
		return
	}
	if err := presenterStoreVideo(path, data); err != nil {
		log.Printf("⚠️ presenter job %d: store: %v", id, err)
		presenterVideoError(w, http.StatusInternalServerError, "could not store the video")
		return
	}
	presenterFinish(id, "ready", "")
	log.Printf("🎬 presenter job %d ready: %s/%s (%d bytes)", id, version, key, len(data))
	presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// presenterNodeFailHandler: POST /api/presenter/node/fail {id, error}
func presenterNodeFailHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    int64  `json:"id"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil || req.ID <= 0 {
		presenterVideoError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	var status string
	var attempts int
	if err := db.QueryRow(`SELECT status, attempts FROM presenter_jobs WHERE id = ?`, req.ID).Scan(&status, &attempts); err != nil {
		presenterVideoError(w, http.StatusNotFound, "no such job")
		return
	}
	if status != "rendering" {
		presenterVideoError(w, http.StatusConflict, "job is not being rendered")
		return
	}
	if attempts < presenterMaxAttempts {
		db.Exec(`UPDATE presenter_jobs SET status = 'queued', claimed_at = NULL WHERE id = ?`, req.ID)
	} else {
		presenterFinish(req.ID, "failed", "render_failed")
	}
	log.Printf("🎬 presenter job %d failed on the node (attempt %d): %s", req.ID, attempts, truncateForLog(req.Error, 200))
	presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// presenterNodeVideoHandler: PUT /api/presenter/node/video?key=&v= — a catalog video.
func presenterNodeVideoHandler(w http.ResponseWriter, r *http.Request) {
	path, ok := presenterVideoPath(r.URL.Query().Get("v"), r.URL.Query().Get("key"))
	if !ok {
		presenterVideoError(w, http.StatusBadRequest, "key must be 40 hex characters and v like v17")
		return
	}
	data, problem := presenterReadVideo(r)
	if problem != "" {
		presenterVideoError(w, http.StatusBadRequest, problem)
		return
	}
	if err := presenterStoreVideo(path, data); err != nil {
		log.Printf("⚠️ presenter catalog video: store: %v", err)
		presenterVideoError(w, http.StatusInternalServerError, "could not store the video")
		return
	}
	presenterJSON(w, http.StatusOK, map[string]interface{}{"success": true, "bytes": len(data)})
}
