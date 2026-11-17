package main

// A124 — the owner's "pult" (control panel) on our own server, so it does not
// depend on a claude.ai account. Sessions/coordinator write blocks (items) and
// session report pages into pult.db over ssh with tools/pult.sh; the owner reads
// them and answers through the shell page /api/admin/pult (pult_shell.html).
//
// Storage is its own SQLite file next to analytics.db (same open string: WAL +
// busy_timeout). If it cannot be opened the server still starts and the pult
// endpoints answer 503. No background loops here.

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

//go:embed pult_shell.html
var pultShellHTML []byte

var pultDB *sql.DB

var pultSlugRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)

const pultMaxBody = 64 << 10

// pultDBPath: same directory as analytics.db (the server's working dir);
// tools/pult.sh honours the same PULT_DB override.
func pultDBPath() string {
	return getEnv("PULT_DB", "./pult.db")
}

func openPultDB(path string) (*sql.DB, error) {
	d, err := sql.Open("sqlite",
		"file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("open %s: %v", path, err)
	}
	_, err = d.Exec(`
	CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, data TEXT, version INTEGER, updated_at TEXT);
	CREATE TABLE IF NOT EXISTS replies (id TEXT PRIMARY KEY, data TEXT, version INTEGER, updated_at TEXT);
	CREATE TABLE IF NOT EXISTS general (id TEXT PRIMARY KEY, data TEXT, version INTEGER, updated_at TEXT);
	CREATE TABLE IF NOT EXISTS pages (slug TEXT PRIMARY KEY, title TEXT, session TEXT, html TEXT, updated_at TEXT);
	CREATE TABLE IF NOT EXISTS reply_log (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, data TEXT, at TEXT);`)
	if err != nil {
		if cerr := d.Close(); cerr != nil {
			log.Printf("⚠️ pult db close: %v", cerr)
		}
		return nil, fmt.Errorf("schema %s: %v", path, err)
	}
	return d, nil
}

// initPultDB never fails the server: on error pultDB stays nil → 503.
func initPultDB() {
	d, err := openPultDB(pultDBPath())
	if err != nil {
		log.Printf("⚠️ pult db unavailable, /api/admin/pult/* will answer 503: %v", err)
		return
	}
	pultDB = d
}

func registerPultRoutes(router *mux.Router) {
	router.HandleFunc("/api/admin/pult", pultShell).Methods("GET")
	router.HandleFunc("/api/admin/pult/", pultShell).Methods("GET")
	router.HandleFunc("/api/admin/pult/state", adminGuardMiddleware(pultState)).Methods("GET")
	router.HandleFunc("/api/admin/pult/reply", adminGuardMiddleware(pultReply)).Methods("POST")
	router.HandleFunc("/api/admin/pult/general", adminGuardMiddleware(pultGeneral)).Methods("POST")
	router.HandleFunc("/api/admin/pult/page/{slug}", adminGuardMiddleware(pultPage)).Methods("GET")
}

// Same check as adminRadioMailbag / adminGetSpeechUsage: admin email + secret in
// the query string; an empty ADMIN_SECRET_KEY refuses everyone. Then 503 when
// the store is down (only after auth, so the state of the box is not leaked).
func pultGate(w http.ResponseWriter, r *http.Request) bool {
	if !isAdminEmail(r.URL.Query().Get("admin_email")) || ADMIN_SECRET_KEY == "" ||
		r.URL.Query().Get("admin_secret") != ADMIN_SECRET_KEY {
		radioJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "error": "Unauthorized"})
		return false
	}
	if pultDB == nil {
		radioJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"success": false, "error": "pult db unavailable"})
		return false
	}
	return true
}

func pultFail(w http.ResponseWriter, where string, err error) {
	log.Printf("⚠️ pult %s: %v", where, err)
	radioJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": "db"})
}

func pultNow() string { return time.Now().UTC().Format(time.RFC3339) }

// GET /api/admin/pult[/] — the HTML shell, no auth and no data inside.
func pultShell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	if _, err := w.Write(pultShellHTML); err != nil {
		log.Printf("⚠️ pult shell write: %v", err)
	}
}

// GET /api/admin/pult/state
func pultState(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	items := []map[string]interface{}{}
	rows, err := pultDB.Query(`SELECT id, data, version FROM items ORDER BY id`)
	if err != nil {
		pultFail(w, "state items", err)
		return
	}
	for rows.Next() {
		var id string
		var data sql.NullString
		var version sql.NullInt64
		if err := rows.Scan(&id, &data, &version); err != nil {
			rows.Close()
			pultFail(w, "state items", err)
			return
		}
		m := map[string]interface{}{}
		if data.String != "" {
			if err := json.Unmarshal([]byte(data.String), &m); err != nil {
				log.Printf("⚠️ pult state: item %q has bad JSON: %v", id, err)
				m = map[string]interface{}{"title": id, "body": "Блок записан с ошибкой (не JSON)."}
			}
		}
		m["id"] = id
		m["version"] = version.Int64
		items = append(items, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		pultFail(w, "state items", err)
		return
	}

	replies := map[string]interface{}{}
	rows, err = pultDB.Query(`SELECT id, data FROM replies`)
	if err != nil {
		pultFail(w, "state replies", err)
		return
	}
	for rows.Next() {
		var id string
		var data sql.NullString
		if err := rows.Scan(&id, &data); err != nil {
			rows.Close()
			pultFail(w, "state replies", err)
			return
		}
		m := map[string]interface{}{}
		if err := json.Unmarshal([]byte(data.String), &m); err != nil {
			log.Printf("⚠️ pult state: reply %q has bad JSON: %v", id, err)
			continue
		}
		replies[id] = m
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		pultFail(w, "state replies", err)
		return
	}

	pages := []map[string]interface{}{}
	rows, err = pultDB.Query(`SELECT slug, COALESCE(title,''), COALESCE(session,''), COALESCE(updated_at,'')
		FROM pages ORDER BY updated_at DESC, slug`)
	if err != nil {
		pultFail(w, "state pages", err)
		return
	}
	for rows.Next() {
		var slug, title, session, at string
		if err := rows.Scan(&slug, &title, &session, &at); err != nil {
			rows.Close()
			pultFail(w, "state pages", err)
			return
		}
		pages = append(pages, map[string]interface{}{"slug": slug, "title": title, "session": session, "updated_at": at})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		pultFail(w, "state pages", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "items": items, "replies": replies, "pages": pages})
}

// POST /api/admin/pult/reply {id, ok, text, rev, title, task}
func pultReply(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	var req struct {
		ID    string  `json:"id"`
		OK    bool    `json:"ok"`
		Text  string  `json:"text"`
		Rev   float64 `json:"rev"`
		Title string  `json:"title"`
		Task  string  `json:"task"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, pultMaxBody)).Decode(&req); err != nil {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad json"})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" || len(req.ID) > 200 {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad id"})
		return
	}
	// No "item must exist" check on purpose: a block can be removed while the
	// owner is typing — his words must still land (replies + reply_log).
	at := pultNow()
	data, err := json.Marshal(map[string]interface{}{"text": strings.TrimSpace(req.Text), "ok": req.OK, "at": at,
		"rev": req.Rev, "title": req.Title, "task": req.Task})
	if err != nil {
		pultFail(w, "reply marshal", err)
		return
	}
	tx, err := pultDB.Begin()
	if err != nil {
		pultFail(w, "reply begin", err)
		return
	}
	if _, err := tx.Exec(`INSERT INTO replies(id, data, version, updated_at) VALUES(?, ?, 1, ?)
		ON CONFLICT(id) DO UPDATE SET data = excluded.data, version = replies.version + 1, updated_at = excluded.updated_at`,
		req.ID, string(data), at); err != nil {
		pultRollback(tx)
		pultFail(w, "reply upsert", err)
		return
	}
	if _, err := tx.Exec(`INSERT INTO reply_log(id, data, at) VALUES(?, ?, ?)`, req.ID, string(data), at); err != nil {
		pultRollback(tx)
		pultFail(w, "reply log", err)
		return
	}
	if err := tx.Commit(); err != nil {
		pultFail(w, "reply commit", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "at": at})
}

func pultRollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil {
		log.Printf("⚠️ pult rollback: %v", err)
	}
}

// POST /api/admin/pult/general {text, page?, title?}
func pultGeneral(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	var req struct {
		Text  string `json:"text"`
		Page  string `json:"page"`
		Title string `json:"title"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, pultMaxBody)).Decode(&req); err != nil {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad json"})
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "empty text"})
		return
	}
	at := pultNow()
	m := map[string]interface{}{"text": req.Text, "at": at, "handled": false}
	if req.Page != "" {
		m["page"] = req.Page
	}
	if req.Title != "" {
		m["title"] = req.Title
	}
	data, err := json.Marshal(m)
	if err != nil {
		pultFail(w, "general marshal", err)
		return
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		pultFail(w, "general id", err)
		return
	}
	id := "g-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(rnd[:])
	if _, err := pultDB.Exec(`INSERT INTO general(id, data, version, updated_at) VALUES(?, ?, 1, ?)`, id, string(data), at); err != nil {
		pultFail(w, "general insert", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "id": id, "at": at})
}

// GET /api/admin/pult/page/{slug}
func pultPage(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	slug := mux.Vars(r)["slug"]
	if !pultSlugRe.MatchString(slug) {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad slug"})
		return
	}
	var title, session, html, at sql.NullString
	err := pultDB.QueryRow(`SELECT title, session, html, updated_at FROM pages WHERE slug = ?`, slug).
		Scan(&title, &session, &html, &at)
	if err == sql.ErrNoRows {
		radioJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "not found"})
		return
	}
	if err != nil {
		pultFail(w, "page", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "slug": slug, "title": title.String,
		"session": session.String, "html": html.String, "updated_at": at.String})
}
