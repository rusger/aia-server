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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
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

var pultAnswerKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

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
	CREATE TABLE IF NOT EXISTS reply_log (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, data TEXT, at TEXT);
	CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, label TEXT, created_at TEXT, revoked INTEGER DEFAULT 0);
	CREATE TABLE IF NOT EXISTS page_answers (slug TEXT, key TEXT, data TEXT, version INTEGER, updated_at TEXT, PRIMARY KEY(slug, key));`)
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
	router.HandleFunc("/api/admin/pult/archive", adminGuardMiddleware(pultArchive)).Methods("GET")
	router.HandleFunc("/api/admin/pult/general", adminGuardMiddleware(pultGeneral)).Methods("POST")
	router.HandleFunc("/api/admin/pult/page/{slug}", adminGuardMiddleware(pultPage)).Methods("GET")
	router.HandleFunc("/api/admin/pult/page-answers/{slug}", adminGuardMiddleware(pultPageAnswers)).Methods("GET")
	router.HandleFunc("/api/admin/pult/page-answer", adminGuardMiddleware(pultPageAnswer)).Methods("POST")
}

// Auth is a pult-only token (header X-Pult-Token), NOT the main
// ADMIN_SECRET_KEY: that key opens every /api/admin/* and must not live in a
// browser's localStorage or in URLs. Tokens are minted on the box by
// tools/pult.sh new-token; pult.db keeps only sha256(token) hex. admin_email /
// admin_secret are deliberately not accepted here. A 403 is counted by
// adminGuardMiddleware, so guessing gets locked out.
const pultTokenHeader = "X-Pult-Token"

func pultTokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func pultGate(w http.ResponseWriter, r *http.Request) bool {
	deny := func() bool {
		radioJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "error": "Unauthorized"})
		return false
	}
	tok := strings.TrimSpace(r.Header.Get(pultTokenHeader))
	if tok == "" || len(tok) > 256 {
		return deny()
	}
	if pultDB == nil {
		// tokens live in pult.db: cannot verify → 503 (initPultDB already logged why)
		radioJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"success": false, "error": "pult db unavailable"})
		return false
	}
	// lookup by the hash (PRIMARY KEY): the secret itself is never compared byte-by-byte
	var revoked int
	err := pultDB.QueryRow(`SELECT COALESCE(revoked,0) FROM tokens WHERE hash = ?`, pultTokenHash(tok)).Scan(&revoked)
	if err == sql.ErrNoRows || (err == nil && revoked != 0) {
		return deny()
	}
	if err != nil {
		pultFail(w, "token check", err)
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

// pultActiveSQL: a block is on the pult unless its data says active=false (json false extracts as 0).
const pultActiveSQL = `COALESCE(json_extract(data, '$.active'), 1) != 0`

// pultArchiveDays: how far back the archive list goes (owner 23.11.2026: "вся история не нужна, это я спрошу").
const pultArchiveDays = 14

// GET /api/admin/pult/state — only what is open right now (owner 23.11.2026: «это не журнал и не лог, это пульт
// самого актуального»): active blocks newest first, the owner's replies to those blocks, and the number of blocks
// in the archive. Closed blocks, session pages and their html are not sent here: the archive comes from
// /archive on a click, a page from /page/{slug} on a click.
func pultState(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	items := []map[string]interface{}{}
	ids := map[string]bool{}
	rows, err := pultDB.Query(`SELECT id, data, version, COALESCE(updated_at,'') FROM items WHERE ` + pultActiveSQL +
		` ORDER BY updated_at DESC, id`)
	if err != nil {
		pultFail(w, "state items", err)
		return
	}
	for rows.Next() {
		var id, at string
		var data sql.NullString
		var version sql.NullInt64
		if err := rows.Scan(&id, &data, &version, &at); err != nil {
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
		m["updated_at"] = at
		items = append(items, m)
		ids[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		pultFail(w, "state items", err)
		return
	}

	replies := map[string]interface{}{}
	rows, err = pultDB.Query(`SELECT id, data FROM replies WHERE id IN (SELECT id FROM items WHERE ` + pultActiveSQL + `)`)
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
		if !ids[id] {
			continue
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

	var archived int
	if err := pultDB.QueryRow(`SELECT COUNT(*) FROM items WHERE NOT (`+pultActiveSQL+`) AND updated_at >= ?`,
		pultArchiveSince()).Scan(&archived); err != nil {
		pultFail(w, "state archive count", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "items": items, "replies": replies, "archived": archived})
}

func pultArchiveSince() string {
	return time.Now().UTC().AddDate(0, 0, -pultArchiveDays).Format(time.RFC3339)
}

// pultCut: the first n runes of s, with … when cut.
func pultCut(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n]) + "…"
}

// GET /api/admin/pult/archive — closed blocks of the last pultArchiveDays days, newest first, one line each:
// task, title, when closed, and the owner's answer ("ok" and the start of his text). No bodies, no pages.
func pultArchive(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	rows, err := pultDB.Query(`SELECT i.id, COALESCE(json_extract(i.data,'$.task'),''), COALESCE(json_extract(i.data,'$.title'),''),
		COALESCE(json_extract(i.data,'$.closed_at'), i.updated_at, ''),
		COALESCE(json_extract(rp.data,'$.ok'),0), COALESCE(json_extract(rp.data,'$.text'),'')
		FROM items i LEFT JOIN replies rp ON rp.id = i.id
		WHERE NOT (`+strings.ReplaceAll(pultActiveSQL, "data", "i.data")+`) AND i.updated_at >= ?
		ORDER BY i.updated_at DESC, i.id`, pultArchiveSince())
	if err != nil {
		pultFail(w, "archive", err)
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id, task, title, at, text string
		var ok int
		if err := rows.Scan(&id, &task, &title, &at, &ok, &text); err != nil {
			pultFail(w, "archive", err)
			return
		}
		out = append(out, map[string]interface{}{"id": id, "task": task, "title": pultCut(title, 160),
			"closed_at": at, "ok": ok != 0, "text": pultCut(text, 140)})
	}
	if err := rows.Err(); err != nil {
		pultFail(w, "archive", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "days": pultArchiveDays, "items": out})
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
	// The owner answered → the block leaves the pult (owner 23.11.2026: «ответ получен, ждёт сессию» blocks made the
	// page unreadable). Only when he answered the version he saw: a block the session updated after he opened the
	// page (rev grew) stays. A session that needs more puts a new block or sets active=true again.
	res, err := tx.Exec(`UPDATE items SET data = json_set(COALESCE(data,'{}'), '$.active', json('false'), '$.closed_at', ?),
		version = COALESCE(version,0) + 1, updated_at = ?
		WHERE id = ? AND `+pultActiveSQL+` AND COALESCE(json_extract(data,'$.rev'),0) <= ?`, at, at, req.ID, req.Rev)
	if err != nil {
		pultRollback(tx)
		pultFail(w, "reply close", err)
		return
	}
	closed, err := res.RowsAffected()
	if err != nil {
		pultRollback(tx)
		pultFail(w, "reply close", err)
		return
	}
	if err := tx.Commit(); err != nil {
		pultFail(w, "reply commit", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "at": at, "closed": closed > 0})
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

// A128 — the owner's answers INSIDE a session page (checkmarks, comments per
// row). The page lives in a sandboxed iframe without the token; the shell
// relays its postMessage to the two endpoints below.

// GET /api/admin/pult/page-answers/{slug} → {slug, answers:{<key>:{...data, at, version}}}
// No "page must exist" check: an unknown slug simply has no answers.
func pultPageAnswers(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	slug := mux.Vars(r)["slug"]
	if !pultSlugRe.MatchString(slug) {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad slug"})
		return
	}
	answers := map[string]interface{}{}
	rows, err := pultDB.Query(`SELECT key, COALESCE(data,''), COALESCE(version,0), COALESCE(updated_at,'')
		FROM page_answers WHERE slug = ?`, slug)
	if err != nil {
		pultFail(w, "page answers", err)
		return
	}
	for rows.Next() {
		var key, data, at string
		var version int64
		if err := rows.Scan(&key, &data, &version, &at); err != nil {
			rows.Close()
			pultFail(w, "page answers", err)
			return
		}
		m := map[string]interface{}{}
		if err := json.Unmarshal([]byte(data), &m); err != nil || m == nil {
			log.Printf("⚠️ pult page answers: %s/%s has bad JSON: %v", slug, key, err)
			m = map[string]interface{}{}
		}
		m["at"] = at
		m["version"] = version
		answers[key] = m
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		pultFail(w, "page answers", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "slug": slug, "answers": answers})
}

// POST /api/admin/pult/page-answer {slug, key, data} — data is the JSON object
// the page sent (free-form fields), stored as is; version+1; journaled in
// reply_log as "page:<slug>:<key>".
func pultPageAnswer(w http.ResponseWriter, r *http.Request) {
	if !pultGate(w, r) {
		return
	}
	var req struct {
		Slug string          `json:"slug"`
		Key  string          `json:"key"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, pultMaxBody)).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			radioJSON(w, http.StatusRequestEntityTooLarge, map[string]interface{}{"success": false, "error": "too large"})
			return
		}
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad json"})
		return
	}
	if !pultSlugRe.MatchString(req.Slug) {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad slug"})
		return
	}
	if !pultAnswerKeyRe.MatchString(req.Key) {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad key"})
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(req.Data, &obj); err != nil || obj == nil {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "data must be a JSON object"})
		return
	}
	var data bytes.Buffer
	if err := json.Compact(&data, req.Data); err != nil {
		pultFail(w, "page answer compact", err)
		return
	}
	at := pultNow()
	tx, err := pultDB.Begin()
	if err != nil {
		pultFail(w, "page answer begin", err)
		return
	}
	var one int
	if err := tx.QueryRow(`SELECT 1 FROM pages WHERE slug = ?`, req.Slug).Scan(&one); err != nil {
		pultRollback(tx)
		if err == sql.ErrNoRows {
			radioJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "not found"})
			return
		}
		pultFail(w, "page answer page", err)
		return
	}
	var version int64
	if err := tx.QueryRow(`INSERT INTO page_answers(slug, key, data, version, updated_at) VALUES(?, ?, ?, 1, ?)
		ON CONFLICT(slug, key) DO UPDATE SET data = excluded.data, version = COALESCE(page_answers.version,0) + 1,
		updated_at = excluded.updated_at RETURNING version`, req.Slug, req.Key, data.String(), at).Scan(&version); err != nil {
		pultRollback(tx)
		pultFail(w, "page answer upsert", err)
		return
	}
	if _, err := tx.Exec(`INSERT INTO reply_log(id, data, at) VALUES(?, ?, ?)`,
		"page:"+req.Slug+":"+req.Key, data.String(), at); err != nil {
		pultRollback(tx)
		pultFail(w, "page answer log", err)
		return
	}
	if err := tx.Commit(); err != nil {
		pultFail(w, "page answer commit", err)
		return
	}
	radioJSON(w, http.StatusOK, map[string]interface{}{"success": true, "slug": req.Slug, "key": req.Key, "at": at, "version": version})
}
