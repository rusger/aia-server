package main

// radio_mailbag.go — «a voice message from a listener» archive (insta-agent/docs/radio/CALL-IN.md, stage 4) and the
// owner's radio switches for Stellar Vault.
//
// Friends of the show record questions; the Mac (insta-agent scripts/radio_mailbag.py) turns each into a ready
// episode and uploads it atomically to <RADIO_ROOT>/mailbag/<id>/ (files land in mailbag/.incoming-<id>/, the
// manifest is written last, then the directory is renamed — dot-dirs are ignored here). A goroutine airs an episode
// through the same line as live calls, but only when somebody is listening (distinct IPs fetching HLS segments in the
// nginx log over the last minute), the line is free and the last episode was long enough ago.
// Rotation (owner 27.10.2026): the episodes are a bank drawn at random WITHOUT replacement — every round airs each
// episode once (plays = how many times it aired; the pick is a random one among the fewest plays), then a new round
// starts. A new episode joins the CURRENT round (it starts at the current minimum of plays, so it is shuffled in with
// the ones not yet aired this round rather than jumping the queue). The episode that aired last never opens the next
// round when another one is available. Honest format: «a voice message in our mailbox», never «on the line now».
//
// Env: RADIO_MAILBAG=1 (scheduler on; default off), RADIO_MAILBAG_MIN_LISTENERS (1), RADIO_MAILBAG_GAP_MIN (30),
// RADIO_ACCESS_LOG (/var/log/nginx/access.log). Switches (DB, Stellar Vault): calls_off, mailbag_off.

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

const (
	radioMailbagEvery      = 20 * time.Second
	radioMailbagLogTail    = 4 << 20 // bytes of the access log read per listener count
	radioMailbagListenWin  = 60 * time.Second
	radioMailbagSegPause   = 1.0 // seconds the feeder leaves before each part (CALL_PAUSE_S ≈ 0.3–2 s)
	radioMailbagIDPrefix   = "mb-"
	radioMailbagManifestMB = 1 << 20
)

// radioMailbagLiveFor: how long now.json says «live» (so the site/app players, which only join a live call, pick it
// up — they poll every 3 s) before it turns «done» (the feeders and players play the rest out, no hold phrases).
// radioMailbagSlack: extra time the line stays busy after the planned end — the stations first finish their
// current line, and a new call document would cut the rest of the episode on the feeders.
var radioMailbagLiveFor, radioMailbagSlack atomic.Int64

func init() {
	radioMailbagLiveFor.Store(int64(15 * time.Second))
	radioMailbagSlack.Store(int64(90 * time.Second))
}

var radioMailbagNow = time.Now

// radioMailbagShuffle orders the candidates of one plays level (tests make it deterministic).
var radioMailbagShuffle = radioMailbagShuffleRandom

func radioMailbagShuffleRandom(ids []string) {
	rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
}

var radioMailbagIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// ---------------------------------------------------------------------------
// Schema and switches

var radioMailbagSchemaReady atomic.Bool

func ensureRadioMailbagSchema() {
	if radioMailbagSchemaReady.Load() {
		return
	}
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS radio_mailbag (
			id TEXT PRIMARY KEY, name TEXT, lang TEXT, bank_n INTEGER,
			question_text TEXT, answer_text TEXT,
			created_at TEXT, aired_at TEXT, deleted_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS radio_switches (
			name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
	} {
		if _, err := db.Exec(s); err != nil {
			log.Printf("⚠️ radio mailbag schema: %v — will retry", err)
			return
		}
	}
	// plays (rotation, 27.10.2026): added to tables created before it; rows aired under the old «airs once» rule
	// count as played once. A failed ALTER (other than «already there») leaves the schema not ready → retried.
	if _, err := db.Exec(`ALTER TABLE radio_mailbag ADD COLUMN plays INTEGER NOT NULL DEFAULT 0`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("⚠️ radio mailbag schema (plays): %v — will retry", err)
			return
		}
	} else if _, err := db.Exec(`UPDATE radio_mailbag SET plays = 1 WHERE aired_at IS NOT NULL AND plays = 0`); err != nil {
		log.Printf("⚠️ radio mailbag schema (plays backfill): %v", err)
	}
	radioMailbagSchemaReady.Store(true)
}

var radioSwitchNames = []string{"calls_off", "mailbag_off"}

// radioSwitchOn reads a Stellar Vault switch. A DB error counts as «on» for calls_off/mailbag_off (both are «off»
// switches: when we cannot tell, nothing new goes on air).
func radioSwitchOn(name string) bool {
	ensureRadioMailbagSchema()
	var v int
	err := db.QueryRow(`SELECT value FROM radio_switches WHERE name = ?`, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		log.Printf("⚠️ radio switch %s: %v — treated as on", name, err)
		return true
	}
	return v != 0
}

func radioSetSwitch(name string, on bool) error {
	ensureRadioMailbagSchema()
	_, err := db.Exec(`INSERT INTO radio_switches (name, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, name, boolToInt(on))
	return err
}

// ---------------------------------------------------------------------------
// Episodes on disk

type radioMailbagManifest struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Lang         string         `json:"lang"`
	BankN        *int           `json:"bank_n"`
	Created      string         `json:"created"`
	QuestionText string         `json:"question_text"`
	QuestionEN   string         `json:"question_en"`
	AnswerText   string         `json:"answer_text"`
	AnswerEN     string         `json:"answer_en"`
	Segments     []radioSegment `json:"segments"`
}

func radioMailbagDir() string { return filepath.Join(radioRoot(), "mailbag") }

// radioMailbagLoad reads and validates mailbag/<id>/manifest.json: every segment file is inside the episode's
// directory and on disk, per-station segments carry a duration for all stations.
func radioMailbagLoad(id string) (*radioMailbagManifest, error) {
	if !radioMailbagIDRe.MatchString(id) {
		return nil, errors.New("bad id")
	}
	f, err := os.Open(filepath.Join(radioMailbagDir(), id, "manifest.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, radioMailbagManifestMB))
	if err != nil {
		return nil, err
	}
	var m radioMailbagManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %v", err)
	}
	if m.ID != id {
		return nil, fmt.Errorf("manifest id %q ≠ dir %q", m.ID, id)
	}
	if len(m.Segments) == 0 {
		return nil, errors.New("no segments")
	}
	prefix := "mailbag/" + id + "/"
	for i, s := range m.Segments {
		if s.Kind == "" || !strings.HasPrefix(s.Src, prefix) || strings.Contains(s.Src, "..") {
			return nil, fmt.Errorf("segment %d: bad src/kind %q %q", i, s.Src, s.Kind)
		}
		if strings.Contains(s.Src, "{ch}") {
			for _, ch := range radioCallStations {
				if s.Durs[ch] <= 0 {
					return nil, fmt.Errorf("segment %d: no duration for %s", i, ch)
				}
				if _, err := os.Stat(filepath.Join(radioRoot(), strings.ReplaceAll(s.Src, "{ch}", ch))); err != nil {
					return nil, fmt.Errorf("segment %d: %v", i, err)
				}
			}
		} else {
			if s.Dur <= 0 {
				return nil, fmt.Errorf("segment %d: no duration", i)
			}
			if _, err := os.Stat(filepath.Join(radioRoot(), s.Src)); err != nil {
				return nil, fmt.Errorf("segment %d: %v", i, err)
			}
		}
	}
	m.Name = strings.TrimSpace(m.Name)
	if f := strings.Fields(m.Name); len(f) > 1 {
		m.Name = f[0] // first name only
	}
	return &m, nil
}

// radioMailbagBad: last logged reason per invalid episode dir (the scan runs every 20 s — log changes only).
var radioMailbagBad sync.Map

// radioMailbagScan registers valid episodes on disk in radio_mailbag (deleted ones stay deleted).
func radioMailbagScan() {
	ensureRadioMailbagSchema()
	entries, err := os.ReadDir(radioMailbagDir())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️ radio mailbag scan: %v", err)
		}
		return
	}
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || strings.HasPrefix(id, ".") {
			continue // .incoming-<id>: upload in progress
		}
		m, err := radioMailbagLoad(id)
		if err != nil {
			if prev, ok := radioMailbagBad.Load(id); !ok || prev.(string) != err.Error() {
				log.Printf("⚠️ radio mailbag %s skipped: %v", id, err)
				radioMailbagBad.Store(id, err.Error())
			}
			continue
		}
		radioMailbagBad.Delete(id)
		created := radioMailbagNow().UTC()
		if t, err := time.Parse(time.RFC3339, m.Created); err == nil {
			created = t.UTC()
		}
		var bank interface{}
		if m.BankN != nil {
			bank = *m.BankN
		}
		answer := m.AnswerText
		if m.AnswerEN != "" && m.AnswerEN != m.AnswerText {
			answer += "\n---\n" + m.AnswerEN
		}
		// a new row starts at the current round's minimum of plays (joins the round in progress)
		if _, err := db.Exec(`INSERT INTO radio_mailbag (id, name, lang, bank_n, question_text, answer_text, created_at, plays)
			VALUES (?, ?, ?, ?, ?, ?, ?,
				(SELECT COALESCE(MIN(plays), 0) FROM radio_mailbag WHERE deleted_at IS NULL))
			ON CONFLICT(id) DO UPDATE SET name = excluded.name, lang = excluded.lang, bank_n = excluded.bank_n,
				question_text = excluded.question_text, answer_text = excluded.answer_text
			WHERE radio_mailbag.deleted_at IS NULL`,
			id, m.Name, m.Lang, bank, m.QuestionText, answer, created.Format("2006-01-02 15:04:05")); err != nil {
			log.Printf("⚠️ radio mailbag %s register: %v", id, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Listeners: distinct client IPs that fetched an HLS segment under /radio/ in the last minute (nginx access log,
// combined/timing format: `IP - user [02/Jan/2006:15:04:05 -0700] "GET /radio/moon/live/aac_1.ts HTTP/2.0" 200 …`).

var radioHLSLineRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "GET (/radio/[^ "?]+\.(?:ts|aac|m4s))(?:\?[^ "]*)? HTTP/[^"]*" (\d{3}) `)

var radioListenersFn = radioListenersFromLog

func radioListenersFromLog(now time.Time) (int, error) {
	f, err := os.Open(envDefault("RADIO_ACCESS_LOG", "/var/log/nginx/access.log"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	off := st.Size() - radioMailbagLogTail
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	buf, err := io.ReadAll(io.LimitReader(f, radioMailbagLogTail))
	if err != nil {
		return 0, err
	}
	if off > 0 { // the first line is cut
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return radioCountListeners(buf, now), nil
}

func radioCountListeners(logTail []byte, now time.Time) int {
	ips := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(logTail))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := radioHLSLineRe.FindSubmatch(sc.Bytes())
		if m == nil {
			continue
		}
		if code := string(m[4]); code != "200" && code != "206" && code != "304" {
			continue
		}
		t, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(m[2]))
		if err != nil {
			continue
		}
		if age := now.Sub(t); age >= 0 && age <= radioMailbagListenWin {
			ips[string(m[1])] = true
		}
	}
	return len(ips)
}

// ---------------------------------------------------------------------------
// Scheduler

func envIntDefault(key string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil && v >= 0 {
		return v
	}
	return def
}

// radioMailbagTick airs one episode when every condition holds; returns the aired episode id or "".
func radioMailbagTick() string {
	if os.Getenv("RADIO_MAILBAG") != "1" {
		return ""
	}
	ensureRadioMailbagSchema()
	if radioSwitchOn("mailbag_off") {
		return ""
	}
	radioMailbagScan()
	radioLine.Lock()
	radioReapIdle()
	busy := radioLine.call != nil
	radioLine.Unlock()
	if busy {
		return ""
	}
	now := radioMailbagNow()
	var last sql.NullString
	if err := db.QueryRow(`SELECT MAX(aired_at) FROM radio_mailbag`).Scan(&last); err != nil {
		log.Printf("⚠️ radio mailbag last aired: %v", err)
		return ""
	}
	if last.Valid {
		t, err := time.Parse("2006-01-02 15:04:05", last.String)
		if err != nil {
			log.Printf("⚠️ radio mailbag last aired %q: %v", last.String, err)
			return ""
		}
		if now.Sub(t) < time.Duration(envIntDefault("RADIO_MAILBAG_GAP_MIN", 30))*time.Minute {
			return ""
		}
	}
	n, err := radioListenersFn(now)
	if err != nil {
		log.Printf("⚠️ radio mailbag listeners: %v — not airing", err)
		return ""
	}
	if n < envIntDefault("RADIO_MAILBAG_MIN_LISTENERS", 1) {
		return ""
	}
	ids, plays, err := radioMailbagCandidates()
	if err != nil {
		log.Printf("⚠️ radio mailbag pick: %v", err)
		return ""
	}
	for _, id := range ids {
		m, err := radioMailbagLoad(id)
		if err != nil {
			log.Printf("⚠️ radio mailbag %s not airable: %v", id, err)
			continue
		}
		if radioMailbagAir(m, plays[id], now, n) {
			return id
		}
		return ""
	}
	return ""
}

// radioMailbagCandidates: every episode that is not deleted, fewest plays first, random order inside one plays level
// (draw without replacement within a round). The episode that aired last moves to the end of its level, so a new
// round never opens with the episode that has just closed the previous one (unless it is the only one).
func radioMailbagCandidates() ([]string, map[string]int, error) {
	var last sql.NullString
	if err := db.QueryRow(`SELECT id FROM radio_mailbag WHERE aired_at IS NOT NULL AND deleted_at IS NULL
		ORDER BY aired_at DESC, id LIMIT 1`).Scan(&last); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}
	rows, err := db.Query(`SELECT id, plays FROM radio_mailbag WHERE deleted_at IS NULL ORDER BY plays, id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	plays := map[string]int{}
	var levels [][]string
	prev := -1
	for rows.Next() {
		var id string
		var p int
		if err := rows.Scan(&id, &p); err != nil {
			return nil, nil, err
		}
		if p != prev || len(levels) == 0 {
			levels = append(levels, nil)
			prev = p
		}
		levels[len(levels)-1] = append(levels[len(levels)-1], id)
		plays[id] = p
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	var out []string
	for _, lv := range levels {
		radioMailbagShuffle(lv)
		if last.Valid && len(lv) > 1 {
			for i, id := range lv {
				if id == last.String {
					lv = append(append(lv[:i:i], lv[i+1:]...), id)
					break
				}
			}
		}
		out = append(out, lv...)
	}
	return out, plays, nil
}

// radioMailbagAir takes the free line and publishes the episode; the row is marked aired first (plays+1, guarded by
// the plays value it was picked with, so two ticks can never count one airing twice).
func radioMailbagAir(m *radioMailbagManifest, plays int, now time.Time, listeners int) bool {
	radioLine.Lock()
	defer radioLine.Unlock()
	radioReapIdle()
	if radioLine.call != nil {
		return false
	}
	res, err := db.Exec(`UPDATE radio_mailbag SET aired_at = ?, plays = plays + 1
		WHERE id = ? AND plays = ? AND deleted_at IS NULL`, now.UTC().Format("2006-01-02 15:04:05"), m.ID, plays)
	if err != nil {
		log.Printf("⚠️ radio mailbag %s mark aired: %v", m.ID, err)
		return false
	}
	if k, err := res.RowsAffected(); err != nil || k != 1 {
		return false
	}
	c := &radioCall{ID: radioMailbagIDPrefix + m.ID, Lang: m.Lang, Name: m.Name, State: "aired", HoldSet: "day",
		Live: true, Mailbag: true, Aired: true, Touched: radioCallNow()}
	total := 0.0
	for _, s := range m.Segments {
		s.N = len(c.Segments)
		c.Segments = append(c.Segments, s)
		total += radioMailbagSegPause + radioSegMaxDur(s)
	}
	if src, durs, ok := radioCue("cta"); ok {
		s := radioSegment{N: len(c.Segments), Src: src, Durs: durs, Kind: "cta"}
		c.Segments = append(c.Segments, s)
		total += radioMailbagSegPause + radioSegMaxDur(s)
	} else {
		log.Printf("⚠️ radio mailbag %s: no \"cta\" cues on disk", m.ID)
	}
	c.OnAir = true
	c.Until = radioCallNow().Add(time.Duration(total*float64(time.Second)) + time.Duration(radioMailbagSlack.Load()))
	radioLine.call = c
	radioWriteNow(c)
	log.Printf("📮 radio mailbag %s on air (%s, %s, %.0f s, play %d, %d listeners)", m.ID, m.Name, m.Lang, total, plays+1, listeners)
	go radioMailbagRelease(c)
	return true
}

func radioSegMaxDur(s radioSegment) float64 {
	d := s.Dur
	for _, v := range s.Durs {
		d = math.Max(d, v)
	}
	return d
}

// radioMailbagRelease: «live» for radioMailbagLiveFor (players join), then «done» (everyone plays it out), then the
// line is freed at c.Until.
func radioMailbagRelease(c *radioCall) {
	time.Sleep(time.Duration(radioMailbagLiveFor.Load()))
	radioLine.Lock()
	if radioLine.call != c {
		radioLine.Unlock()
		return
	}
	c.Live = false
	radioWriteNow(c)
	until := c.Until
	radioLine.Unlock()
	if d := until.Sub(radioCallNow()); d > 0 {
		time.Sleep(d)
	}
	radioLine.Lock()
	if radioLine.call == c {
		radioLine.call = nil
	}
	radioLine.Unlock()
}

// startRadioMailbag runs the scheduler (every 20 s; it does nothing unless RADIO_MAILBAG=1).
func startRadioMailbag() {
	go func() {
		for {
			radioMailbagTick()
			time.Sleep(radioMailbagEvery)
		}
	}()
}

// ---------------------------------------------------------------------------
// Stellar Vault (admin_email + admin_secret, like the other /api/admin/* reads; behind adminGuardMiddleware)

func radioAdminOK(w http.ResponseWriter, r *http.Request) bool {
	if !isAdminEmail(r.URL.Query().Get("admin_email")) || ADMIN_SECRET_KEY == "" ||
		r.URL.Query().Get("admin_secret") != ADMIN_SECRET_KEY {
		radioJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "error": "Unauthorized"})
		return false
	}
	return true
}

func radioNullStr(s sql.NullString) interface{} {
	if s.Valid {
		return s.String
	}
	return nil
}

// GET /api/admin/radio/calls?days=14
func adminRadioCalls(w http.ResponseWriter, r *http.Request) {
	if !radioAdminOK(w, r) {
		return
	}
	ensureRadioCallSchema()
	days := 14
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v > 0 && v <= 365 {
		days = v
	}
	since := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02 15:04:05")
	rows, err := db.Query(`SELECT id, created_at, name, lang, state, reason, aired, charged_usd_micro
		FROM radio_calls WHERE created_at >= ? ORDER BY created_at DESC LIMIT 1000`, since)
	if err != nil {
		log.Printf("⚠️ admin radio calls: %v", err)
		radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id, created, state string
		var name, lang, reason sql.NullString
		var aired int
		var charged int64
		if err := rows.Scan(&id, &created, &name, &lang, &state, &reason, &aired, &charged); err != nil {
			log.Printf("⚠️ admin radio calls: %v", err)
			radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
			return
		}
		out = append(out, map[string]interface{}{"id": id, "created": created, "name": radioNullStr(name),
			"lang": radioNullStr(lang), "state": state, "reason": radioNullStr(reason), "aired": aired == 1,
			"charged_usd": float64(charged) / 1e6})
	}
	if err := rows.Err(); err != nil {
		log.Printf("⚠️ admin radio calls: %v", err)
		radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
		return
	}
	radioJSON(w, 200, map[string]interface{}{"success": true, "days": days, "calls": out})
}

// GET /api/admin/radio/mailbag
func adminRadioMailbag(w http.ResponseWriter, r *http.Request) {
	if !radioAdminOK(w, r) {
		return
	}
	radioMailbagScan()
	rows, err := db.Query(`SELECT id, name, lang, bank_n, created_at, aired_at, deleted_at, question_text, answer_text, plays
		FROM radio_mailbag ORDER BY created_at DESC, id`)
	if err != nil {
		log.Printf("⚠️ admin radio mailbag: %v", err)
		radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id string
		var name, lang, created, aired, deleted, q, a sql.NullString
		var bank sql.NullInt64
		var plays int
		if err := rows.Scan(&id, &name, &lang, &bank, &created, &aired, &deleted, &q, &a, &plays); err != nil {
			log.Printf("⚠️ admin radio mailbag: %v", err)
			radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
			return
		}
		var bn interface{}
		if bank.Valid {
			bn = bank.Int64
		}
		out = append(out, map[string]interface{}{"id": id, "name": radioNullStr(name), "lang": radioNullStr(lang),
			"bank_n": bn, "created": radioNullStr(created), "aired_at": radioNullStr(aired),
			"deleted_at": radioNullStr(deleted), "question_text": radioNullStr(q), "answer_text": radioNullStr(a),
			"plays": plays})
	}
	if err := rows.Err(); err != nil {
		log.Printf("⚠️ admin radio mailbag: %v", err)
		radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
		return
	}
	radioJSON(w, 200, map[string]interface{}{"success": true, "episodes": out})
}

// POST /api/admin/radio/mailbag/{id}/delete — marks the episode deleted (it never airs) and removes its files.
func adminRadioMailbagDelete(w http.ResponseWriter, r *http.Request) {
	if !radioAdminOK(w, r) {
		return
	}
	ensureRadioMailbagSchema()
	id := mux.Vars(r)["id"]
	if !radioMailbagIDRe.MatchString(id) {
		radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad id"})
		return
	}
	radioLine.Lock()
	onAir := radioLine.call != nil && radioLine.call.ID == radioMailbagIDPrefix+id
	radioLine.Unlock()
	if onAir {
		radioJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "error": "on_air"})
		return
	}
	dir := filepath.Join(radioMailbagDir(), id)
	_, statErr := os.Stat(dir)
	var known int
	if err := db.QueryRow(`SELECT COUNT(*) FROM radio_mailbag WHERE id = ?`, id).Scan(&known); err != nil {
		log.Printf("⚠️ admin radio mailbag delete %s: %v", id, err)
		radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
		return
	}
	if known == 0 && os.IsNotExist(statErr) {
		radioJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "not_found"})
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	if _, err := db.Exec(`INSERT INTO radio_mailbag (id, created_at, deleted_at) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET deleted_at = COALESCE(radio_mailbag.deleted_at, excluded.deleted_at)`, id, now, now); err != nil {
		log.Printf("⚠️ admin radio mailbag delete %s: %v", id, err)
		radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		log.Printf("⚠️ admin radio mailbag delete %s files: %v", id, err)
		radioJSON(w, 500, map[string]interface{}{"success": false, "error": "files"})
		return
	}
	log.Printf("📮 radio mailbag %s deleted from Stellar Vault", id)
	radioJSON(w, 200, map[string]interface{}{"success": true})
}

// GET/POST /api/admin/radio/switches  {"calls_off": bool, "mailbag_off": bool} (POST: only the fields given change)
func adminRadioSwitches(w http.ResponseWriter, r *http.Request) {
	if !radioAdminOK(w, r) {
		return
	}
	ensureRadioMailbagSchema()
	if r.Method == http.MethodPost {
		var req map[string]*bool
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			radioJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "bad json"})
			return
		}
		for _, name := range radioSwitchNames {
			if v := req[name]; v != nil {
				if err := radioSetSwitch(name, *v); err != nil {
					log.Printf("⚠️ admin radio switch %s: %v", name, err)
					radioJSON(w, 500, map[string]interface{}{"success": false, "error": "db"})
					return
				}
				log.Printf("🎛 radio switch %s = %v (Stellar Vault)", name, *v)
			}
		}
	}
	out := map[string]interface{}{"success": true}
	for _, name := range radioSwitchNames {
		out[name] = radioSwitchOn(name)
	}
	radioJSON(w, 200, out)
}
