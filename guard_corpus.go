package main

// Guard corpus (owner decision 2026-08-30, hallucination triage): counters in
// ai_guard_events tell us HOW OFTEN a guard fires, never WHY a specific answer
// erred. To debug a hallucination — and to replay it on the simulator until
// the bug is beaten before a fix lands in the codebase — we need the concrete
// failing case: the exact fact basis the model saw + its raw answer + the
// shipped (grounded) answer.
//
// Privacy (owner decision 2026-08-30): DE-IDENTIFIED by construction. We store
// only what the model saw — the COMPUTED chart + lenses (positions, houses,
// divisional charts, dashas, transits, radar, varshaphal, muhurta, yogas) —
// never the raw birth date/time/place or name. The app's prompt already strips
// birth-date headers (_strippedNatalForPrompt), so the captured messages carry
// no birth data. No device_id is stored: the corpus cannot be joined back to a
// user. Because nothing identifying leaves the device, no new consent is
// required beyond the existing AI-data consent (owner decision 2026-08-30).
//
// Trigger (client side): a case is captured when the grounding/Barnum pipeline
// ALTERED the answer (flagged = the suspect set) plus a small random baseline
// sample (the control, so we can tell a real fix from a stricter validator).

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-field byte cap — a full chart+lenses fact basis is a few KB; this bounds
// a pathological or abusive row without truncating a legitimate one.
const maxCorpusFieldBytes = 120000

// Rows older than this are purged opportunistically (see maybePurgeCorpus).
const corpusRetentionDays = 90

var (
	corpusTableOnce sync.Once
	corpusTableErr  error

	corpusPurgeMu   sync.Mutex
	corpusLastPurge time.Time
)

// ensureCorpusTable creates ai_guard_corpus + indexes on first use. Lazy so
// this module stays self-contained (no edit to the analytics-DB init path).
func ensureCorpusTable() error {
	corpusTableOnce.Do(func() {
		if analyticsDB == nil {
			corpusTableErr = fmt.Errorf("analytics DB not initialized")
			return
		}
		_, corpusTableErr = analyticsDB.Exec(`
        CREATE TABLE IF NOT EXISTS ai_guard_corpus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feature TEXT NOT NULL,
            model TEXT DEFAULT '',
            language TEXT DEFAULT '',
            kinds TEXT DEFAULT '',
            sampled INTEGER DEFAULT 0,
            fact_basis TEXT DEFAULT '',
            raw_answer TEXT DEFAULT '',
            shipped_answer TEXT DEFAULT '',
            app_version TEXT DEFAULT '',
            ruleset_version TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_corpus_feature ON ai_guard_corpus(feature);
        CREATE INDEX IF NOT EXISTS idx_corpus_sampled ON ai_guard_corpus(sampled);
        CREATE INDEX IF NOT EXISTS idx_corpus_date ON ai_guard_corpus(created_at);
        `)
		if corpusTableErr != nil {
			log.Printf("❌ ai_guard_corpus table create failed: %v", corpusTableErr)
		}
	})
	return corpusTableErr
}

// maybePurgeCorpus deletes rows past the retention window, at most once every
// 6 hours per process. Cheap (indexed on created_at); keeps the corpus a
// rolling debugging window rather than an ever-growing store.
func maybePurgeCorpus() {
	corpusPurgeMu.Lock()
	due := time.Since(corpusLastPurge) > 6*time.Hour
	if due {
		corpusLastPurge = time.Now()
	}
	corpusPurgeMu.Unlock()
	if !due || analyticsDB == nil {
		return
	}
	res, err := analyticsDB.Exec(
		`DELETE FROM ai_guard_corpus WHERE created_at < datetime('now', ?)`,
		fmt.Sprintf("-%d days", corpusRetentionDays))
	if err != nil {
		log.Printf("⚠️ ai_guard_corpus purge failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("🧹 ai_guard_corpus: purged %d row(s) older than %d days", n, corpusRetentionDays)
	}
}

func clampCorpusField(s string) string {
	if len(s) <= maxCorpusFieldBytes {
		return s
	}
	cut := maxCorpusFieldBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 { // don't split a UTF-8 rune
		cut--
	}
	return s[:cut]
}

// GuardCorpusRequest is one captured case sent by the app. NO device id, NO
// birth data — the fact basis is the computed chart+lenses the model saw.
type GuardCorpusRequest struct {
	Feature        string `json:"feature"`
	Model          string `json:"model"`
	Language       string `json:"language"`
	Kinds          string `json:"kinds"` // comma-joined guard kinds; "" for a baseline sample
	Sampled        bool   `json:"sampled"`
	FactBasis      string `json:"fact_basis"`
	RawAnswer      string `json:"raw_answer"`
	ShippedAnswer  string `json:"shipped_answer"`
	AppVersion     string `json:"app_version"`
	RulesetVersion string `json:"ruleset_version"`
}

// guardCorpusReport ingests one captured case. JWT-protected (any signed-in
// device), but the identity is deliberately DROPPED before storage.
func guardCorpusReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if _, ok := r.Context().Value("claims").(*JWTClaims); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}

	var req GuardCorpusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request body"})
		return
	}
	if strings.TrimSpace(req.ShippedAnswer) == "" && strings.TrimSpace(req.RawAnswer) == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "empty case"})
		return
	}
	if req.Feature == "" {
		req.Feature = "other"
	}

	if err := ensureCorpusTable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "corpus unavailable"})
		return
	}

	sampledInt := 0
	if req.Sampled {
		sampledInt = 1
	}
	go func() {
		if _, err := analyticsDB.Exec(
			`INSERT INTO ai_guard_corpus
			 (feature, model, language, kinds, sampled, fact_basis, raw_answer, shipped_answer, app_version, ruleset_version)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			req.Feature, req.Model, req.Language, req.Kinds, sampledInt,
			clampCorpusField(req.FactBasis), clampCorpusField(req.RawAnswer),
			clampCorpusField(req.ShippedAnswer), req.AppVersion, req.RulesetVersion,
		); err != nil {
			log.Printf("⚠️ ai_guard_corpus insert failed: %v", err)
		}
		maybePurgeCorpus()
	}()

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// adminGetGuardCorpus exports captured cases for offline triage. Admin-gated.
// Query: ?days=N (default 30, 0=all), ?feature=F, ?flagged_only=1 (drop the
// baseline sample), ?limit=N (default 200, max 1000).
func adminGetGuardCorpus(w http.ResponseWriter, r *http.Request) {
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
	if analyticsDB == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Analytics database not initialized"})
		return
	}
	if err := ensureCorpusTable(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n >= 0 {
			days = n
		}
	}
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	where := []string{}
	args := []interface{}{}
	if days > 0 {
		where = append(where, "created_at >= datetime('now', ?)")
		args = append(args, fmt.Sprintf("-%d days", days))
	}
	if f := r.URL.Query().Get("feature"); f != "" {
		where = append(where, "feature = ?")
		args = append(args, f)
	}
	if r.URL.Query().Get("flagged_only") == "1" {
		where = append(where, "sampled = 0")
	}
	sqlStr := `SELECT id, feature, model, language, kinds, sampled,
	                  fact_basis, raw_answer, shipped_answer,
	                  app_version, ruleset_version, created_at
	           FROM ai_guard_corpus`
	if len(where) > 0 {
		sqlStr += " WHERE " + strings.Join(where, " AND ")
	}
	sqlStr += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := analyticsDB.Query(sqlStr, args...)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()

	cases := []map[string]interface{}{}
	for rows.Next() {
		var id, sampled int
		var feature, model, language, kinds, factBasis, rawAnswer, shippedAnswer string
		var appVersion, rulesetVersion, createdAt string
		if err := rows.Scan(&id, &feature, &model, &language, &kinds, &sampled,
			&factBasis, &rawAnswer, &shippedAnswer, &appVersion, &rulesetVersion, &createdAt); err != nil {
			continue
		}
		cases = append(cases, map[string]interface{}{
			"id":              id,
			"feature":         feature,
			"model":           model,
			"language":        language,
			"kinds":           kinds,
			"sampled":         sampled == 1,
			"fact_basis":      factBasis,
			"raw_answer":      rawAnswer,
			"shipped_answer":  shippedAnswer,
			"app_version":     appVersion,
			"ruleset_version": rulesetVersion,
			"created_at":      createdAt,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"days":    days,
		"count":   len(cases),
		"cases":   cases,
	})
}

// corpusSummary is a light count-only view (no bodies) for a quick health
// check — how many flagged vs baseline cases per feature in the window.
func adminGetGuardCorpusSummary(w http.ResponseWriter, r *http.Request) {
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
	if analyticsDB == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Analytics database not initialized"})
		return
	}
	if err := ensureCorpusTable(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n >= 0 {
			days = n
		}
	}
	base := `SELECT feature,
	                SUM(CASE WHEN sampled = 0 THEN 1 ELSE 0 END) AS flagged,
	                SUM(CASE WHEN sampled = 1 THEN 1 ELSE 0 END) AS baseline,
	                MAX(created_at) AS last_seen
	         FROM ai_guard_corpus`
	var rows *sql.Rows
	var err error
	if days > 0 {
		rows, err = analyticsDB.Query(base+` WHERE created_at >= datetime('now', ?)
		         GROUP BY feature ORDER BY flagged DESC`, fmt.Sprintf("-%d days", days))
	} else {
		rows, err = analyticsDB.Query(base + ` GROUP BY feature ORDER BY flagged DESC`)
	}
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()

	out := []map[string]interface{}{}
	for rows.Next() {
		var feature, lastSeen string
		var flagged, baseline int
		if err := rows.Scan(&feature, &flagged, &baseline, &lastSeen); err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"feature":   feature,
			"flagged":   flagged,
			"baseline":  baseline,
			"last_seen": lastSeen,
		})
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"days":    days,
		"rows":    out,
	})
}
