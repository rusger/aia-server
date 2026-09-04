package main

// Arbiter layer (owner request 2026-08-30): a SECOND model ("dublyor") on the
// server cross-checks a generated astrology answer against the computed chart
// facts and applies the MINIMAL edits needed to remove claims the facts don't
// support — chiefly yogas the model named whose condition doesn't hold (the
// interpretive-fidelity run showed GPT-4o fabricating yogas on 4/8 charts, a
// failure the position-only grounding cannot catch). The corrected text is
// what the client swaps in behind the scenes; every arbitration is logged
// server-side for audit and improvement.
//
// Model: runs `claude -p` (headless) via the server's authenticated Claude Max
// login (~/.local/bin/claude) — no API key needed (owner order 2026-08-30).
// Kill-switches: ARBITER_DISABLED=1 (global) and ARBITER_DISABLED_FEATURES
// ("ayurveda,other" — per feature) => logged no-op. Every row also records
// latency_ms and prompt_bytes (triage 2026-09-04). Any exec error / unparsable /
// runaway-length rewrite also returns the answer UNCHANGED (logged), so a user
// reply is never broken.
//
// Privacy: de-identified like the guard corpus — no device id is stored; the
// fact basis is the computed chart the model already saw (birth-date headers
// stripped upstream).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxArbiterFieldBytes = 120000

var (
	arbiterTableOnce sync.Once
	arbiterTableErr  error
)

// Model label recorded in the audit log. Empty ARBITER_MODEL => the Claude
// CLI's configured default (Opus 5 on this server).
func arbiterModel() string {
	if m := os.Getenv("ARBITER_MODEL"); m != "" {
		return m
	}
	return "claude-cli-default"
}

func serverHome() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/home/ruslan"
}

// claudeBin is the absolute path to the `claude` binary (found via a login
// shell: ~/.local/bin/claude). Overridable with CLAUDE_BIN.
func claudeBin() string {
	if b := os.Getenv("CLAUDE_BIN"); b != "" {
		return b
	}
	return filepath.Join(serverHome(), ".local/bin/claude")
}

func ensureArbiterTable() error {
	arbiterTableOnce.Do(func() {
		if analyticsDB == nil {
			arbiterTableErr = fmt.Errorf("analytics DB not initialized")
			return
		}
		_, arbiterTableErr = analyticsDB.Exec(`
        CREATE TABLE IF NOT EXISTS ai_arbiter_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feature TEXT NOT NULL,
            model TEXT DEFAULT '',
            changed INTEGER DEFAULT 0,
            reason TEXT DEFAULT '',
            change_summary TEXT DEFAULT '',
            original_answer TEXT DEFAULT '',
            corrected_answer TEXT DEFAULT '',
            fact_basis TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_arbiter_feature ON ai_arbiter_events(feature);
        CREATE INDEX IF NOT EXISTS idx_arbiter_changed ON ai_arbiter_events(changed);
        CREATE INDEX IF NOT EXISTS idx_arbiter_date ON ai_arbiter_events(created_at);
        `)
		if arbiterTableErr != nil {
			log.Printf("❌ ai_arbiter_events create failed: %v", arbiterTableErr)
			return
		}
		// Additive migration (triage 2026-09-04): how long the second-model
		// pass took and how big the prompt was — the audit could not answer
		// "is the arbiter worth its latency/cost per feature" without them.
		// "duplicate column" on an already-migrated DB is expected and ignored.
		for _, c := range []string{
			"latency_ms INTEGER DEFAULT 0",
			"prompt_bytes INTEGER DEFAULT 0",
			// Omission probe (triage 2026-09-04, plan W6): what the answer
			// SHOULD have said and did not — report-only, never applied.
			"omissions TEXT DEFAULT ''",
		} {
			if _, err := analyticsDB.Exec("ALTER TABLE ai_arbiter_events ADD COLUMN " + c); err != nil &&
				!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
				log.Printf("⚠️ ai_arbiter_events migration (%s): %v", c, err)
			}
		}
	})
	return arbiterTableErr
}

// arbiterFeatureDisabled reports whether feature is listed in the
// ARBITER_DISABLED_FEATURES kill-switch (comma-separated, case-insensitive,
// spaces tolerated) — a per-feature no-op without redeploy, for features where
// the pass is not worth its wait (non-streamed screens block on it).
func arbiterFeatureDisabled(feature, disabledList string) bool {
	f := strings.ToLower(strings.TrimSpace(feature))
	if f == "" {
		return false
	}
	for _, d := range strings.Split(disabledList, ",") {
		if strings.ToLower(strings.TrimSpace(d)) == f {
			return true
		}
	}
	return false
}

func trimForLog(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

func clampArbiterField(s string) string {
	if len(s) <= maxArbiterFieldBytes {
		return s
	}
	cut := maxArbiterFieldBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func logArbiter(feature, model string, changed bool, reason, summary, original, corrected, facts string, latency time.Duration, promptBytes int, omissions string) {
	if analyticsDB == nil {
		return
	}
	ci := 0
	if changed {
		ci = 1
	}
	go func() {
		if _, err := analyticsDB.Exec(
			`INSERT INTO ai_arbiter_events
			 (feature, model, changed, reason, change_summary, original_answer, corrected_answer, fact_basis, latency_ms, prompt_bytes, omissions)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			feature, model, ci, reason, clampArbiterField(summary),
			clampArbiterField(original), clampArbiterField(corrected), clampArbiterField(facts),
			latency.Milliseconds(), promptBytes, clampArbiterField(omissions),
		); err != nil {
			log.Printf("⚠️ ai_arbiter_events insert failed: %v", err)
		}
	}()
}

// ArbiterRequest is one answer to cross-check. fact_basis = the computed chart
// + lenses the answer was written from (de-identified).
type ArbiterRequest struct {
	Feature   string `json:"feature"`
	FactBasis string `json:"fact_basis"`
	Answer    string `json:"answer"`
}

type ArbiterResponse struct {
	Success   bool     `json:"success"`
	Changed   bool     `json:"changed"`
	Corrected string   `json:"corrected"`
	Changes   []string `json:"changes"`
	Reason    string   `json:"reason,omitempty"`
}

func arbiterPrompt(factBasis, answer string) string {
	return `You are a rigorous fact-checker for a Vedic (Jyotish) astrology answer. You are given the COMPUTED chart facts (ground truth — planetary signs, houses, dignities) and an answer written for a user.

Your job: find astrological CLAIMS in the answer that the facts do NOT support — most importantly a named yoga or combination whose defining condition is not actually met by the chart (e.g. a Mahapurusha yoga claimed for a planet that is not in a kendra; a "parivartana" between planets that are merely conjunct; a yoga asserted where the planets are not in the stated relationship). Also flag any planetary position stated that contradicts the facts.

Do NOT flag legitimate interpretation, tone, or a different-but-valid school of thought. Only flag claims that are factually wrong against the given chart.

Then produce a corrected answer that makes the MINIMAL edits needed to remove or fix the unsupported claims, preserving the original wording, structure, and length everywhere else. The edit must be as unobtrusive as possible.

Separately (report only — do NOT add anything to the corrected answer): list in "omitted" up to 5 IMPORTANT facts from the chart that an answer on this topic should have mentioned but did not — e.g. an exact or strong yoga the topic depends on, a retrograde/debilitated/exalted planet ruling the topic, the running dasha, a marked house emphasis. Only facts present in the ground truth; empty list if nothing important is missing.

Return ONLY a JSON object, no prose:
{"changed": <true|false>, "changes": ["short description of each fix"], "omitted": ["short fact the answer should have mentioned"], "corrected": "<the full answer, edited or unchanged>"}

=== COMPUTED CHART FACTS (ground truth) ===
` + factBasis + `

=== ANSWER TO CHECK ===
` + answer + `

Return the JSON now.`
}

// callClaudeCLI runs `claude -p` headless (owner order 2026-08-30) using the
// server's authenticated Claude Max login — no API key. The prompt is piped on
// stdin; the reply is read from stdout. Runs as the service user (ruslan) with
// HOME set so the CLI finds its auth.
func callClaudeCLI(prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	args := []string{"-p", "--output-format", "text"}
	if m := os.Getenv("ARBITER_MODEL"); m != "" {
		args = append(args, "--model", m)
	}
	cmd := exec.CommandContext(ctx, claudeBin(), args...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Dir = serverHome()
	cmd.Env = append(os.Environ(), "HOME="+serverHome())
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("claude -p failed: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// parseArbiterJSON extracts the {changed,changes,corrected} object from the
// model's reply, tolerating markdown fences / leading prose.
func parseArbiterJSON(s string) (changed bool, changes []string, corrected string, ok bool) {
	changed, changes, _, corrected, ok = parseArbiterJSONFull(s)
	return
}

// parseArbiterJSONFull also returns the report-only "omitted" list (absent or
// null => empty).
func parseArbiterJSONFull(s string) (changed bool, changes, omitted []string, corrected string, ok bool) {
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i < 0 || j <= i {
		return false, nil, nil, "", false
	}
	var obj struct {
		Changed   bool     `json:"changed"`
		Changes   []string `json:"changes"`
		Omitted   []string `json:"omitted"`
		Corrected string   `json:"corrected"`
	}
	if err := json.Unmarshal([]byte(s[i:j+1]), &obj); err != nil {
		return false, nil, nil, "", false
	}
	return obj.Changed, obj.Changes, obj.Omitted, obj.Corrected, true
}

// arbiterReview cross-checks one answer. Fail-open: any error or a missing key
// returns the answer UNCHANGED (logged), so a user reply is never broken.
func arbiterReview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if _, ok := r.Context().Value("claims").(*JWTClaims); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}
	var req ArbiterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request body"})
		return
	}
	if req.Feature == "" {
		req.Feature = "other"
	}
	_ = ensureArbiterTable()
	model := arbiterModel()

	// Every outcome is logged (owner order 2026-08-30: success / no-change /
	// refusal / error / limit — all of it, for the running audit). `detail`
	// carries the specific reason (e.g. the claude -p error text).
	prompt := arbiterPrompt(req.FactBasis, req.Answer)
	started := time.Now()
	noop := func(reason, detail string) {
		logArbiter(req.Feature, model, false, reason, detail, req.Answer, req.Answer, req.FactBasis,
			time.Since(started), len(prompt), "")
		json.NewEncoder(w).Encode(ArbiterResponse{Success: true, Changed: false, Corrected: req.Answer, Reason: reason})
	}

	// Kill-switch without redeploy: ARBITER_DISABLED=1 => logged no-op.
	if os.Getenv("ARBITER_DISABLED") == "1" {
		noop("arbiter_disabled", "")
		return
	}
	// Per-feature kill-switch: ARBITER_DISABLED_FEATURES="ayurveda,other".
	if arbiterFeatureDisabled(req.Feature, os.Getenv("ARBITER_DISABLED_FEATURES")) {
		noop("arbiter_disabled_feature", "")
		return
	}
	if strings.TrimSpace(req.Answer) == "" {
		noop("empty_answer", "")
		return
	}

	// claude -p via the owner's Claude Max. If the subscription has run out or
	// hit a temporary limit — or any other failure — we skip the correction and
	// ship the original answer UNCHANGED, but we LOG the failure (limit vs other
	// error) so the audit sees exactly what was skipped and why.
	reply, err := callClaudeCLI(prompt)
	if err != nil {
		es := err.Error()
		low := strings.ToLower(es)
		reason := "arbiter_error"
		if strings.Contains(low, "limit") || strings.Contains(low, "quota") ||
			strings.Contains(low, "usage") || strings.Contains(low, "rate") ||
			strings.Contains(low, "subscription") || strings.Contains(low, "credit") {
			reason = "arbiter_limit" // subscription exhausted / throttled
		}
		log.Printf("⚠️ arbiter %s: %v", reason, err)
		noop(reason, es)
		return
	}
	changed, changes, omitted, corrected, ok := parseArbiterJSONFull(reply)
	if !ok || strings.TrimSpace(corrected) == "" {
		noop("arbiter_unparsable", trimForLog(reply))
		return
	}
	// Guard against a runaway rewrite: if the "corrected" text is wildly
	// different in length, distrust it and keep the original.
	if changed && looksLikeRunaway(req.Answer, corrected) {
		noop("arbiter_runaway_rejected", "")
		return
	}
	summary := strings.Join(changes, " | ")
	logArbiter(req.Feature, model, changed, "ok", summary, req.Answer, corrected, req.FactBasis,
		time.Since(started), len(prompt), strings.Join(omitted, " | "))
	json.NewEncoder(w).Encode(ArbiterResponse{
		Success: true, Changed: changed, Corrected: corrected, Changes: changes,
	})
}

// looksLikeRunaway is true when the corrected text length departs too far from
// the original (the arbiter is meant to make MINIMAL edits, not rewrite).
func looksLikeRunaway(orig, corrected string) bool {
	lo, lc := len(orig), len(corrected)
	if lo == 0 {
		return false
	}
	ratio := float64(lc) / float64(lo)
	return ratio < 0.5 || ratio > 1.6
}

// adminGetArbiter exports arbiter events for audit. Admin-gated.
// ?days=N (default 30, 0=all), ?changed_only=1, ?feature=F, ?limit=N (max 1000).
func adminGetArbiter(w http.ResponseWriter, r *http.Request) {
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
	_ = ensureArbiterTable()
	days, limit := 30, 200
	if d := r.URL.Query().Get("days"); d != "" {
		fmt.Sscanf(d, "%d", &days)
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit > 1000 {
		limit = 1000
	}
	where, args := []string{}, []interface{}{}
	if days > 0 {
		where = append(where, "created_at >= datetime('now', ?)")
		args = append(args, fmt.Sprintf("-%d days", days))
	}
	if r.URL.Query().Get("changed_only") == "1" {
		where = append(where, "changed = 1")
	}
	if f := r.URL.Query().Get("feature"); f != "" {
		where = append(where, "feature = ?")
		args = append(args, f)
	}
	q := `SELECT id, feature, model, changed, reason, change_summary,
	             original_answer, corrected_answer, fact_basis, created_at,
	             latency_ms, prompt_bytes, omissions
	      FROM ai_arbiter_events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)
	rows, err := analyticsDB.Query(q, args...)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()
	events := []map[string]interface{}{}
	for rows.Next() {
		var id, changed int
		var latencyMs, promptBytes int64
		var feature, model, reason, summary, orig, corr, facts, created, omissions string
		if err := rows.Scan(&id, &feature, &model, &changed, &reason, &summary, &orig, &corr, &facts, &created,
			&latencyMs, &promptBytes, &omissions); err != nil {
			continue
		}
		events = append(events, map[string]interface{}{
			"id": id, "feature": feature, "model": model, "changed": changed == 1,
			"reason": reason, "change_summary": summary, "original_answer": orig,
			"corrected_answer": corr, "fact_basis": facts, "created_at": created,
			"latency_ms": latencyMs, "prompt_bytes": promptBytes, "omissions": omissions,
		})
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "days": days, "count": len(events), "events": events})
}

var _ = sql.ErrNoRows
