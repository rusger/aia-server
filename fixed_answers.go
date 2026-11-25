package main

// Corrected answers for replies that reached users cut off (A194, owner
// 24.11.2026 via the coordinator: «дошлёт им всё-таки правильные сообщения…
// появятся у них на телефоне», «при тапе открыть тот экран»).
//
// Between 19.11 and 24.11 the paid grounding rewrite ran with a token limit
// smaller than the answer it rewrote, so 18 answers shipped truncated. Each
// one gets a row here; a push with payload `fix:<answer_id>` makes the app
// fetch the row (GET /api/ai/fixed-answer), find the truncated text on the
// phone by shipped_head, replace it, open that chat/section and report back
// (POST /api/ai/fixed-answer/ack).
//
//   mode "replace"    — full_text is the complete answer (the model's answer
//                       before the rewrite, or a paid continuation of it),
//                       already through the guard strip before it was added;
//                       the app stores and shows it as is, no second pass.
//   mode "regenerate" — nothing is left to restore (no corpus row): the app
//                       drops its saved copy and builds the answer again.
//
// Rows are added by hand with the CLI below; nothing writes them at runtime.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const fixedAnswerHeadChars = 400

var fixedAnswerIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

var fixedAnswerAckResults = map[string]bool{
	"replaced": true, "shown": true, "regenerated": true, "not_found": true,
}

func migrateFixedAnswers() {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS fixed_answers (
			answer_id    TEXT PRIMARY KEY,
			device_id    TEXT NOT NULL,
			feature      TEXT NOT NULL DEFAULT '',
			language     TEXT NOT NULL DEFAULT '',
			answered_at  TEXT NOT NULL DEFAULT '',  -- UTC "YYYY-MM-DD HH:MM:SS" of the original answer
			mode         TEXT NOT NULL,             -- replace | regenerate
			shipped_head TEXT NOT NULL DEFAULT '',
			full_text    TEXT NOT NULL DEFAULT '',
			created_at   INTEGER NOT NULL,
			fetched_at   INTEGER,
			ack_result   TEXT,
			ack_at       INTEGER
		)`); err != nil {
		fmt.Printf("fixed_answers migration: %v\n", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_fixed_answers_device ON fixed_answers (device_id)`); err != nil {
		fmt.Printf("fixed_answers index: %v\n", err)
	}
}

// headRunes returns the first n characters (not bytes) of s.
func headRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// addFixedAnswer builds the row for answerID from analyticsDB (read only) and
// upserts it into db. override, when non-nil, is the full text to deliver.
func addFixedAnswer(answerID string, override *string) (string, error) {
	if !fixedAnswerIDRe.MatchString(answerID) {
		return "", fmt.Errorf("bad answer_id")
	}
	var deviceID, answeredAt, mainFinish string
	err := analyticsDB.QueryRow(`SELECT device_id, strftime('%Y-%m-%d %H:%M:%S', created_at) FROM api_calls
		WHERE answer_id = ? AND call_type = 'chatgpt' ORDER BY id LIMIT 1`, answerID).Scan(&deviceID, &answeredAt)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no chatgpt call with this answer_id in api_calls")
	}
	if err != nil {
		return "", err
	}
	if err := analyticsDB.QueryRow(`SELECT COALESCE(finish_reason,'') FROM api_calls
		WHERE answer_id = ? AND call_type = 'chatgpt' ORDER BY id DESC LIMIT 1`, answerID).Scan(&mainFinish); err != nil {
		return "", fmt.Errorf("read finish_reason: %v", err)
	}

	var feature, language, raw, shipped string
	err = analyticsDB.QueryRow(`SELECT feature, language, raw_answer, shipped_answer FROM ai_guard_corpus
		WHERE answer_id = ? ORDER BY id DESC LIMIT 1`, answerID).Scan(&feature, &language, &raw, &shipped)
	hasCorpus := err == nil
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}

	mode, text, head := "replace", "", ""
	switch {
	case override != nil:
		text = strings.TrimSpace(*override)
		if text == "" {
			return "", fmt.Errorf("full text file is empty")
		}
	case !hasCorpus:
		mode = "regenerate"
	case mainFinish == "length":
		return "", fmt.Errorf("the main answer itself was cut (finish_reason=length): pass the completed text as a file")
	default:
		text = strings.TrimSpace(raw)
		if text == "" {
			return "", fmt.Errorf("corpus raw_answer is empty")
		}
	}
	if hasCorpus {
		head = headRunes(shipped, fixedAnswerHeadChars)
	} else {
		if err := analyticsDB.QueryRow(`SELECT feature FROM ai_guard_events WHERE answer_id = ? AND feature != ''
			ORDER BY id LIMIT 1`, answerID).Scan(&feature); err != nil && err != sql.ErrNoRows {
			return "", fmt.Errorf("read guard event feature: %v", err)
		}
		var lang sql.NullString
		if err := db.QueryRow(`SELECT language FROM devices WHERE device_id = ? LIMIT 1`, deviceID).Scan(&lang); err != nil && err != sql.ErrNoRows {
			return "", fmt.Errorf("read device language: %v", err)
		}
		language = lang.String
	}
	if feature == "" {
		return "", fmt.Errorf("feature unknown (no corpus row, no guard event)")
	}
	_, err = db.Exec(`INSERT INTO fixed_answers
		(answer_id, device_id, feature, language, answered_at, mode, shipped_head, full_text, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(answer_id) DO UPDATE SET device_id=excluded.device_id, feature=excluded.feature,
			language=excluded.language, answered_at=excluded.answered_at, mode=excluded.mode,
			shipped_head=excluded.shipped_head, full_text=excluded.full_text, created_at=excluded.created_at`,
		answerID, deviceID, feature, language, answeredAt, mode, head, text, time.Now().Unix())
	if err != nil {
		return "", err
	}
	return mode, nil
}

func shortDeviceHash(deviceID string) string {
	h := sha256.Sum256([]byte(deviceID))
	return hex.EncodeToString(h[:])[:8]
}

func openFixedAnswerCLIDBs(needAnalytics bool) {
	var err error
	db, err = sql.Open("sqlite", usersDBDSN(getEnv("USERS_DB_PATH", "./users.db")))
	if err != nil {
		fmt.Printf("open users.db: %v\n", err)
		os.Exit(1)
	}
	migrateFixedAnswers()
	if needAnalytics {
		analyticsDB, err = sql.Open("sqlite", "file:"+getEnv("ANALYTICS_DB_PATH", "./analytics.db")+"?mode=ro&_pragma=busy_timeout(5000)")
		if err != nil {
			fmt.Printf("open analytics.db: %v\n", err)
			os.Exit(1)
		}
	}
}

// ./astrolog_api fixed-answer-add <answer_id> [full_text_file]
func runFixedAnswerAddCLI(args []string) {
	if len(args) < 1 || len(args) > 2 {
		fmt.Println("usage: astrolog_api fixed-answer-add <answer_id> [full_text_file]")
		os.Exit(2)
	}
	var override *string
	if len(args) == 2 {
		b, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Printf("read %s: %v\n", args[1], err)
			os.Exit(1)
		}
		s := string(b)
		override = &s
	}
	openFixedAnswerCLIDBs(true)
	defer db.Close()
	defer analyticsDB.Close()
	mode, err := addFixedAnswer(args[0], override)
	if err != nil {
		fmt.Printf("%s: %v\n", headRunes(args[0], 8), err)
		os.Exit(1)
	}
	fmt.Printf("%s: %s\n", headRunes(args[0], 8), mode)
}

// ./astrolog_api fixed-answer-list
func runFixedAnswerListCLI() {
	openFixedAnswerCLIDBs(false)
	defer db.Close()
	rows, err := db.Query(`SELECT answer_id, device_id, feature, language, answered_at, mode,
		length(full_text), COALESCE(fetched_at,0), COALESCE(ack_result,'') FROM fixed_answers ORDER BY answered_at`)
	if err != nil {
		fmt.Printf("query: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()
	for rows.Next() {
		var id, dev, feature, lang, at, mode, ack string
		var n int
		var fetched int64
		if err := rows.Scan(&id, &dev, &feature, &lang, &at, &mode, &n, &fetched, &ack); err != nil {
			fmt.Printf("scan: %v\n", err)
			os.Exit(1)
		}
		f := "-"
		if fetched > 0 {
			f = time.Unix(fetched, 0).UTC().Format("01-02 15:04")
		}
		fmt.Printf("%s\tdev#%s\t%s\t%s\t%s\t%s\t%d\tfetched=%s\tack=%s\n",
			headRunes(id, 8), shortDeviceHash(dev), at, feature, lang, mode, n, f, ack)
	}
	if err := rows.Err(); err != nil { // a partial list must not pass as complete
		fmt.Printf("iterate: %v\n", err)
		os.Exit(1)
	}
}

// GET /api/ai/fixed-answer?id=<answer_id> → the correction for this device.
func fixedAnswerGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		streamJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	id := r.URL.Query().Get("id")
	if !fixedAnswerIDRe.MatchString(id) {
		streamJSONError(w, http.StatusBadRequest, "id required", "")
		return
	}
	var feature, language, answeredAt, mode, head, text string
	err := db.QueryRow(`SELECT feature, language, answered_at, mode, shipped_head, full_text
		FROM fixed_answers WHERE answer_id = ? AND device_id = ?`, id, claims.DeviceID).
		Scan(&feature, &language, &answeredAt, &mode, &head, &text)
	if err == sql.ErrNoRows {
		streamJSONError(w, http.StatusNotFound, "not found", "not_found")
		return
	}
	if err != nil {
		streamJSONError(w, http.StatusInternalServerError, "Database error", "")
		return
	}
	if _, err := db.Exec(`UPDATE fixed_answers SET fetched_at = ? WHERE answer_id = ?`, time.Now().Unix(), id); err != nil {
		// Delivery itself is fine; only the bookkeeping mark is missing.
		log.Printf("fixed_answers: fetched_at for %s: %v", headRunes(id, 8), err)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"answer_id":    id,
		"feature":      feature,
		"language":     language,
		"answered_at":  answeredAt,
		"mode":         mode,
		"shipped_head": head,
		"text":         text,
	})
}

// POST /api/ai/fixed-answer/ack {answer_id, result} → what the app did with it.
func fixedAnswerAck(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		streamJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	var req struct {
		AnswerID string `json:"answer_id"`
		Result   string `json:"result"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		!fixedAnswerIDRe.MatchString(req.AnswerID) || !fixedAnswerAckResults[req.Result] {
		streamJSONError(w, http.StatusBadRequest, "answer_id and result required", "")
		return
	}
	res, err := db.Exec(`UPDATE fixed_answers SET ack_result = ?, ack_at = ? WHERE answer_id = ? AND device_id = ?`,
		req.Result, time.Now().Unix(), req.AnswerID, claims.DeviceID)
	if err != nil {
		streamJSONError(w, http.StatusInternalServerError, "Database error", "")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		streamJSONError(w, http.StatusNotFound, "not found", "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}
