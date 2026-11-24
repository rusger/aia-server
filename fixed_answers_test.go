package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func openFixedAnswerTestDBs(t *testing.T) {
	t.Helper()
	prevDB, prevA := db, analyticsDB
	var err error
	if db, err = sql.Open("sqlite", ":memory:"); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if analyticsDB, err = sql.Open("sqlite", ":memory:"); err != nil {
		t.Fatal(err)
	}
	analyticsDB.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close(); analyticsDB.Close(); db, analyticsDB = prevDB, prevA })
	migrateFixedAnswers()
	for _, q := range []string{
		`CREATE TABLE devices (device_id TEXT, language TEXT)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`CREATE TABLE api_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, call_type TEXT,
			answer_id TEXT, finish_reason TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE ai_guard_corpus (id INTEGER PRIMARY KEY AUTOINCREMENT, feature TEXT, language TEXT,
			raw_answer TEXT, shipped_answer TEXT, answer_id TEXT)`,
		`CREATE TABLE ai_guard_events (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, feature TEXT,
			kind TEXT, answer_id TEXT)`,
	} {
		if _, err := analyticsDB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

func seedChain(t *testing.T, answerID, device, mainFinish string, corpus bool) {
	t.Helper()
	analyticsDB.Exec(`INSERT INTO api_calls (device_id, call_type, answer_id, finish_reason, created_at)
		VALUES (?, 'chatgpt', ?, ?, '2026-11-23 11:32:38')`, device, answerID, mainFinish)
	analyticsDB.Exec(`INSERT INTO api_calls (device_id, call_type, answer_id, finish_reason)
		VALUES (?, 'grounding_fix', ?, 'length')`, device, answerID)
	analyticsDB.Exec(`INSERT INTO ai_guard_events (device_id, feature, kind, answer_id)
		VALUES (?, 'natal_interpretation', 'grounding_fix', ?)`, device, answerID)
	if corpus {
		analyticsDB.Exec(`INSERT INTO ai_guard_corpus (feature, language, raw_answer, shipped_answer, answer_id)
			VALUES ('astrologer_chat', 'zh', ' 完整的回答。 ', '截断的回', ?)`, answerID)
	}
}

func fixedReq(method, url, body, device string) *http.Request {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), "claims", &JWTClaims{DeviceID: device}))
}

func TestFixedAnswerAddModes(t *testing.T) {
	openFixedAnswerTestDBs(t)
	db.Exec(`INSERT INTO devices VALUES ('DEV-B', 'ru')`)
	seedChain(t, "ans-corpus-1", "DEV-A", "stop", true)
	seedChain(t, "ans-cut-main", "DEV-A", "length", true)
	seedChain(t, "ans-nocorpus", "DEV-B", "stop", false)

	if mode, err := addFixedAnswer("ans-corpus-1", nil); err != nil || mode != "replace" {
		t.Fatalf("corpus row: mode=%q err=%v", mode, err)
	}
	var text, head, lang, at string
	db.QueryRow(`SELECT full_text, shipped_head, language, answered_at FROM fixed_answers WHERE answer_id='ans-corpus-1'`).
		Scan(&text, &head, &lang, &at)
	if text != "完整的回答。" || head != "截断的回" || lang != "zh" || at != "2026-11-23 11:32:38" {
		t.Fatalf("row: text=%q head=%q lang=%q at=%q", text, head, lang, at)
	}

	if _, err := addFixedAnswer("ans-cut-main", nil); err == nil {
		t.Fatal("main answer cut and no file: want error")
	}
	full := "开头。续写的结尾。"
	if mode, err := addFixedAnswer("ans-cut-main", &full); err != nil || mode != "replace" {
		t.Fatalf("override: mode=%q err=%v", mode, err)
	}
	db.QueryRow(`SELECT full_text FROM fixed_answers WHERE answer_id='ans-cut-main'`).Scan(&text)
	if text != full {
		t.Fatalf("override not stored: %q", text)
	}

	if mode, err := addFixedAnswer("ans-nocorpus", nil); err != nil || mode != "regenerate" {
		t.Fatalf("no corpus: mode=%q err=%v", mode, err)
	}
	var feature string
	db.QueryRow(`SELECT feature, language, full_text FROM fixed_answers WHERE answer_id='ans-nocorpus'`).Scan(&feature, &lang, &text)
	if feature != "natal_interpretation" || lang != "ru" || text != "" {
		t.Fatalf("regenerate row: feature=%q lang=%q text=%q", feature, lang, text)
	}

	if _, err := addFixedAnswer("missing-answer", nil); err == nil {
		t.Fatal("unknown answer_id: want error")
	}
	if _, err := addFixedAnswer("bad id!", nil); err == nil {
		t.Fatal("bad answer_id: want error")
	}
}

func TestFixedAnswerGetAndAck(t *testing.T) {
	openFixedAnswerTestDBs(t)
	seedChain(t, "ans-corpus-1", "DEV-A", "stop", true)
	if _, err := addFixedAnswer("ans-corpus-1", nil); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	fixedAnswerGet(w, fixedReq("GET", "/api/ai/fixed-answer?id=ans-corpus-1", "", "DEV-A"))
	if w.Code != 200 {
		t.Fatalf("own device: %d %s", w.Code, w.Body)
	}
	var got map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &got)
	if got["text"] != "完整的回答。" || got["mode"] != "replace" || got["feature"] != "astrologer_chat" || got["shipped_head"] != "截断的回" {
		t.Fatalf("body: %v", got)
	}
	var fetched sql.NullInt64
	db.QueryRow(`SELECT fetched_at FROM fixed_answers WHERE answer_id='ans-corpus-1'`).Scan(&fetched)
	if !fetched.Valid {
		t.Fatal("fetched_at not set")
	}

	for _, c := range []struct {
		url, dev string
		code     int
	}{
		{"/api/ai/fixed-answer?id=ans-corpus-1", "DEV-OTHER", 404},
		{"/api/ai/fixed-answer?id=ans-nothing", "DEV-A", 404},
		{"/api/ai/fixed-answer?id=bad%20id", "DEV-A", 400},
		{"/api/ai/fixed-answer", "DEV-A", 400},
	} {
		w := httptest.NewRecorder()
		fixedAnswerGet(w, fixedReq("GET", c.url, "", c.dev))
		if w.Code != c.code {
			t.Errorf("%s as %s: got %d want %d", c.url, c.dev, w.Code, c.code)
		}
	}

	for _, c := range []struct {
		body, dev string
		code      int
	}{
		{`{"answer_id":"ans-corpus-1","result":"maybe"}`, "DEV-A", 400},
		{`{"answer_id":"ans-corpus-1","result":"replaced"}`, "DEV-OTHER", 404},
		{`{"answer_id":"ans-corpus-1","result":"replaced"}`, "DEV-A", 200},
	} {
		w := httptest.NewRecorder()
		fixedAnswerAck(w, fixedReq("POST", "/api/ai/fixed-answer/ack", c.body, c.dev))
		if w.Code != c.code {
			t.Errorf("ack %s as %s: got %d want %d", c.body, c.dev, w.Code, c.code)
		}
	}
	var ack string
	db.QueryRow(`SELECT ack_result FROM fixed_answers WHERE answer_id='ans-corpus-1'`).Scan(&ack)
	if ack != "replaced" {
		t.Fatalf("ack_result=%q", ack)
	}
}
