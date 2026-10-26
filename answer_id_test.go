package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// setupAnswerIDTestDB points analyticsDB at a fresh in-memory DB holding the
// PRE-migration shapes of api_calls and ai_guard_events (no answer_id), the
// state every production analytics.db is in before this change deploys.
func setupAnswerIDTestDB(t *testing.T) {
	t.Helper()
	var err error
	analyticsDB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// One connection: every :memory: connection is its own database.
	analyticsDB.SetMaxOpenConns(1)
	t.Cleanup(func() { analyticsDB.Close(); analyticsDB = nil })
	for _, q := range []string{
		`CREATE TABLE api_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
			call_type TEXT NOT NULL, model TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			prompt_tokens INTEGER DEFAULT 0, completion_tokens INTEGER DEFAULT 0,
			total_tokens INTEGER DEFAULT 0, cached_tokens INTEGER DEFAULT 0)`,
		`CREATE TABLE ai_guard_events (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
			feature TEXT NOT NULL, kind TEXT NOT NULL, model TEXT DEFAULT '', language TEXT DEFAULT '',
			count INTEGER DEFAULT 1, detail TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			app_version TEXT DEFAULT '', ruleset_version TEXT DEFAULT '')`,
	} {
		if _, err := analyticsDB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// waitForString polls an async (goroutine) insert until query returns a row.
func waitForString(t *testing.T, query string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var v string
		if err := analyticsDB.QueryRow(query).Scan(&v); err == nil {
			return v
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no row for %q", query)
	return ""
}

func TestAnswerIDColumnMigrationIsIdempotent(t *testing.T) {
	setupAnswerIDTestDB(t)
	addAnswerIDColumn("api_calls")
	addAnswerIDColumn("api_calls") // second run: "duplicate column" is expected and ignored
	var n int
	if err := analyticsDB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('api_calls') WHERE name='answer_id'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("answer_id column count = %d, err %v", n, err)
	}
	if err := analyticsDB.QueryRow(`SELECT COUNT(*) FROM pragma_index_list('api_calls') WHERE name='idx_api_calls_answer_id'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("answer_id index count = %d, err %v", n, err)
	}
}

func TestAnswerIDReachesApiCallsAndGuardEvents(t *testing.T) {
	setupAnswerIDTestDB(t)
	addAnswerIDColumn("api_calls")
	addAnswerIDColumn("ai_guard_events")

	logAPICallForAnswer("dev1", "grounding_fix", "gpt-4.1-mini", "ans-42", 10, 5, 15, 0)
	if got := waitForString(t, `SELECT answer_id FROM api_calls WHERE call_type='grounding_fix'`); got != "ans-42" {
		t.Fatalf("api_calls.answer_id = %q", got)
	}
	// Older call sites keep working and write an empty id.
	logAPICallWithTokens("dev1", "chatgpt", "gpt-4.1-mini", 1, 1, 2, 0)
	if got := waitForString(t, `SELECT answer_id FROM api_calls WHERE call_type='chatgpt'`); got != "" {
		t.Fatalf("legacy api_calls.answer_id = %q, want empty", got)
	}

	logGuardEvent("dev1", "horoscope", "claim_audit_result", "gpt-4o-mini", "zh", 2, "", "2.1.23+161", "gr2026-10-19", "ans-42")
	if got := waitForString(t, `SELECT answer_id FROM ai_guard_events WHERE kind='claim_audit_result'`); got != "ans-42" {
		t.Fatalf("ai_guard_events.answer_id = %q", got)
	}
}

func TestAnswerIDReachesArbiterRows(t *testing.T) {
	setupAnswerIDTestDB(t)
	// The table is created once per process; this test owns a fresh DB.
	arbiterTableOnce, arbiterTableErr = sync.Once{}, nil
	t.Cleanup(func() { arbiterTableOnce, arbiterTableErr = sync.Once{}, nil })
	if err := ensureArbiterTable(); err != nil {
		t.Fatal(err)
	}
	logArbiter(ArbiterRequest{
		Feature: "horoscope", FactBasis: "facts", Answer: "orig",
		AnswerID: "ans-7", Language: "zh", AppVersion: "2.1.23+161", RulesetVersion: "gr2026-10-19",
	}, "sonnet", true, "ok", "fixed", "corrected", time.Second, 10, "")
	got := waitForString(t, `SELECT answer_id||'/'||language||'/'||app_version||'/'||ruleset_version||'/'||original_answer||'/'||corrected_answer FROM ai_arbiter_events`)
	if got != "ans-7/zh/2.1.23+161/gr2026-10-19/orig/corrected" {
		t.Fatalf("arbiter row = %q", got)
	}
}

func TestAnswerIDReachesCorpusRows(t *testing.T) {
	setupAnswerIDTestDB(t)
	corpusTableOnce, corpusTableErr = sync.Once{}, nil
	t.Cleanup(func() { corpusTableOnce, corpusTableErr = sync.Once{}, nil })
	body := `{"feature":"natal_interpretation","raw_answer":"a","shipped_answer":"b","answer_id":"ans-9"}`
	r := httptest.NewRequest(http.MethodPost, "/api/ai/guard/corpus", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), "claims", &JWTClaims{DeviceID: "dev1"}))
	w := httptest.NewRecorder()
	guardCorpusReport(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if got := waitForString(t, `SELECT answer_id FROM ai_guard_corpus`); got != "ans-9" {
		t.Fatalf("corpus answer_id = %q", got)
	}
}

func TestClampAnswerID(t *testing.T) {
	if got := clampAnswerID("  abc  "); got != "abc" {
		t.Fatalf("trim: %q", got)
	}
	long := strings.Repeat("я", 40) // 80 bytes
	got := clampAnswerID(long)
	if len(got) > maxAnswerIDBytes || !strings.HasPrefix(long, got) || len(got)%2 != 0 {
		t.Fatalf("clamp broke UTF-8 or length: %d bytes", len(got))
	}
}
