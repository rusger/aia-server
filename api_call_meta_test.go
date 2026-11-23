package main

import (
	"database/sql"
	"io"
	"strings"
	"testing"
	"time"
)

func waitForMetaRow(t *testing.T, where string) (reqMax, maxTok int, finish, tag, reqModel, model, callType string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		err := analyticsDB.QueryRow(`SELECT req_max_tokens, max_tokens, finish_reason, client_tag, req_model, model, call_type
			FROM api_calls WHERE `+where).Scan(&reqMax, &maxTok, &finish, &tag, &reqModel, &model, &callType)
		if err == nil {
			return
		}
		if err != sql.ErrNoRows {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no row for %q", where)
	return
}

func TestAPICallMetaMigrationIsIdempotent(t *testing.T) {
	setupAnswerIDTestDB(t)
	addAnswerIDColumn("api_calls")
	analyticsDB.Exec(`INSERT INTO api_calls (device_id, call_type, model) VALUES ('old', 'chatgpt', 'gpt-4.1-mini')`)
	addAPICallMetaColumns()
	addAPICallMetaColumns() // second run: duplicate column is expected and ignored
	for _, c := range apiCallMetaColumns {
		var n int
		if err := analyticsDB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('api_calls') WHERE name=?`, c.name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s column count = %d, err %v", c.name, n, err)
		}
	}
	// rows written before the migration read as defaults
	reqMax, maxTok, finish, tag, reqModel, _, _ := waitForMetaRow(t, `device_id='old'`)
	if reqMax != 0 || maxTok != 0 || finish != "" || tag != "" || reqModel != "" {
		t.Fatalf("old row defaults: %d %d %q %q %q", reqMax, maxTok, finish, tag, reqModel)
	}
}

func TestAPICallMetaIsWritten(t *testing.T) {
	setupAnswerIDTestDB(t)
	addAnswerIDColumn("api_calls")
	addAPICallMetaColumns()

	req := ChatGPTProxyRequest{Model: "gpt-4.1-mini", MaxTokens: 1500, CallType: "weird_tag"}
	meta := newAPICallMeta(req)
	meta.MaxTokens = 2000 // floor raised it
	meta.FinishReason = "length"
	callType, _ := normalizeAICallType(req.CallType)
	logAPICallWithMeta("dev1", callType, "gpt-6-luna", "ans-1", 100, 2000, 2100, 0, meta)

	reqMax, maxTok, finish, tag, reqModel, model, ct := waitForMetaRow(t, `answer_id='ans-1'`)
	if reqMax != 1500 || maxTok != 2000 || finish != "length" || tag != "weird_tag" || reqModel != "gpt-4.1-mini" {
		t.Fatalf("meta = %d %d %q %q %q", reqMax, maxTok, finish, tag, reqModel)
	}
	if model != "gpt-6-luna" || ct != "chatgpt" {
		t.Fatalf("billing columns changed: model %q call_type %q", model, ct)
	}

	// long / hostile strings are clamped, negatives zeroed
	long := strings.Repeat("я", 100)
	logAPICallWithMeta("dev2", "chatgpt", "m", "ans-2", 1, 1, 2, 0,
		apiCallMeta{ReqMaxTokens: -5, MaxTokens: -1, ClientTag: long, ReqModel: "  x  "})
	reqMax, maxTok, _, tag, reqModel, _, _ = waitForMetaRow(t, `answer_id='ans-2'`)
	if reqMax != 0 || maxTok != 0 || len(tag) > apiCallMetaMaxLen || !strings.HasPrefix(long, tag) || reqModel != "x" {
		t.Fatalf("clamp: %d %d %q %q", reqMax, maxTok, tag, reqModel)
	}

	// old call sites still write rows with default meta
	logAPICallForAnswer("dev3", "tts", "tts-1", "ans-3", 5, 0, 5, 0)
	reqMax, _, finish, tag, _, _, _ = waitForMetaRow(t, `answer_id='ans-3'`)
	if reqMax != 0 || finish != "" || tag != "" {
		t.Fatalf("old call site meta: %d %q %q", reqMax, finish, tag)
	}
}

func TestAPICallMetaFallsBackWithoutColumns(t *testing.T) {
	setupAnswerIDTestDB(t)
	addAnswerIDColumn("api_calls") // meta columns deliberately NOT added
	logAPICallWithMeta("dev1", "chatgpt", "gpt-6-luna", "ans-fb", 10, 5, 15, 0, apiCallMeta{FinishReason: "stop"})
	if got := waitForString(t, `SELECT model FROM api_calls WHERE answer_id='ans-fb'`); got != "gpt-6-luna" {
		t.Fatalf("fallback row model = %q", got)
	}
}

func TestStreamRecordsFinishReason(t *testing.T) {
	setupAnswerIDTestDB(t)
	addAnswerIDColumn("api_calls")
	addAPICallMetaColumns()
	sse := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hel"},"finish_reason":null}]}`,
		`data: {"choices":[{"delta":{"content":"lo"},"finish_reason":"length"}]}`,
		`data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":2000,"total_tokens":2007}}`,
		`data: [DONE]`, ``}, "\n")
	meta := newAPICallMeta(ChatGPTProxyRequest{Model: "gpt-4.1-mini", MaxTokens: 1000, CallType: "chatgpt"})
	meta.MaxTokens = 2000
	chatGPTStreamGenerate(newStreamBuf(time.Now()), io.NopCloser(strings.NewReader(sse)),
		"dev-s", "chatgpt", "gpt-6-luna", "ans-s", false, "", "", meta)
	reqMax, maxTok, finish, _, reqModel, model, _ := waitForMetaRow(t, `answer_id='ans-s'`)
	if finish != "length" || reqMax != 1000 || maxTok != 2000 || reqModel != "gpt-4.1-mini" || model != "gpt-6-luna" {
		t.Fatalf("stream meta = %q %d %d %q %q", finish, reqMax, maxTok, reqModel, model)
	}
}
