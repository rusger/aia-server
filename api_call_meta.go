package main

// A117 (owner 17.11.2026, «замеры чего не видно» 1–4): the chat proxy rows of
// api_calls also record what was asked and how the model stopped, so length
// cut-offs, the max_tokens floor (ai_token_floor.go) and the model remap
// (model_remap.go) can be measured from data instead of guessed from
// completion_tokens landing on a round number.
//
//	req_max_tokens  max_tokens the client sent (0 = none)
//	max_tokens      max_tokens actually sent upstream after the floor (0 = none)
//	finish_reason   OpenAI finish_reason of the first choice ("stop", "length", …; '' = unknown)
//	client_tag      call_type exactly as the client sent it (call_type keeps the
//	                allowlisted value — unknown tags are clamped to "chatgpt" there)
//	req_model       model the client asked for (model keeps what was billed upstream)
//
// Only the two chat proxy paths (/api/chatgpt, /api/chatgpt-stream) fill them;
// every other row keeps the column defaults. Readers select columns by name
// (map checked 23.11.2026: finance.go, engagement_insights.go, identity.go,
// tts.go, the rollup into api_calls_monthly, weekly_report.py, MCP finance /
// subscriptions, ~/aia/tools/*.sh) — new columns change none of them.

import (
	"log"
	"strings"
)

// apiCallMetaColumns: ADD COLUMN with a constant DEFAULT is a schema-only
// change in SQLite (no table rewrite), so it is instant on the big analytics.db.
var apiCallMetaColumns = []struct{ name, decl string }{
	{"req_max_tokens", "INTEGER DEFAULT 0"},
	{"max_tokens", "INTEGER DEFAULT 0"},
	{"finish_reason", "TEXT DEFAULT ''"},
	{"client_tag", "TEXT DEFAULT ''"},
	{"req_model", "TEXT DEFAULT ''"},
}

const apiCallMetaMaxLen = 64

type apiCallMeta struct {
	ReqMaxTokens int
	MaxTokens    int
	FinishReason string
	ClientTag    string
	ReqModel     string
}

// newAPICallMeta snapshots the client's request before any server-side change
// (entitlement model, marathon override, token floor, remap).
func newAPICallMeta(req ChatGPTProxyRequest) apiCallMeta {
	return apiCallMeta{ReqMaxTokens: req.MaxTokens, ClientTag: req.CallType, ReqModel: req.Model}
}

func clampMeta(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > apiCallMetaMaxLen {
		// byte cut, then drop a rune split by it
		s = strings.ToValidUTF8(s[:apiCallMetaMaxLen], "")
	}
	return s
}

// addAPICallMetaColumns is idempotent: "duplicate column" on an already
// migrated DB is expected; any other failure is logged, never fatal.
func addAPICallMetaColumns() {
	if analyticsDB == nil {
		return
	}
	for _, c := range apiCallMetaColumns {
		if _, err := analyticsDB.Exec(`ALTER TABLE api_calls ADD COLUMN ` + c.name + ` ` + c.decl); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			log.Printf("⚠️ api_calls.%s migration: %v", c.name, err)
		}
	}
}

// logAPICallWithMeta is logAPICallForAnswer plus the request/response
// metadata. If the columns are missing (migration failed) the row is still
// written without them — cost accounting must never be lost to telemetry.
func logAPICallWithMeta(deviceID, callType, model, answerID string, promptTokens, completionTokens, totalTokens, cachedTokens int, meta apiCallMeta) {
	if analyticsDB == nil {
		return
	}
	answerID = clampAnswerID(answerID)
	if meta.ReqMaxTokens < 0 {
		meta.ReqMaxTokens = 0
	}
	if meta.MaxTokens < 0 {
		meta.MaxTokens = 0
	}
	finish, tag, reqModel := clampMeta(meta.FinishReason), clampMeta(meta.ClientTag), clampMeta(meta.ReqModel)
	go func() {
		_, err := analyticsDB.Exec(
			`INSERT INTO api_calls (device_id, call_type, model, prompt_tokens, completion_tokens, total_tokens, cached_tokens, answer_id,
			  req_max_tokens, max_tokens, finish_reason, client_tag, req_model) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, callType, model, promptTokens, completionTokens, totalTokens, cachedTokens, answerID,
			meta.ReqMaxTokens, meta.MaxTokens, finish, tag, reqModel)
		if err == nil {
			return
		}
		log.Printf("⚠️ api_calls meta insert failed, writing without meta: %v", err)
		if _, err := analyticsDB.Exec(
			`INSERT INTO api_calls (device_id, call_type, model, prompt_tokens, completion_tokens, total_tokens, cached_tokens, answer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, callType, model, promptTokens, completionTokens, totalTokens, cachedTokens, answerID); err != nil {
			log.Printf("⚠️ Failed to log API call: %v", err)
		}
	}()
}
