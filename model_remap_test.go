package main

import (
	"encoding/json"
	"testing"
)

func remapRequest() map[string]interface{} {
	return map[string]interface{}{
		"model":       "gpt-4.1-mini",
		"messages":    []map[string]string{{"role": "user", "content": "hi"}},
		"temperature": 0.7,
		"max_tokens":  2500,
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Flag unset (the default): the upstream body is byte-identical and the
// logged model is the requested one.
func TestModelRemapOffIsByteIdentical(t *testing.T) {
	cfg := loadModelRemap("", "", "")
	for _, callType := range []string{"chatgpt", "grounding_fix", "claim_audit"} {
		req := remapRequest()
		before := mustJSON(t, req)
		if got := applyModelRemap(cfg, req, "gpt-4.1-mini", callType, ""); got != "gpt-4.1-mini" {
			t.Fatalf("%s: logged model = %q, want the requested one", callType, got)
		}
		if after := mustJSON(t, req); after != before {
			t.Fatalf("%s: body changed with the flag off:\n%s\n%s", callType, before, after)
		}
	}
}

func TestModelRemapOnRewritesRequest(t *testing.T) {
	cfg := loadModelRemap("gpt-4.1-mini=gpt-6-luna, gpt-4o-mini=gpt-6-luna", "", "")
	req := remapRequest()
	if got := applyModelRemap(cfg, req, "gpt-4.1-mini", "chatgpt", ""); got != "gpt-6-luna" {
		t.Fatalf("logged model = %q, want gpt-6-luna", got)
	}
	want := `{"max_completion_tokens":2500,"messages":[{"content":"hi","role":"user"}],"model":"gpt-6-luna","reasoning_effort":"none"}`
	if got := mustJSON(t, req); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
}

// The streaming request carries extra keys; they survive the rewrite.
func TestModelRemapKeepsStreamOptions(t *testing.T) {
	cfg := loadModelRemap("gpt-4o-mini=gpt-6-luna", "", "low")
	req := map[string]interface{}{"model": "gpt-4o-mini", "messages": []map[string]string{}, "stream": true,
		"stream_options": map[string]interface{}{"include_usage": true}}
	applyModelRemap(cfg, req, "gpt-4o-mini", "chatgpt", "")
	want := `{"messages":[],"model":"gpt-6-luna","reasoning_effort":"low","stream":true,"stream_options":{"include_usage":true}}`
	if got := mustJSON(t, req); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
}

// claim_audit and barnum_judge stay on the old model until reconciled.
func TestModelRemapSkipsAuditAndJudgeByDefault(t *testing.T) {
	cfg := loadModelRemap("gpt-4o-mini=gpt-6-luna", "", "")
	for _, callType := range []string{"claim_audit", "barnum_judge"} {
		req := remapRequest()
		req["model"] = "gpt-4o-mini"
		before := mustJSON(t, req)
		if got := applyModelRemap(cfg, req, "gpt-4o-mini", callType, ""); got != "gpt-4o-mini" {
			t.Fatalf("%s was remapped to %q", callType, got)
		}
		if after := mustJSON(t, req); after != before {
			t.Fatalf("%s: body changed", callType)
		}
	}
	// An explicit skip list replaces the default one.
	cfg = loadModelRemap("gpt-4o-mini=gpt-6-luna", "yoga_fix", "")
	req := remapRequest()
	if got := applyModelRemap(cfg, req, "gpt-4o-mini", "claim_audit", ""); got != "gpt-6-luna" {
		t.Fatalf("explicit skip list: claim_audit not remapped (%q)", got)
	}
}

func TestModelRemapUnknownModelAndGarbage(t *testing.T) {
	cfg := loadModelRemap("garbage,=x,y=, a=a ,gpt-4.1=gpt-6-luna,,", "", "")
	if len(cfg.models) != 1 || cfg.models["gpt-4.1"] != "gpt-6-luna" {
		t.Fatalf("parsed map = %v", cfg.models)
	}
	req := remapRequest()
	req["model"] = "o1"
	before := mustJSON(t, req)
	if got := applyModelRemap(cfg, req, "o1", "chatgpt", ""); got != "o1" {
		t.Fatalf("unmapped model changed to %q", got)
	}
	if after := mustJSON(t, req); after != before {
		t.Fatal("unmapped model: body changed")
	}
}

// The proxy clamps unknown tags to "chatgpt"; the skip list must still see
// the tag the app sent.
func TestModelRemapSkipsByRawCallType(t *testing.T) {
	cfg := loadModelRemap("gpt-4.1-mini=gpt-6-luna", "claim_audit,highlights,marathon_report", "")
	for _, raw := range []string{"highlights", "marathon_report"} {
		req := remapRequest()
		before := mustJSON(t, req)
		if got := applyModelRemap(cfg, req, "gpt-4.1-mini", "chatgpt", raw); got != "gpt-4.1-mini" {
			t.Fatalf("raw tag %q was remapped to %q", raw, got)
		}
		if after := mustJSON(t, req); after != before {
			t.Fatalf("raw tag %q: body changed", raw)
		}
	}
	// A plain answer (no tag, or a tag outside the skip list) is remapped.
	for _, raw := range []string{"", "something_else"} {
		req := remapRequest()
		if got := applyModelRemap(cfg, req, "gpt-4.1-mini", "chatgpt", raw); got != "gpt-6-luna" {
			t.Fatalf("raw tag %q: got %q, want gpt-6-luna", raw, got)
		}
	}
}
