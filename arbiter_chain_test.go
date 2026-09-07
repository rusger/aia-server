package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeBin(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func readJournal(t *testing.T, path string) []llmUsageEntry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	var out []llmUsageEntry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e llmUsageEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// claude hits the subscription limit (production signature 06.09: exit 1 with
// the JSON on stdout) → codex answers; both attempts are journaled and the
// audit label names the fallback provider.
func TestArbiterChainLimitToCodex(t *testing.T) {
	dir := t.TempDir()
	claude := fakeBin(t, dir, "claude", `echo 'usage limit reached' >&2; exit 1`+"\n")
	codex := fakeBin(t, dir, "codex", `while [ $# -gt 0 ]; do [ "$1" = "-o" ] && O=$2; [ "$1" = "-c" ] && echo "$2" >> "`+dir+`/args"; shift; done
printf '{"changed":false,"changes":[],"corrected":"same"}' > "$O"
echo '{"type":"turn.completed","usage":{"input_tokens":9,"output_tokens":3}}'`+"\n")
	journal := filepath.Join(dir, "usage.jsonl")
	t.Setenv("CLAUDE_BIN", claude)
	t.Setenv("CODEX_BIN", codex)
	t.Setenv("LLM_USAGE_LOG", journal)
	t.Setenv("LLM_FALLBACK", "codex,openai")
	t.Setenv("CODEX_MODEL", "gpt-5.6-sol")

	reply, label, err := callModelChain(context.Background(), "check this", "claude-cli-default")
	if err != nil || !strings.Contains(reply, `"corrected":"same"`) || label != "codex:gpt-5.6-sol" {
		t.Fatalf("reply=%q label=%q err=%v", reply, label, err)
	}
	rows := readJournal(t, journal)
	if len(rows) != 2 || rows[0].Provider != "claude" || rows[0].OK || rows[0].ErrClass != "limit" ||
		rows[1].Provider != "codex" || !rows[1].OK || rows[1].Tier != 2 || !rows[1].Fallback || rows[1].In != 9 {
		t.Fatalf("journal: %+v", rows)
	}
	if rows[0].Comp != "astro-arbiter" || rows[0].Purpose != "arbiter" {
		t.Fatalf("labels: %+v", rows[0])
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	for _, must := range []string{"features.shell_tool=false", "features.unified_exec=false", `web_search="disabled"`} {
		if !strings.Contains(string(args), must) {
			t.Fatalf("codex without %s: %s", must, args)
		}
	}
}

// claude and codex both fail → the OpenAI API tier answers with gpt-4.1;
// with LLM_FALLBACK=off the claude error comes back untouched.
func TestArbiterChainThirdTierAndOff(t *testing.T) {
	dir := t.TempDir()
	claude := fakeBin(t, dir, "claude", `exit 1`+"\n")
	codex := fakeBin(t, dir, "codex", `echo boom >&2; exit 2`+"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string              `json:"model"`
			Messages []map[string]string `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "gpt-4.1" || len(req.Messages) != 2 || req.Messages[1]["content"] != "p" {
			t.Errorf("api request: %+v", req)
		}
		_, _ = w.Write([]byte(`{"model":"gpt-4.1","choices":[{"message":{"content":"from api"}}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`))
	}))
	defer srv.Close()
	journal := filepath.Join(dir, "usage.jsonl")
	t.Setenv("CLAUDE_BIN", claude)
	t.Setenv("CODEX_BIN", codex)
	t.Setenv("LLM_USAGE_LOG", journal)
	t.Setenv("LLM_FALLBACK", "codex,openai")
	t.Setenv("OPENAI_BASE_URL", srv.URL)
	oldKey := OPENAI_API_KEY
	OPENAI_API_KEY = "sk-test"
	defer func() { OPENAI_API_KEY = oldKey }()

	reply, label, err := callModelChain(context.Background(), "p", "m")
	if err != nil || reply != "from api" || label != "openai:gpt-4.1" {
		t.Fatalf("reply=%q label=%q err=%v", reply, label, err)
	}
	rows := readJournal(t, journal)
	if len(rows) != 3 || rows[2].Provider != "openai" || rows[2].Tier != 3 || !rows[2].OK || rows[2].In != 4 {
		t.Fatalf("journal: %+v", rows)
	}

	t.Setenv("LLM_FALLBACK", "off")
	_ = os.Remove(journal)
	if _, _, err := callModelChain(context.Background(), "p", "m"); err == nil || !strings.Contains(err.Error(), "claude -p failed") {
		t.Fatalf("off: expected the claude error, got %v", err)
	}
	if rows := readJournal(t, journal); len(rows) != 1 || rows[0].OK {
		t.Fatalf("off journal: %+v", rows)
	}
}

// Empty key → third tier fails without network; the chain reports the last error.
func TestArbiterChainAllFail(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLAUDE_BIN", fakeBin(t, dir, "claude", `exit 1`+"\n"))
	t.Setenv("CODEX_BIN", fakeBin(t, dir, "codex", `exit 1`+"\n"))
	t.Setenv("LLM_USAGE_LOG", filepath.Join(dir, "usage.jsonl"))
	t.Setenv("LLM_FALLBACK", "codex,openai")
	oldKey := OPENAI_API_KEY
	OPENAI_API_KEY = ""
	defer func() { OPENAI_API_KEY = oldKey }()
	if _, _, err := callModelChain(context.Background(), "p", "m"); err == nil || !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Fatalf("expected key error, got %v", err)
	}
	if rows := readJournal(t, filepath.Join(dir, "usage.jsonl")); len(rows) != 3 || rows[2].ErrClass != "error" {
		t.Fatalf("journal: %+v", rows)
	}
}

func TestLLMClassOf(t *testing.T) {
	if got := llmClassOf(&llmTierErr{"timeout", nil}); got != "timeout" {
		t.Fatalf("tier class: %s", got)
	}
	for text, want := range map[string]string{
		`claude -p failed: exit status 1: {"duration_api_ms":0`: "limit",
		"You've hit your limit":                                 "limit",
		"HTTP 429":                                              "limit",
		"json parse error":                                      "error",
	} {
		if got := llmClassOf(errors.New(text)); got != want {
			t.Errorf("%q: %s != %s", text, got, want)
		}
	}
}
