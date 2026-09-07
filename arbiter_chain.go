package main

// Fallback chain for the arbiter's model call (owner order 2026-09-07,
// mirrors insta-agent tgbot/llmchain.go): the server's `claude -p` runs on
// the owner's Claude Max subscription and shares that session limit with his
// working sessions — it ran dry twice (05.09, 06.09). Tiers:
//
//  1. `claude -p` (as before);
//  2. `codex exec` on the owner's ChatGPT subscription (Codex CLI logged in on
//     the server), CODEX_MODEL (default gpt-5.6-sol), all tools disabled;
//  3. OpenAI API with OPENAI_API_KEY, LLM_API_FALLBACK_MODEL (default gpt-4.1),
//     logged through logAPICallWithTokens with callType "arbiter" so the spend
//     stays attributable (project rule).
//
// Any failure of a tier moves to the next one; LLM_FALLBACK sets the order
// ("codex,openai"; "off" = claude only). Every attempt is appended to the
// usage journal LLM_USAGE_LOG (default <home>/aia/server/llm-usage.jsonl; on
// the production box it points at the shared insta-agent journal so one
// report covers every bot): ts, comp, purpose, provider, model, tier, ok,
// err_class (limit|timeout|error), err, ms, in, out, fallback.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const llmChainTimeout = 150 * time.Second

var llmLimitRe = regexp.MustCompile(`(?i)limit|quota|429|overloaded|rate.?limit|hit your|"duration_api_ms":0|insufficient`)

// llmTierErr carries the journal class of a failed tier.
type llmTierErr struct {
	class string // limit | timeout | error
	err   error
}

func (e *llmTierErr) Error() string { return e.err.Error() }
func (e *llmTierErr) Unwrap() error { return e.err }

func llmClassOf(err error) string {
	if err == nil {
		return ""
	}
	var te *llmTierErr
	if errors.As(err, &te) {
		return te.class
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if llmLimitRe.MatchString(err.Error()) {
		return "limit"
	}
	return "error"
}

func llmFallbackOrder() []string {
	raw := strings.TrimSpace(os.Getenv("LLM_FALLBACK"))
	if raw == "" {
		raw = "codex,openai"
	}
	if raw == "off" || raw == "none" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// --- usage journal ---

type llmUsageEntry struct {
	TS       string `json:"ts"`
	Comp     string `json:"comp"`
	Purpose  string `json:"purpose"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Tier     int    `json:"tier"`
	OK       bool   `json:"ok"`
	MS       int64  `json:"ms"`
	In       int64  `json:"in"`
	Out      int64  `json:"out"`
	Fallback bool   `json:"fallback"`
	ErrClass string `json:"err_class,omitempty"`
	Err      string `json:"err,omitempty"`
}

var llmLogMu sync.Mutex

func llmUsageLogPath() string {
	if p := os.Getenv("LLM_USAGE_LOG"); p != "" {
		return p
	}
	return filepath.Join(serverHome(), "aia", "server", "llm-usage.jsonl")
}

// logLLMUsage appends one line; a journal failure never breaks the reply.
func logLLMUsage(e llmUsageEntry) {
	e.TS = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	e.Comp = "astro-arbiter"
	e.Err = trimForLog(e.Err)
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	llmLogMu.Lock()
	defer llmLogMu.Unlock()
	path := llmUsageLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("⚠️ llm usage journal dir: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("⚠️ llm usage journal: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		log.Printf("⚠️ llm usage journal write: %v", err)
	}
}

// --- tiers ---

// callClaudeTier wraps callClaudeCLI with the journal class (limit vs other).
// An empty reply is a tier failure too (review r1): the chain must fall
// through to codex instead of ending on a silent-empty answer.
func callClaudeTier(ctx context.Context, prompt, model string) (string, int64, int64, error) {
	reply, err := callClaudeCLI(prompt)
	if err != nil {
		return "", 0, 0, &llmTierErr{llmClassOf(err), err}
	}
	if strings.TrimSpace(reply) == "" {
		return "", 0, 0, &llmTierErr{"error", errors.New("claude -p: empty reply")}
	}
	return reply, 0, 0, nil
}

// codexArgs: instructions via file (Linux caps one argv entry at 128 KB), all
// tools off (verified 07.09: asked to run `id`, the model answers NO_TOOLS),
// no environment inheritance, no session persisted.
func codexArgs(model, sysPath, outPath string) []string {
	return []string{"exec", "-m", model, "--skip-git-repo-check", "--ephemeral",
		"--sandbox", "read-only", "--color", "never", "--json",
		"-c", fmt.Sprintf("model_instructions_file=%q", sysPath),
		"-c", "features.shell_tool=false", "-c", "features.unified_exec=false",
		"-c", `web_search="disabled"`, "-c", "tools.view_image=false",
		"-c", `shell_environment_policy.inherit="none"`,
		"-c", `approval_policy="never"`,
		"-o", outPath, "-"}
}

const codexArbiterInstructions = "You are a careful fact-checking assistant. Follow the task in the message exactly and return only what it asks for."

func callCodexTier(ctx context.Context, prompt, model string) (string, int64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, llmChainTimeout)
	defer cancel()
	work, err := os.MkdirTemp("", "arbiter-codex-")
	if err != nil {
		return "", 0, 0, &llmTierErr{"error", fmt.Errorf("codex: temp dir: %w", err)}
	}
	defer os.RemoveAll(work)
	sysPath := filepath.Join(work, "instructions.md")
	outPath := filepath.Join(work, "last.txt")
	if err := os.WriteFile(sysPath, []byte(codexArbiterInstructions), 0o600); err != nil {
		return "", 0, 0, &llmTierErr{"error", fmt.Errorf("codex: write instructions: %w", err)}
	}
	bin := envDefault("CODEX_BIN", filepath.Join(serverHome(), ".local/bin/codex"))
	cmd := exec.CommandContext(ctx, bin, codexArgs(model, sysPath, outPath)...)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "HOME="+serverHome())
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	var errLines []string
	for _, l := range strings.Split(stderr.String(), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.Contains(l, "bubblewrap") {
			errLines = append(errLines, l)
		}
	}
	errText := strings.Join(errLines, " ")
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", 0, 0, &llmTierErr{"timeout", errors.New("codex: timeout")}
		}
		e := fmt.Errorf("codex: %w: stderr=%s stdout=%s", runErr, trimForLog(errText), trimForLog(stdout.String()))
		return "", 0, 0, &llmTierErr{llmClassOf(fmt.Errorf("%s %s", stdout.String(), errText)), e}
	}
	raw, _ := os.ReadFile(outPath)
	result := strings.TrimSpace(string(raw))
	if result == "" {
		return "", 0, 0, &llmTierErr{llmClassOf(errors.New(errText)), fmt.Errorf("codex: empty reply: %s", trimForLog(errText))}
	}
	var in, out int64
	for _, line := range strings.Split(stdout.String(), "\n") {
		if !strings.Contains(line, `"turn.completed"`) {
			continue
		}
		var ev struct {
			Usage struct {
				In  int64 `json:"input_tokens"`
				Out int64 `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(line), &ev) == nil {
			in, out = ev.Usage.In, ev.Usage.Out
		}
	}
	return result, in, out, nil
}

// openaiChatURL: OPENAI_BASE_URL lets tests point at a local server.
func openaiChatURL() string {
	return strings.TrimRight(envDefault("OPENAI_BASE_URL", "https://api.openai.com/v1"), "/") + "/chat/completions"
}

// callOpenAITier is the third tier: Chat Completions with the server's key;
// token spend is attributed to callType "arbiter".
func callOpenAITier(ctx context.Context, prompt, model string) (string, int64, int64, error) {
	if OPENAI_API_KEY == "" {
		return "", 0, 0, &llmTierErr{"error", errors.New("openai: OPENAI_API_KEY is empty")}
	}
	ctx, cancel := context.WithTimeout(ctx, llmChainTimeout)
	defer cancel()
	body, err := json.Marshal(map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": codexArbiterInstructions},
			{"role": "user", "content": prompt},
		},
	})
	if err != nil {
		return "", 0, 0, &llmTierErr{"error", err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openaiChatURL(), bytes.NewReader(body))
	if err != nil {
		return "", 0, 0, &llmTierErr{"error", err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, 0, &llmTierErr{llmClassOf(err), fmt.Errorf("openai: %w", err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", 0, 0, &llmTierErr{"error", fmt.Errorf("openai: read: %w", err)}
	}
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
			Total      int `json:"total_tokens"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", 0, 0, &llmTierErr{"error", fmt.Errorf("openai: HTTP %d, non-JSON: %s", resp.StatusCode, trimForLog(string(raw)))}
	}
	if out.Error != nil {
		class := "error"
		if resp.StatusCode == 429 || resp.StatusCode == 402 || llmLimitRe.MatchString(out.Error.Message) {
			class = "limit"
		}
		return "", 0, 0, &llmTierErr{class, fmt.Errorf("openai: HTTP %d: %s", resp.StatusCode, out.Error.Message)}
	}
	if len(out.Choices) == 0 {
		return "", 0, 0, &llmTierErr{"error", fmt.Errorf("openai: empty choices (HTTP %d)", resp.StatusCode)}
	}
	logAPICallWithTokens("server", "arbiter", model, out.Usage.Prompt, out.Usage.Completion, out.Usage.Total, 0)
	return out.Choices[0].Message.Content, int64(out.Usage.Prompt), int64(out.Usage.Completion), nil
}

// callModelChain runs the arbiter prompt through the tiers. It returns the
// reply and a provider-qualified model label for the audit row ("claude:<model>"
// when the first tier answered, "codex:gpt-5.6-sol" / "openai:gpt-4.1" when a
// fallback did). On total failure the last tier's error is returned; every
// attempt is already in the journal.
func callModelChain(ctx context.Context, prompt, claudeModel string) (string, string, error) {
	type tier struct {
		provider, model string
		run             func(context.Context, string, string) (string, int64, int64, error)
	}
	tiers := []tier{{"claude", claudeModel, callClaudeTier}}
	for _, p := range llmFallbackOrder() {
		switch p {
		case "codex":
			tiers = append(tiers, tier{"codex", envDefault("CODEX_MODEL", "gpt-5.6-sol"), callCodexTier})
		case "openai":
			tiers = append(tiers, tier{"openai", envDefault("LLM_API_FALLBACK_MODEL", "gpt-4.1"), callOpenAITier})
		}
	}
	var last error
	for i, t := range tiers {
		start := time.Now()
		reply, in, out, err := t.run(ctx, prompt, t.model)
		entry := llmUsageEntry{Purpose: "arbiter", Provider: t.provider, Model: t.model, Tier: i + 1,
			OK: err == nil, MS: time.Since(start).Milliseconds(), In: in, Out: out, Fallback: i > 0}
		if err != nil {
			entry.ErrClass = llmClassOf(err)
			entry.Err = err.Error()
			logLLMUsage(entry)
			last = err
			if i+1 < len(tiers) {
				log.Printf("⚠️ arbiter: %s failed (%s) — falling back to tier %d (%s)", t.provider, entry.ErrClass, i+2, tiers[i+1].provider)
			}
			continue
		}
		logLLMUsage(entry)
		if i > 0 {
			log.Printf("✅ arbiter: tier %d (%s %s) answered in %d ms", i+1, t.provider, t.model, entry.MS)
		}
		return reply, t.provider + ":" + t.model, nil
	}
	return "", "", last
}
