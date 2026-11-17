package main

import (
	"log"
	"os"
	"strings"
)

// Upstream model remap (A118, 17.11.2026). OpenAI shuts down gpt-4.1-mini,
// gpt-4.1 and gpt-4o-mini on 14.01.2027, and shipped app builds have those
// names hard-coded — so the swap happens here, right before the upstream
// call: the client, the tier check and the quotas keep seeing the old names.
//
//	OPENAI_MODEL_REMAP        "from=to,from=to"; empty (default) = OFF, the
//	                          upstream request and the api_calls row are
//	                          exactly what they were before this file.
//	OPENAI_MODEL_REMAP_SKIP   call types never remapped. Default
//	                          "claim_audit,barnum_judge": on gpt-6-luna they
//	                          behave differently (probe 17.11.2026) and stay
//	                          on the old model until that is reconciled.
//	OPENAI_MODEL_REMAP_EFFORT reasoning_effort sent with a remapped call.
//	                          Default "none" (API accepts none|low|medium|
//	                          high|xhigh).
type modelRemapConfig struct {
	models map[string]string
	skip   map[string]bool
	effort string
}

var modelRemap = loadModelRemap(
	os.Getenv("OPENAI_MODEL_REMAP"),
	os.Getenv("OPENAI_MODEL_REMAP_SKIP"),
	os.Getenv("OPENAI_MODEL_REMAP_EFFORT"),
)

const defaultModelRemapSkip = "claim_audit,barnum_judge"

// loadModelRemap parses the three settings. Malformed pairs are dropped with
// a log line — a typo in the env must never take the AI proxy down.
func loadModelRemap(pairs, skip, effort string) modelRemapConfig {
	cfg := modelRemapConfig{models: map[string]string{}, skip: map[string]bool{}, effort: "none"}
	for _, pair := range strings.Split(pairs, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		from, to, ok := strings.Cut(pair, "=")
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if !ok || from == "" || to == "" || from == to {
			log.Printf("⚠️ OPENAI_MODEL_REMAP: ignoring malformed pair %q", pair)
			continue
		}
		cfg.models[from] = to
	}
	if strings.TrimSpace(skip) == "" {
		skip = defaultModelRemapSkip
	}
	for _, ct := range strings.Split(skip, ",") {
		if ct = strings.TrimSpace(ct); ct != "" {
			cfg.skip[ct] = true
		}
	}
	if e := strings.TrimSpace(effort); e != "" {
		cfg.effort = e
	}
	if len(cfg.models) > 0 {
		log.Printf("🔁 OpenAI model remap ON: %v (skip call types: %v, reasoning_effort=%s)", cfg.models, cfg.skip, cfg.effort)
	}
	return cfg
}

// applyModelRemap rewrites an OpenAI chat-completions request in place when
// [model] is remapped for this [callType], and returns the model actually
// called (what api_calls must record so cost reports price it correctly).
// Not remapped — the request is not touched at all and [model] comes back.
//
// The replacement family rejects `temperature` and takes
// `max_completion_tokens` instead of `max_tokens`.
func applyModelRemap(cfg modelRemapConfig, openAIRequest map[string]interface{}, model, callType string) string {
	to, ok := cfg.models[model]
	if !ok || cfg.skip[callType] {
		return model
	}
	openAIRequest["model"] = to
	delete(openAIRequest, "temperature")
	if mt, has := openAIRequest["max_tokens"]; has {
		delete(openAIRequest, "max_tokens")
		openAIRequest["max_completion_tokens"] = mt
	}
	openAIRequest["reasoning_effort"] = cfg.effort
	return to
}
