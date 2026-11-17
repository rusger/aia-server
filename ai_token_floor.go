package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// Per-call-type floor for the client-supplied max_tokens (A117, 17.11.2026).
//
// The app sends max_tokens with every overhead call, and shipped builds keep
// sending what they were built with. The claim audit asks for 900, which
// truncates the JSON on dense answers — 349 of 2343 audits in 14 days ended
// exactly at 900 tokens, the app could not parse them and the answer shipped
// unaudited. Raising the limit for builds already in users' hands is only
// possible here.
//
//	AI_MAX_TOKENS_FLOOR  "call_type=N,call_type:M=N" (e.g.
//	                     "claim_audit=2500,chatgpt:1000=2000").
//	                     Empty (default) = OFF: nothing is changed.
//
// "call_type=N" raises every smaller limit of that call type. "call_type:M=N"
// raises ONLY a request that asked for exactly M. The exact form exists for
// "chatgpt": the proxy logs translations (500), the short forecast (500),
// highlights (900) and the marathon report (900, a deliberate cost guard on
// the super model) under that same call type, so a blanket chatgpt floor
// would lift all of them — while the truncated chat answers ask for exactly
// 1000 or 1500.
const aiMaxTokensFloorCeiling = 8000 // typo guard

var aiMaxTokensFloor = loadMaxTokensFloor(os.Getenv("AI_MAX_TOKENS_FLOOR"))

// loadMaxTokensFloor parses the setting; malformed pairs are dropped with a
// log line so a typo can never take the AI proxy down.
func loadMaxTokensFloor(pairs string) map[string]int {
	floors := map[string]int{}
	for _, pair := range strings.Split(pairs, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		callType, raw, ok := strings.Cut(pair, "=")
		callType = strings.TrimSpace(callType)
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if !ok || callType == "" || err != nil || n <= 0 || n > aiMaxTokensFloorCeiling {
			log.Printf("⚠️ AI_MAX_TOKENS_FLOOR: ignoring malformed pair %q", pair)
			continue
		}
		// "call_type:M" — the exact-value form; M must be a positive number
		// below the new limit, otherwise the pair is malformed.
		if name, exact, has := strings.Cut(callType, ":"); has {
			m, err := strconv.Atoi(strings.TrimSpace(exact))
			name = strings.TrimSpace(name)
			if name == "" || err != nil || m <= 0 || m >= n {
				log.Printf("⚠️ AI_MAX_TOKENS_FLOOR: ignoring malformed pair %q", pair)
				continue
			}
			callType = name + ":" + strconv.Itoa(m)
		}
		floors[callType] = n
	}
	if len(floors) > 0 {
		log.Printf("📏 AI max_tokens floors ON: %v", floors)
	}
	return floors
}

// applyMaxTokensFloor returns the max_tokens to send upstream. A client value
// of 0 means "not set" and stays 0 — the floor only ever raises a limit the
// client did set.
//
// [rawCallType] is the tag exactly as the app sent it. A tag the proxy
// clamped to another call type ("highlights", "marathon_report" → "chatgpt")
// marks a feature with its own deliberate limit — the marathon report's 900
// is a cost guard on the super model — and is never raised, whatever the
// setting says.
func applyMaxTokensFloor(floors map[string]int, callType, rawCallType string, maxTokens int) int {
	if maxTokens <= 0 || (rawCallType != "" && rawCallType != callType) {
		return maxTokens
	}
	if floor, ok := floors[callType+":"+strconv.Itoa(maxTokens)]; ok {
		return floor
	}
	if floor, ok := floors[callType]; ok && maxTokens < floor {
		return floor
	}
	return maxTokens
}
