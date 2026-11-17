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
//	AI_MAX_TOKENS_FLOOR  "call_type=N,call_type=N" (e.g. "claim_audit=2500").
//	                     Empty (default) = OFF: nothing is changed.
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
func applyMaxTokensFloor(floors map[string]int, callType string, maxTokens int) int {
	if floor, ok := floors[callType]; ok && maxTokens > 0 && maxTokens < floor {
		return floor
	}
	return maxTokens
}
