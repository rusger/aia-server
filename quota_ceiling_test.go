package main

import (
	"testing"
	"time"
)

// The daily quota counts only call_type='chatgpt' rows while the tag comes
// from the request body — so without a secondary ceiling a patched client
// could label every call as overhead and never hit the cap (2026-07-27
// paywall review). These tests pin the normalization allowlist and the
// anti-spoof total ceiling.

func addTaggedCalls(t *testing.T, deviceID, callType string, n int) {
	t.Helper()
	today := time.Now().UTC().Format("2006-01-02 15:04:05")
	for i := 0; i < n; i++ {
		if _, err := analyticsDB.Exec(
			`INSERT INTO api_calls (device_id, call_type, created_at) VALUES (?, ?, ?)`,
			deviceID, callType, today); err != nil {
			t.Fatalf("insert %s call: %v", callType, err)
		}
	}
}

func TestNormalizeAICallType(t *testing.T) {
	for _, ct := range []string{"grounding_fix", "claim_audit", "barnum_judge", "barnum_fix", "barnum_point_fix", "yoga_fix"} {
		got, overhead := normalizeAICallType(ct)
		if got != ct || !overhead {
			t.Errorf("normalizeAICallType(%q) = (%q, %v), want (%q, true)", ct, got, overhead, ct)
		}
	}
	// Unknown or empty tags must clamp to the fully-counted bucket — a spoofed
	// label may only make accounting stricter, never looser.
	for _, ct := range []string{"", "chatgpt", "astrolog", "made_up_tag", "GROUNDING_FIX"} {
		got, overhead := normalizeAICallType(ct)
		if got != "chatgpt" || overhead {
			t.Errorf("normalizeAICallType(%q) = (%q, %v), want (\"chatgpt\", false)", ct, got, overhead)
		}
	}
}

func TestDailyAICallCountSpansTagsButNotChartWork(t *testing.T) {
	setupIdentityTestDBs(t)
	register(t, "dev-ceiling", "hw-ceiling", "1.2.3.4")

	addTaggedCalls(t, "dev-ceiling", "chatgpt", 3)
	addTaggedCalls(t, "dev-ceiling", "grounding_fix", 4)
	addTaggedCalls(t, "dev-ceiling", "claim_audit", 2)
	addTaggedCalls(t, "dev-ceiling", "barnum_judge", 1)
	// Chart computation rows must NOT count toward the AI ceiling — one
	// transit-year request logs hundreds of them for honest users.
	addTaggedCalls(t, "dev-ceiling", "astrolog", 50)
	addTaggedCalls(t, "dev-ceiling", "transit-year", 20)

	if got := dailyChatGPTCount("dev-ceiling"); got != 3 {
		t.Errorf("dailyChatGPTCount = %d, want 3", got)
	}
	if got := dailyAICallCount("dev-ceiling"); got != 10 {
		t.Errorf("dailyAICallCount = %d, want 10 (3+4+2+1, chart rows excluded)", got)
	}
}

func TestSpoofedOverheadHitsSecondaryCeiling(t *testing.T) {
	setupIdentityTestDBs(t)
	register(t, "dev-spoof", "hw-spoof", "1.2.3.5")

	// An all-overhead client: zero 'chatgpt' rows, so the primary ceiling
	// never fires — but the secondary one must.
	addTaggedCalls(t, "dev-spoof", "grounding_fix", aiLimitFree*aiOverheadFactor)

	if got := dailyChatGPTCount("dev-spoof"); got != 0 {
		t.Fatalf("primary counter should see 0 spoofed calls, got %d", got)
	}
	if total := dailyAICallCount("dev-spoof"); total < aiLimitFree*aiOverheadFactor {
		t.Errorf("secondary counter = %d, want >= %d (ceiling must fire)", total, aiLimitFree*aiOverheadFactor)
	}
}

func TestOverheadSkipsPrimaryButHonestUserStaysBounded(t *testing.T) {
	setupIdentityTestDBs(t)
	register(t, "dev-honest", "hw-honest", "1.2.3.6")

	// Honest day at the free cap: 10 answers + their overhead. The last
	// answer's grounding fix arrives when used==limit; it must not be blocked
	// by the primary check (overhead skips it) and the total stays far under
	// the secondary ceiling.
	addTaggedCalls(t, "dev-honest", "chatgpt", aiLimitFree)
	addTaggedCalls(t, "dev-honest", "grounding_fix", aiLimitFree*2)
	addTaggedCalls(t, "dev-honest", "claim_audit", aiLimitFree)

	if got := dailyChatGPTCount("dev-honest"); got != aiLimitFree {
		t.Fatalf("primary counter = %d, want %d", got, aiLimitFree)
	}
	if total := dailyAICallCount("dev-honest"); total >= aiLimitFree*aiOverheadFactor {
		t.Errorf("honest 4x-per-answer day reached the secondary ceiling (%d >= %d) — factor too tight",
			total, aiLimitFree*aiOverheadFactor)
	}
}
