package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The old byte slice (`detail[:200]`) cut CJK runes in half — 10 of the
// first 107 live snippets landed with an invalid UTF-8 tail (triage
// 2026-08-28). clampDetail must always return valid UTF-8 within the cap.
func TestClampDetailRuneSafe(t *testing.T) {
	// 3-byte runes; pick a length so the byte cap lands mid-rune.
	cjk := strings.Repeat("宫", maxGuardDetailBytes/3+10) // > cap, 2000 % 3 != 0
	got := clampDetail(cjk)
	if len(got) > maxGuardDetailBytes {
		t.Fatalf("clamped detail is %d bytes, cap is %d", len(got), maxGuardDetailBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("clamped detail is not valid UTF-8")
	}
	if !strings.HasSuffix(got, "宫") {
		t.Fatalf("clamp did not end on a complete rune")
	}
}

func TestClampDetailShortUntouched(t *testing.T) {
	for _, s := range []string{"", "err: timeout", "Марс в 6-м доме ||| 火星"} {
		if got := clampDetail(s); got != s {
			t.Fatalf("short detail modified: %q -> %q", s, got)
		}
	}
}

func TestClampDetailAsciiExactCap(t *testing.T) {
	s := strings.Repeat("a", maxGuardDetailBytes+7)
	got := clampDetail(s)
	if len(got) != maxGuardDetailBytes {
		t.Fatalf("ascii clamp = %d bytes, want %d", len(got), maxGuardDetailBytes)
	}
}
