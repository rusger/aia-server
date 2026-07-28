package main

import "testing"

func TestExternalCheckTagAllowlisted(t *testing.T) {
	got, overhead := normalizeAICallType("external_check")
	if got != "external_check" || !overhead {
		t.Errorf("normalizeAICallType(external_check) = (%q, %v), want (external_check, true)", got, overhead)
	}
}

// The +12 cap used to reject every birth east of UTC+12 — NZDT (+13),
// Chatham (+12.75), Kiribati Line Islands (+14). Found by the 2026-07-27
// ephemeris accuracy audit (tools/forecast_cli, phase 1 edge cases).
func TestSanitizeTimezoneRange(t *testing.T) {
	valid := []string{"-12", "-11.5", "0", "5.5", "12", "12.5", "12.75", "13", "13.75", "14"}
	for _, tz := range valid {
		if _, err := sanitizeTimezone(tz); err != nil {
			t.Errorf("sanitizeTimezone(%q) rejected a real-world offset: %v", tz, err)
		}
	}

	invalid := []string{"-12.5", "14.25", "15", "24", "abc", ""}
	for _, tz := range invalid {
		if _, err := sanitizeTimezone(tz); err == nil {
			t.Errorf("sanitizeTimezone(%q) accepted an out-of-range offset", tz)
		}
	}
}
