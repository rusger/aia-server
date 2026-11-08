package main

import "testing"

func TestMarathonReportModel(t *testing.T) {
	if m, n := marathonReportModel("marathon_report", MODEL_PREMIUM, 700); m != MODEL_SUPER || n != 700 {
		t.Fatalf("report: got %s %d", m, n)
	}
	for _, in := range []int{0, 5000} {
		if _, n := marathonReportModel("marathon_report", MODEL_ECONOMY, in); n != marathonReportMaxTokens {
			t.Fatalf("cap for %d: got %d", in, n)
		}
	}
	for _, ct := range []string{"", "chatgpt", "marathon_task", "guru_chat"} {
		if m, n := marathonReportModel(ct, MODEL_PREMIUM, 5000); m != MODEL_PREMIUM || n != 5000 {
			t.Fatalf("%q must stay untouched: got %s %d", ct, m, n)
		}
	}
}
