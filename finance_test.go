package main

import (
	"testing"
	"time"
)

func d(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func TestParseRateSchedule(t *testing.T) {
	cases := []struct {
		in       string
		fallback float64
		wantErr  bool
		probes   map[string]float64 // date → expected pct
	}{
		{"", 15, false, map[string]float64{"2026-01-01 00:00:00": 15, "2030-01-01 00:00:00": 15}},
		{"30", 15, false, map[string]float64{"2026-01-01 00:00:00": 30}},
		{"30;2026-09-01=15", 15, false, map[string]float64{
			"2026-08-31 23:59:59": 30, "2026-09-01 00:00:00": 15, "2027-03-01 00:00:00": 15}},
		// steps given out of order are sorted
		{"30;2027-01-01=30;2026-09-01=15", 15, false, map[string]float64{
			"2026-10-01 00:00:00": 15, "2027-01-01 00:00:00": 30}},
		// only steps, base falls back
		{"2026-09-01=15", 30, false, map[string]float64{"2026-08-01 00:00:00": 30, "2026-09-02 00:00:00": 15}},
		{"abc", 15, true, nil},
		{"30;2026-13-01=15", 15, true, nil},
		{"30;2026-09-01=150", 15, true, nil},
		{"30;2026-09-01", 15, true, nil},
	}
	for _, c := range cases {
		rs, err := parseRateSchedule(c.in, c.fallback)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		for when, want := range c.probes {
			if got := rs.at(d(when)); got != want {
				t.Errorf("%q at %s: got %v want %v", c.in, when, got, want)
			}
		}
	}
}

func TestParsePriceSchedule(t *testing.T) {
	ps, err := parsePriceSchedule(`{"2026-09-08":{"yearly":29.99},"2026-12-01":{"astrolytix_pro_lifetime_v2":79.99}}`,
		map[string]float64{"astrolytix_pro_monthly_v2": 5.49})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		pid  string
		when string
		want float64
	}{
		{"astrolytix_pro_yearly_v2", "2026-09-07 23:59:59", 49.99}, // before the step: default
		{"astrolytix_pro_yearly_v2", "2026-09-08 00:00:00", 29.99}, // plan key matches product id
		{"yearly", "2026-10-01 00:00:00", 29.99},                   // bare plan name (MRR)
		{"astrolytix_pro_monthly_v2", "2026-10-01 00:00:00", 5.49}, // undated override still applies
		{"astrolytix_pro_lifetime_v2", "2026-11-30 00:00:00", 99.99},
		{"astrolytix_pro_lifetime_v2", "2026-12-01 00:00:00", 79.99}, // product-id key
		{"astrolytix_pro_yearly_v2", "2027-01-01 00:00:00", 29.99},   // earlier step persists past later unrelated step
	}
	for _, c := range cases {
		if got := ps.priceAt(c.pid, d(c.when)); got != c.want {
			t.Errorf("%s at %s: got %v want %v", c.pid, c.when, got, c.want)
		}
	}

	if _, err := parsePriceSchedule(`{"2026-09-08":{"yearly":-1}}`, nil); err == nil {
		t.Error("negative price accepted")
	}
	if _, err := parsePriceSchedule(`{"09/08/2026":{"yearly":29.99}}`, nil); err == nil {
		t.Error("bad date accepted")
	}
	if _, err := parsePriceSchedule(`not json`, nil); err == nil {
		t.Error("bad json accepted")
	}
	empty, err := parsePriceSchedule("", nil)
	if err != nil || empty.priceAt("astrolytix_pro_yearly_v2", d("2026-09-09 00:00:00")) != 49.99 {
		t.Errorf("empty schedule must fall back to defaults (err=%v)", err)
	}
}

func TestFinanceIsTrialStart(t *testing.T) {
	ends := map[string]bool{"DID_RENEW": true, "EXPIRED": true}
	now := d("2026-09-07 12:00:00")
	ev := func(kind, when string) financeSubEvent { return financeSubEvent{kind: kind, ts: d(when)} }
	start := ev("SUBSCRIBED", "2026-08-01 00:00:00")

	cases := []struct {
		name         string
		start        financeSubEvent
		later        []financeSubEvent
		wantTrial    bool
		wantInferred bool
	}{
		{"offer says free trial", financeSubEvent{kind: "SUBSCRIBED", ts: start.ts, offerKnown: true, freeTrial: true},
			[]financeSubEvent{ev("DID_RENEW", "2026-09-01 00:00:00")}, true, false},
		{"offer known, no trial — even if it expires fast", financeSubEvent{kind: "SUBSCRIBED", ts: start.ts, offerKnown: true, freeTrial: false},
			[]financeSubEvent{ev("EXPIRED", "2026-08-08 00:00:00")}, false, false},
		{"legacy: renewed on day 7 → trial", start,
			[]financeSubEvent{start, ev("DID_RENEW", "2026-08-07 16:00:00"), ev("DID_RENEW", "2026-09-07 16:00:00")}, true, true},
		{"legacy: expired on day 7 → trial", start,
			[]financeSubEvent{start, ev("DID_CHANGE_RENEWAL_STATUS", "2026-08-03 00:00:00"), ev("EXPIRED", "2026-08-08 00:00:00")}, true, true},
		{"legacy: first renewal after a month → paid up front", start,
			[]financeSubEvent{start, ev("DID_RENEW", "2026-09-01 00:00:00")}, false, true},
		{"legacy: expired after 66 days, never renewed → paid", start,
			[]financeSubEvent{ev("EXPIRED", "2026-10-06 00:00:00")}, false, true},
		{"legacy: events before the start belong to a previous cycle", ev("SUBSCRIBED", "2026-08-20 00:00:00"),
			[]financeSubEvent{ev("SUBSCRIBED", "2026-06-01 00:00:00"), ev("DID_RENEW", "2026-06-07 16:00:00"),
				ev("EXPIRED", "2026-07-07 00:00:00"), ev("DID_RENEW", "2026-09-20 00:00:00")}, false, true},
		{"legacy: no events yet, started 3 days ago → trial in progress", ev("SUBSCRIBED", "2026-09-04 12:00:00"),
			nil, true, true},
		{"legacy: no events, started 30 days ago → paid", ev("SUBSCRIBED", "2026-08-08 12:00:00"),
			nil, false, true},
		{"legacy: yearly with no events for months → paid", ev("SUBSCRIBED", "2026-06-12 18:29:39"),
			[]financeSubEvent{ev("SUBSCRIBED", "2026-06-12 18:29:39")}, false, true},
	}
	for _, c := range cases {
		trial, inferred := financeIsTrialStart(c.start, c.later, ends, now)
		if trial != c.wantTrial || inferred != c.wantInferred {
			t.Errorf("%s: got (trial=%v inferred=%v) want (%v %v)", c.name, trial, inferred, c.wantTrial, c.wantInferred)
		}
	}
}

func TestFinanceStoreMonthAddUsesEventRate(t *testing.T) {
	var sm financeStoreMonth
	sm.add(4.99, 30) // August event, pre-SBP
	sm.add(4.99, 15) // September event
	sm.add(-4.99, 15)
	if got := round2(sm.Gross); got != 4.99 {
		t.Errorf("gross %v", got)
	}
	if got := round2(sm.feeAcc); got != round2(4.99*0.30) {
		t.Errorf("fee %v want %v", got, round2(4.99*0.30))
	}
}
