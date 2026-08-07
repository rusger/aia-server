package main

import (
	"strings"
	"testing"
)

// composeEventPush guards the "one push per delivery window" rule: several
// server events due together must merge into a single push, and an eclipse
// must swallow its own lunation (a solar eclipse IS the New Moon).

func TestComposeSingleEventKeepsOwnText(t *testing.T) {
	title, body, payload := composeEventPush([]dueItem{
		{kind: "lunar_new", params: `{"isNew":true}`, payload: "astro:lunar_phase:lunar_phase:new:2026-08-12"},
	}, "ru")
	if title != lunarNewTitle["ru"] {
		t.Fatalf("single event must keep its own title, got %q", title)
	}
	if body != lunarNewBody["ru"] {
		t.Fatalf("single event must keep its own body, got %q", body)
	}
	if payload != "astro:lunar_phase:lunar_phase:new:2026-08-12" {
		t.Fatalf("single event must keep its own payload, got %q", payload)
	}
}

func TestEclipseSwallowsSameWindowLunation(t *testing.T) {
	title, body, payload := composeEventPush([]dueItem{
		{kind: "lunar_new", params: `{"isNew":true}`, payload: "astro:lunar_phase:lunar_phase:new:2026-08-12"},
		{kind: "eclipse_solar", params: `{"solar":true}`, payload: "astro:eclipse:eclipse:solar:2026-08-12"},
	}, "en")
	// After suppression only the eclipse remains → plain eclipse push, not
	// a digest.
	if title != solarEclipseTitle["en"] {
		t.Fatalf("eclipse must swallow the lunation, got title %q", title)
	}
	if body != solarEclipseBody["en"] {
		t.Fatalf("expected plain eclipse body, got %q", body)
	}
	if payload != "astro:eclipse:eclipse:solar:2026-08-12" {
		t.Fatalf("expected eclipse payload, got %q", payload)
	}
}

func TestLunarEclipseSwallowsFullMoonOnly(t *testing.T) {
	// A full-moon lunation with a SOLAR eclipse in the group is impossible
	// astronomically but must not be suppressed by mistake — suppression is
	// pairwise (solar↔new, lunar↔full).
	title, _, _ := composeEventPush([]dueItem{
		{kind: "lunar_full", params: `{"isNew":false}`, payload: "p1"},
		{kind: "eclipse_solar", params: `{"solar":true}`, payload: "p2"},
	}, "en")
	if title != groupedEventsTitle["en"] {
		t.Fatalf("solar eclipse must not swallow a full moon; want digest, got %q", title)
	}
}

func TestPluralEventsBecomeLocalizedDigest(t *testing.T) {
	title, body, payload := composeEventPush([]dueItem{
		{kind: "station", params: `{"planet":"Mercury","retro":true}`, payload: "astro:station:station:Mercury:retro:2026-08-12"},
		{kind: "eclipse_lunar", params: `{"solar":false}`, payload: "astro:eclipse:eclipse:lunar:2026-08-12"},
	}, "ru")
	if title != groupedEventsTitle["ru"] {
		t.Fatalf("plural events must use the grouped title, got %q", title)
	}
	// Digest carries every member's title.
	if !strings.Contains(body, lunarEclipseTitle["ru"]) {
		t.Fatalf("digest must mention the eclipse, got %q", body)
	}
	if !strings.Contains(body, planetName("Mercury", "ru")) {
		t.Fatalf("digest must mention the station planet, got %q", body)
	}
	// Highest-ranked member (eclipse) donates the payload so the tap routes
	// to a relevant screen.
	if payload != "astro:eclipse:eclipse:lunar:2026-08-12" {
		t.Fatalf("expected eclipse payload to win, got %q", payload)
	}
	// Eclipse is ranked above the station, so it leads the digest.
	if !strings.HasPrefix(body, "• "+lunarEclipseTitle["ru"]) {
		t.Fatalf("eclipse must lead the digest, got %q", body)
	}
}

func TestDigestFallsBackToEnglishForUnknownLang(t *testing.T) {
	title, _, _ := composeEventPush([]dueItem{
		{kind: "station", params: `{"planet":"Venus","retro":false}`, payload: "p1"},
		{kind: "slow_ingress", params: `{"planet":"Saturn","signIdx":3}`, payload: "p2"},
	}, "xx")
	if title != groupedEventsTitle["en"] {
		t.Fatalf("unknown lang must fall back to English, got %q", title)
	}
}
