package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Every SEO string must exist in all 16 languages and keep the placeholders
// of the reference locale (ru), so a page never falls back to English or
// renders a literal "{planet}".
func TestSeoStringsCoverAllLangs(t *testing.T) {
	for key, m := range seoStr {
		ref, ok := m["ru"]
		if !ok {
			t.Errorf("%s: missing ru reference", key)
			continue
		}
		for _, lang := range seoLangs {
			v, ok := m[lang]
			if !ok || strings.TrimSpace(v) == "" {
				t.Errorf("%s: missing %s", key, lang)
				continue
			}
			for _, ph := range []string{"{planet}", "{sign}", "{year}"} {
				if strings.Contains(ref, ph) != strings.Contains(v, ph) {
					t.Errorf("%s[%s]: placeholder %s mismatch vs ru", key, lang, ph)
				}
			}
		}
	}
	for _, lang := range seoLangs {
		if seoLangNames[lang] == "" {
			t.Errorf("seoLangNames missing %s", lang)
		}
	}
	for _, p := range seoRetroPlanets {
		if _, ok := seoStr["retro_meaning_"+p]; !ok {
			t.Errorf("retro_meaning_%s missing", p)
		}
	}
}

func TestSeoTSubstitutes(t *testing.T) {
	got := seoT("enters", "ru", map[string]string{"planet": "Марс", "sign": "Овен"})
	if got != "Марс входит в Овен" {
		t.Errorf("got %q", got)
	}
	if seoT("enters", "xx", map[string]string{"planet": "Mars", "sign": "Aries"}) != "Mars enters Aries" {
		t.Error("unknown lang must fall back to en")
	}
}

func TestMoonLonShift(t *testing.T) {
	// 12 h after noon the Moon has moved ~6.6°; wrap-around stays in [0,360).
	if got := moonLonShift(10, 12*time.Hour); got < 16.5 || got > 16.7 {
		t.Errorf("12h shift: %v", got)
	}
	if got := moonLonShift(2, -12*time.Hour); got < 355 || got >= 360 {
		t.Errorf("negative wrap: %v", got)
	}
}

func TestTruncDesc(t *testing.T) {
	long := strings.Repeat("word ", 60)
	if d := truncDesc(long); len([]rune(d)) > 160 || !strings.HasSuffix(d, "…") {
		t.Errorf("truncDesc: %q", d)
	}
	if truncDesc("short") != "short" {
		t.Error("short must be untouched")
	}
}

func TestSeoURL(t *testing.T) {
	if seoURL("ru", "index.html") != "https://astrolytix.com/astro/ru/" {
		t.Error("hub must be a directory URL")
	}
	if seoURL("ru", "2026/transits.html") != "https://astrolytix.com/astro/ru/2026/transits.html" {
		t.Error("page URL")
	}
}

func day(y, m, d int) time.Time { return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC) }

func TestPairRetroPeriods(t *testing.T) {
	signAt := func(planet string, d time.Time) (int, error) { return d.Day() % 12, nil }
	stations := []stationEvt{
		// leading direct station whose retro start is before the window: skipped
		{planet: "Mars", retro: false, date: day(2025, 2, 24)},
		// period straddling the year boundary into 2026
		{planet: "Jupiter", retro: true, date: day(2025, 11, 11)},
		{planet: "Jupiter", retro: false, date: day(2026, 3, 11)},
		// period fully inside 2026 (given out of order on purpose)
		{planet: "Jupiter", retro: false, date: day(2027, 4, 15)},
		{planet: "Jupiter", retro: true, date: day(2026, 12, 13)},
		// other planet's stations must be ignored
		{planet: "Saturn", retro: true, date: day(2026, 7, 28)},
	}
	got, err := pairRetroPeriods(stations, "Jupiter", 2026, signAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].start.Equal(day(2025, 11, 11)) || !got[0].end.Equal(day(2026, 3, 11)) ||
		!got[1].start.Equal(day(2026, 12, 13)) || !got[1].end.Equal(day(2027, 4, 15)) {
		t.Fatalf("unexpected periods: %+v", got)
	}
	if got[0].startSign != 11 || got[0].endSign != 11 {
		t.Errorf("signs not taken from signAt: %+v", got[0])
	}
	// Same straddling period must NOT be reported for a year it does not touch.
	if got2027, _ := pairRetroPeriods(stations, "Jupiter", 2027, signAt); len(got2027) != 1 {
		t.Errorf("2027 should see only the Dec-2026 period, got %+v", got2027)
	}
	if got, err := pairRetroPeriods(stations, "Mars", 2026, signAt); err != nil || len(got) != 0 {
		t.Errorf("Mars: leading direct station must be skipped, got %+v err=%v", got, err)
	}
	// Unclosed retro period inside the year → error, never a silent half-row.
	_, err = pairRetroPeriods([]stationEvt{{planet: "Venus", retro: true, date: day(2026, 10, 3)}}, "Venus", 2026, signAt)
	if err == nil {
		t.Error("unclosed period must fail")
	}
	// Two consecutive retro stations → error.
	_, err = pairRetroPeriods([]stationEvt{
		{planet: "Venus", retro: true, date: day(2026, 1, 3)},
		{planet: "Venus", retro: true, date: day(2026, 2, 3)},
	}, "Venus", 2026, signAt)
	if err == nil {
		t.Error("double retro must fail")
	}
}

// Every seoT("key", ...) literal used by the page builders must exist in
// seoStr — seoT returns the raw key otherwise and a typo would ship as text.
func TestSeoBuilderKeysExist(t *testing.T) {
	src, err := os.ReadFile("seo.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`seoT\("([a-z_]+)"`)
	found := 0
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		found++
		if strings.HasSuffix(m[1], "_") {
			continue // dynamic prefix ("retro_meaning_"+planet) — checked below
		}
		if _, ok := seoStr[m[1]]; !ok {
			t.Errorf("seo.go uses unknown key %q", m[1])
		}
	}
	if found < 20 {
		t.Fatalf("only %d seoT literals found — regexp broken?", found)
	}
	for _, p := range seoRetroPlanets {
		if _, ok := seoStr["retro_meaning_"+p]; !ok {
			t.Errorf("retro_meaning_%s missing", p)
		}
	}
}
