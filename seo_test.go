package main

import (
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
