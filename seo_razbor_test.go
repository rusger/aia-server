package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRazborDataValid(t *testing.T) {
	// loadRazbors skips broken files; the repo's own data must all load.
	paths, _ := filepath.Glob(filepath.Join(seoRazborDir, "*.json"))
	rs, err := loadRazbors(seoRazborDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != len(paths) {
		t.Fatalf("%d of %d seo_razbor files load", len(rs), len(paths))
	}
	slugs := map[string]bool{}
	for _, r := range rs {
		slugs[r.Slug] = true
	}
	for _, want := range []string{"rahu-ketu", "saturn-direct-jupiter-retrograde"} {
		if !slugs[want] {
			t.Errorf("seo_razbor/%s.json missing", want)
		}
	}
}

func TestRazborStringsCoverLangs(t *testing.T) {
	for k, m := range razborStr {
		for _, l := range razborLangs {
			if m[l] == "" {
				t.Errorf("razborStr[%q] has no %s", k, l)
			}
		}
	}
}

func testRazbor() *seoRazbor {
	tx := func(en, ru string) seoRazborText { return seoRazborText{"en": en, "ru": ru} }
	return &seoRazbor{
		Slug: "rahu-ketu", Year: 2026, Video: "VID", Published: "2026-11-16", Duration: "PT1H19M19S",
		Related: []string{"eclipses"}, Langs: []string{"ru", "en"},
		Title: tx("Rahu & Ketu <2026>", "Раху и Кету"), Lead: tx("Lead.", "Вступление."),
		Sections: []seoRazborSection{
			{T: 0, Sign: -1, H: tx("Intro", "Вступление"), Lines: []seoRazborLine{{Host: "A", Text: tx("Question?", "Вопрос?")}}},
			{T: 277, Sign: 0, H: tx("Aries rising", "Асцендент Овен"), Clip: &seoRazborClip{ID: "PAST", PublishAt: "2026-11-21T17:00:00Z"},
				Lines: []seoRazborLine{{Host: "B", Text: tx("Answer.", "Ответ."), Sub: tx("Aries: where it lands", "Овен: куда попадает")}}},
			{T: 560, Sign: 1, H: tx("Taurus rising", "Асцендент Телец"), Clip: &seoRazborClip{ID: "FUTURE", PublishAt: "2026-11-30T17:00:00Z"},
				Lines: []seoRazborLine{{Host: "B", Text: tx("More.", "Ещё.")}}},
		},
	}
}

func TestRazborPage(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	r := testRazbor()
	pg := buildRazborPage("en", r, now)
	if pg.rel != "2026/rahu-ketu.html" {
		t.Fatalf("rel %q", pg.rel)
	}
	if strings.Join(pg.langs, ",") != "en,ru" {
		t.Errorf("langs %v, want seoLangs order en,ru", pg.langs)
	}
	for _, want := range []string{
		"Rahu &amp; Ketu &lt;2026&gt;", // escaped
		`href="https://youtu.be/VID?t=277"`, "Watch from 4:37",
		`id="aries"`, `id="taurus"`, `id="part-1"`,
		`href="https://youtu.be/PAST"`,
		`<p class="q">Question?</p>`, "<h3>Aries: where it lands</h3>",
		"sub_confirmation=1",
		`var L=["en","ru"],C="en"`,
	} {
		if !strings.Contains(pg.body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(pg.body, "FUTURE") {
		t.Error("unpublished chapter video is linked")
	}
	if !strings.Contains(pg.ld, `"startOffset":277,"endOffset":560`) || !strings.Contains(pg.ld, `"@type":"VideoObject"`) {
		t.Errorf("VideoObject clips: %s", pg.ld)
	}
	ru := buildRazborPage("ru", r, now)
	if !strings.Contains(ru.body, "Смотреть с 4:37") || !strings.Contains(ru.body, "Ответ.") || strings.Contains(ru.body, "Answer.") {
		t.Error("ru page not in Russian")
	}
	full := renderSeoLayout("ru", pg.rel, ru, []int{2026, 2027}, "2026-11-25")
	if strings.Contains(full, "/2027/rahu-ketu.html") || strings.Contains(full, "/2026/rahu-ketu.html\">2026") {
		t.Error("razbor page links other years of itself (they do not exist)")
	}
	for _, want := range []string{
		`hreflang="en" href="` + seoBaseURL + `/en/2026/rahu-ketu.html"`,
		`hreflang="x-default" href="` + seoBaseURL + `/en/2026/rahu-ketu.html"`,
		`<link rel="canonical" href="` + seoBaseURL + `/ru/2026/rahu-ketu.html"`,
	} {
		if !strings.Contains(full, want) {
			t.Errorf("layout lacks %q", want)
		}
	}
	if strings.Contains(full, `hreflang="de"`) {
		t.Error("hreflang for a language without text")
	}
}

func TestRazborLangJSNeverMovesBots(t *testing.T) {
	js := razborLangJS("en", "2026/rahu-ketu.html", []string{"en", "ru"})
	bot := strings.Index(js, "bot|crawl")
	move := strings.Index(js, "location.replace")
	save := strings.Index(js, "localStorage.setItem")
	if bot < 0 || move < 0 || save < 0 || save > bot {
		t.Fatalf("footer choice must be saved for everyone, bots return before any move: %s", js)
	}
	if !strings.Contains(js, `RU:"ru"`) || !strings.Contains(js, seoGeoIPAPI) {
		t.Error("GeoIP map missing")
	}
}

func TestRazborValidateRefusesPartialLanguage(t *testing.T) {
	r := testRazbor()
	delete(r.Sections[2].Lines[0].Text, "ru")
	if err := r.validate(); err == nil {
		t.Fatal("ru listed with a missing line must be refused")
	}
	r = testRazbor()
	r.Langs = append(r.Langs, "fr")
	r.Title["fr"], r.Lead["fr"] = "t", "l"
	for i := range r.Sections {
		r.Sections[i].H["fr"] = "h"
		for j := range r.Sections[i].Lines {
			r.Sections[i].Lines[j].Text["fr"] = "x"
			if r.Sections[i].Lines[j].Sub != nil {
				r.Sections[i].Lines[j].Sub["fr"] = "s"
			}
		}
	}
	if err := r.validate(); err == nil {
		t.Fatal("a language without UI labels must be refused")
	}
	r = testRazbor()
	r.Slug = "../x"
	if err := r.validate(); err == nil {
		t.Fatal("slug with a path must be refused")
	}
}

func TestRazborLinks(t *testing.T) {
	rs := []*seoRazbor{testRazbor()}
	if b := razborLinks("en", "2026/eclipses.html", rs); !strings.Contains(b, "/en/2026/rahu-ketu.html") {
		t.Errorf("related year page lacks the link: %q", b)
	}
	if b := razborLinks("en", "", rs); !strings.Contains(b, "/en/2026/rahu-ketu.html") {
		t.Error("hub lacks the link")
	}
	for _, c := range [][2]string{{"en", "2027/eclipses.html"}, {"en", "2026/transits.html"}, {"de", "2026/eclipses.html"}, {"en", "2026/12/aries.html"}} {
		if b := razborLinks(c[0], c[1], rs); b != "" {
			t.Errorf("%v: unexpected link block", c)
		}
	}
}

func TestRazborPagesWritten(t *testing.T) {
	data := fixtureWithRetro(t)
	dir := t.TempDir()
	if _, err := writeSeoSiteAt(dir, data, time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	rs, _ := loadRazbors(seoRazborDir)
	sm, err := os.ReadFile(filepath.Join(dir, "sitemap.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		for _, l := range r.siteLangs() {
			if _, err := os.Stat(filepath.Join(dir, l, r.rel())); err != nil {
				t.Errorf("%s/%s not written", l, r.rel())
			}
			if !strings.Contains(string(sm), seoURL(l, r.rel())) {
				t.Errorf("sitemap lacks %s", seoURL(l, r.rel()))
			}
		}
		for _, l := range seoLangs {
			if !hasLang(r.siteLangs(), l) {
				if _, err := os.Stat(filepath.Join(dir, l, r.rel())); err == nil {
					t.Errorf("%s/%s written without text", l, r.rel())
				}
			}
		}
	}
}

// The page script must pick the same language as the main site.
func TestRazborCountryMapMatchesSite(t *testing.T) {
	home, _ := os.UserHomeDir()
	raw, err := os.ReadFile(filepath.Join(home, "aia", "astrolytix", "i18n.js"))
	if err != nil {
		t.Skip("astrolytix checkout not here")
	}
	js := string(raw)
	block := js[strings.Index(js, "COUNTRY_TO_LANGUAGE = {"):]
	block = block[:strings.Index(block, "};")]
	site := map[string]string{}
	for _, m := range regexp.MustCompile(`([A-Z]{2}): '([a-z]{2})'`).FindAllStringSubmatch(block, -1) {
		site[m[1]] = m[2]
	}
	if len(site) != len(seoCountryLang) {
		t.Errorf("site maps %d countries, seo %d", len(site), len(seoCountryLang))
	}
	for k, v := range site {
		if seoCountryLang[k] != v {
			t.Errorf("%s: site %s, seo %s", k, v, seoCountryLang[k])
		}
	}
	for _, c := range []string{"'" + seoLangStorageKey + "'", "'" + seoGeoIPAPI + "'"} {
		if !strings.Contains(js, c) {
			t.Errorf("i18n.js lacks %s", c)
		}
	}
}

func TestRazborBrokenFileSkipped(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{"), 0o644)
	os.WriteFile(filepath.Join(dir, "partial.json"), []byte(`{"slug":"p","year":2026,"video":"V","langs":["en"],"title":{"en":"t"},"lead":{"en":""},"sections":[{"h":{"en":"h"},"lines":[]}]}`), 0o644)
	rs, err := loadRazbors(dir)
	if err != nil || len(rs) != 0 {
		t.Fatalf("broken files must be skipped, not abort: %v %d", err, len(rs))
	}
}
