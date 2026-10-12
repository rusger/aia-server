package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNakshatraOf(t *testing.T) {
	cases := []struct {
		lon       float64
		idx, pada int
	}{
		{0, 0, 1}, {13.3, 0, 4}, {13.34, 1, 1}, {186.7, 14, 1}, // Swati starts at 186°40′
		{359.99, 26, 4}, {-1, 26, 4}, {360, 0, 1},
	}
	for _, c := range cases {
		idx, pada := nakshatraOf(c.lon)
		if idx != c.idx || pada != c.pada {
			t.Errorf("nakshatraOf(%v) = %d/%d, want %d/%d", c.lon, idx, pada, c.idx, c.pada)
		}
	}
}

func TestTithiOf(t *testing.T) {
	cases := []struct {
		moon, sun float64
		want      int
	}{
		{10, 10, 1}, {22, 10, 2}, {190, 10, 16}, {189.9, 10, 15}, {9.9, 10, 30}, {5, 350, 2},
	}
	for _, c := range cases {
		if got := tithiOf(c.moon, c.sun); got != c.want {
			t.Errorf("tithiOf(%v,%v) = %d, want %d", c.moon, c.sun, got, c.want)
		}
	}
}

func TestTithiLabel(t *testing.T) {
	if got := tithiLabel(5, "en"); got != "Shukla Panchami (5)" {
		t.Errorf("tithi 5: %q", got)
	}
	if got := tithiLabel(15, "en"); got != "Shukla Purnima (15)" {
		t.Errorf("tithi 15: %q", got)
	}
	if got := tithiLabel(16, "ru"); got != "Кришна Пратипада (1)" {
		t.Errorf("tithi 16 ru: %q", got)
	}
	if got := tithiLabel(30, "en"); got != "Krishna Amavasya (15)" {
		t.Errorf("tithi 30: %q", got)
	}
}

func TestMotionIsRetro(t *testing.T) {
	if motionIsRetro("Mercury", 100, 101) != true || motionIsRetro("Mercury", 101, 100) != false {
		t.Error("sign of the daily delta decides")
	}
	if motionIsRetro("Venus", 1, 359) != false || motionIsRetro("Venus", 359, 1) != true {
		t.Error("wrap-around at 0°")
	}
	if motionIsRetro("Rahu", 10, 9) != true || motionIsRetro("Moon", 10, 11) != false {
		t.Error("nodes always retro, luminaries never")
	}
}

func TestSeoDateFormats(t *testing.T) {
	d := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	want := map[string]string{
		"en": "12 October 2026", "ru": "12 октября 2026", "es": "12 de octubre de 2026", "de": "12. Oktober 2026",
		"zh": "2026年10月12日", "ko": "2026년 10월 12일", "hi": "12 अक्टूबर 2026",
	}
	for lang, w := range want {
		if got := seoDate(lang, d); got != w {
			t.Errorf("%s: %q != %q", lang, got, w)
		}
	}
	for _, lang := range seoLangs {
		if seoMonthName(10, lang) == "" || seoWeekdayName(1, lang) == "" || seoNakshatraName(14, lang) == "" || seoTithiName(14, lang) == "" {
			t.Errorf("%s: a name table is incomplete", lang)
		}
	}
}

func TestSeoStateKeepsDateWhileContentUnchanged(t *testing.T) {
	s := newSeoState()
	if got := s.lastmod("u", "h1", "2026-10-12"); got != "2026-10-12" {
		t.Fatalf("new url: %s", got)
	}
	if got := s.lastmod("u", "h1", "2026-10-13"); got != "2026-10-12" {
		t.Fatalf("unchanged content must keep its date, got %s", got)
	}
	if got := s.lastmod("u", "h2", "2026-10-14"); got != "2026-10-14" {
		t.Fatalf("changed content moves the date, got %s", got)
	}
	path := filepath.Join(t.TempDir(), seoStateFile)
	if err := s.save(path); err != nil {
		t.Fatal(err)
	}
	back, err := loadSeoState(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Pages["u"].Modified != "2026-10-14" || back.Pages["u"].Hash != "h2" {
		t.Fatalf("round trip: %+v", back.Pages["u"])
	}
	if _, err := loadSeoState(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("missing state is an empty state, got %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{"), 0o644)
	if _, err := loadSeoState(bad); err == nil {
		t.Fatal("corrupt state must fail, not reset every date")
	}
	if contentHash("a", "b") == contentHash("ab", "") {
		t.Fatal("parts must be delimited")
	}
}

// synthetic ephemeris: no astrolog on the Mac. Sun 1°/day, Moon 13.2°/day,
// Mercury retrograde 2026-10-10..10-25, nodes backwards.
func fixtureYear(t *testing.T) *seoYearData {
	t.Helper()
	lons := newNoonLons()
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		day := base.AddDate(0, 0, i)
		f := float64(i)
		merc := 170 + f*1.2
		if day.After(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)) && day.Before(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)) {
			merc = 185 - f*0.8
		}
		lons.memo[day.Format("2006-01-02")] = map[string]float64{
			"Sun": math.Mod(165+f, 360), "Moon": math.Mod(200+f*13.2, 360), "Mercury": math.Mod(merc, 360),
			"Venus": math.Mod(150+f*1.1, 360), "Mars": math.Mod(220+f*0.6, 360), "Jupiter": 95 + f*0.1,
			"Saturn": 335 - f*0.05, "Rahu": math.Mod(320-f*0.053+360, 360), "Ketu": math.Mod(140-f*0.053+360, 360),
		}
	}
	d := &seoYearData{year: 2026, retro: map[string][]seoRetroPeriod{}, lons: lons}
	d.ingresses = []seoIngress{{date: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC), planet: "Sun", signIdx: 6}}
	d.stations = []stationEvt{{planet: "Mercury", retro: true, date: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)}}
	d.moons = []seoMoonEvent{{at: time.Date(2026, 10, 10, 15, 50, 0, 0, time.UTC), full: false, signIdx: 5}}
	return d
}

func TestWriteSeoSiteDayPages(t *testing.T) {
	out := t.TempDir()
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	data := []*seoYearData{fixtureYear(t)}
	n, err := writeSeoSiteAt(out, data, now)
	if err != nil {
		t.Fatal(err)
	}
	// 16 hubs + 16×8 year pages + 4 langs × (72 days 10-01..12-11 + 3 months + today) + 16 json + root + sitemap
	if want := 16 + 128 + 4*(72+3+1) + 16 + 2; n != want {
		t.Fatalf("%d files, want %d", n, want)
	}
	page, err := os.ReadFile(filepath.Join(out, "ru", "2026", "10", "12.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	for _, want := range []string{
		`<link rel="canonical" href="https://astrolytix.com/astro/ru/2026/10/12.html">`,
		`<h1>Небо 12 октября 2026</h1>`,
		`href="https://astrolytix.com/astro/ru/2026/10/11.html"`, // prev
		`href="https://astrolytix.com/astro/ru/2026/10/13.html"`, // next
		`href="https://astrolytix.com/astro/ru/2026/10/"`,        // month hub
		`href="https://astrolytix.com/astro/ru/today/"`,
		`class="btn ios" rel="noopener" href="https://astrolytix.com/go/ios/"`,
		`<td>Меркурий</td><td>`, "ретроградное", "Накшатра", "Титхи:",
		`<time datetime="2026-10-17">17 октября 2026</time> — <a href="https://astrolytix.com/astro/ru/2026/transits.html">Солнце входит в Весы</a>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("day page lacks %s", want)
		}
	}
	if strings.Contains(html, "Другие годы") {
		t.Error("day page must not carry the year-page 'other years' line")
	}
	hreflang := regexp.MustCompile(`hreflang="([a-z-]+)"`).FindAllStringSubmatch(html[:strings.Index(html, "</head>")], -1)
	got := map[string]bool{}
	for _, m := range hreflang {
		got[m[1]] = true
	}
	if len(got) != len(seoDayLangs)+1 || !got["x-default"] || got["de"] {
		t.Errorf("day page hreflang set = %v, want seoDayLangs + x-default", got)
	}
	// First and last rendered days have no dangling neighbour link.
	first, _ := os.ReadFile(filepath.Join(out, "en", "2026", "10", "01.html"))
	if strings.Contains(string(first), "/2026/09/30.html") {
		t.Error("first day links a page that is not rendered")
	}
	if _, err := os.Stat(filepath.Join(out, "en", "2026", "12", "11.html")); err != nil {
		t.Error("window must reach today+60 (2026-12-11)")
	}
	if _, err := os.Stat(filepath.Join(out, "de", "2026", "10", "12.html")); err == nil {
		t.Error("day pages are rendered for seoDayLangs only")
	}
	// Today page is its own canonical and links the dated page; the hub links today.
	today, _ := os.ReadFile(filepath.Join(out, "en", "today", "index.html"))
	if !strings.Contains(string(today), `<link rel="canonical" href="https://astrolytix.com/astro/en/today/">`) ||
		!strings.Contains(string(today), `href="https://astrolytix.com/astro/en/2026/10/12.html"`) ||
		!strings.Contains(string(today), "<h1>Planets today: 12 October 2026</h1>") {
		t.Error("today page canonical/links/title")
	}
	hub, _ := os.ReadFile(filepath.Join(out, "en", "index.html"))
	if !strings.Contains(string(hub), `href="https://astrolytix.com/astro/en/today/"`) || !strings.Contains(string(hub), `href="https://astrolytix.com/astro/en/2026/10/"`) {
		t.Error("language hub must link today and the current month")
	}
	deHub, _ := os.ReadFile(filepath.Join(out, "de", "index.html"))
	if strings.Contains(string(deHub), "/today/") {
		t.Error("languages without day pages must not link them")
	}
	// Year pages keep their 'other years' line and full hreflang set.
	yr, _ := os.ReadFile(filepath.Join(out, "en", "2026", "transits.html"))
	if !strings.Contains(string(yr), "Other years") || strings.Count(string(yr), `rel="alternate" hreflang=`) != len(seoLangs)+1 {
		t.Error("year page navigation/hreflang regressed")
	}
	// today.json: every language, valid, url to own today page or en.
	for _, lang := range seoLangs {
		raw, err := os.ReadFile(filepath.Join(out, lang, "today.json"))
		if err != nil {
			t.Fatal(err)
		}
		var j struct {
			Date, Label, Weekday, URL string
			Lines                     []string
		}
		if err := json.Unmarshal(raw, &j); err != nil {
			t.Fatalf("%s today.json: %v", lang, err)
		}
		wantURL := "https://astrolytix.com/astro/en/today/"
		if hasLang(seoDayLangs, lang) {
			wantURL = "https://astrolytix.com/astro/" + lang + "/today/"
		}
		if j.Date != "2026-10-12" || j.URL != wantURL || len(j.Lines) != 3 || j.Label == "" || j.Weekday == "" {
			t.Errorf("%s today.json: %+v", lang, j)
		}
		for _, l := range j.Lines {
			if strings.Contains(l, "{") {
				t.Errorf("%s: unsubstituted placeholder in %q", lang, l)
			}
		}
	}
	// Sitemap: day pages with alternates limited to seoDayLangs, per-url lastmod.
	sm, _ := os.ReadFile(filepath.Join(out, "sitemap.xml"))
	smap := string(sm)
	if !strings.Contains(smap, "<loc>https://astrolytix.com/astro/zh/2026/10/12.html</loc><lastmod>2026-10-12</lastmod>") {
		t.Error("sitemap lacks the day page")
	}
	dayEntry := smap[strings.Index(smap, "<loc>https://astrolytix.com/astro/zh/2026/10/12.html</loc>"):]
	dayEntry = dayEntry[:strings.Index(dayEntry, "</url>")]
	if strings.Count(dayEntry, "hreflang=") != len(seoDayLangs)+1 {
		t.Errorf("day entry alternates: %s", dayEntry)
	}
	if locs := strings.Count(smap, "<loc>"); locs != n-16-2+1 { // every html page + the root hub (no json/sitemap)
		t.Errorf("sitemap has %d locs for %d files", locs, n)
	}
}

// The whole point of seo_state.go: a second run on another day with the
// same data must not move a single lastmod, while the today page (whose
// content really changed) does.
func TestWriteSeoSiteHonestLastmod(t *testing.T) {
	out := t.TempDir()
	data := []*seoYearData{fixtureYear(t)}
	if _, err := writeSeoSiteAt(out, data, time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	sm1, _ := os.ReadFile(filepath.Join(out, "sitemap.xml"))
	if _, err := writeSeoSiteAt(out, data, time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	sm2, _ := os.ReadFile(filepath.Join(out, "sitemap.xml"))
	lastmods := func(sm []byte) map[string]string {
		m := map[string]string{}
		for _, x := range regexp.MustCompile(`<loc>([^<]+)</loc><lastmod>([^<]+)</lastmod>`).FindAllStringSubmatch(string(sm), -1) {
			m[x[1]] = x[2]
		}
		return m
	}
	a, b := lastmods(sm1), lastmods(sm2)
	// Legitimately changed on day 2: the today pages, the former last day of
	// the window (it gained a "next day" link) and the month hub that gained
	// a row — 3 pages per day language. Everything else must stand still.
	moved := 0
	for loc, d := range b {
		if prev, ok := a[loc]; ok && prev != d {
			moved++
			if !strings.Contains(loc, "/today/") && !strings.HasSuffix(loc, "/2026/12/11.html") && !strings.HasSuffix(loc, "/2026/12/") {
				t.Errorf("%s moved %s → %s although its content is unchanged", loc, prev, d)
			}
		}
	}
	if moved != 3*len(seoDayLangs) {
		t.Errorf("%d pages moved, want %d", moved, 3*len(seoDayLangs))
	}
	if b["https://astrolytix.com/astro/en/today/"] != "2026-10-13" {
		t.Errorf("today page must carry today's date, got %s", b["https://astrolytix.com/astro/en/today/"])
	}
	if b["https://astrolytix.com/astro/en/2026/transits.html"] != "2026-10-12" {
		t.Errorf("year page must keep its first date, got %s", b["https://astrolytix.com/astro/en/2026/transits.html"])
	}
	// The new day (2026-12-12) appears with the new date; the old ones keep theirs.
	if b["https://astrolytix.com/astro/en/2026/12/12.html"] != "2026-10-13" || b["https://astrolytix.com/astro/en/2026/10/05.html"] != "2026-10-12" {
		t.Error("new day page gets the run date, existing ones keep theirs")
	}
	// Rendered HTML carries the same date (JSON-LD dateModified).
	page, _ := os.ReadFile(filepath.Join(out, "en", "2026", "transits.html"))
	if !strings.Contains(string(page), `"dateModified":"2026-10-12"`) {
		t.Error("dateModified must be the content date, not the run date")
	}
}
