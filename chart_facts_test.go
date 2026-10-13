package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Fixture: real astrolog natal output for 15 May 1990 10:30, tz +2,
// lon 13.4E, lat 52.52 (Berlin).
func loadNatalFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/natal_sample.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// fixtureSky is a synthetic sidereal sky for 2026-10-13 (no astrolog
// locally): Saturn in Pisces, Moon 100° ahead of the Sun (tithi 9, sukla).
var fixtureSky = map[string]float64{"Saturn": 336.5, "Sun": 176.0, "Moon": 276.0}

func TestChartFactsNatalArgs(t *testing.T) {
	got := astrologChartArgs("5 15 1990", "10:30", "2", "13.4", "52.52", false)
	want := []string{"-qa", "5", "15", "1990", "10:30", "-2", "-13.4", "52.52",
		"-s", "0.883208", "-R", "8", "9", "10", "-c", "14", "-C", "-RC", "22", "31"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("natal args = %v\nwant %v", got, want)
	}
	nav := astrologChartArgs("5 15 1990", "10:30", "2", "13.4", "52.52", true)
	if strings.Join(nav, " ") != strings.Join(append(want[:14:14], "-9", "-c", "14", "-C", "-RC", "22", "31"), " ") {
		t.Fatalf("navamsha args = %v", nav)
	}
}

func TestChartFactsParseNatalFixture(t *testing.T) {
	b, err := parseNatalChart(loadNatalFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, sign, deg, min, house int) {
		t.Helper()
		got := b[name]
		if got.sign != sign || got.deg != deg || got.min != min || got.house != house {
			t.Errorf("%s = %s %d°%02d′ house %d, want %s %d°%02d′ house %d", name,
				chartFactsSigns[got.sign], got.deg, got.min, got.house, chartFactsSigns[sign], deg, min, house)
		}
	}
	check("lagna", 3, 13, 25, 1) // Cancer 13°25′
	check("moon", 9, 1, 38, 7)   // Capricorn 1°38′, 7th
	check("sun", 1, 0, 31, 11)   // Taurus 0°31′, 11th
	check("mercury", 0, 14, 18, 10)
	check("jupiter", 2, 15, 47, 12)
	check("saturn", 9, 1, 31, 7)
	check("rahu", 9, 17, 37, 7)
	check("ketu", 3, 17, 37, 1) // Cancer, 1st
	for name, retro := range map[string]bool{
		"sun": false, "moon": false, "mercury": true, "venus": false,
		"mars": false, "jupiter": false, "saturn": true,
	} {
		if got := b[name].speed < 0; got != retro {
			t.Errorf("%s retro = %v, want %v", name, got, retro)
		}
	}
}

func TestChartFactsParseRejectsIncomplete(t *testing.T) {
	var kept []string
	for _, l := range strings.Split(loadNatalFixture(t), "\n") {
		if !strings.HasPrefix(l, "Satu") {
			kept = append(kept, l)
		}
	}
	if _, err := parseNatalChart(strings.Join(kept, "\n")); err == nil {
		t.Fatal("chart without Saturn must fail")
	}
	if _, err := parseNatalChart(""); err == nil {
		t.Fatal("empty output must fail")
	}
}

func fixtureFacts(t *testing.T) *chartFacts {
	t.Helper()
	b, err := parseNatalChart(loadNatalFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	f, err := buildChartFacts(b, time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), fixtureSky)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestChartFactsFixture(t *testing.T) {
	f := fixtureFacts(t)
	js, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture facts:\n%s", js)

	if f.Lagna != (chartFactsSignDeg{Sign: "cancer", Deg: 13.42}) {
		t.Errorf("lagna = %+v", f.Lagna)
	}
	want := map[string]chartFactsPlanet{
		"moon":    {Planet: "moon", Sign: "capricorn", Deg: 1.63, House: 7},
		"mercury": {Planet: "mercury", Sign: "aries", Deg: 14.3, House: 10, Retro: true},
		"saturn":  {Planet: "saturn", Sign: "capricorn", Deg: 1.52, House: 7, Retro: true},
		"ketu":    {Planet: "ketu", Sign: "cancer", Deg: 17.62, House: 1, Retro: false}, // nodes: never flagged, as in the app
	}
	if len(f.Planets) != 9 {
		t.Fatalf("planets = %d, want 9", len(f.Planets))
	}
	for _, p := range f.Planets {
		if w, ok := want[p.Planet]; ok && p != w {
			t.Errorf("%s = %+v, want %+v", p.Planet, p, w)
		}
	}
	wantConj := [][2]string{{"moon", "saturn"}, {"moon", "rahu"}, {"saturn", "rahu"}}
	if !reflect.DeepEqual(f.Conjunctions, wantConj) {
		t.Errorf("conjunctions = %v, want %v", f.Conjunctions, wantConj)
	}
	if f.Moon != (chartFactsMoon{Sign: "capricorn", Nakshatra: "uttara-ashadha", Pada: 2}) {
		t.Errorf("moon = %+v", f.Moon)
	}
	// Cross-checked independently: Sun MD from 1988-02-19, Rahu MD
	// 2011-02-18..2029-02-17, Moon AD 2026-08-02..2028-02-01.
	if f.Dasha == nil || *f.Dasha != (chartFactsDasha{Maha: "rahu", Antar: "moon", MahaUntil: "2029-02-17", AntarUntil: "2028-02-01"}) {
		t.Errorf("dasha = %+v", f.Dasha)
	}
	if f.SadeSati.Active || f.SadeSati.Phase != nil {
		t.Errorf("sade sati = %+v, want inactive (Saturn in Pisces, Moon in Capricorn)", f.SadeSati)
	}
	if f.TithiToday != (chartFactsTithi{Paksha: "sukla", N: 9}) {
		t.Errorf("tithi = %+v", f.TithiToday)
	}
	if !reflect.DeepEqual(f.Yogas, []string{"Sasha Yoga", "Adhi Yoga"}) {
		t.Errorf("yogas = %v", f.Yogas)
	}
	if !strings.Contains(string(js), `"phase": null`) {
		t.Errorf("inactive sade sati must serialize phase as null")
	}
}

func TestChartFactsDashaKnownDates(t *testing.T) {
	birth := time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC)
	moon := (9*30+1)*60 + 38 // 1Cap38: Uttara Ashadha (Sun), 37.25 % traversed
	cases := []struct {
		at                          time.Time
		maha, antar, mUntil, aUntil string
	}{
		{birth, "sun", "jupiter", "1994-02-18", "1990-12-27"},
		{time.Date(2011, 2, 18, 0, 0, 0, 0, time.UTC), "rahu", "rahu", "2029-02-17", "2013-10-31"},
		{time.Date(2011, 2, 17, 0, 0, 0, 0, time.UTC), "mars", "moon", "2011-02-18", "2011-02-18"},
		{time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), "rahu", "sun", "2029-02-17", "2026-08-02"},
	}
	for _, c := range cases {
		d := vimshottariAt(birth, moon, c.at)
		want := chartFactsDasha{Maha: c.maha, Antar: c.antar, MahaUntil: c.mUntil, AntarUntil: c.aUntil}
		if d == nil || *d != want {
			t.Errorf("dasha at %s = %+v, want %+v", c.at.Format("2006-01-02"), d, want)
		}
	}
	if d := vimshottariAt(birth, moon, time.Date(2130, 1, 1, 0, 0, 0, 0, time.UTC)); d != nil {
		t.Errorf("dasha beyond 120 years = %+v, want nil", d)
	}
	// Moon at 0°00′ Ashwini: the whole Ketu dasha lies ahead.
	d := vimshottariAt(birth, 0, birth)
	if d == nil || d.Maha != "ketu" || d.MahaUntil != "1997-05-15" {
		t.Errorf("Ashwini 0° dasha = %+v, want ketu until 1997-05-15", d)
	}
}

// nakshatraOfArcmin must match nakshatraOf everywhere except exactly on a
// boundary, where it follows the app (the new nakshatra starts there).
func TestChartFactsNakshatraArcmin(t *testing.T) {
	for am := 0; am < 21600; am++ {
		idx, pada := nakshatraOfArcmin(am)
		if am%200 == 0 {
			if want := am / 800; idx != want || pada != (am%800)/200+1 {
				t.Fatalf("arcmin %d boundary: %d/%d", am, idx, pada)
			}
			continue
		}
		fi, fp := nakshatraOf(float64(am) / 60)
		if idx != fi || pada != fp {
			t.Fatalf("arcmin %d: exact %d/%d, nakshatraOf %d/%d", am, idx, pada, fi, fp)
		}
	}
	if idx, pada := nakshatraOfArcmin(5600); idx != 7 || pada != 1 {
		t.Errorf("93°20′ = %d/%d, want Pushya (7) pada 1", idx, pada)
	}
}

func TestChartFactsSadeSati(t *testing.T) {
	cases := []struct {
		saturn, moon int
		want         string
	}{
		{8, 9, "rising"}, {9, 9, "peak"}, {10, 9, "setting"}, {11, 9, ""}, {7, 9, ""},
		{11, 0, "rising"}, {0, 0, "peak"}, {1, 0, "setting"}, // wrap around Aries
		{10, 11, "rising"}, {11, 11, "peak"}, {0, 11, "setting"}, // wrap around Pisces
	}
	for _, c := range cases {
		if got := sadeSatiPhase(c.saturn, c.moon); got != c.want {
			t.Errorf("saturn %d moon %d: %q, want %q", c.saturn, c.moon, got, c.want)
		}
	}
	// Through buildChartFacts: Saturn at 285° (Capricorn) on a Capricorn Moon.
	b, err := parseNatalChart(loadNatalFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	f, err := buildChartFacts(b, time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC),
		time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC), map[string]float64{"Saturn": 285, "Sun": 50, "Moon": 230})
	if err != nil {
		t.Fatal(err)
	}
	if !f.SadeSati.Active || f.SadeSati.Phase == nil || *f.SadeSati.Phase != "peak" {
		t.Errorf("sade sati = %+v, want active peak", f.SadeSati)
	}
	if f.TithiToday != (chartFactsTithi{Paksha: "krishna", N: 1}) { // 180° → tithi 16 = krishna 1
		t.Errorf("tithi = %+v, want krishna 1", f.TithiToday)
	}
}

// synthChart places bodies by sign; houses are whole signs from the lagna.
func synthChart(lagna int, signs map[string]int) map[string]natalBody {
	out := map[string]natalBody{"lagna": {sign: lagna, house: 1}}
	// Defaults keep every yoga off: Moon in the 2nd house, Mercury in the
	// 4th, everyone else in the 3rd (Jupiter 2nd from the Moon — no Gaja
	// Kesari, no Adhi; Sun/Mercury and Moon/Mars in different houses).
	def := map[string]int{"sun": 2, "moon": 1, "mercury": 3, "venus": 2, "mars": 2, "jupiter": 2, "saturn": 2, "rahu": 2}
	for p, off := range def {
		s := (lagna + off) % 12
		if v, ok := signs[p]; ok {
			s = v
		}
		out[p] = natalBody{sign: s, house: (s-lagna+12)%12 + 1}
	}
	r := out["rahu"]
	out["ketu"] = natalBody{sign: (r.sign + 6) % 12, house: (r.house+5)%12 + 1}
	return out
}

func TestChartFactsYogasSynthetic(t *testing.T) {
	// Lagna Aries (0). Default chart: Moon Taurus, Mercury Cancer, the rest
	// in Gemini — no yoga.
	if got := chartFactsYogas(synthChart(0, nil)); len(got) != 0 {
		t.Fatalf("baseline chart yogas = %v, want none", got)
	}
	cases := []struct {
		name  string
		signs map[string]int
		want  string
	}{
		{"jupiter kendra from moon", map[string]int{"moon": 1, "jupiter": 4, "sun": 1}, "Gaja Kesari Yoga"},
		{"jupiter trikona from moon", map[string]int{"moon": 1, "jupiter": 5}, "Gaja Kesari Yoga"},
		{"sun with mercury", map[string]int{"sun": 2, "mercury": 2}, "Budhaditya Raja Yoga"},
		{"jupiter cancer 4th", map[string]int{"jupiter": 3, "moon": 2}, "Hamsa Yoga"},
		{"venus libra 7th", map[string]int{"venus": 6}, "Malavya Yoga"},
		{"mars capricorn 10th", map[string]int{"mars": 9}, "Ruchaka Yoga"},
		{"mars aries 1st", map[string]int{"mars": 0}, "Ruchaka Yoga"},
		{"mercury own sign but 6th house", map[string]int{"mercury": 5}, ""},
		{"saturn libra 7th", map[string]int{"saturn": 6}, "Sasha Yoga"},
		{"venus 7th from moon", map[string]int{"moon": 1, "venus": 7}, "Adhi Yoga"},
		{"moon with mars", map[string]int{"moon": 1, "mars": 1}, "Chandra Mangala Yoga"},
		{"mars in aquarius, saturn in aries", map[string]int{"mars": 10, "saturn": 0}, "Parivartana Yoga"},
	}
	for _, c := range cases {
		got := chartFactsYogas(synthChart(0, c.signs))
		has := false
		for _, y := range got {
			if y == c.want {
				has = true
			}
		}
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: yogas = %v, want none", c.name, got)
			}
			continue
		}
		if !has {
			t.Errorf("%s: yogas = %v, want %s", c.name, got, c.want)
		}
	}
	// Bhadra on a Gemini lagna: Mercury in Gemini, 1st house.
	if got := chartFactsYogas(synthChart(2, map[string]int{"mercury": 2, "sun": 3})); !reflect.DeepEqual(got, []string{"Bhadra Yoga"}) {
		t.Errorf("Gemini lagna Mercury 1st: %v, want [Bhadra Yoga]", got)
	}
	// Nodes never form Parivartana; Ketu derived as Rahu + 6.
	c := synthChart(0, map[string]int{"rahu": 9})
	if c["ketu"].sign != 3 || c["ketu"].house != 4 {
		t.Errorf("ketu = %+v", c["ketu"])
	}
}

func TestChartFactsConjunctions(t *testing.T) {
	b := synthChart(0, map[string]int{"sun": 5, "mercury": 5, "venus": 5, "rahu": 5, "moon": 7})
	f, err := buildChartFacts(b, time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), fixtureSky)
	if err != nil {
		t.Fatal(err)
	}
	// Mars, Jupiter, Saturn sit together in Gemini by default (index 2).
	want := [][2]string{
		{"sun", "mercury"}, {"sun", "venus"}, {"sun", "rahu"}, {"mercury", "venus"}, {"mercury", "rahu"},
		{"venus", "rahu"}, {"mars", "jupiter"}, {"mars", "saturn"}, {"jupiter", "saturn"},
	}
	if !reflect.DeepEqual(f.Conjunctions, want) {
		t.Errorf("conjunctions = %v\nwant %v", f.Conjunctions, want)
	}
}

// --- HTTP -------------------------------------------------------------------

func newTestChartFacts(t *testing.T) (*chartFactsService, *fakeClock, *[][]string) {
	clk := &fakeClock{t: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
	fixture := loadNatalFixture(t)
	var calls [][]string
	s := newChartFactsService()
	s.now = clk.now
	s.astrolog = func(args []string) ([]byte, error) {
		calls = append(calls, args)
		return []byte(fixture), nil
	}
	s.sky = func(date time.Time) (map[string]float64, error) {
		if date.Format("2006-01-02") != "2026-10-13" {
			t.Errorf("sky asked for %s, want 2026-10-13", date)
		}
		return fixtureSky, nil
	}
	return s, clk, &calls
}

const chartFactsFixtureBody = `{"date":"5 15 1990","time":"10:30","timezone":"2","longitude":"13.4","latitude":"52.52","lang":"en"}`

func postChartFacts(s *chartFactsService, ip, origin, auth, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/chart-facts", strings.NewReader(body))
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	s.handle(w, r)
	return w
}

func TestChartFactsHTTPSite(t *testing.T) {
	s, _, calls := newTestChartFacts(t)

	if w := postChartFacts(s, "198.51.100.7", "", "", chartFactsFixtureBody); w.Code != http.StatusForbidden {
		t.Fatalf("no Origin: status %d, want 403", w.Code)
	}
	if w := postChartFacts(s, "198.51.100.7", "https://evil.example", "", chartFactsFixtureBody); w.Code != http.StatusForbidden {
		t.Fatalf("foreign Origin: status %d, want 403", w.Code)
	}
	if len(*calls) != 0 {
		t.Fatalf("astrolog ran for a rejected request")
	}

	w := postChartFacts(s, "198.51.100.7", "https://astrolytix.com", "", chartFactsFixtureBody)
	if w.Code != http.StatusOK {
		t.Fatalf("site request: status %d body %s", w.Code, w.Body)
	}
	want, err := json.Marshal(fixtureFacts(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(w.Body.String()) != string(want) {
		t.Errorf("body = %s\nwant %s", w.Body, want)
	}
	if got := strings.Join((*calls)[0], " "); got != "-qa 5 15 1990 10:30 -2 -13.4 52.52 -s 0.883208 -R 8 9 10 -c 14 -C -RC 22 31" {
		t.Errorf("astrolog args = %s", got)
	}

	for _, bad := range []string{
		`{"date":"2 31 1990","time":"10:30","timezone":"2","longitude":"13.4","latitude":"52.52"}`,
		`{"date":"5 15 1990","time":"25:30","timezone":"2","longitude":"13.4","latitude":"52.52"}`,
		`{"date":"5 15 1990","time":"10:30","timezone":"2","longitude":"13.4","latitude":"52.52","at":"13.10.2026"}`,
		`{"date":"5 15 1990","time":"10:30","timezone":"2","longitude":"13.4","latitude":"52.52","lang":"EN!"}`,
		`{"date":"5 15 1990","time":"10:30","timezone":"2","longitude":"13.4; rm -rf /","latitude":"52.52"}`,
	} {
		if w := postChartFacts(s, "203.0.113.9", "https://www.astrolytix.com", "", bad); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, w.Code)
		}
	}
}

func TestChartFactsHTTPSiteLimits(t *testing.T) {
	s, clk, _ := newTestChartFacts(t)
	ip := "192.0.2.44"
	for i := 0; i < chartFactsPerIPHourLimit; i++ {
		if w := postChartFacts(s, ip, "https://astrolytix.com", "", chartFactsFixtureBody); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, w.Code)
		}
	}
	w := postChartFacts(s, ip, "https://astrolytix.com", "", chartFactsFixtureBody)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("11th request in an hour: status %d, want 429 with Retry-After", w.Code)
	}
	if w := postChartFacts(s, "192.0.2.45", "https://astrolytix.com", "", chartFactsFixtureBody); w.Code != http.StatusOK {
		t.Fatalf("other IP: status %d", w.Code)
	}
	// 30 per day: two more full hours fill the day window.
	for h := 0; h < 2; h++ {
		clk.advance(time.Hour + time.Second)
		for i := 0; i < chartFactsPerIPHourLimit; i++ {
			if w := postChartFacts(s, ip, "https://astrolytix.com", "", chartFactsFixtureBody); w.Code != http.StatusOK {
				t.Fatalf("hour %d request %d: status %d", h+2, i+1, w.Code)
			}
		}
	}
	clk.advance(time.Hour + time.Second)
	if w := postChartFacts(s, ip, "https://astrolytix.com", "", chartFactsFixtureBody); w.Code != http.StatusTooManyRequests {
		t.Fatalf("31st request in a day: status %d, want 429", w.Code)
	}
}

func TestChartFactsHTTPBadToken(t *testing.T) {
	s, _, calls := newTestChartFacts(t)
	// A present but invalid token is a 401 — never a fallback to the site path.
	w := postChartFacts(s, "198.51.100.8", "https://astrolytix.com", "Bearer not-a-token", chartFactsFixtureBody)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: status %d, want 401", w.Code)
	}
	if len(*calls) != 0 {
		t.Fatalf("astrolog ran for an unauthorized request")
	}
}

func TestChartFactsUpstreamFailure(t *testing.T) {
	s, _, _ := newTestChartFacts(t)
	s.astrolog = func([]string) ([]byte, error) { return []byte("garbage\n"), nil }
	if w := postChartFacts(s, "198.51.100.9", "https://astrolytix.com", "", chartFactsFixtureBody); w.Code != http.StatusBadGateway {
		t.Fatalf("unparseable astrolog output: status %d, want 502", w.Code)
	}
}
