package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var radioAllStations = []string{"sun", "moon", "mars", "mercury", "jupiter", "venus", "saturn", "rahu", "ketu"}

// radioTestDir copies the testdata/radio fixtures into a temp RADIO_DIR.
// The only real station day is moon/2026-10-13; its schedule is copied to
// every station for each date in days so the station of the day (and the
// music bed of each planet) resolve.
func radioTestDir(t *testing.T, days ...string) string {
	t.Helper()
	dir := t.TempDir()
	cp := func(src, dst string) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cp("testdata/radio/lib/index.json", filepath.Join(dir, "lib", "index.json"))
	cp("testdata/radio/cat/index.json", filepath.Join(dir, "cat", "index.json"))
	for _, d := range days {
		for _, st := range radioAllStations {
			cp("testdata/radio/moon/2026-10-13/schedule.json", filepath.Join(dir, st, d, "schedule.json"))
		}
	}
	return dir
}

// radioBuild runs the builder against dir like serve does.
func radioBuild(t *testing.T, dir string, f *chartFacts, at time.Time, lang string, birth *time.Time, extra []string) *radioPlaylist {
	t.Helper()
	c := &radioFileCache{}
	lib, err := c.load(filepath.Join(dir, "lib", "index.json"), parseRadioLib)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := c.load(filepath.Join(dir, "cat", "index.json"), parseRadioCat)
	if err != nil {
		t.Fatal(err)
	}
	day := at.Format("2006-01-02")
	return buildRadioPlaylist(radioInputs{facts: f, extraYogas: extra, birth: birth, lang: lang, at: at,
		lib: lib.(*radioLib), cat: cat.(*radioCat), schedule: func(st string) *radioSchedule {
			v, err := c.load(filepath.Join(dir, st, day, "schedule.json"), parseRadioSchedule)
			if err != nil {
				return nil
			}
			return v.(*radioSchedule)
		}, loops: func(st string) []radioLoop {
			v, err := c.load(filepath.Join(dir, st, "ever", "loops.json"), parseRadioLoops)
			if err != nil {
				return nil
			}
			return v.([]radioLoop)
		}})
}

// radioStationAt: the station of the item playing at sec (the last one started).
func radioStationAt(pl *radioPlaylist, sec float64) string {
	st := ""
	for _, it := range pl.Items {
		if it.Start <= sec+0.05 {
			st = it.station
		}
	}
	return st
}

// radioCheckMusic: loops back to back from 0 through the end of the speech,
// each one played once: never the same src twice in a row, no src twice in
// one run of a station, at most radioGenreRun of a genre or a station in a row.
func radioCheckMusic(t *testing.T, pl *radioPlaylist) {
	t.Helper()
	last := pl.Items[len(pl.Items)-1]
	end := last.Start + last.span
	tr := pl.Music.Tracks
	if len(tr) == 0 || tr[0].From != 0 {
		t.Fatalf("music must start at 0: %+v", tr)
	}
	run, stRun := 0, 0
	runSrcs := map[string]bool{}
	for i, m := range tr {
		if m.Dur <= 0 || m.From >= end || m.Genre == "" {
			t.Errorf("track %d = %+v (end %.1f)", i, m, end)
		}
		if i == 0 || m.Station != tr[i-1].Station {
			stRun, runSrcs = 1, map[string]bool{}
		} else {
			stRun++
		}
		if runSrcs[m.Src] {
			t.Errorf("track %d: %s again in the same %s run", i, m.Src, m.Station)
		}
		runSrcs[m.Src] = true
		if stRun > radioGenreRun {
			t.Errorf("track %d: %d loops of station %s in a row", i, stRun, m.Station)
		}
		if i == 0 {
			run = 1
			continue
		}
		if m.Src == tr[i-1].Src {
			t.Errorf("track %d: %s twice in a row", i, m.Src)
		}
		if p := tr[i-1]; math.Abs(m.From-(p.From+p.Dur)) > 0.11 {
			t.Errorf("track %d from %.1f, want %.1f (previous plays once)", i, m.From, p.From+p.Dur)
		}
		if m.Genre == tr[i-1].Genre {
			run++
		} else {
			run = 1
		}
		if run > radioGenreRun {
			t.Errorf("track %d: %d loops of %s in a row", i, run, m.Genre)
		}
	}
	if l := tr[len(tr)-1]; l.From+l.Dur < end-0.11 {
		t.Errorf("music ends at %.1f before the speech (%.1f)", l.From+l.Dur, end)
	}
}

// radioCheckDeck: the tracks are passes of n loops (the whole deck), every
// loop exactly once per pass.
func radioCheckDeck(t *testing.T, pl *radioPlaylist, n int) {
	t.Helper()
	tr := pl.Music.Tracks
	for p := 0; p < len(tr); p += n {
		seen := map[string]bool{}
		for i := p; i < p+n && i < len(tr); i++ {
			if seen[tr[i].Src] {
				t.Errorf("track %d: %s twice in deck pass %d", i, tr[i].Src, p/n)
			}
			seen[tr[i].Src] = true
		}
	}
}

// radioNoteIDs: radioIDs with the lang_note variants folded to "lang_note".
func radioNoteIDs(items []radioItem) []string {
	out := radioIDs(items)
	for i, id := range out {
		if strings.HasPrefix(id, "you/lang_note/") {
			out[i] = "lang_note"
		}
	}
	return out
}

var radioFixtureBirth = time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC)

func radioDay(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

func radioRubrics(pl *radioPlaylist) []string {
	var out []string
	for _, it := range pl.Items {
		if len(out) == 0 || out[len(out)-1] != it.Rubric {
			out = append(out, it.Rubric)
		}
	}
	return out
}

func radioByRubric(pl *radioPlaylist, rubric string) []radioItem {
	var out []radioItem
	for _, it := range pl.Items {
		if it.Rubric == rubric {
			out = append(out, it)
		}
	}
	return out
}

func radioIDs(items []radioItem) []string {
	out := []string{}
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

func radioCompact(pl *radioPlaylist) string {
	var sb strings.Builder
	for _, it := range pl.Items {
		ref := it.Src
		if it.Cat != "" {
			ref = "cat:" + it.Cat + " " + it.Src
		}
		fmt.Fprintf(&sb, "%7.1f %-8s %-12s %-6.1f %s | %s\n", it.Start, it.Kind, it.Rubric, it.Dur, it.Title, ref)
	}
	for _, m := range pl.Music.Tracks {
		fmt.Fprintf(&sb, "music from %7.1f %-8s %-8s %s (%.0f s)\n", m.From, m.Station, m.Genre, m.Src, m.Dur)
	}
	return sb.String()
}

func TestRadioPlaylistFixture(t *testing.T) {
	dir := radioTestDir(t, "2026-10-13")
	f := fixtureFacts(t)
	pl := radioBuild(t, dir, f, radioDay("2026-10-13"), "ru", &radioFixtureBirth, nil)
	t.Logf("playlist:\n%s", radioCompact(pl))

	// Sade Sati is not active for the fixture (Saturn in Pisces, Moon in Capricorn).
	want := []string{rubIdent, rubSkyToday, rubTithi, rubLagna, rubMonth, rubTransits, rubDasha, rubYogas,
		rubPlanetHouse, rubConjunction, rubNakshatra, rubTopic, rubYear, rubRelease, rubEvent, rubClosing}
	if got := radioRubrics(pl); !reflect.DeepEqual(got, want) {
		t.Fatalf("rubrics = %v\nwant %v", got, want)
	}
	if pl.Items[0].Title != "Your Chart" || pl.Items[1].Title != "Coming up" {
		t.Errorf("untitled lines: %q %q", pl.Items[0].Title, pl.Items[1].Title)
	}
	if pl.Wave != "you" || pl.Date != "2026-10-13" || pl.Lang != "ru" || pl.TZ != "UTC" {
		t.Errorf("header = %+v", pl)
	}
	// 2026-10-13 is a Tuesday: the station of the day is Mars.
	if pl.FactsUsed.Station != "mars" {
		t.Errorf("station = %s", pl.FactsUsed.Station)
	}

	// Every rubric opens with its lead (ident/closing are single tracks).
	for _, r := range want[1 : len(want)-1] {
		items := radioByRubric(pl, r)
		if items[0].Kind != "lead" || !strings.HasPrefix(items[0].ID, "you/"+r+"/") || len(items) < 2 {
			t.Errorf("%s: want lead + topic, got %v", r, radioIDs(items))
		}
	}

	check := func(rubric string, want ...string) {
		t.Helper()
		if got := radioNoteIDs(radioByRubric(pl, rubric))[1:]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v\nwant %v", rubric, got, want)
		}
	}
	check(rubSkyToday, "sky_news")
	// ru: the rubrics with a catalog insert announce the language after the lead.
	check(rubTithi, "lang_note", "insert_tithi_sukla_9")
	check(rubLagna, "signs/04-cancer")
	check(rubMonth, "month/2026-10-moon/capricorn", "month/2026-10-sun/taurus", "month/2026-10-lagna/cancer")
	// Lens: one per ref, the one expiring soonest wins — on 13.10 the current
	// lens (valid to 30.10), not q4; q4 takes over from 2026-11-01 (tested below).
	check(rubTransits, "transit-lens/lagna/04-cancer", "transit-lens/sun/02-taurus",
		"transit-lens/moon/10-capricorn", "transit-combo/10-saturn-for-capricorn-moon",
		"graha-watch/01-saturn", "graha-watch/02-jupiter", "graha-watch/03-rahu-ketu")
	check(rubDasha, "lang_note", "insert_mahadasha_Rahu", "dashas/08-rahu")
	// Every yoga is named before its insert.
	check(rubYogas, "lang_note", "yoga-name/sasha-yoga", "insert_yoga_Sasha Yoga", "yoga-name/adhi-yoga", "insert_yoga_Adhi Yoga")
	// Moon, Saturn and Rahu stand in the 7th: saturn-7th, houses/07, grahas/<maha>.
	check(rubPlanetHouse, "breakdowns/26-saturn-7th", "houses/07-seventh-house", "grahas/08-rahu")
	check(rubConjunction, "breakdowns/02-moon-saturn", "breakdowns/03-moon-rahu-afflicted", "breakdowns/23-saturn-rahu")
	check(rubNakshatra, "nakshatras/21-uttara-ashadha")
	check(rubTopic, "topics/01-love")
	check(rubYear, "year-2027/10-capricorn")
	check(rubRelease, "release_series-2-nakshatras-02-bharani-yaml", "release_series-3-breakdowns-05-sun-saturn-yaml")
	check(rubEvent, "events/retrograde-start_2026-10-24")

	// Catalog insert: en src/dur, every language in durs; timeline uses the longer ru.
	if n := radioByRubric(pl, rubTithi)[1]; n.Kind != "lang_note" || !strings.HasPrefix(n.Src, "/radio/lib/you-lang-note-") ||
		n.Title != "Your Chart" || n.station != "moon" {
		t.Errorf("lang note = %+v", n)
	}
	if n := radioByRubric(pl, rubYogas)[2]; n.Kind != "yoga_name" || n.Title != "Sasha Yoga" || n.Src != "/radio/lib/yoga-name-sasha-yoga.m4a" {
		t.Errorf("yoga name = %+v", n)
	}
	tithi := radioByRubric(pl, rubTithi)[2]
	if tithi.Kind != "insert" || tithi.Cat != "tithi_sukla_9" ||
		tithi.Src != "/api/radio/cat/2c12529fd7f091c882ab646b099def116a1d6b1b" || tithi.Dur != 29.16 ||
		tithi.Durs["ru"] != 30.12 || len(tithi.Durs) != 16 ||
		len(tithi.Srcs) != 16 || tithi.Srcs["ru"] == "" || tithi.Srcs["ru"] == tithi.Src ||
		!strings.HasPrefix(tithi.Srcs["ru"], "/api/radio/cat/") {
		t.Errorf("tithi insert = %+v", tithi)
	}
	// Station sources are absolute under the station day folder.
	if s := radioByRubric(pl, rubSkyToday)[1].Src; s != "/radio/mars/2026-10-13/seg/sky_news.m4a" {
		t.Errorf("sky_news src = %s", s)
	}
	if s := radioByRubric(pl, rubRelease)[1].Src; s != "/radio/rel/series-2-nakshatras-02-bharani-yaml.m4a" {
		t.Errorf("release src = %s", s)
	}
	if s := radioByRubric(pl, rubLagna)[1].Src; s != "/radio/lib/signs-04-cancer.m4a" {
		t.Errorf("lib src = %s", s)
	}

	// Gaps: 1 s after a yoga name / the language note, 2 s after a lead,
	// 10 s otherwise; the timeline uses the item span.
	for i := 1; i < len(pl.Items); i++ {
		prev, cur := pl.Items[i-1], pl.Items[i]
		gap := radioSpeechGap
		if (prev.Kind == "yoga_name" || prev.Kind == "lang_note") && prev.Rubric == cur.Rubric {
			gap = radioNoteGap
		} else if prev.Kind == "lead" && prev.Rubric == cur.Rubric {
			gap = radioLeadGap
		}
		if d := cur.Start - (prev.Start + prev.span); d < gap-0.11 || d > gap+0.11 {
			t.Errorf("gap before %s = %.2f, want %.0f", cur.ID, d, gap)
		}
	}

	// Music without loops.json: each station's music.m4a (genre = station),
	// played once; the deck plays all nine stations before any repeats,
	// the rubric's station (Mars, the station of the day) first.
	radioCheckMusic(t, pl)
	radioCheckDeck(t, pl, 9)
	for _, m := range pl.Music.Tracks {
		if m.Src != "/radio/"+m.Station+"/ever/music.m4a" || m.Dur != 112 || m.Genre != m.Station {
			t.Errorf("music track = %+v", m)
		}
	}
	if len(pl.Music.Tracks) < 18 {
		t.Fatalf("want two deck passes, got %d tracks", len(pl.Music.Tracks))
	}
	if pl.Music.Tracks[0].Station != "mars" {
		t.Errorf("first loop = %+v", pl.Music.Tracks[0])
	}
	if pl.Music.Duck != 0.15 || pl.Music.Xfade != 8 {
		t.Errorf("music = %+v", pl.Music)
	}
	if pl.FactsUsed.Topic != "love" || pl.FactsUsed.TopHouse != 7 || pl.FactsUsed.Maha != "rahu" || pl.FactsUsed.SadeSatiN != nil {
		t.Errorf("facts_used = %+v", pl.FactsUsed)
	}
}

func TestRadioPlaylistExpiryAndMonth(t *testing.T) {
	// 2026-11-01 (Sunday → sun): the current lens and Jupiter's graha-watch
	// (valid_until 2026-10-30) are over; the month is November.
	dir := radioTestDir(t, "2026-11-01")
	f := fixtureFacts(t)
	pl := radioBuild(t, dir, f, radioDay("2026-11-01"), "en", &radioFixtureBirth, nil)
	got := radioIDs(radioByRubric(pl, rubTransits))[1:]
	want := []string{"transit-lens-q4/lagna/04-cancer", "transit-lens-q4/sun/02-taurus", "transit-lens-q4/moon/10-capricorn",
		"transit-combo/10-saturn-for-capricorn-moon", "graha-watch/01-saturn", "graha-watch/03-rahu-ketu"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("transits = %v\nwant %v", got, want)
	}
	if got := radioIDs(radioByRubric(pl, rubMonth))[1:]; !reflect.DeepEqual(got, []string{
		"month/2026-11-moon/capricorn", "month/2026-11-sun/taurus", "month/2026-11-lagna/cancer"}) {
		t.Errorf("month = %v", got)
	}
	if pl.FactsUsed.Station != "sun" {
		t.Errorf("station = %s", pl.FactsUsed.Station)
	}

	// 2027-02-01: q4 lenses (2027-01-24) are expired too, nothing has a
	// January/February month spec beyond 2027-01, and no station schedule
	// exists — those rubrics drop out instead of playing stale content.
	pl = radioBuild(t, dir, f, radioDay("2027-02-01"), "en", &radioFixtureBirth, nil)
	if got := radioIDs(radioByRubric(pl, rubTransits)); !reflect.DeepEqual(got[1:], []string{"transit-combo/10-saturn-for-capricorn-moon"}) {
		t.Errorf("transits 2027-02 = %v", got)
	}
	for _, r := range []string{rubMonth, rubSkyToday, rubRelease, rubEvent} {
		if items := radioByRubric(pl, r); len(items) != 0 {
			t.Errorf("%s must be skipped on 2027-02-01, got %v", r, radioIDs(items))
		}
	}
	if len(pl.Music.Tracks) != 0 || len(pl.missingMusic) == 0 {
		t.Errorf("no schedules: music = %+v missing = %v", pl.Music.Tracks, pl.missingMusic)
	}
	for _, it := range pl.Items {
		if strings.HasPrefix(it.ID, "events/") || strings.HasPrefix(it.ID, "month/") {
			t.Errorf("expired %s played", it.ID)
		}
	}
}

func TestRadioPlaylistYogasCap(t *testing.T) {
	dir := radioTestDir(t, "2026-10-13")
	f := fixtureFacts(t) // server: Sasha Yoga, Adhi Yoga
	extra := []string{"Adhi Yoga", "No Such Yoga", "Gaja Kesari Yoga", "Hamsa Yoga", "Malavya Yoga", "Ruchaka Yoga", "Bhadra Yoga"}
	pl := radioBuild(t, dir, f, radioDay("2026-10-13"), "en", nil, extra)
	// en: no language note; a yoga without a yoga-name track plays without it.
	got := radioIDs(radioByRubric(pl, rubYogas))[1:]
	want := []string{"yoga-name/sasha-yoga", "insert_yoga_Sasha Yoga", "yoga-name/adhi-yoga", "insert_yoga_Adhi Yoga",
		"insert_yoga_Gaja Kesari Yoga", "insert_yoga_Hamsa Yoga", "insert_yoga_Malavya Yoga"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("yogas = %v\nwant %v", got, want)
	}
	if len(pl.FactsUsed.Yogas) != 5 {
		t.Errorf("facts_used.yogas = %v", pl.FactsUsed.Yogas)
	}
}

func TestRadioPlaylistDeterministic(t *testing.T) {
	dir := radioTestDir(t, "2026-10-13")
	f := fixtureFacts(t)
	a, err := json.Marshal(radioBuild(t, dir, f, radioDay("2026-10-13"), "en", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(radioBuild(t, dir, fixtureFacts(t), radioDay("2026-10-13"), "en", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("same facts + at must give the same playlist")
	}
	// The seed moves with the facts: across lagnas the lead variants differ.
	leads := map[string]bool{}
	for _, sign := range chartFactsSigns {
		g := *fixtureFacts(t)
		g.Lagna.Sign = sign
		pl := radioBuild(t, dir, &g, radioDay("2026-10-13"), "en", nil, nil)
		leads[strings.Join(radioIDs(radioByRubric(pl, rubIdent)), ",")+"|"+radioByRubric(pl, rubMonth)[0].ID] = true
	}
	if len(leads) < 2 {
		t.Errorf("lead variants never change with the seed: %v", leads)
	}
}

func TestRadioSadeSati(t *testing.T) {
	for _, c := range []struct {
		moon, sat int
		age       float64
		want      int
	}{
		{9, 9, 27.5, 1}, // k = 11 signs ≈ 27.0 years: the first one
		{9, 9, 10, 1},   // before the first: clamped
		{9, 9, 57, 2},   // 27.0 + 29.46
		{3, 2, 1, 1},    // k = 0: from birth
		{3, 2, 30, 2},
		{3, 2, 400, 5}, // clamped
	} {
		if got := sadeSatiOrdinal(c.moon, c.sat, c.age); got != c.want {
			t.Errorf("sadeSatiOrdinal(%d, %d, %.1f) = %d, want %d", c.moon, c.sat, c.age, got, c.want)
		}
	}

	dir := radioTestDir(t, "2026-10-13")
	f := *fixtureFacts(t)
	ph := "rising"
	f.SadeSati = chartFactsSadeSati{Active: true, Phase: &ph}
	pl := radioBuild(t, dir, &f, radioDay("2026-10-13"), "en", &radioFixtureBirth, nil)
	items := radioByRubric(pl, rubSadeSati)
	// Born 1990, Moon and Saturn in Capricorn: age 36.4 → the first (from ~27).
	if len(items) != 2 || items[1].Cat != "sade_sati_1" || items[1].station != "saturn" {
		t.Fatalf("sade sati items = %+v", items)
	}
	if r := radioRubrics(pl); r[7] != rubSadeSati || r[6] != rubDasha || r[8] != rubYogas {
		t.Errorf("sade sati out of order: %v", r)
	}
	// Facts without a birth date: the ordinal is unknown, the rubric drops out.
	if items := radioByRubric(radioBuild(t, dir, &f, radioDay("2026-10-13"), "en", nil, nil), rubSadeSati); len(items) != 0 {
		t.Errorf("sade sati without birth = %v", radioIDs(items))
	}
}

// --- HTTP ---------------------------------------------------------------

func newTestRadio(t *testing.T, days ...string) (*radioService, string, string) {
	t.Helper()
	facts, clk, _ := newTestChartFacts(t)
	s := newRadioService(facts)
	s.now = clk.now
	dir := radioTestDir(t, days...)
	tts := t.TempDir()
	s.dir = func() string { return dir }
	s.ttsDir = func() string { return tts }
	return s, dir, tts
}

func postRadio(s *radioService, origin, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/radio/your-chart", strings.NewReader(body))
	r.RemoteAddr = "198.51.100.20:40000"
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.handle(w, r)
	return w
}

func TestRadioHTTP(t *testing.T) {
	s, dir, _ := newTestRadio(t, "2026-10-13")
	factsJSON, err := json.Marshal(fixtureFacts(t))
	if err != nil {
		t.Fatal(err)
	}
	withFacts := `{"facts":` + string(factsJSON) + `,"date":"5 15 1990","lang":"ru","at":"2026-10-13"}`

	if w := postRadio(s, "", withFacts); w.Code != http.StatusForbidden {
		t.Fatalf("no Origin: status %d, want 403", w.Code)
	}
	w := postRadio(s, "https://astrolytix.com", withFacts)
	if w.Code != http.StatusOK {
		t.Fatalf("facts request: status %d body %s", w.Code, w.Body)
	}
	var viaFacts, viaBirth radioPlaylist
	if err := json.Unmarshal(w.Body.Bytes(), &viaFacts); err != nil {
		t.Fatal(err)
	}
	if viaFacts.Lang != "ru" || len(viaFacts.Items) == 0 || viaFacts.Items[0].Kind != "ident" {
		t.Errorf("playlist = %+v", viaFacts)
	}

	// Birth data instead of facts: computed through chart-facts, same playlist
	// (at defaults to the fake clock's 2026-10-13).
	w = postRadio(s, "https://astrolytix.com", strings.Replace(chartFactsFixtureBody, `"lang":"en"`, `"lang":"ru"`, 1))
	if w.Code != http.StatusOK {
		t.Fatalf("birth request: status %d body %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &viaBirth); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(viaFacts, viaBirth) {
		t.Errorf("birth-data playlist differs from the facts one")
	}

	for _, bad := range []string{
		`{"facts":` + string(factsJSON) + `,"lang":"xx"}`,
		`{"facts":` + string(factsJSON) + `,"at":"13.10.2026"}`,
		`{"facts":` + strings.Replace(string(factsJSON), `"cancer"`, `"cancerx"`, 1) + `}`,
		`{"facts":` + string(factsJSON) + `,"yogas":["` + strings.Repeat("y", 65) + `"]}`,
		`{"facts":` + string(factsJSON) + `,"date":"2 31 1990"}`,
		`{"date":"5 15 1990","time":"25:30","timezone":"2","longitude":"13.4","latitude":"52.52"}`,
	} {
		if w := postRadio(s, "https://www.astrolytix.com", bad); w.Code != http.StatusBadRequest {
			t.Errorf("%.80s…: status %d, want 400", bad, w.Code)
		}
	}

	if err := os.Remove(filepath.Join(dir, "lib", "index.json")); err != nil {
		t.Fatal(err)
	}
	if w := postRadio(s, "https://astrolytix.com", withFacts); w.Code != http.StatusServiceUnavailable {
		t.Errorf("no library: status %d, want 503", w.Code)
	}
}

func TestRadioHTTPBadToken(t *testing.T) {
	s, _, _ := newTestRadio(t, "2026-10-13")
	r := httptest.NewRequest(http.MethodPost, "/api/radio/your-chart", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer not-a-token")
	r.Header.Set("Origin", "https://astrolytix.com")
	w := httptest.NewRecorder()
	s.handle(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: status %d, want 401", w.Code)
	}
}

func getRadioCat(s *radioService, key, rng string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/radio/cat/"+key, nil)
	if rng != "" {
		r.Header.Set("Range", rng)
	}
	w := httptest.NewRecorder()
	s.handleCat(w, r)
	return w
}

func TestRadioCatRoute(t *testing.T) {
	s, dir, tts := newTestRadio(t)
	const known = "2c12529fd7f091c882ab646b099def116a1d6b1b" // tithi_sukla_9 en
	if err := os.WriteFile(filepath.Join(tts, known+".mp3"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"xyz", strings.ToUpper(known), known + "0", "../" + known[3:], ""} {
		if w := getRadioCat(s, bad, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", bad, w.Code)
		}
	}
	// A cache file that is not in the catalog index is never served.
	other := strings.Repeat("ab", 20)
	if err := os.WriteFile(filepath.Join(tts, other+".mp3"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := getRadioCat(s, other, ""); w.Code != http.StatusNotFound {
		t.Errorf("not in index: status %d, want 404", w.Code)
	}
	// In the index but missing from the cache.
	if w := getRadioCat(s, "ef2fb1664ea193732fd49d325b2038f92bb39b51", ""); w.Code != http.StatusNotFound {
		t.Errorf("missing file: status %d, want 404", w.Code)
	}

	w := getRadioCat(s, known, "")
	if w.Code != http.StatusOK || w.Body.String() != "0123456789" ||
		w.Header().Get("Content-Type") != "audio/mpeg" || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("known: status %d type %q cache %q body %q", w.Code, w.Header().Get("Content-Type"),
			w.Header().Get("Cache-Control"), w.Body)
	}
	if w := getRadioCat(s, known, "bytes=2-4"); w.Code != http.StatusPartialContent || w.Body.String() != "234" {
		t.Errorf("range: status %d body %q", w.Code, w.Body)
	}

	// The index is re-read when it changes: add `other` to it.
	idx := filepath.Join(dir, "cat", "index.json")
	b, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), "{", `{"extra_slug":{"en":{"key":"`+other+`","dur":1}},`, 1))
	if err := os.WriteFile(idx, b, 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(idx, later, later); err != nil {
		t.Fatal(err)
	}
	if w := getRadioCat(s, other, ""); w.Code != http.StatusOK || w.Body.String() != "secret" {
		t.Errorf("after index update: status %d body %q", w.Code, w.Body)
	}
}

func TestRadioLangNote(t *testing.T) {
	dir := radioTestDir(t, "2026-10-13")
	f := fixtureFacts(t)
	notes := func(pl *radioPlaylist) []string {
		var out []string
		for _, it := range pl.Items {
			if it.Kind == "lang_note" {
				out = append(out, it.Rubric)
			}
		}
		return out
	}
	if got := notes(radioBuild(t, dir, f, radioDay("2026-10-13"), "en", nil, nil)); len(got) != 0 {
		t.Errorf("en: lang notes in %v", got)
	}
	if got := notes(radioBuild(t, dir, f, radioDay("2026-10-13"), "de", nil, nil)); !reflect.DeepEqual(got,
		[]string{rubTithi, rubDasha, rubYogas}) {
		t.Errorf("de: lang notes in %v", got)
	}

	// The tithi insert is not voiced in German: no note there.
	idx := filepath.Join(dir, "cat", "index.json")
	b, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	var cat map[string]map[string]radioCatEntry
	if err := json.Unmarshal(b, &cat); err != nil {
		t.Fatal(err)
	}
	delete(cat["tithi_sukla_9"], "de")
	if b, err = json.Marshal(cat); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, b, 0o644); err != nil {
		t.Fatal(err)
	}
	pl := radioBuild(t, dir, f, radioDay("2026-10-13"), "de", nil, nil)
	if got := notes(pl); !reflect.DeepEqual(got, []string{rubDasha, rubYogas}) {
		t.Errorf("de without tithi/de: lang notes in %v", got)
	}
	// The note follows the lead.
	if items := radioByRubric(pl, rubDasha); items[0].Kind != "lead" || items[1].Kind != "lang_note" {
		t.Errorf("dasha = %v", radioIDs(items))
	}
}

func TestRadioMusicLoops(t *testing.T) {
	dir := radioTestDir(t, "2026-10-13")
	write := func(st, body string) {
		t.Helper()
		p := filepath.Join(dir, st, "ever", "loops.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Mars (the station of the day) and Mercury play metal; the Moon two
	// genres and an entry escaping ever/ that must be ignored.
	write("mars", `[{"src":"metal-1.m4a","dur":30,"genre":"metal"},{"src":"metal-2.m4a","dur":35,"genre":"metal"}]`)
	write("mercury", `[{"src":"metal-3.m4a","dur":25,"genre":"metal"}]`)
	write("moon", `[{"src":"ambient.m4a","dur":40,"genre":"ambient"},{"src":"../../lib/x.m4a","dur":20,"genre":"x"},`+
		`{"src":"piano.m4a","dur":45,"genre":"piano"}]`)
	pl := radioBuild(t, dir, fixtureFacts(t), radioDay("2026-10-13"), "en", nil, nil)
	t.Logf("music:\n%s", radioCompact(pl))
	radioCheckMusic(t, pl)

	// The deck: 11 loops (mars 2, moon 2, seven music.m4a), each once per
	// pass; the first round has one loop of every station.
	radioCheckDeck(t, pl, 11)
	if len(pl.Music.Tracks) < 22 {
		t.Fatalf("want two deck passes, got %d tracks", len(pl.Music.Tracks))
	}
	first := map[string]bool{}
	for _, m := range pl.Music.Tracks[:9] {
		first[m.Station] = true
	}
	if len(first) != 9 {
		t.Errorf("first 9 loops cover stations %v, want all 9", first)
	}
	loopDur := map[string]float64{"/radio/mars/ever/metal-1.m4a": 30, "/radio/mars/ever/metal-2.m4a": 35,
		"/radio/mercury/ever/metal-3.m4a": 25, "/radio/moon/ever/ambient.m4a": 40, "/radio/moon/ever/piano.m4a": 45}
	lastBy := map[string]string{}
	for i, m := range pl.Music.Tracks {
		switch m.Station {
		case "mars", "moon", "mercury":
			if loopDur[m.Src] != m.Dur {
				t.Errorf("track %d = %+v: not a loop of loops.json", i, m)
			}
		default:
			if m.Src != "/radio/"+m.Station+"/ever/music.m4a" || m.Genre != m.Station {
				t.Errorf("track %d = %+v: want the station's music.m4a", i, m)
			}
		}
		// A station's loops take turns, across deck passes too.
		if m.Station == "mars" || m.Station == "moon" {
			if lastBy[m.Station] == m.Src {
				t.Errorf("track %d: %s repeats %s", i, m.Station, m.Src)
			}
			lastBy[m.Station] = m.Src
		}
	}
	b, err := json.Marshal(pl.Music.Tracks[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"genre":"metal"`) {
		t.Errorf("track json = %s", b)
	}
}

// TestRadioMusicDeckSeam: small decks, many seeds — a pass never opens with
// the loop that closed the previous one, and the run rules hold across the
// seam (radioCheckMusic) while every loop plays once per pass.
func TestRadioMusicDeckSeam(t *testing.T) {
	dir := radioTestDir(t) // no schedules: only loops.json has music
	write := func(st, body string) {
		t.Helper()
		p := filepath.Join(dir, st, "ever", "loops.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("mars", `[{"src":"m1.m4a","dur":20,"genre":"metal"},{"src":"m2.m4a","dur":20,"genre":"metal"}]`)
	write("venus", `[{"src":"v1.m4a","dur":20,"genre":"lounge"}]`)
	for _, sign := range chartFactsSigns {
		g := *fixtureFacts(t)
		g.Lagna.Sign = sign
		pl := radioBuild(t, dir, &g, radioDay("2026-10-13"), "en", nil, nil)
		radioCheckMusic(t, pl)
		radioCheckDeck(t, pl, 3)
		if len(pl.Music.Tracks) < 9 {
			t.Fatalf("%s: want several passes, got %d tracks", sign, len(pl.Music.Tracks))
		}
	}
	// One loop in all: it is all there is, so it plays on.
	write("venus", `[]`)
	write("mars", `[{"src":"m1.m4a","dur":200,"genre":"metal"}]`)
	pl := radioBuild(t, dir, fixtureFacts(t), radioDay("2026-10-13"), "en", nil, nil)
	if len(pl.Music.Tracks) < 2 {
		t.Fatalf("single loop: %+v", pl.Music.Tracks)
	}
	for _, m := range pl.Music.Tracks {
		if m.Src != "/radio/mars/ever/m1.m4a" {
			t.Errorf("single loop: %+v", m)
		}
	}
}

// TestRadioYogaNameLocalized: yoganame_<Name> voiced in the listener's
// language announces the yoga from the catalog; otherwise the English
// yoga-name library track does.
func TestRadioYogaNameLocalized(t *testing.T) {
	dir := radioTestDir(t, "2026-10-13")
	idx := filepath.Join(dir, "cat", "index.json")
	b, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	var cat map[string]map[string]radioCatEntry
	if err := json.Unmarshal(b, &cat); err != nil {
		t.Fatal(err)
	}
	ruKey := strings.Repeat("ab", 20)
	cat["yoganame_Sasha Yoga"] = map[string]radioCatEntry{"ru": {Key: ruKey, Dur: 1.8}}
	if b, err = json.Marshal(cat); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, b, 0o644); err != nil {
		t.Fatal(err)
	}
	f := fixtureFacts(t)

	pl := radioBuild(t, dir, f, radioDay("2026-10-13"), "ru", nil, nil)
	got := radioNoteIDs(radioByRubric(pl, rubYogas))[1:]
	want := []string{"lang_note", "insert_yoganame_Sasha Yoga", "insert_yoga_Sasha Yoga", "yoga-name/adhi-yoga", "insert_yoga_Adhi Yoga"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ru yogas = %v\nwant %v", got, want)
	}
	items := radioByRubric(pl, rubYogas)
	n, ins := items[2], items[3]
	if n.Kind != "insert" || n.Title != "Sasha Yoga" || n.Rubric != rubYogas || n.Cat != "yoganame_Sasha Yoga" ||
		n.Src != "/api/radio/cat/"+ruKey || n.Srcs["ru"] != "/api/radio/cat/"+ruKey || n.Durs["ru"] != 1.8 {
		t.Errorf("localized yoga name = %+v", n)
	}
	if d := ins.Start - (n.Start + n.span); math.Abs(d-radioNoteGap) > 0.11 {
		t.Errorf("gap after the yoga name = %.2f, want %.0f", d, radioNoteGap)
	}
	if a := items[4]; a.Kind != "yoga_name" || a.Src != "/radio/lib/yoga-name-adhi-yoga.m4a" {
		t.Errorf("Adhi Yoga name = %+v", a)
	}

	// No German voice for the name: the English library track.
	for _, lang := range []string{"de", "en"} {
		pl = radioBuild(t, dir, f, radioDay("2026-10-13"), lang, nil, nil)
		got = radioNoteIDs(radioByRubric(pl, rubYogas))[1:]
		want = []string{"yoga-name/sasha-yoga", "insert_yoga_Sasha Yoga", "yoga-name/adhi-yoga", "insert_yoga_Adhi Yoga"}
		if lang != "en" {
			want = append([]string{"lang_note"}, want...)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s yogas = %v\nwant %v", lang, got, want)
		}
	}
}
