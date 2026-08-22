package main

// SEO calendar pages generator (phase 1 of the organic-search channel,
// owner decision 2026-08-22).
//
//   ./astrolog_api seo-gen <outdir> [year ...]
//
// Computes, from the same ephemeris the app uses (./astrolog via
// siderealLongitudes + the pure-Go moon-phase code in events.go), the
// astro-calendar of each requested year and writes static HTML for all 16
// app languages into <outdir>:
//
//   <outdir>/index.html                      language hub
//   <outdir>/sitemap.xml                     every page, hreflang alternates
//   <outdir>/<lang>/index.html               per-language hub
//   <outdir>/<lang>/<year>/transits.html     sidereal sign ingresses
//   <outdir>/<lang>/<year>/retrograde-<planet>.html   (5 planets)
//   <outdir>/<lang>/<year>/moon-phases.html
//   <outdir>/<lang>/<year>/eclipses.html
//
// No DB, no HTTP server. Meant to run from cron on the production box and
// be served by nginx under https://astrolytix.com/astro/. Every file is
// written to a temp name and renamed into place, so a crash mid-run never
// leaves a truncated page behind. Any ephemeris failure aborts with a
// non-zero exit instead of publishing half-empty tables.

import (
	"fmt"
	"html"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	seoBaseURL     = "https://astrolytix.com/astro"
	seoSiteURL     = "https://astrolytix.com"
	seoAppStoreURL = "https://apps.apple.com/app/astrolytix/id6759404465"
	seoPlayURL     = "https://play.google.com/store/apps/details?id=com.astrolytix.app"
	seoInstagram   = "https://www.instagram.com/astrolytix/"
	// seoYouTube is filled in once the channel URL is known (owner); an
	// empty value simply omits the link and the sameAs entry.
	seoYouTube = ""
)

// Moon's mean daily motion, used to shift a noon longitude to the exact
// phase/eclipse instant (error well under 1°, fine for a sign label).
const moonMeanDegPerDay = 13.176396

var seoIngressPlanets = []string{"Sun", "Mercury", "Venus", "Mars", "Jupiter", "Saturn", "Rahu", "Ketu"}
var seoRetroPlanets = []string{"Mercury", "Venus", "Mars", "Jupiter", "Saturn"}

type seoIngress struct {
	date    time.Time // UTC day (noon sample that first shows the new sign)
	planet  string
	signIdx int
}

type seoRetroPeriod struct {
	planet    string
	start     time.Time // turns retrograde (calendar day)
	end       time.Time // turns direct (calendar day); zero if not found in scan window
	startSign int
	endSign   int
}

type seoMoonEvent struct {
	at      time.Time
	full    bool
	signIdx int
}

type seoEclipse struct {
	at      time.Time
	solar   bool
	signIdx int
}

// seoYearData is everything the pages of one year are rendered from.
type seoYearData struct {
	year      int
	ingresses []seoIngress
	retro     map[string][]seoRetroPeriod
	moons     []seoMoonEvent
	eclipses  []seoEclipse
}

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

func runSeoGenCLI(args []string) {
	if len(args) < 1 {
		fmt.Println("usage: astrolog_api seo-gen <outdir> [year ...]")
		os.Exit(2)
	}
	outDir := args[0]
	var years []int
	for _, a := range args[1:] {
		y, err := strconv.Atoi(a)
		if err != nil || y < 1900 || y > 2200 {
			fmt.Printf("bad year %q\n", a)
			os.Exit(2)
		}
		years = append(years, y)
	}
	if len(years) == 0 {
		now := time.Now().UTC().Year()
		years = []int{now, now + 1}
	}
	sort.Ints(years)

	start := time.Now()
	var data []*seoYearData
	for _, y := range years {
		d, err := computeSeoYear(y)
		if err != nil {
			log.Fatalf("seo-gen: year %d: %v", y, err)
		}
		data = append(data, d)
		log.Printf("seo-gen: %d computed — %d ingresses, %d moon events, %d eclipses, retro periods: %s",
			y, len(d.ingresses), len(d.moons), len(d.eclipses), retroSummary(d))
	}

	n, err := writeSeoSite(outDir, data)
	if err != nil {
		log.Fatalf("seo-gen: write: %v", err)
	}
	fmt.Printf("seo-gen: wrote %d files to %s for years %v in %s\n", n, outDir, years, time.Since(start).Round(time.Second))
}

func retroSummary(d *seoYearData) string {
	var parts []string
	for _, p := range seoRetroPlanets {
		parts = append(parts, fmt.Sprintf("%s=%d", p, len(d.retro[p])))
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// Computation
// ---------------------------------------------------------------------------

// noonLons memoizes siderealLongitudes per calendar day; the ingress scan,
// the station refinement and the moon/eclipse sign lookups all revisit the
// same days, and each miss is one ./astrolog exec.
type noonLons struct {
	memo map[string]map[string]float64
}

func newNoonLons() *noonLons { return &noonLons{memo: map[string]map[string]float64{}} }

func (n *noonLons) at(day time.Time) (map[string]float64, error) {
	day = time.Date(day.Year(), day.Month(), day.Day(), 12, 0, 0, 0, time.UTC)
	k := day.Format("2006-01-02")
	if v, ok := n.memo[k]; ok {
		return v, nil
	}
	v, err := siderealLongitudes(day)
	if err != nil {
		return nil, fmt.Errorf("ephemeris for %s: %w", k, err)
	}
	n.memo[k] = v
	return v, nil
}

func computeSeoYear(year int) (*seoYearData, error) {
	lons := newNoonLons()
	d := &seoYearData{year: year, retro: map[string][]seoRetroPeriod{}}

	from := time.Date(year, 1, 1, 12, 0, 0, 0, time.UTC)
	to := time.Date(year+1, 1, 1, 12, 0, 0, 0, time.UTC)

	// Sign ingresses: daily noon samples; the first day whose noon position
	// sits in a new sign is the ingress day (day precision by design —
	// see sidereal_note on the pages).
	prev, err := lons.at(from.AddDate(0, 0, -1))
	if err != nil {
		return nil, err
	}
	for day := from; day.Before(to); day = day.AddDate(0, 0, 1) {
		cur, err := lons.at(day)
		if err != nil {
			return nil, err
		}
		for _, p := range seoIngressPlanets {
			pl, okp := prev[p]
			cl, okc := cur[p]
			if !okp || !okc {
				return nil, fmt.Errorf("ephemeris for %s lacks %s", day.Format("2006-01-02"), p)
			}
			if signOf(cl) != signOf(pl) {
				d.ingresses = append(d.ingresses, seoIngress{date: day, planet: p, signIdx: signOf(cl)})
			}
		}
		prev = cur
	}

	// Retrograde periods: stations scanned with a margin so a period that
	// straddles the year boundary is paired completely. findStations is the
	// push-event scanner from events.go (calendar-day precision).
	margin := 200 * 24 * time.Hour // longest retro (Saturn ~140 d) + slack
	stations := findStations(from.Add(-margin), to.Add(margin))
	if len(stations) == 0 {
		return nil, fmt.Errorf("no stations found in %d±200d — ephemeris unavailable?", year)
	}
	sort.Slice(stations, func(i, j int) bool { return stations[i].date.Before(stations[j].date) })
	if os.Getenv("SEO_DEBUG") != "" {
		for _, s := range stations {
			log.Printf("station %s retro=%v %s", s.planet, s.retro, s.date.Format("2006-01-02"))
		}
	}
	for _, p := range seoRetroPlanets {
		var open *seoRetroPeriod
		for _, s := range stations {
			if s.planet != p {
				continue
			}
			if s.retro {
				if open != nil {
					return nil, fmt.Errorf("%s: two retro stations without a direct station between %s and %s", p, open.start.Format("2006-01-02"), s.date.Format("2006-01-02"))
				}
				sl, err := lons.at(s.date)
				if err != nil {
					return nil, err
				}
				open = &seoRetroPeriod{planet: p, start: s.date, startSign: signOf(sl[p])}
				continue
			}
			if open == nil {
				continue // direct station whose retro start lies before the scan window
			}
			el, err := lons.at(s.date)
			if err != nil {
				return nil, err
			}
			open.end = s.date
			open.endSign = signOf(el[p])
			if open.end.Year() >= year && open.start.Year() <= year {
				d.retro[p] = append(d.retro[p], *open)
			}
			open = nil
		}
		if open != nil && open.start.Year() <= year {
			// Retro start inside the window but the direct station is beyond
			// it: can only happen if the margin is too small — fail loudly.
			return nil, fmt.Errorf("%s: retro period starting %s has no direct station within scan window", p, open.start.Format("2006-01-02"))
		}
	}

	// Moon phases: walk the year with the events.go finders.
	cursor := time.Date(year-1, 12, 20, 0, 0, 0, 0, time.UTC)
	for _, full := range []bool{false, true} {
		target := 0.0
		if full {
			target = 0.5
		}
		t := cursor
		for {
			next := findNextPhase(t, target)
			if next.IsZero() {
				return nil, fmt.Errorf("moon phase search failed after %s", t.Format("2006-01-02"))
			}
			if next.Year() > year {
				break
			}
			if next.Year() == year {
				idx, err := moonSignAt(lons, next)
				if err != nil {
					return nil, err
				}
				d.moons = append(d.moons, seoMoonEvent{at: next, full: full, signIdx: idx})
			}
			t = next.AddDate(0, 0, 20)
		}
	}
	sort.Slice(d.moons, func(i, j int) bool { return d.moons[i].at.Before(d.moons[j].at) })

	// Eclipses from the curated table in events.go.
	for _, e := range eclipses {
		if e.date.Year() != year {
			continue
		}
		var idx int
		if e.solar {
			l, err := lons.at(e.date)
			if err != nil {
				return nil, err
			}
			idx = signOf(l["Sun"])
		} else {
			idx, err = moonSignAt(lons, e.date)
			if err != nil {
				return nil, err
			}
		}
		d.eclipses = append(d.eclipses, seoEclipse{at: e.date, solar: e.solar, signIdx: idx})
	}
	sort.Slice(d.eclipses, func(i, j int) bool { return d.eclipses[i].at.Before(d.eclipses[j].at) })

	return d, nil
}

// moonSignAt returns the sidereal sign of the Moon at instant t, shifting the
// day's noon longitude by the mean motion for the hours between.
func moonSignAt(lons *noonLons, t time.Time) (int, error) {
	l, err := lons.at(t)
	if err != nil {
		return 0, err
	}
	noon := time.Date(t.Year(), t.Month(), t.Day(), 12, 0, 0, 0, time.UTC)
	return signOf(moonLonShift(l["Moon"], t.Sub(noon))), nil
}

// moonLonShift moves a Moon longitude by the mean motion over dt (pure, tested).
func moonLonShift(noonLon float64, dt time.Duration) float64 {
	lon := noonLon + moonMeanDegPerDay*dt.Hours()/24.0
	lon = math.Mod(lon, 360)
	if lon < 0 {
		lon += 360
	}
	return lon
}

// ---------------------------------------------------------------------------
// Site writer
// ---------------------------------------------------------------------------

type seoPage struct {
	rel   string // path relative to lang dir, e.g. "2026/transits.html"; "" = lang hub
	title string
	desc  string
	body  string // inner HTML (already escaped where needed)
}

func writeSeoSite(outDir string, data []*seoYearData) (int, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, err
	}
	years := make([]int, 0, len(data))
	for _, d := range data {
		years = append(years, d.year)
	}
	generated := time.Now().UTC().Format("2006-01-02")

	count := 0
	var sitemap []string
	for _, lang := range seoLangs {
		var pages []seoPage
		pages = append(pages, buildLangHub(lang, data))
		for _, d := range data {
			pages = append(pages, buildTransitsPage(lang, d))
			for _, p := range seoRetroPlanets {
				pages = append(pages, buildRetroPage(lang, d, p))
			}
			pages = append(pages, buildMoonPage(lang, d))
			pages = append(pages, buildEclipsesPage(lang, d))
		}
		for _, pg := range pages {
			rel := pg.rel
			if rel == "" {
				rel = "index.html"
			}
			full := renderSeoLayout(lang, rel, pg, years, generated)
			if err := writeAtomic(filepath.Join(outDir, lang, rel), []byte(full)); err != nil {
				return count, err
			}
			count++
			sitemap = append(sitemap, rel)
		}
	}
	// Root hub: list of languages (x-default), no astrology content itself.
	if err := writeAtomic(filepath.Join(outDir, "index.html"), []byte(renderRootHub(years))); err != nil {
		return count, err
	}
	count++
	if err := writeAtomic(filepath.Join(outDir, "sitemap.xml"), []byte(renderSitemap(uniqueStrings(sitemap), generated))); err != nil {
		return count, err
	}
	count++
	return count, nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// writeAtomic writes to <path>.tmp then renames, so readers (nginx) never see
// a partially written file.
func writeAtomic(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------

func esc(s string) string { return html.EscapeString(s) }

func yearStr(y int) string { return strconv.Itoa(y) }

func planetSlug(p string) string { return strings.ToLower(p) }

func fmtDay(t time.Time) string { return t.UTC().Format("2006-01-02") }

func fmtInstant(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" }

func buildLangHub(lang string, data []*seoYearData) seoPage {
	years := make([]int, 0, len(data))
	for _, d := range data {
		years = append(years, d.year)
	}
	yr := strings.Trim(strings.Join(intsToStrings(years), "–"), "–")
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("hub_h1", lang, nil)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("hub_intro", lang, nil)) + "</p>\n")
	for _, d := range data {
		y := yearStr(d.year)
		b.WriteString("<section class=\"year\"><h2>" + y + "</h2><ul class=\"links\">\n")
		b.WriteString(fmt.Sprintf("<li><a href=\"%s/transits.html\">%s %s</a></li>\n", y, esc(seoT("section_transits", lang, nil)), y))
		for _, p := range seoRetroPlanets {
			b.WriteString(fmt.Sprintf("<li><a href=\"%s/retrograde-%s.html\">%s %s</a></li>\n", y, planetSlug(p),
				esc(seoT("retro_short", lang, map[string]string{"planet": planetName(p, lang)})), y))
		}
		b.WriteString(fmt.Sprintf("<li><a href=\"%s/moon-phases.html\">%s %s</a></li>\n", y, esc(seoT("section_moon", lang, nil)), y))
		b.WriteString(fmt.Sprintf("<li><a href=\"%s/eclipses.html\">%s %s</a></li>\n", y, esc(seoT("section_eclipses", lang, nil)), y))
		b.WriteString("</ul></section>\n")
	}
	title := seoT("hub_title", lang, map[string]string{"year": yr})
	return seoPage{rel: "", title: title, desc: seoT("hub_intro", lang, nil), body: b.String()}
}

func intsToStrings(in []int) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strconv.Itoa(v)
	}
	return out
}

func buildTransitsPage(lang string, d *seoYearData) seoPage {
	y := yearStr(d.year)
	repl := map[string]string{"year": y}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("transits_title", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("transits_intro", lang, repl)) + "</p>\n")
	b.WriteString("<table><thead><tr><th>" + esc(seoT("col_date", lang, nil)) + "</th><th>" + esc(seoT("col_planet", lang, nil)) + "</th><th>" + esc(seoT("col_event", lang, nil)) + "</th></tr></thead><tbody>\n")
	for _, in := range d.ingresses {
		ev := seoT("enters", lang, map[string]string{"planet": planetName(in.planet, lang), "sign": signName(in.signIdx, lang)})
		b.WriteString("<tr><td><time datetime=\"" + fmtDay(in.date) + "\">" + fmtDay(in.date) + "</time></td><td>" + esc(planetName(in.planet, lang)) + "</td><td>" + esc(ev) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("sidereal_note", lang, nil)) + "</p>\n")
	b.WriteString(seoRelatedLinks(lang, d.year, "transits"))
	return seoPage{rel: y + "/transits.html", title: seoT("transits_title", lang, repl), desc: seoT("transits_intro", lang, repl), body: b.String()}
}

func buildRetroPage(lang string, d *seoYearData, planet string) seoPage {
	y := yearStr(d.year)
	pn := planetName(planet, lang)
	repl := map[string]string{"year": y, "planet": pn}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("retro_title", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("retro_intro", lang, repl)) + "</p>\n")
	periods := d.retro[planet]
	if len(periods) == 0 {
		b.WriteString("<p class=\"empty\">" + esc(seoT("no_retro", lang, repl)) + "</p>\n")
	} else {
		b.WriteString("<table><thead><tr><th>" + esc(seoT("col_start", lang, nil)) + "</th><th>" + esc(seoT("sign_at_start", lang, nil)) + "</th><th>" + esc(seoT("col_end", lang, nil)) + "</th><th>" + esc(seoT("sign_at_end", lang, nil)) + "</th><th>" + esc(seoT("col_days", lang, nil)) + "</th></tr></thead><tbody>\n")
		for _, p := range periods {
			days := int(math.Round(p.end.Sub(p.start).Hours() / 24))
			b.WriteString("<tr><td><time datetime=\"" + fmtDay(p.start) + "\">" + fmtDay(p.start) + "</time></td><td>" + esc(signName(p.startSign, lang)) +
				"</td><td><time datetime=\"" + fmtDay(p.end) + "\">" + fmtDay(p.end) + "</time></td><td>" + esc(signName(p.endSign, lang)) + "</td><td>" + strconv.Itoa(days) + "</td></tr>\n")
		}
		b.WriteString("</tbody></table>\n")
		b.WriteString("<p class=\"note\">" + esc(seoT("spans_note", lang, nil)) + "</p>\n")
	}
	b.WriteString("<h2>" + esc(seoT("retro_short", lang, map[string]string{"planet": pn})) + "</h2>\n")
	b.WriteString("<p>" + esc(seoT("retro_meaning_"+planet, lang, nil)) + "</p>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("sidereal_note", lang, nil)) + "</p>\n")
	b.WriteString(seoRelatedLinks(lang, d.year, "retrograde-"+planetSlug(planet)))
	return seoPage{rel: y + "/retrograde-" + planetSlug(planet) + ".html", title: seoT("retro_title", lang, repl), desc: seoT("retro_intro", lang, repl), body: b.String()}
}

func buildMoonPage(lang string, d *seoYearData) seoPage {
	y := yearStr(d.year)
	repl := map[string]string{"year": y}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("moon_title", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("moon_intro", lang, repl)) + "</p>\n")
	b.WriteString("<table><thead><tr><th>" + esc(seoT("col_date", lang, nil)) + "</th><th>" + esc(seoT("col_event", lang, nil)) + "</th><th>" + esc(seoT("col_sign", lang, nil)) + "</th></tr></thead><tbody>\n")
	for _, m := range d.moons {
		kind := "new_moon"
		if m.full {
			kind = "full_moon"
		}
		b.WriteString("<tr><td><time datetime=\"" + m.at.UTC().Format(time.RFC3339) + "\">" + fmtInstant(m.at) + "</time></td><td>" + esc(seoT(kind, lang, nil)) + "</td><td>" + esc(signName(m.signIdx, lang)) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("sidereal_note", lang, nil)) + "</p>\n")
	b.WriteString(seoRelatedLinks(lang, d.year, "moon-phases"))
	return seoPage{rel: y + "/moon-phases.html", title: seoT("moon_title", lang, repl), desc: seoT("moon_intro", lang, repl), body: b.String()}
}

func buildEclipsesPage(lang string, d *seoYearData) seoPage {
	y := yearStr(d.year)
	repl := map[string]string{"year": y}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("eclipses_title", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("eclipses_intro", lang, repl)) + "</p>\n")
	b.WriteString("<table><thead><tr><th>" + esc(seoT("col_date", lang, nil)) + "</th><th>" + esc(seoT("col_event", lang, nil)) + "</th><th>" + esc(seoT("col_sign", lang, nil)) + "</th></tr></thead><tbody>\n")
	for _, e := range d.eclipses {
		kind := "lunar_eclipse"
		if e.solar {
			kind = "solar_eclipse"
		}
		b.WriteString("<tr><td><time datetime=\"" + e.at.UTC().Format(time.RFC3339) + "\">" + fmtInstant(e.at) + "</time></td><td>" + esc(seoT(kind, lang, nil)) + "</td><td>" + esc(signName(e.signIdx, lang)) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("sidereal_note", lang, nil)) + "</p>\n")
	b.WriteString(seoRelatedLinks(lang, d.year, "eclipses"))
	return seoPage{rel: y + "/eclipses.html", title: seoT("eclipses_title", lang, repl), desc: seoT("eclipses_intro", lang, repl), body: b.String()}
}

// seoRelatedLinks is the in-year navigation block under every page (internal
// linking is what lets crawlers discover the whole set from one entry).
func seoRelatedLinks(lang string, year int, current string) string {
	y := yearStr(year)
	var b strings.Builder
	b.WriteString("<nav class=\"related\"><ul>\n")
	add := func(slug, label string) {
		if slug == current {
			b.WriteString("<li><span>" + esc(label) + "</span></li>\n")
			return
		}
		b.WriteString("<li><a href=\"" + slug + ".html\">" + esc(label) + "</a></li>\n")
	}
	add("transits", seoT("section_transits", lang, nil)+" "+y)
	for _, p := range seoRetroPlanets {
		add("retrograde-"+planetSlug(p), seoT("retro_short", lang, map[string]string{"planet": planetName(p, lang)})+" "+y)
	}
	add("moon-phases", seoT("section_moon", lang, nil)+" "+y)
	add("eclipses", seoT("section_eclipses", lang, nil)+" "+y)
	b.WriteString("</ul></nav>\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

const seoCSS = `:root{--bg:#0f0c29;--bg2:#302b63;--card:#1a1640;--gold:#d4af37;--text:#f5f5f5;--muted:#b8b8b8;--accent:#e94560}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:Raleway,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:linear-gradient(160deg,var(--bg),var(--bg2) 60%,#24243e);color:var(--text);line-height:1.6;min-height:100vh}
a{color:var(--gold)}main{max-width:880px;margin:0 auto;padding:24px 16px 120px}
header.top{display:flex;align-items:center;gap:14px;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.08)}
header.top a.brand{font-family:Cinzel,Georgia,serif;font-weight:700;letter-spacing:.04em;color:var(--gold);text-decoration:none;font-size:1.15rem}
header.top nav a{color:var(--muted);text-decoration:none;margin-inline-start:14px;font-size:.95rem}
h1{font-family:Cinzel,Georgia,serif;font-size:1.7rem;line-height:1.25;margin:.4em 0}
h2{font-family:Cinzel,Georgia,serif;font-size:1.25rem;margin-top:1.6em;color:var(--gold)}
p.lead{font-size:1.05rem;color:#e6e6e6}p.note,p.empty{color:var(--muted);font-size:.9rem}
table{width:100%;border-collapse:collapse;margin:16px 0;font-size:.95rem}
th,td{text-align:start;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.1);vertical-align:top}
th{color:var(--gold);font-weight:600}time{white-space:nowrap}
.wrap{overflow-x:auto}
nav.related ul,ul.links{list-style:none;padding:0;margin:12px 0;display:flex;flex-wrap:wrap;gap:8px}
nav.related li a,nav.related li span,ul.links li a{display:inline-block;padding:6px 12px;border:1px solid rgba(212,175,55,.45);border-radius:999px;text-decoration:none;font-size:.9rem}
nav.related li span{color:var(--muted);border-color:rgba(255,255,255,.15)}
section.year h2{margin-top:1.2em}
.cta{margin:32px 0;padding:20px;background:var(--card);border:1px solid rgba(212,175,55,.35);border-radius:14px}
.cta h2{margin-top:0}.cta .btns{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}
.btn{display:inline-block;padding:10px 18px;border-radius:10px;background:var(--gold);color:#1a0a2e;font-weight:600;text-decoration:none}
.btn.alt{background:transparent;color:var(--gold);border:1px solid var(--gold)}
footer{color:var(--muted);font-size:.85rem;padding:24px 16px;border-top:1px solid rgba(255,255,255,.08)}
footer a{color:var(--muted);margin-inline-end:12px}.langs a{margin-inline-end:10px;white-space:nowrap}
#stickybar{position:fixed;left:0;right:0;bottom:0;z-index:50;display:flex;align-items:center;justify-content:center;gap:12px;padding:10px 14px;background:rgba(26,22,64,.96);border-top:1px solid rgba(212,175,55,.5);backdrop-filter:blur(6px);box-shadow:0 -6px 24px rgba(0,0,0,.35)}
#stickybar span{font-size:.9rem;color:#e6e6e6}
#stickybar a.btn{animation:pulse 2.4s ease-in-out infinite;white-space:nowrap}
@keyframes pulse{0%,100%{transform:scale(1);box-shadow:0 0 0 rgba(212,175,55,0)}50%{transform:scale(1.05);box-shadow:0 0 18px rgba(212,175,55,.55)}}
@media (prefers-reduced-motion:reduce){#stickybar a.btn{animation:none}}
@media (max-width:600px){#stickybar span{display:none}#stickybar a.btn{width:100%;text-align:center}h1{font-size:1.4rem}}`

// seoStickyJS picks the store button for the visitor's platform; no
// redirect — the owner's 2026-08-22 decision is "invite, don't hijack".
const seoStickyJS = `(function(){var ua=navigator.userAgent||'';var ios=/iPhone|iPad|iPod/i.test(ua)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);var and=/Android/i.test(ua);var bar=document.getElementById('stickybar');if(!bar)return;var a=bar.querySelector('a.ios'),g=bar.querySelector('a.android');if(ios&&g)g.style.display='none';if(and&&a)a.style.display='none';})();`

// seoURL is the public URL of a page; hubs are addressed by their directory.
func seoURL(lang, rel string) string {
	if rel == "index.html" {
		return seoBaseURL + "/" + lang + "/"
	}
	return seoBaseURL + "/" + lang + "/" + rel
}

func renderSeoLayout(lang, rel string, pg seoPage, years []int, generated string) string {
	dir := "ltr"
	if lang == "ar" {
		dir = "rtl"
	}
	canonical := seoURL(lang, rel)
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"" + lang + "\" dir=\"" + dir + "\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>" + esc(pg.title) + " | Astrolytix</title>\n")
	b.WriteString("<meta name=\"description\" content=\"" + esc(truncDesc(pg.desc)) + "\">\n")
	b.WriteString("<link rel=\"canonical\" href=\"" + canonical + "\">\n")
	for _, l := range seoLangs {
		b.WriteString("<link rel=\"alternate\" hreflang=\"" + l + "\" href=\"" + seoURL(l, rel) + "\">\n")
	}
	b.WriteString("<link rel=\"alternate\" hreflang=\"x-default\" href=\"" + seoURL("en", rel) + "\">\n")
	b.WriteString("<meta property=\"og:title\" content=\"" + esc(pg.title) + "\">\n<meta property=\"og:description\" content=\"" + esc(truncDesc(pg.desc)) + "\">\n<meta property=\"og:url\" content=\"" + canonical + "\">\n<meta property=\"og:type\" content=\"article\">\n<meta property=\"og:site_name\" content=\"Astrolytix\">\n")
	b.WriteString("<link rel=\"icon\" href=\"/logo-star.svg\" type=\"image/svg+xml\">\n")
	b.WriteString("<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"><link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n")
	b.WriteString("<link href=\"https://fonts.googleapis.com/css2?family=Cinzel:wght@600;700&family=Raleway:wght@400;600&display=swap\" rel=\"stylesheet\">\n")
	b.WriteString("<style>" + seoCSS + "</style>\n")
	b.WriteString("<script type=\"application/ld+json\">" + seoJSONLD(lang, rel, pg, canonical, generated) + "</script>\n")
	b.WriteString("</head>\n<body>\n")
	b.WriteString("<header class=\"top\"><a class=\"brand\" href=\"" + seoSiteURL + "/\">Astrolytix</a><nav><a href=\"" + seoBaseURL + "/" + lang + "/\">" + esc(seoT("nav_calendar", lang, nil)) + "</a></nav></header>\n")
	b.WriteString("<main>\n<div class=\"wrap\">\n" + pg.body + "</div>\n")
	if rel != "index.html" {
		b.WriteString("<p class=\"note\">" + esc(seoT("other_years", lang, nil)) + ": ")
		for i, y := range years {
			if i > 0 {
				b.WriteString(" · ")
			}
			b.WriteString("<a href=\"" + seoBaseURL + "/" + lang + "/" + strconv.Itoa(y) + "/" + filepath.Base(rel) + "\">" + strconv.Itoa(y) + "</a>")
		}
		b.WriteString("</p>\n")
	}
	b.WriteString("<section class=\"cta\"><h2>" + esc(seoT("cta_h", lang, nil)) + "</h2><p>" + esc(seoT("cta_p", lang, nil)) + "</p><div class=\"btns\">")
	b.WriteString("<a class=\"btn\" rel=\"noopener\" href=\"" + seoAppStoreURL + "\">" + esc(seoT("cta_ios", lang, nil)) + "</a>")
	b.WriteString("<a class=\"btn alt\" rel=\"noopener\" href=\"" + seoPlayURL + "\">" + esc(seoT("cta_android", lang, nil)) + "</a></div></section>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("updated", lang, nil)) + ": " + generated + "</p>\n")
	b.WriteString("</main>\n<footer>\n<div class=\"langs\">" + esc(seoT("languages", lang, nil)) + ": ")
	for _, l := range seoLangs {
		if l == lang {
			b.WriteString("<strong>" + esc(seoLangNames[l]) + "</strong> ")
			continue
		}
		b.WriteString("<a href=\"" + seoURL(l, rel) + "\" hreflang=\"" + l + "\">" + esc(seoLangNames[l]) + "</a> ")
	}
	b.WriteString("</div>\n<div><a href=\"" + seoSiteURL + "/privacy.html\">" + esc(seoT("privacy", lang, nil)) + "</a><a href=\"" + seoSiteURL + "/terms.html\">" + esc(seoT("terms", lang, nil)) + "</a>")
	b.WriteString("<a rel=\"me noopener\" href=\"" + seoInstagram + "\">Instagram</a>")
	if seoYouTube != "" {
		b.WriteString("<a rel=\"me noopener\" href=\"" + seoYouTube + "\">YouTube</a>")
	}
	b.WriteString("</div>\n<div>© Astrolytix</div>\n</footer>\n")
	b.WriteString("<div id=\"stickybar\"><span>" + esc(seoT("cta_h", lang, nil)) + "</span><a class=\"btn ios\" rel=\"noopener\" href=\"" + seoAppStoreURL + "\">" + esc(seoT("cta_ios", lang, nil)) + "</a><a class=\"btn android\" rel=\"noopener\" href=\"" + seoPlayURL + "\">" + esc(seoT("cta_android", lang, nil)) + "</a></div>\n")
	b.WriteString("<script>" + seoStickyJS + "</script>\n</body>\n</html>\n")
	return b.String()
}

// truncDesc keeps meta descriptions within the ~160-char snippet budget.
func truncDesc(s string) string {
	r := []rune(s)
	if len(r) <= 160 {
		return s
	}
	cut := 157
	for cut > 100 && r[cut] != ' ' {
		cut--
	}
	return strings.TrimSpace(string(r[:cut])) + "…"
}

func seoJSONLD(lang, rel string, pg seoPage, canonical, generated string) string {
	same := []string{seoInstagram}
	if seoYouTube != "" {
		same = append(same, seoYouTube)
	}
	var sameJSON []string
	for _, s := range same {
		sameJSON = append(sameJSON, strconv.Quote(s))
	}
	org := `{"@type":"Organization","name":"Astrolytix","url":"` + seoSiteURL + `/","logo":"` + seoSiteURL + `/logo.svg","sameAs":[` + strings.Join(sameJSON, ",") + `]}`
	crumbs := `{"@type":"BreadcrumbList","itemListElement":[{"@type":"ListItem","position":1,"name":"Astrolytix","item":"` + seoSiteURL + `/"},{"@type":"ListItem","position":2,"name":` + strconv.Quote(seoT("nav_calendar", lang, nil)) + `,"item":"` + seoBaseURL + "/" + lang + `/"}`
	if rel != "index.html" {
		crumbs += `,{"@type":"ListItem","position":3,"name":` + strconv.Quote(pg.title) + `,"item":"` + canonical + `"}`
	}
	crumbs += `]}`
	page := `{"@type":"WebPage","@id":"` + canonical + `","url":"` + canonical + `","name":` + strconv.Quote(pg.title) + `,"description":` + strconv.Quote(truncDesc(pg.desc)) + `,"inLanguage":"` + lang + `","dateModified":"` + generated + `","isPartOf":{"@type":"WebSite","name":"Astrolytix","url":"` + seoSiteURL + `/"},"publisher":` + org + `}`
	return `{"@context":"https://schema.org","@graph":[` + page + `,` + crumbs + `]}`
}

func renderRootHub(years []int) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>Vedic astrology calendar — Astrolytix</title>\n<meta name=\"description\" content=\"Planetary transits, retrograde periods, moon phases and eclipses in the sidereal zodiac, in 16 languages.\">\n")
	b.WriteString("<link rel=\"canonical\" href=\"" + seoBaseURL + "/\">\n")
	for _, l := range seoLangs {
		b.WriteString("<link rel=\"alternate\" hreflang=\"" + l + "\" href=\"" + seoBaseURL + "/" + l + "/\">\n")
	}
	b.WriteString("<link rel=\"alternate\" hreflang=\"x-default\" href=\"" + seoBaseURL + "/en/\">\n")
	b.WriteString("<style>" + seoCSS + "</style>\n</head>\n<body>\n")
	b.WriteString("<header class=\"top\"><a class=\"brand\" href=\"" + seoSiteURL + "/\">Astrolytix</a></header>\n<main>\n<h1>Vedic astrology calendar</h1>\n<p class=\"lead\">Years: " + strings.Join(intsToStrings(years), ", ") + ". Choose your language:</p>\n<ul class=\"links\">\n")
	for _, l := range seoLangs {
		b.WriteString("<li><a href=\"" + seoBaseURL + "/" + l + "/\" hreflang=\"" + l + "\" lang=\"" + l + "\">" + esc(seoLangNames[l]) + "</a></li>\n")
	}
	b.WriteString("</ul>\n</main>\n</body>\n</html>\n")
	return b.String()
}

func renderSitemap(rels []string, generated string) string {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n")
	b.WriteString("<url><loc>" + seoBaseURL + "/</loc><lastmod>" + generated + "</lastmod></url>\n")
	for _, rel := range rels {
		for _, l := range seoLangs {
			b.WriteString("<url><loc>" + seoURL(l, rel) + "</loc><lastmod>" + generated + "</lastmod>\n")
			for _, alt := range seoLangs {
				b.WriteString("<xhtml:link rel=\"alternate\" hreflang=\"" + alt + "\" href=\"" + seoURL(alt, rel) + "\"/>\n")
			}
			b.WriteString("<xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"" + seoURL("en", rel) + "\"/>\n</url>\n")
		}
	}
	b.WriteString("</urlset>\n")
	return b.String()
}
