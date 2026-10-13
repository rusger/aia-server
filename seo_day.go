package main

// Daily SEO pages (phase 2 of the calendar, owner 2026-10-12):
//
//   <outdir>/<lang>/<yyyy>/<mm>/<dd>.html   positions of the nine grahas at
//                                           noon UTC, nakshatra, tithi, events
//   <outdir>/<lang>/<yyyy>/<mm>/            month hub listing the days
//   <outdir>/<lang>/today/                  today's page under a stable URL
//   <outdir>/<lang>/today.json              three lines for the site's
//                                           "sky today" block (all 16 langs)
//
// A dated page never changes once its day has passed, so its sitemap
// <lastmod> stays put (seo_state.go); each new day is one genuinely new URL
// per language — the honest version of "fresh content" (a page that
// recomputes on every visit is invisible to a crawler that fetches it once
// a week, and the nightly stamp that moved every date was a non-signal).
//
// All positions come from the noon longitudes computeSeoYear already
// sampled for the ingress scan, so the daily pages cost no extra astrolog
// runs. Rendered for seoDayLangs — started as the four languages with most
// of the calendar's search traffic, every site language since 13.10.2026.

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Started as en/zh/ru/es (70 % of the calendar's search traffic) to spare
// the crawl budget; owner 13.10.2026: every site language.
var seoDayLangs = seoLangs

// First day that gets a page; nothing before the launch is rendered, and
// pages already written are never deleted (an indexed URL must keep living).
var seoDayEpoch = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

const (
	seoDayAhead    = 60 // days after today that get a page
	seoUpcomingMax = 5  // events listed under "Upcoming"
	seoUpcomingWin = 45 // days ahead to look for them
)

var seoDayPlanets = []string{"Sun", "Moon", "Mercury", "Venus", "Mars", "Jupiter", "Saturn", "Rahu", "Ketu"}

type seoDayPos struct {
	planet  string
	lon     float64
	signIdx int
	deg     float64 // degrees within the sign
	nak     int     // 0..26
	pada    int     // 1..4
	retro   bool
}

type seoDay struct {
	date  time.Time // UTC calendar day (midnight)
	pos   []seoDayPos
	tithi int // 1..30
}

// seoDayEvent is one calendar-day event flattened out of the year data, so
// a day page can list "events on this day" and "upcoming" with a link to
// the year page that holds the full table.
type seoDayEvent struct {
	day     time.Time // UTC calendar day
	kind    string    // ingress | station_retro | station_direct | new_moon | full_moon | solar_eclipse | lunar_eclipse
	planet  string
	signIdx int
	page    string // year page rel, e.g. "2026/transits.html"
}

// --- pure astronomy helpers -------------------------------------------------

func norm360(x float64) float64 {
	x = math.Mod(x, 360)
	if x < 0 {
		x += 360
	}
	return x
}

// nakshatraOf maps a sidereal longitude to its nakshatra (0 = Ashwini) and
// pada (1..4); each nakshatra spans 13°20′, each pada 3°20′.
func nakshatraOf(lon float64) (idx, pada int) {
	lon = norm360(lon)
	span := 360.0 / 27.0
	idx = int(lon / span)
	if idx > 26 {
		idx = 26
	}
	pada = int((lon-float64(idx)*span)/(span/4)) + 1
	if pada > 4 {
		pada = 4
	}
	return idx, pada
}

// tithiOf is the lunar day 1..30 from the Moon–Sun elongation (12° each);
// 15 = Purnima, 30 = Amavasya.
func tithiOf(moonLon, sunLon float64) int {
	t := int(norm360(moonLon-sunLon)/12) + 1
	if t > 30 {
		t = 30
	}
	return t
}

// motionIsRetro decides the day's direction from two noon samples. The
// luminaries never retrograde; the mean nodes always do.
func motionIsRetro(planet string, today, yesterday float64) bool {
	switch planet {
	case "Sun", "Moon":
		return false
	case "Rahu", "Ketu":
		return true
	}
	delta := math.Mod(today-yesterday+540, 360) - 180 // (-180, 180]
	return delta < 0
}

func dayPositions(today, yesterday map[string]float64) ([]seoDayPos, error) {
	out := make([]seoDayPos, 0, len(seoDayPlanets))
	for _, p := range seoDayPlanets {
		lon, ok := today[p]
		if !ok {
			return nil, fmt.Errorf("ephemeris lacks %s", p)
		}
		prev, ok := yesterday[p]
		if !ok {
			return nil, fmt.Errorf("previous-day ephemeris lacks %s", p)
		}
		lon = norm360(lon)
		s := signOf(lon)
		n, pada := nakshatraOf(lon)
		out = append(out, seoDayPos{
			planet: p, lon: lon, signIdx: s, deg: lon - float64(s)*30,
			nak: n, pada: pada, retro: motionIsRetro(p, lon, prev),
		})
	}
	return out, nil
}

func (d seoDay) planet(p string) (seoDayPos, bool) {
	for _, x := range d.pos {
		if x.planet == p {
			return x, true
		}
	}
	return seoDayPos{}, false
}

// --- data assembly ----------------------------------------------------------

func seoYearFor(data []*seoYearData, year int) *seoYearData {
	for _, d := range data {
		if d.year == year {
			return d
		}
	}
	return nil
}

// computeSeoDays builds one seoDay per calendar day in [from, to] for which
// year data (and therefore memoized noon longitudes) exists; days outside
// the computed years are skipped, not failed, so a window reaching into
// next January simply ends at New Year until that year is generated.
func computeSeoDays(data []*seoYearData, from, to time.Time) ([]seoDay, error) {
	var days []seoDay
	for day := utcDay(from); !day.After(utcDay(to)); day = day.AddDate(0, 0, 1) {
		yd := seoYearFor(data, day.Year())
		if yd == nil || yd.lons == nil {
			continue
		}
		cur, err := yd.lons.at(day)
		if err != nil {
			return nil, err
		}
		prevDay := day.AddDate(0, 0, -1)
		src := yd
		if y := seoYearFor(data, prevDay.Year()); y != nil && y.lons != nil {
			src = y
		}
		prev, err := src.lons.at(prevDay)
		if err != nil {
			return nil, err
		}
		pos, err := dayPositions(cur, prev)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", day.Format("2006-01-02"), err)
		}
		days = append(days, seoDay{date: day, pos: pos, tithi: tithiOf(cur["Moon"], cur["Sun"])})
	}
	return days, nil
}

func utcDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// seoYearEvents flattens ingresses, stations, lunations and eclipses of all
// computed years into calendar-day events, sorted by day.
func seoYearEvents(data []*seoYearData) []seoDayEvent {
	var ev []seoDayEvent
	for _, d := range data {
		y := yearStr(d.year)
		for _, in := range d.ingresses {
			ev = append(ev, seoDayEvent{day: utcDay(in.date), kind: "ingress", planet: in.planet, signIdx: in.signIdx, page: y + "/transits.html"})
		}
		for _, s := range d.stations {
			kind := "station_direct"
			if s.retro {
				kind = "station_retro"
			}
			ev = append(ev, seoDayEvent{day: utcDay(s.date), kind: kind, planet: s.planet, page: y + "/retrograde-" + planetSlug(s.planet) + ".html"})
		}
		for _, m := range d.moons {
			kind := "new_moon"
			if m.full {
				kind = "full_moon"
			}
			ev = append(ev, seoDayEvent{day: utcDay(m.at), kind: kind, signIdx: m.signIdx, page: y + "/moon-phases.html"})
		}
		for _, e := range d.eclipses {
			kind := "lunar_eclipse"
			if e.solar {
				kind = "solar_eclipse"
			}
			ev = append(ev, seoDayEvent{day: utcDay(e.at), kind: kind, signIdx: e.signIdx, page: y + "/eclipses.html"})
		}
	}
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].day.Before(ev[j].day) })
	return ev
}

func seoEventText(e seoDayEvent, lang string) string {
	switch e.kind {
	case "ingress":
		return seoT("enters", lang, map[string]string{"planet": planetName(e.planet, lang), "sign": signName(e.signIdx, lang)})
	case "station_retro", "station_direct":
		return seoT(e.kind, lang, map[string]string{"planet": planetName(e.planet, lang)})
	default:
		return seoT(e.kind, lang, nil) + " · " + signName(e.signIdx, lang)
	}
}

// --- formatting ---------------------------------------------------------------

// seoDate renders a calendar date the way the language writes it.
func seoDate(lang string, t time.Time) string {
	d, m, y := t.Day(), int(t.Month()), strconv.Itoa(t.Year())
	ds := strconv.Itoa(d)
	switch lang {
	case "ru":
		return ds + " " + seoMonthGenitiveRu[m-1] + " " + y
	case "es", "pt":
		return ds + " de " + seoMonthName(m, lang) + " de " + y
	case "de":
		return ds + ". " + seoMonthName(m, lang) + " " + y
	case "zh", "ja":
		return y + "年" + strconv.Itoa(m) + "月" + ds + "日"
	case "ko":
		return y + "년 " + strconv.Itoa(m) + "월 " + ds + "일"
	default: // en, fr, it, hi, ar, mr, te, ta, kn: "12 October 2026"
		return ds + " " + seoMonthName(m, lang) + " " + y
	}
}

// fmtDeg renders a within-sign longitude as D°MM′; a value a hair under
// the boundary stays "29°59′" so the figure never reads as the next sign.
func fmtDeg(deg float64) string {
	whole := int(deg)
	min := int(math.Round((deg - float64(whole)) * 60))
	if min == 60 {
		whole++
		min = 0
	}
	if whole >= 30 {
		whole, min = 29, 59
	}
	return fmt.Sprintf("%d°%02d′", whole, min)
}

func tithiLabel(t int, lang string) string {
	paksha := "paksha_shukla"
	n := t
	nameIdx := t - 1
	switch {
	case t == 15:
		nameIdx = 14
	case t == 30:
		paksha, n, nameIdx = "paksha_krishna", 15, 15
	case t > 15:
		paksha, n, nameIdx = "paksha_krishna", t-15, t-16
	}
	return seoT("tithi_fmt", lang, map[string]string{
		"paksha": seoT(paksha, lang, nil), "tithi": seoTithiName(nameIdx, lang), "n": strconv.Itoa(n),
	})
}

func nakshatraLabel(p seoDayPos, lang string) string {
	return seoT("pada_fmt", lang, map[string]string{"nakshatra": seoNakshatraName(p.nak, lang), "n": strconv.Itoa(p.pada)})
}

// seoDayLines are the three sentences shared by the page lead, the meta
// description and today.json: Sun sign, Moon sign + nakshatra, tithi.
func seoDayLines(d seoDay, lang string) []string {
	sun, _ := d.planet("Sun")
	moon, _ := d.planet("Moon")
	return []string{
		seoT("sun_line", lang, map[string]string{"sign": signName(sun.signIdx, lang)}),
		seoT("moon_line", lang, map[string]string{"sign": signName(moon.signIdx, lang), "nakshatra": seoNakshatraName(moon.nak, lang)}),
		seoT("tithi_line", lang, map[string]string{"tithi": tithiLabel(d.tithi, lang)}),
	}
}

func dayRel(t time.Time) string   { return t.UTC().Format("2006/01/02.html") }
func monthRel(t time.Time) string { return t.UTC().Format("2006/01/index.html") }

const todayRel = "today/index.html"

// --- page builders --------------------------------------------------------------

func dayPageLangs() []string { return append([]string(nil), seoDayLangs...) }

func seoDayBody(lang string, d seoDay, events []seoDayEvent) string {
	var b strings.Builder
	lines := seoDayLines(d, lang)
	b.WriteString("<p class=\"lead\">" + esc(seoWeekdayName(int(d.date.Weekday()), lang)) + ". " + esc(strings.Join(lines, ". ")) + ".</p>\n")
	b.WriteString("<table><thead><tr><th>" + esc(seoT("col_planet", lang, nil)) + "</th><th>" + esc(seoT("col_sign", lang, nil)) + "</th><th>" +
		esc(seoT("col_degree", lang, nil)) + "</th><th>" + esc(seoT("col_nakshatra", lang, nil)) + "</th><th>" + esc(seoT("col_motion", lang, nil)) + "</th></tr></thead><tbody>\n")
	for _, p := range d.pos {
		motion := "motion_direct"
		if p.retro {
			motion = "motion_retro"
		}
		b.WriteString("<tr><td>" + esc(planetName(p.planet, lang)) + "</td><td>" + esc(signName(p.signIdx, lang)) + "</td><td>" + fmtDeg(p.deg) +
			"</td><td>" + esc(nakshatraLabel(p, lang)) + "</td><td>" + esc(seoT(motion, lang, nil)) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("noon_note", lang, nil)) + "</p>\n")

	b.WriteString("<h2>" + esc(seoT("events_today", lang, nil)) + "</h2>\n")
	var today, upcoming []seoDayEvent
	limit := d.date.AddDate(0, 0, seoUpcomingWin)
	for _, e := range events {
		switch {
		case e.day.Equal(d.date):
			today = append(today, e)
		case e.day.After(d.date) && !e.day.After(limit) && len(upcoming) < seoUpcomingMax:
			upcoming = append(upcoming, e)
		}
	}
	if len(today) == 0 {
		b.WriteString("<p class=\"empty\">" + esc(seoT("no_events", lang, nil)) + "</p>\n")
	} else {
		b.WriteString("<ul class=\"links\">\n")
		for _, e := range today {
			b.WriteString("<li><a href=\"" + seoURL(lang, e.page) + "\">" + esc(seoEventText(e, lang)) + "</a></li>\n")
		}
		b.WriteString("</ul>\n")
	}
	if len(upcoming) > 0 {
		b.WriteString("<h2>" + esc(seoT("upcoming", lang, nil)) + "</h2>\n<ul class=\"links\">\n")
		for _, e := range upcoming {
			b.WriteString("<li><time datetime=\"" + fmtDay(e.day) + "\">" + esc(seoDate(lang, e.day)) + "</time> — <a href=\"" + seoURL(lang, e.page) + "\">" + esc(seoEventText(e, lang)) + "</a></li>\n")
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString("<p class=\"note\">" + esc(seoT("sidereal_note", lang, nil)) + "</p>\n")
	return b.String()
}

// buildDayPage renders the permanent page of one date. prev/next are only
// linked when that neighbour is rendered too (no dangling links at the
// edges of the window).
func buildDayPage(lang string, d seoDay, events []seoDayEvent, hasPrev, hasNext bool) seoPage {
	date := seoDate(lang, d.date)
	repl := map[string]string{"date": date}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("day_h1", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("day_intro", lang, repl)) + "</p>\n")
	b.WriteString(seoDayBody(lang, d, events))
	b.WriteString("<nav class=\"related\"><ul>\n")
	if hasPrev {
		b.WriteString("<li><a href=\"" + seoURL(lang, dayRel(d.date.AddDate(0, 0, -1))) + "\">← " + esc(seoT("prev_day", lang, nil)) + "</a></li>\n")
	}
	b.WriteString("<li><a href=\"" + seoURL(lang, monthRel(d.date)) + "\">" + esc(seoT("this_month", lang, nil)) + "</a></li>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, todayRel) + "\">" + esc(seoT("section_today", lang, nil)) + "</a></li>\n")
	if hasNext {
		b.WriteString("<li><a href=\"" + seoURL(lang, dayRel(d.date.AddDate(0, 0, 1))) + "\">" + esc(seoT("next_day", lang, nil)) + " →</a></li>\n")
	}
	b.WriteString("</ul></nav>\n")
	desc := seoWeekdayName(int(d.date.Weekday()), lang) + ", " + date + ". " + strings.Join(seoDayLines(d, lang), ". ") + "."
	return seoPage{rel: dayRel(d.date), title: seoT("day_title", lang, repl), desc: desc, body: b.String(), langs: dayPageLangs()}
}

// buildTodayPage is the same content under the stable /today/ URL, its own
// canonical (it targets "planets today" queries), linking to the dated page.
func buildTodayPage(lang string, d seoDay, events []seoDayEvent) seoPage {
	date := seoDate(lang, d.date)
	repl := map[string]string{"date": date}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("today_h1", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("today_intro", lang, nil)) + "</p>\n")
	b.WriteString(seoDayBody(lang, d, events))
	b.WriteString("<nav class=\"related\"><ul>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, dayRel(d.date)) + "\">" + esc(seoT("dated_link", lang, nil)) + "</a></li>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, monthRel(d.date)) + "\">" + esc(seoT("this_month", lang, nil)) + "</a></li>\n")
	b.WriteString("</ul></nav>\n")
	desc := seoWeekdayName(int(d.date.Weekday()), lang) + ", " + date + ". " + strings.Join(seoDayLines(d, lang), ". ") + "."
	return seoPage{rel: todayRel, title: seoT("today_title", lang, repl), desc: desc, body: b.String(), langs: dayPageLangs()}
}

// buildMonthPage lists the rendered days of one month with the Moon's sign,
// nakshatra and the tithi, each linking to its day page.
func buildMonthPage(lang string, year, month int, days []seoDay, signLinks string) seoPage {
	repl := map[string]string{"month": seoMonthName(month, lang), "year": strconv.Itoa(year)}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("month_title", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(seoT("month_intro", lang, repl)) + "</p>\n")
	b.WriteString("<table><thead><tr><th>" + esc(seoT("col_date", lang, nil)) + "</th><th>" + esc(planetName("Moon", lang)) + "</th><th>" +
		esc(seoT("col_nakshatra", lang, nil)) + "</th><th>" + esc(seoT("col_tithi", lang, nil)) + "</th></tr></thead><tbody>\n")
	for _, d := range days {
		moon, _ := d.planet("Moon")
		b.WriteString("<tr><td><a href=\"" + seoURL(lang, dayRel(d.date)) + "\"><time datetime=\"" + fmtDay(d.date) + "\">" + esc(seoDate(lang, d.date)) + "</time></a>, " +
			esc(seoWeekdayName(int(d.date.Weekday()), lang)) + "</td><td>" + esc(signName(moon.signIdx, lang)) + "</td><td>" + esc(seoNakshatraName(moon.nak, lang)) +
			"</td><td>" + esc(tithiLabel(d.tithi, lang)) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")
	b.WriteString(signLinks)
	b.WriteString("<nav class=\"related\"><ul>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, todayRel) + "\">" + esc(seoT("section_today", lang, nil)) + "</a></li>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, strconv.Itoa(year)+"/transits.html") + "\">" + esc(seoT("section_transits", lang, nil)) + " " + strconv.Itoa(year) + "</a></li>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, strconv.Itoa(year)+"/moon-phases.html") + "\">" + esc(seoT("section_moon", lang, nil)) + " " + strconv.Itoa(year) + "</a></li>\n")
	b.WriteString("</ul></nav>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("sidereal_note", lang, nil)) + "</p>\n")
	rel := fmt.Sprintf("%04d/%02d/index.html", year, month)
	return seoPage{rel: rel, title: seoT("month_title", lang, repl), desc: seoT("month_intro", lang, repl), body: b.String(), langs: dayPageLangs()}
}

// seoTodayJSON feeds the site's home-page block: a localized date label,
// the three summary lines and where to go for more. Languages without day
// pages link to the English today page.
func seoTodayJSON(lang string, d seoDay) ([]byte, error) {
	urlLang := "en"
	for _, l := range seoDayLangs {
		if l == lang {
			urlLang = lang
			break
		}
	}
	return json.Marshal(struct {
		Date    string   `json:"date"`
		Label   string   `json:"label"`
		Weekday string   `json:"weekday"`
		URL     string   `json:"url"`
		Lines   []string `json:"lines"`
	}{
		Date:    fmtDay(d.date),
		Label:   seoDate(lang, d.date),
		Weekday: seoWeekdayName(int(d.date.Weekday()), lang),
		URL:     seoURL(urlLang, todayRel),
		Lines:   seoDayLines(d, lang),
	})
}
