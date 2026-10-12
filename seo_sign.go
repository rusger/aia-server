package main

// Phase 3 of the SEO calendar (owner 2026-10-12): one page per Moon sign
// (rashi) and month, /astro/<lang>/<yyyy>/<mm>/<sign>.html.
//
// The deterministic half lives here: seo-gen writes the FACTS of a
// (year, month, sign) — every planet's sign and house counted from the Moon
// sign at the start and end of the month, retrograde status, ingresses,
// stations, lunations and eclipses with their house — to
// <outdir>/.facts/<yyyy>-<mm>-<sign>.json, together with the localized
// names the text must use. A separate script (insta-agent
// scripts/seo_sign_text.py, subscription `claude -p`, one call per page,
// ever) turns the facts into <outdir>/.text/<lang>/<yyyy>-<mm>-<sign>.json;
// only when that text exists is the page rendered, with the facts table and
// key dates computed here regardless of what the model wrote. No text, no
// page — never a placeholder.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	seoFactsDir     = ".facts"
	seoTextDir      = ".text"
	seoSignMonthsOk = 4 // current month + 3 ahead get facts
)

var seoSignPlanets = []string{"Sun", "Mercury", "Venus", "Mars", "Jupiter", "Saturn", "Rahu", "Ketu"}

type seoFactIngress struct {
	Date  string `json:"date"`
	Sign  string `json:"sign"`
	House int    `json:"house"`
}

type seoFactStation struct {
	Date  string `json:"date"`
	Turns string `json:"turns"` // retrograde | direct
}

type seoFactPlanet struct {
	Planet     string           `json:"planet"`
	SignStart  string           `json:"sign_start"`
	HouseStart int              `json:"house_start"`
	SignEnd    string           `json:"sign_end"`
	HouseEnd   int              `json:"house_end"`
	RetroStart bool             `json:"retro_start"`
	RetroEnd   bool             `json:"retro_end"`
	Ingresses  []seoFactIngress `json:"ingresses"`
	Stations   []seoFactStation `json:"stations"`
}

type seoFactEvent struct {
	Date  string `json:"date"`
	Kind  string `json:"kind"` // new_moon | full_moon | solar_eclipse | lunar_eclipse
	Sign  string `json:"sign"`
	House int    `json:"house"`
}

type seoFactNames struct {
	Signs   map[string]string `json:"signs"`
	Planets map[string]string `json:"planets"`
	Sign    string            `json:"sign"`
	Month   string            `json:"month"`
}

type seoSignFacts struct {
	Year       int                     `json:"year"`
	Month      int                     `json:"month"`
	MonthStart string                  `json:"month_start"`
	MonthEnd   string                  `json:"month_end"`
	Sign       string                  `json:"sign"`
	SignIndex  int                     `json:"sign_index"`
	Planets    []seoFactPlanet         `json:"planets"`
	MoonEvents []seoFactEvent          `json:"moon_events"`
	Names      map[string]seoFactNames `json:"names"`
}

// seoSignText is what the text script writes; sections keep the script's
// order and keys (overview, career_money, relationships, energy, advice).
type seoSignText struct {
	Lead     string `json:"lead"`
	Sections []struct {
		Key string `json:"key"`
		H   string `json:"h"`
		P   string `json:"p"`
	} `json:"sections"`
	Model    string `json:"model"`
	Provider string `json:"provider"`
}

func signSlug(idx int) string { return strings.ToLower(signNames[idx]["en"]) }

// houseFrom counts houses from the Moon sign: the sign itself is house 1.
func houseFrom(moonSign, sign int) int { return (sign-moonSign+12)%12 + 1 }

func signEn(idx int) string { return signNames[idx]["en"] }

func retroAt(periods []seoRetroPeriod, day time.Time) bool {
	for _, p := range periods {
		if !day.Before(utcDay(p.start)) && !day.After(utcDay(p.end)) {
			return true
		}
	}
	return false
}

// computeSignFacts builds the facts of one (year, month, Moon sign) from
// the year data; the memoized noon longitudes give the start/end positions.
func computeSignFacts(data []*seoYearData, year, month, moonSign int) (*seoSignFacts, error) {
	yd := seoYearFor(data, year)
	if yd == nil || yd.lons == nil {
		return nil, fmt.Errorf("no data for %d", year)
	}
	first := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	last := first.AddDate(0, 1, -1)
	startLons, err := yd.lons.at(first)
	if err != nil {
		return nil, err
	}
	endLons, err := yd.lons.at(last)
	if err != nil {
		return nil, err
	}
	inMonth := func(t time.Time) bool {
		d := utcDay(t)
		return !d.Before(first) && !d.After(last)
	}
	f := &seoSignFacts{
		Year: year, Month: month, MonthStart: fmtDay(first), MonthEnd: fmtDay(last),
		Sign: signEn(moonSign), SignIndex: moonSign, Names: map[string]seoFactNames{},
	}
	for _, p := range seoSignPlanets {
		ls, ok1 := startLons[p]
		le, ok2 := endLons[p]
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("ephemeris lacks %s", p)
		}
		fp := seoFactPlanet{
			Planet:    p,
			SignStart: signEn(signOf(ls)), HouseStart: houseFrom(moonSign, signOf(ls)),
			SignEnd: signEn(signOf(le)), HouseEnd: houseFrom(moonSign, signOf(le)),
			Ingresses: []seoFactIngress{}, Stations: []seoFactStation{},
		}
		switch p {
		case "Rahu", "Ketu":
			fp.RetroStart, fp.RetroEnd = true, true
		case "Sun":
		default:
			fp.RetroStart = retroAt(yd.retro[p], first)
			fp.RetroEnd = retroAt(yd.retro[p], last)
		}
		for _, in := range yd.ingresses {
			if in.planet == p && inMonth(in.date) {
				fp.Ingresses = append(fp.Ingresses, seoFactIngress{Date: fmtDay(in.date), Sign: signEn(in.signIdx), House: houseFrom(moonSign, in.signIdx)})
			}
		}
		for _, s := range yd.stations {
			if s.planet == p && inMonth(s.date) {
				turns := "direct"
				if s.retro {
					turns = "retrograde"
				}
				fp.Stations = append(fp.Stations, seoFactStation{Date: fmtDay(s.date), Turns: turns})
			}
		}
		f.Planets = append(f.Planets, fp)
	}
	f.MoonEvents = []seoFactEvent{}
	for _, m := range yd.moons {
		if inMonth(m.at) {
			kind := "new_moon"
			if m.full {
				kind = "full_moon"
			}
			f.MoonEvents = append(f.MoonEvents, seoFactEvent{Date: fmtDay(m.at), Kind: kind, Sign: signEn(m.signIdx), House: houseFrom(moonSign, m.signIdx)})
		}
	}
	for _, e := range yd.eclipses {
		if inMonth(e.at) {
			kind := "lunar_eclipse"
			if e.solar {
				kind = "solar_eclipse"
			}
			f.MoonEvents = append(f.MoonEvents, seoFactEvent{Date: fmtDay(e.at), Kind: kind, Sign: signEn(e.signIdx), House: houseFrom(moonSign, e.signIdx)})
		}
	}
	sort.SliceStable(f.MoonEvents, func(i, j int) bool { return f.MoonEvents[i].Date < f.MoonEvents[j].Date })
	for _, lang := range seoDayLangs {
		n := seoFactNames{Signs: map[string]string{}, Planets: map[string]string{}, Sign: signName(moonSign, lang), Month: seoMonthName(month, lang)}
		for i := range signNames {
			n.Signs[signEn(i)] = signName(i, lang)
		}
		for _, p := range seoSignPlanets {
			n.Planets[p] = planetName(p, lang)
		}
		n.Planets["Moon"] = planetName("Moon", lang)
		f.Names[lang] = n
	}
	return f, nil
}

func factsKey(year, month int, slug string) string {
	return fmt.Sprintf("%04d-%02d-%s", year, month, slug)
}

// seoSignMonths lists the (year, month) pairs that get facts: the current
// month and the next seoSignMonthsOk-1, limited to computed years.
func seoSignMonths(data []*seoYearData, now time.Time) [][2]int {
	var out [][2]int
	m := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < seoSignMonthsOk; i++ {
		if seoYearFor(data, m.Year()) != nil {
			out = append(out, [2]int{m.Year(), int(m.Month())})
		}
		m = m.AddDate(0, 1, 0)
	}
	return out
}

// writeSignFacts writes the facts files for every sign of every month in
// the window and returns them keyed by factsKey.
func writeSignFacts(outDir string, data []*seoYearData, now time.Time) (map[string]*seoSignFacts, error) {
	dir := filepath.Join(outDir, seoFactsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	all := map[string]*seoSignFacts{}
	for _, ym := range seoSignMonths(data, now) {
		for s := 0; s < 12; s++ {
			f, err := computeSignFacts(data, ym[0], ym[1], s)
			if err != nil {
				return nil, fmt.Errorf("facts %d-%02d %s: %w", ym[0], ym[1], signSlug(s), err)
			}
			raw, err := json.MarshalIndent(f, "", " ")
			if err != nil {
				return nil, err
			}
			key := factsKey(ym[0], ym[1], signSlug(s))
			if err := writeAtomic(filepath.Join(dir, key+".json"), raw); err != nil {
				return nil, err
			}
			all[key] = f
		}
	}
	return all, nil
}

// loadSignText reads the generated text for one page; (nil, nil) when the
// script has not produced it yet, an error for a corrupt file (a bad file
// must be noticed, not silently skipped forever).
func loadSignText(outDir, lang, key string) (*seoSignText, error) {
	raw, err := os.ReadFile(filepath.Join(outDir, seoTextDir, lang, key+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t seoSignText
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("text %s/%s: %w", lang, key, err)
	}
	if strings.TrimSpace(t.Lead) == "" || len(t.Sections) == 0 {
		return nil, fmt.Errorf("text %s/%s: empty lead or sections", lang, key)
	}
	return &t, nil
}

func signRel(year, month int, slug string) string {
	return fmt.Sprintf("%04d/%02d/%s.html", year, month, slug)
}

// buildSignPage renders one Moon-sign month page: the model's lead and
// sections around a deterministic transit table and key dates. langs is the
// set of languages whose text exists (hreflang must not promise a 404).
func buildSignPage(lang string, f *seoSignFacts, t *seoSignText, langs []string) seoPage {
	y := strconv.Itoa(f.Year)
	repl := map[string]string{"sign": signName(f.SignIndex, lang), "month": seoMonthName(f.Month, lang), "year": y}
	var b strings.Builder
	b.WriteString("<h1>" + esc(seoT("sign_h1", lang, repl)) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(t.Lead) + "</p>\n")

	b.WriteString("<h2>" + esc(seoT("sign_transits_h", lang, repl)) + "</h2>\n")
	b.WriteString("<table><thead><tr><th>" + esc(seoT("col_planet", lang, nil)) + "</th><th>" + esc(seoT("col_house", lang, nil)) + "</th><th>" + esc(seoT("col_sign", lang, nil)) + "</th></tr></thead><tbody>\n")
	for _, p := range f.Planets {
		house := strconv.Itoa(p.HouseStart)
		sign := signName(signIndexEn(p.SignStart), lang)
		if p.HouseEnd != p.HouseStart {
			house += " → " + strconv.Itoa(p.HouseEnd)
			sign += " → " + signName(signIndexEn(p.SignEnd), lang)
		}
		name := planetName(p.Planet, lang)
		if p.RetroStart || p.RetroEnd {
			name += " (R)"
		}
		b.WriteString("<tr><td>" + esc(name) + "</td><td>" + esc(house) + "</td><td>" + esc(sign) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")

	var dates []string
	for _, p := range f.Planets {
		for _, in := range p.Ingresses {
			dates = append(dates, in.Date+" — "+seoT("enters", lang, map[string]string{"planet": planetName(p.Planet, lang), "sign": signName(signIndexEn(in.Sign), lang)})+" ("+seoT("house_n", lang, map[string]string{"n": strconv.Itoa(in.House)})+")")
		}
		for _, s := range p.Stations {
			k := "station_direct"
			if s.Turns == "retrograde" {
				k = "station_retro"
			}
			dates = append(dates, s.Date+" — "+seoT(k, lang, map[string]string{"planet": planetName(p.Planet, lang)}))
		}
	}
	for _, e := range f.MoonEvents {
		dates = append(dates, e.Date+" — "+seoT(e.Kind, lang, nil)+" · "+signName(signIndexEn(e.Sign), lang)+" ("+seoT("house_n", lang, map[string]string{"n": strconv.Itoa(e.House)})+")")
	}
	sort.Strings(dates)
	if len(dates) > 0 {
		b.WriteString("<h2>" + esc(seoT("key_dates", lang, nil)) + "</h2>\n<ul class=\"links\">\n")
		for _, d := range dates {
			b.WriteString("<li><time datetime=\"" + d[:10] + "\">" + esc(seoDate(lang, mustDay(d[:10]))) + "</time>" + esc(d[10:]) + "</li>\n")
		}
		b.WriteString("</ul>\n")
	}

	for _, s := range t.Sections {
		b.WriteString("<h2>" + esc(s.H) + "</h2>\n<p>" + esc(s.P) + "</p>\n")
	}
	b.WriteString("<p class=\"note\">" + esc(seoT("moon_sign_note", lang, nil)) + "</p>\n")
	b.WriteString("<p class=\"note\">" + esc(seoT("sidereal_note", lang, nil)) + "</p>\n")
	b.WriteString("<nav class=\"related\"><ul>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, fmt.Sprintf("%04d/%02d/index.html", f.Year, f.Month)) + "\">" + esc(seoT("this_month", lang, nil)) + "</a></li>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, todayRel) + "\">" + esc(seoT("section_today", lang, nil)) + "</a></li>\n")
	b.WriteString("<li><a href=\"" + seoURL(lang, y+"/transits.html") + "\">" + esc(seoT("section_transits", lang, nil)) + " " + y + "</a></li>\n")
	b.WriteString("</ul></nav>\n")
	desc := t.Lead
	return seoPage{rel: signRel(f.Year, f.Month, signSlug(f.SignIndex)), title: seoT("sign_title", lang, repl), desc: desc, body: b.String(), langs: append([]string(nil), langs...)}
}

func mustDay(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func signIndexEn(en string) int {
	for i := range signNames {
		if signNames[i]["en"] == en {
			return i
		}
	}
	return 0
}

// signPagesFor collects, per language, the sign pages whose text exists,
// so the month hub and the hreflang sets only name real pages.
type seoSignPageSet struct {
	facts map[string]*seoSignFacts
	texts map[string]map[string]*seoSignText // lang -> key -> text
}

func loadSignPages(outDir string, facts map[string]*seoSignFacts) (*seoSignPageSet, error) {
	set := &seoSignPageSet{facts: facts, texts: map[string]map[string]*seoSignText{}}
	for _, lang := range seoDayLangs {
		set.texts[lang] = map[string]*seoSignText{}
		for key := range facts {
			t, err := loadSignText(outDir, lang, key)
			if err != nil {
				return nil, err
			}
			if t != nil {
				set.texts[lang][key] = t
			}
		}
	}
	return set, nil
}

func (s *seoSignPageSet) langsWithText(key string) []string {
	var out []string
	for _, lang := range seoDayLangs {
		if _, ok := s.texts[lang][key]; ok {
			out = append(out, lang)
		}
	}
	return out
}

// sortedKeys gives deterministic output order.
func (s *seoSignPageSet) sortedKeys() []string {
	keys := make([]string, 0, len(s.facts))
	for k := range s.facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// monthSignLinks renders the "by Moon sign" list of a month hub for the
// signs that have a page in this language.
func (s *seoSignPageSet) monthSignLinks(lang string, year, month int) string {
	var b strings.Builder
	for idx := 0; idx < 12; idx++ {
		key := factsKey(year, month, signSlug(idx))
		if _, ok := s.texts[lang][key]; !ok {
			continue
		}
		b.WriteString("<li><a href=\"" + seoURL(lang, signRel(year, month, signSlug(idx))) + "\">" + esc(signName(idx, lang)) + "</a></li>\n")
	}
	if b.Len() == 0 {
		return ""
	}
	return "<h2>" + esc(seoT("section_signs", lang, nil)) + "</h2>\n<ul class=\"links\">\n" + b.String() + "</ul>\n"
}
