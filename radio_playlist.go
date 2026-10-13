package main

// Personal playlist of the «Your Chart» radio wave (owner 2026-10-13,
// insta-agent/docs/radio/YOUR-CHART.md §2, §4, §5).
//
//   POST /api/radio/your-chart
//   {facts:<chart-facts response>, date?:"M D Y"} or the birth data of
//   /api/chart-facts; plus lang? (16 languages, default en),
//   at?:"YYYY-MM-DD" (default today UTC), yogas?:[names from the app's detector]
//
//   GET /api/radio/cat/{sha1}   — public: a catalog insert from the TTS cache
//
// Nothing is recorded for the wave: the playlist is assembled from files
// already on this box under RADIO_DIR (default /var/www/html/radio):
// lib/index.json (the Kokoro library of spec readings), cat/index.json (the
// app's 16-language catalog, audio in TTS_CACHE_DIR/<sha1>.mp3) and the
// station-of-the-day schedule.json (sky news, yesterday's releases, music).
// The answer has the item fields of a station schedule.json, so engine.js and
// the app play it without a new player.
//
// Access and limits are exactly those of /api/chart-facts (chartAccess).
// The build is deterministic: lead variants are chosen by
// seed = sha1(facts + at).

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	radioMaxBody      = 16384 // facts (~1.5 KB) + the app's yoga list
	radioMaxYogas     = 64    // request cap on yogas[]
	radioMaxYogaLen   = 64
	radioYogasPlayed  = 5    // at most this many yoga inserts
	radioSpeechGap    = 10.0 // seconds of pure music between speech tracks
	radioLeadGap      = 2.0  // between a rubric's lead and its first topic
	radioEventWindow  = 14   // days ahead for the «event of the week»
	radioMusicDuck    = 0.15
	radioMusicXfade   = 8
	radioCacheMaxKeys = 256 // parsed files kept by mtime; reset beyond this
)

// Rubric names, in playlist order (they are also the `you/<rubric>/*` lead keys).
const (
	rubIdent       = "ident"
	rubSkyToday    = "sky_today"
	rubTithi       = "tithi"
	rubLagna       = "lagna"
	rubMonth       = "month"
	rubTransits    = "transits"
	rubDasha       = "dasha"
	rubSadeSati    = "sade_sati"
	rubYogas       = "yogas"
	rubPlanetHouse = "planet_house"
	rubConjunction = "conjunction"
	rubNakshatra   = "nakshatra"
	rubTopic       = "topic"
	rubYear        = "year"
	rubRelease     = "release"
	rubEvent       = "event"
	rubClosing     = "closing"
)

// radioWeekdayStation: the station of the day (vara), Sunday first.
var radioWeekdayStation = [7]string{"sun", "moon", "mars", "mercury", "jupiter", "venus", "saturn"}

// radioSignLord: lagna sign -> its lord's station.
var radioSignLord = map[string]string{
	"aries": "mars", "scorpio": "mars", "taurus": "venus", "libra": "venus",
	"gemini": "mercury", "virgo": "mercury", "cancer": "moon", "leo": "sun",
	"sagittarius": "jupiter", "pisces": "jupiter", "capricorn": "saturn", "aquarius": "saturn",
}

// radioHouseTopic: the house holding most planets -> topics/<topic>.
var radioHouseTopic = map[int]string{
	1: "self", 2: "wealth", 3: "courage", 4: "home", 5: "children", 6: "health",
	7: "love", 8: "depth", 9: "luck", 10: "career", 11: "friends", 12: "freedom",
}

var radioCatKeyRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func radioDir() string {
	if d := os.Getenv("RADIO_DIR"); d != "" {
		return d
	}
	return "/var/www/html/radio"
}

// ---------------------------------------------------------------------------
// Data files (read-only, cached by mtime: they are rebuilt nightly)
// ---------------------------------------------------------------------------

type radioLibTags struct {
	Sign      string   `json:"sign"`
	Ref       string   `json:"ref"`
	Planet    string   `json:"planet"`
	Planets   []string `json:"planets"`
	House     int      `json:"house"`
	Flag      string   `json:"flag"`
	Nakshatra string   `json:"nakshatra"`
	Topic     string   `json:"topic"`
	Dasha     string   `json:"dasha"`
	Month     string   `json:"month"`
	Year      int      `json:"year"`
	Event     string   `json:"event"`
	Date      string   `json:"date"`
	Transit   string   `json:"transit"`
	You       string   `json:"you"`
	Rubric    string   `json:"rubric"`
}

type radioLibTrack struct {
	Key        string       `json:"key"`
	File       string       `json:"file"`
	Title      string       `json:"title"`
	Tags       radioLibTags `json:"tags"`
	ValidUntil *string      `json:"valid_until"` // YYYY-MM-DD, null = evergreen
	Dur        float64      `json:"dur"`
}

// radioLib is lib/index.json with tracks sorted by key.
type radioLib struct {
	Tracks []radioLibTrack `json:"tracks"`
}

type radioCatEntry struct {
	Key string  `json:"key"` // sha1 of the TTS cache file
	Dur float64 `json:"dur"`
}

// radioCat is cat/index.json (slug -> lang -> entry) plus the set of every
// sha1 it names (the only files GET /api/radio/cat serves).
type radioCat struct {
	slugs map[string]map[string]radioCatEntry
	keys  map[string]bool
}

type radioScheduleItem struct {
	Start float64 `json:"start"`
	Dur   float64 `json:"dur"`
	Kind  string  `json:"kind"`
	ID    string  `json:"id"`
	Src   string  `json:"src"`
	Title string  `json:"title"`
}

type radioSchedule struct {
	Music struct {
		Src string  `json:"src"`
		Dur float64 `json:"dur"`
	} `json:"music"`
	Items []radioScheduleItem `json:"items"`
}

func parseRadioLib(b []byte) (interface{}, error) {
	var lib radioLib
	if err := json.Unmarshal(b, &lib); err != nil {
		return nil, err
	}
	sort.SliceStable(lib.Tracks, func(i, j int) bool { return lib.Tracks[i].Key < lib.Tracks[j].Key })
	return &lib, nil
}

func parseRadioCat(b []byte) (interface{}, error) {
	c := &radioCat{keys: map[string]bool{}}
	if err := json.Unmarshal(b, &c.slugs); err != nil {
		return nil, err
	}
	for _, langs := range c.slugs {
		for _, e := range langs {
			if radioCatKeyRe.MatchString(e.Key) {
				c.keys[e.Key] = true
			}
		}
	}
	return c, nil
}

func parseRadioSchedule(b []byte) (interface{}, error) {
	var s radioSchedule
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// radioFileCache keeps parsed JSON files keyed by path and re-reads a file
// when its mtime or size changes.
type radioFileCache struct {
	mu      sync.Mutex
	entries map[string]radioCacheEntry
}

type radioCacheEntry struct {
	mod  time.Time
	size int64
	val  interface{}
}

func (c *radioFileCache) load(p string, parse func([]byte) (interface{}, error)) (interface{}, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	e, ok := c.entries[p]
	c.mu.Unlock()
	if ok && e.mod.Equal(st.ModTime()) && e.size == st.Size() {
		return e.val, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	v, err := parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	c.mu.Lock()
	if c.entries == nil || len(c.entries) >= radioCacheMaxKeys {
		c.entries = map[string]radioCacheEntry{}
	}
	c.entries[p] = radioCacheEntry{mod: st.ModTime(), size: st.Size(), val: v}
	c.mu.Unlock()
	return v, nil
}

// ---------------------------------------------------------------------------
// Playlist
// ---------------------------------------------------------------------------

type radioItem struct {
	Start  float64            `json:"start"`
	Dur    float64            `json:"dur"`
	Kind   string             `json:"kind"` // ident|lead|sky_news|insert|lib|release|closing
	ID     string             `json:"id"`
	Title  string             `json:"title"`
	Src    string             `json:"src"`
	Cat    string             `json:"cat,omitempty"`
	Durs   map[string]float64 `json:"durs,omitempty"`
	Rubric string             `json:"rubric"`

	span    float64 // time on the timeline (a catalog insert in the listener's language may be longer than en)
	station string  // music under this item
}

type radioMusicTrack struct {
	From    float64 `json:"from"`
	Src     string  `json:"src"`
	Dur     float64 `json:"dur"`
	Station string  `json:"station"`
}

type radioMusic struct {
	Duck   float64           `json:"duck"`
	Xfade  int               `json:"xfade"`
	Tracks []radioMusicTrack `json:"tracks"`
}

type radioFactsUsed struct {
	Lagna     string   `json:"lagna"`
	Sun       string   `json:"sun"`
	Moon      string   `json:"moon"`
	Nakshatra string   `json:"nakshatra"`
	Maha      string   `json:"maha,omitempty"`
	Tithi     string   `json:"tithi"`
	SadeSatiN *int     `json:"sade_sati_n"`
	Yogas     []string `json:"yogas"`
	TopHouse  int      `json:"top_house"`
	Topic     string   `json:"topic"`
	Station   string   `json:"station"`
}

type radioPlaylist struct {
	Wave      string         `json:"wave"`
	Date      string         `json:"date"`
	Lang      string         `json:"lang"`
	TZ        string         `json:"tz"`
	Items     []radioItem    `json:"items"`
	Music     radioMusic     `json:"music"`
	FactsUsed radioFactsUsed `json:"facts_used"`

	missingMusic []string // stations whose schedule (music dur) was unavailable
}

// radioInputs is everything the pure builder needs.
type radioInputs struct {
	facts      *chartFacts
	extraYogas []string   // the app's detector; merged after the server's
	birth      *time.Time // nil: Sade Sati ordinal unknown (facts-only request without date)
	lang       string
	at         time.Time
	lib        *radioLib
	cat        *radioCat
	schedule   func(station string) *radioSchedule // nil when the station has no schedule for `at`
}

// radioBuilder accumulates rubric groups.
type radioBuilder struct {
	in     radioInputs
	atStr  string
	seed   [20]byte
	groups [][]radioItem
	day    string // station of the day
}

func (b *radioBuilder) active(t *radioLibTrack) bool {
	return t.ValidUntil == nil || *t.ValidUntil >= b.atStr
}

// pick chooses one variant deterministically from the seed and a salt.
func (b *radioBuilder) pick(n int, salt string) int {
	h := sha1.Sum(append(b.seed[:], salt...))
	return int(binary.BigEndian.Uint32(h[:4]) % uint32(n))
}

func (b *radioBuilder) libItem(t *radioLibTrack, kind, rubric, station string) (radioItem, bool) {
	if t.File == "" || strings.ContainsAny(t.File, "/\\") || strings.Contains(t.File, "..") {
		return radioItem{}, false
	}
	title := t.Title
	if title == "" { // you/* voice lines carry no title in the index; station wording
		title = radioDefaultTitles[kind]
	}
	return radioItem{Dur: t.Dur, span: t.Dur, Kind: kind, ID: t.Key, Title: title,
		Src: "/radio/lib/" + t.File, Rubric: rubric, station: station}, true
}

// radioDefaultTitles: titles of untitled library lines, worded as the
// stations' schedule.json items (English, like the rest of the wave).
var radioDefaultTitles = map[string]string{"ident": "Your Chart", "lead": "Coming up", "closing": "Your Chart"}

// you returns one active `you/*` track (ident, closing or the lead of a rubric).
func (b *radioBuilder) you(role, rubric string) *radioLibTrack {
	var cands []*radioLibTrack
	for i := range b.in.lib.Tracks {
		t := &b.in.lib.Tracks[i]
		if t.Tags.You != role || !b.active(t) {
			continue
		}
		if role == "lead" && t.Tags.Rubric != rubric {
			continue
		}
		cands = append(cands, t)
	}
	if len(cands) == 0 {
		return nil
	}
	return cands[b.pick(len(cands), role+"/"+rubric)]
}

// find returns the active lib tracks matching pred, in key order.
func (b *radioBuilder) find(pred func(t *radioLibTrack) bool) []*radioLibTrack {
	var out []*radioLibTrack
	for i := range b.in.lib.Tracks {
		t := &b.in.lib.Tracks[i]
		if t.Tags.You == "" && b.active(t) && pred(t) {
			out = append(out, t)
		}
	}
	return out
}

// catItem is a catalog insert: src is the en audio, durs every language.
func (b *radioBuilder) catItem(slug, title, rubric, station string) (radioItem, bool) {
	langs, ok := b.in.cat.slugs[slug]
	if !ok {
		return radioItem{}, false
	}
	en, ok := langs["en"]
	if !ok || !radioCatKeyRe.MatchString(en.Key) {
		return radioItem{}, false
	}
	durs := map[string]float64{}
	for l, e := range langs {
		durs[l] = e.Dur
	}
	span := en.Dur
	if d, ok := langs[b.in.lang]; ok && d.Dur > span {
		span = d.Dur
	}
	return radioItem{Dur: en.Dur, span: span, Kind: "insert", ID: "insert_" + slug, Title: title,
		Src: "/api/radio/cat/" + en.Key, Cat: slug, Durs: durs, Rubric: rubric, station: station}, true
}

// add appends a rubric: its lead (when rubric != "") and the topic items.
// Nothing is added when there is nothing to play.
func (b *radioBuilder) add(rubric string, topics []radioItem) {
	if len(topics) == 0 {
		return
	}
	lead := b.you("lead", rubric)
	if lead == nil {
		b.groups = append(b.groups, topics)
		return
	}
	li, ok := b.libItem(lead, "lead", rubric, topics[0].station)
	if !ok {
		b.groups = append(b.groups, topics)
		return
	}
	b.groups = append(b.groups, append([]radioItem{li}, topics...))
}

func (b *radioBuilder) addLib(dst *[]radioItem, ts []*radioLibTrack, rubric string, station func(t *radioLibTrack) string) {
	for _, t := range ts {
		if it, ok := b.libItem(t, "lib", rubric, station(t)); ok {
			*dst = append(*dst, it)
		}
	}
}

// radioStationURL resolves a schedule src (relative to the station's day folder)
// to an absolute /radio/ URL; anything escaping /radio/ is refused.
func radioStationURL(station, day, src string) (string, bool) {
	if src == "" || strings.HasPrefix(src, "/") || strings.Contains(src, "://") {
		return "", false
	}
	u := path.Join("/radio", station, day, src)
	return u, strings.HasPrefix(u, "/radio/")
}

func radioTitleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// sadeSatiOrdinal is which Sade Sati of life (1..5) is running. APPROXIMATION
// by Saturn's MEAN motion: the first one starts when transiting Saturn enters
// the 12th sign from the natal Moon; from natal Saturn to that sign there are
// k = (moonSign−1 − natalSaturnSign) mod 12 signs ≈ k·2.455 years, and the
// cycle repeats every 29.46 years. Retrogrades and the real speed are ignored.
func sadeSatiOrdinal(moonSign, natalSaturnSign int, age float64) int {
	k := ((moonSign-1-natalSaturnSign)%12 + 12) % 12
	n := 1 + int(math.Floor((age-float64(k)*2.455)/29.46))
	if n < 1 {
		n = 1
	}
	if n > 5 {
		n = 5
	}
	return n
}

func chartFactsSignIndex(sign string) int {
	for i, s := range chartFactsSigns {
		if s == sign {
			return i
		}
	}
	return -1
}

// buildRadioPlaylist assembles the rubrics 0..16 of YOUR-CHART.md §2 in order.
func buildRadioPlaylist(in radioInputs) *radioPlaylist {
	f := in.facts
	b := &radioBuilder{in: in, atStr: in.at.Format("2006-01-02")}
	factsJSON, err := json.Marshal(f)
	if err != nil { // chartFacts has only plain fields; cannot happen
		log.Printf("radio: marshal facts for seed: %v", err)
	}
	b.seed = sha1.Sum(append(factsJSON, "|"+b.atStr...))
	b.day = radioWeekdayStation[in.at.Weekday()]
	day := b.day
	sched := in.schedule(day)

	planetAt := map[string]chartFactsPlanet{}
	houseCount := map[int]int{}
	for _, p := range f.Planets {
		planetAt[p.Planet] = p
		houseCount[p.House]++
	}
	fixed := func(s string) func(*radioLibTrack) string { return func(*radioLibTrack) string { return s } }

	pl := &radioPlaylist{Wave: "you", Date: b.atStr, Lang: in.lang, TZ: "UTC",
		FactsUsed: radioFactsUsed{Lagna: f.Lagna.Sign, Sun: planetAt["sun"].Sign, Moon: f.Moon.Sign,
			Nakshatra: f.Moon.Nakshatra, Tithi: fmt.Sprintf("%s %d", f.TithiToday.Paksha, f.TithiToday.N),
			Yogas: []string{}, Station: day}}

	// 0. Ident.
	if t := b.you("ident", ""); t != nil {
		if it, ok := b.libItem(t, "ident", rubIdent, day); ok {
			b.groups = append(b.groups, []radioItem{it})
		}
	}

	// 1. Sky today: one sky_news of the station of the day.
	if sched != nil {
		for _, s := range sched.Items {
			if s.Kind != "sky_news" {
				continue
			}
			if u, ok := radioStationURL(day, b.atStr, s.Src); ok {
				b.add(rubSkyToday, []radioItem{{Dur: s.Dur, span: s.Dur, Kind: "sky_news", ID: s.ID,
					Title: s.Title, Src: u, Rubric: rubSkyToday, station: day}})
			}
			break
		}
	}

	// 2. Tithi today (catalog).
	{
		t := f.TithiToday
		name := "Shukla"
		if t.Paksha == "krishna" {
			name = "Krishna"
		}
		if it, ok := b.catItem(fmt.Sprintf("tithi_%s_%d", t.Paksha, t.N),
			fmt.Sprintf("Lunar day: %s %d", name, t.N), rubTithi, "moon"); ok {
			b.add(rubTithi, []radioItem{it})
		}
	}

	// 3. Lagna: signs/<lagna sign>.
	{
		var items []radioItem
		b.addLib(&items, b.find(func(t *radioLibTrack) bool {
			g := t.Tags
			return g.Sign == f.Lagna.Sign && g.Year == 0 && g.Ref == "" && g.Month == "" &&
				g.Transit == "" && g.Event == "" && g.Planet == ""
		}), rubLagna, fixed(radioSignLord[f.Lagna.Sign]))
		b.add(rubLagna, items)
	}

	// 4. This month: month/<YYYY-MM>-{moon,sun,lagna}/<sign>.
	refSign := map[string]string{"moon": f.Moon.Sign, "sun": planetAt["sun"].Sign, "lagna": f.Lagna.Sign}
	{
		month := b.in.at.Format("2006-01")
		var items []radioItem
		for _, ref := range []string{"moon", "sun", "lagna"} {
			b.addLib(&items, b.find(func(t *radioLibTrack) bool {
				return t.Tags.Month == month && t.Tags.Ref == ref && t.Tags.Sign == refSign[ref]
			}), rubMonth, fixed(day))
		}
		b.add(rubMonth, items)
	}

	// 5. Transits: one lens per ref (current and q4 never both — the one
	// expiring SOONEST wins: the current quarter's text until it runs out,
	// then the next quarter's), Saturn combo for the Moon sign, every graha-watch.
	{
		var items []radioItem
		for _, ref := range []string{"lagna", "sun", "moon"} {
			var best *radioLibTrack
			for _, t := range b.find(func(t *radioLibTrack) bool {
				return t.Tags.Transit == "lens" && t.Tags.Ref == ref && t.Tags.Sign == refSign[ref]
			}) {
				if best == nil || (t.ValidUntil != nil && (best.ValidUntil == nil || *t.ValidUntil < *best.ValidUntil)) {
					best = t
				}
			}
			if best != nil {
				b.addLib(&items, []*radioLibTrack{best}, rubTransits, fixed(day))
			}
		}
		b.addLib(&items, b.find(func(t *radioLibTrack) bool {
			return t.Tags.Transit == "combo" && t.Tags.Ref == "moon" && t.Tags.Sign == f.Moon.Sign
		}), rubTransits, fixed(day))
		b.addLib(&items, b.find(func(t *radioLibTrack) bool { return t.Tags.Transit == "watch" }),
			rubTransits, fixed(day))
		b.add(rubTransits, items)
	}

	// 6. Mahadasha: catalog mahadasha_<Maha> + dashas/<maha>.
	if f.Dasha != nil {
		maha := f.Dasha.Maha
		pl.FactsUsed.Maha = maha
		var items []radioItem
		if it, ok := b.catItem("mahadasha_"+radioTitleCase(maha), radioTitleCase(maha)+" period", rubDasha, maha); ok {
			items = append(items, it)
		}
		b.addLib(&items, b.find(func(t *radioLibTrack) bool { return t.Tags.Dasha == maha }), rubDasha, fixed(maha))
		b.add(rubDasha, items)
	}

	// 7. Sade Sati: catalog sade_sati_<n>, n = which one in life.
	if f.SadeSati.Active && in.birth != nil {
		moonIdx := chartFactsSignIndex(f.Moon.Sign)
		satIdx := chartFactsSignIndex(planetAt["saturn"].Sign)
		if moonIdx >= 0 && satIdx >= 0 {
			n := sadeSatiOrdinal(moonIdx, satIdx, ageYears(*in.birth, in.at))
			pl.FactsUsed.SadeSatiN = &n
			if it, ok := b.catItem(fmt.Sprintf("sade_sati_%d", n), fmt.Sprintf("Sade Sati: chapter %d", n),
				rubSadeSati, "saturn"); ok {
				b.add(rubSadeSati, []radioItem{it})
			}
		}
	}

	// 8. Yogas: server-found first, then the app's; at most radioYogasPlayed.
	{
		var items []radioItem
		seen := map[string]bool{}
		for _, y := range append(append([]string{}, f.Yogas...), in.extraYogas...) {
			if len(items) >= radioYogasPlayed || seen[y] {
				continue
			}
			seen[y] = true
			if it, ok := b.catItem("yoga_"+y, y, rubYogas, day); ok {
				items = append(items, it)
				pl.FactsUsed.Yogas = append(pl.FactsUsed.Yogas, y)
			}
		}
		b.add(rubYogas, items)
	}

	// 9. Planets in houses: breakdowns whose planets all stand in tags.house,
	// houses/<n> where ≥2 planets stand, grahas/<maha>.
	{
		var items []radioItem
		first := func(t *radioLibTrack) string { return t.Tags.Planets[0] }
		b.addLib(&items, b.find(func(t *radioLibTrack) bool {
			if t.Tags.House == 0 || len(t.Tags.Planets) == 0 {
				return false
			}
			for _, p := range t.Tags.Planets {
				if pa, ok := planetAt[p]; !ok || pa.House != t.Tags.House {
					return false
				}
			}
			return true
		}), rubPlanetHouse, first)
		for h := 1; h <= 12; h++ {
			if houseCount[h] < 2 {
				continue
			}
			station := day
			for _, p := range f.Planets {
				if p.House == h {
					station = p.Planet
					break
				}
			}
			b.addLib(&items, b.find(func(t *radioLibTrack) bool {
				return t.Tags.House == h && len(t.Tags.Planets) == 0 && t.Tags.Flag == ""
			}), rubPlanetHouse, fixed(station))
		}
		if f.Dasha != nil {
			maha := f.Dasha.Maha
			b.addLib(&items, b.find(func(t *radioLibTrack) bool {
				return t.Tags.Planet == maha && t.Tags.Transit == "" && t.Tags.Sign == ""
			}), rubPlanetHouse, fixed(maha))
		}
		b.add(rubPlanetHouse, items)
	}

	// 10. Conjunctions: breakdowns of exactly the pair (no house); a pair with
	// a node also plays the flag=nodes breakdown of the other planet.
	{
		var items []radioItem
		seen := map[string]bool{}
		isNode := func(p string) bool { return p == "rahu" || p == "ketu" }
		for _, c := range f.Conjunctions {
			a, z := c[0], c[1]
			ts := b.find(func(t *radioLibTrack) bool {
				g := t.Tags
				return g.House == 0 && len(g.Planets) == 2 &&
					((g.Planets[0] == a && g.Planets[1] == z) || (g.Planets[0] == z && g.Planets[1] == a))
			})
			if isNode(a) != isNode(z) {
				other := a
				if isNode(a) {
					other = z
				}
				ts = append(ts, b.find(func(t *radioLibTrack) bool {
					g := t.Tags
					return g.Flag == "nodes" && g.House == 0 && len(g.Planets) == 1 && g.Planets[0] == other
				})...)
			}
			for _, t := range ts {
				if !seen[t.Key] {
					seen[t.Key] = true
					b.addLib(&items, []*radioLibTrack{t}, rubConjunction, func(t *radioLibTrack) string { return t.Tags.Planets[0] })
				}
			}
		}
		b.add(rubConjunction, items)
	}

	// 11. Moon nakshatra.
	{
		var items []radioItem
		b.addLib(&items, b.find(func(t *radioLibTrack) bool { return t.Tags.Nakshatra == f.Moon.Nakshatra }),
			rubNakshatra, fixed(day))
		b.add(rubNakshatra, items)
	}

	// 12. Topic of the house with most planets (lowest house on a tie).
	{
		top := 0
		for h := 1; h <= 12; h++ {
			if houseCount[h] > houseCount[top] {
				top = h
			}
		}
		if top > 0 {
			topic := radioHouseTopic[top]
			pl.FactsUsed.TopHouse, pl.FactsUsed.Topic = top, topic
			var items []radioItem
			b.addLib(&items, b.find(func(t *radioLibTrack) bool { return t.Tags.Topic == topic }), rubTopic, fixed(day))
			b.add(rubTopic, items)
		}
	}

	// 13. Year ahead for the Moon sign: the nearest year-<Y> with Y ≥ at's year
	// (year-2027 during 2026 and 2027).
	{
		var best *radioLibTrack
		for _, t := range b.find(func(t *radioLibTrack) bool {
			return t.Tags.Year >= b.in.at.Year() && t.Tags.Sign == f.Moon.Sign
		}) {
			if best == nil || t.Tags.Year < best.Tags.Year {
				best = t
			}
		}
		if best != nil {
			var items []radioItem
			b.addLib(&items, []*radioLibTrack{best}, rubYear, fixed(day))
			b.add(rubYear, items)
		}
	}

	// 14. Releases of the station of the day (their release_lead is not
	// used: the wave has its own).
	if sched != nil {
		var items []radioItem
		for _, s := range sched.Items {
			if s.Kind != "release" {
				continue
			}
			if u, ok := radioStationURL(day, b.atStr, s.Src); ok {
				items = append(items, radioItem{Dur: s.Dur, span: s.Dur, Kind: "release", ID: s.ID,
					Title: s.Title, Src: u, Rubric: rubRelease, station: day})
			}
		}
		b.add(rubRelease, items)
	}

	// 15. The nearest sky event within radioEventWindow days.
	{
		until := b.in.at.AddDate(0, 0, radioEventWindow).Format("2006-01-02")
		var best *radioLibTrack
		for _, t := range b.find(func(t *radioLibTrack) bool {
			return t.Tags.Event != "" && t.Tags.Date >= b.atStr && t.Tags.Date <= until
		}) {
			if best == nil || t.Tags.Date < best.Tags.Date {
				best = t
			}
		}
		if best != nil {
			var items []radioItem
			b.addLib(&items, []*radioLibTrack{best}, rubEvent, fixed(day))
			b.add(rubEvent, items)
		}
	}

	// 16. Closing.
	if t := b.you("closing", rubClosing); t != nil {
		if it, ok := b.libItem(t, "closing", rubClosing, day); ok {
			b.groups = append(b.groups, []radioItem{it})
		}
	}

	b.layout(pl)
	return pl
}

// layout sets start times (10 s between speech, 2 s after a lead) and the
// music bed: one track per run of the same station, from its first speech.
func (b *radioBuilder) layout(pl *radioPlaylist) {
	round := func(x float64) float64 { return math.Round(x*10) / 10 }
	pl.Items = []radioItem{}
	pl.Music = radioMusic{Duck: radioMusicDuck, Xfade: radioMusicXfade, Tracks: []radioMusicTrack{}}
	t := 0.0
	for gi, g := range b.groups {
		for i, it := range g {
			if gi > 0 || i > 0 {
				if i > 0 && g[i-1].Kind == "lead" {
					t += radioLeadGap
				} else {
					t += radioSpeechGap
				}
			}
			it.Start = round(t)
			t += it.span
			pl.Items = append(pl.Items, it)
		}
	}
	last := ""
	missing := map[string]bool{}
	for _, it := range pl.Items {
		if it.station == last {
			continue
		}
		last = it.station
		s := b.in.schedule(it.station)
		if s == nil || s.Music.Dur <= 0 {
			if !missing[it.station] {
				missing[it.station] = true
				pl.missingMusic = append(pl.missingMusic, it.station)
			}
			continue
		}
		pl.Music.Tracks = append(pl.Music.Tracks, radioMusicTrack{From: it.Start,
			Src: "/radio/" + it.station + "/ever/music.m4a", Dur: s.Music.Dur, Station: it.station})
	}
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

type radioYourChartRequest struct {
	chartFactsRequest             // birth data (date also serves the Sade Sati ordinal with facts), lang, at
	Facts             *chartFacts `json:"facts"`
	Yogas             []string    `json:"yogas"`
}

// radioService: the access gate (own windows, same rules as chart-facts),
// the chart-facts computation for birth-data requests and the file cache.
type radioService struct {
	*chartAccess
	facts  *chartFactsService
	dir    func() string
	ttsDir func() string
	cache  *radioFileCache
}

func newRadioService(facts *chartFactsService) *radioService {
	return &radioService{
		chartAccess: newChartAccess("radio-you", "radio", "your_chart", radioMaxBody),
		facts:       facts,
		dir:         radioDir,
		ttsDir:      ttsCacheDir,
		cache:       &radioFileCache{},
	}
}

var radioSvc = newRadioService(chartFactsSvc)

// handle serves POST /api/radio/your-chart.
func (s *radioService) handle(w http.ResponseWriter, r *http.Request) {
	var req radioYourChartRequest
	s.chartAccess.handle(w, r, &req, func(w http.ResponseWriter, who string) bool {
		return s.serve(w, &req, who)
	})
}

var radioNakshatraRe = regexp.MustCompile(`^[a-z-]{3,24}$`)

// validateRadioFacts checks client-supplied facts (only compared against
// index values, never used in paths, but garbage is still a 400).
func validateRadioFacts(f *chartFacts) error {
	if chartFactsSignIndex(f.Lagna.Sign) < 0 || chartFactsSignIndex(f.Moon.Sign) < 0 {
		return errors.New("bad sign")
	}
	if !radioNakshatraRe.MatchString(f.Moon.Nakshatra) {
		return errors.New("bad nakshatra")
	}
	known := map[string]bool{}
	for _, p := range chartFactsPlanetOrder {
		known[p] = true
	}
	if len(f.Planets) != len(chartFactsPlanetOrder) {
		return errors.New("planets: want 9")
	}
	seen := map[string]bool{}
	for _, p := range f.Planets {
		if !known[p.Planet] || seen[p.Planet] || chartFactsSignIndex(p.Sign) < 0 || p.House < 1 || p.House > 12 {
			return fmt.Errorf("bad planet %q", p.Planet)
		}
		seen[p.Planet] = true
	}
	for _, c := range f.Conjunctions {
		if !known[c[0]] || !known[c[1]] {
			return errors.New("bad conjunction")
		}
	}
	if f.Dasha != nil && !known[f.Dasha.Maha] {
		return errors.New("bad dasha")
	}
	if (f.TithiToday.Paksha != "sukla" && f.TithiToday.Paksha != "krishna") || f.TithiToday.N < 1 || f.TithiToday.N > 15 {
		return errors.New("bad tithi")
	}
	if len(f.Yogas) > radioMaxYogas {
		return errors.New("too many yogas")
	}
	for _, y := range f.Yogas {
		if len(y) > radioMaxYogaLen {
			return errors.New("bad yoga")
		}
	}
	return nil
}

func radioLangOK(lang string) bool {
	for _, l := range seoLangs {
		if l == lang {
			return true
		}
	}
	return false
}

// serve resolves the facts, loads the data files and writes the playlist.
func (s *radioService) serve(w http.ResponseWriter, req *radioYourChartRequest, who string) bool {
	lang := req.Lang
	if lang == "" {
		lang = "en"
	}
	if !radioLangOK(lang) {
		chartFactsError(w, http.StatusBadRequest, "Invalid lang")
		return false
	}
	at := s.now().UTC()
	at = time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
	if req.At != "" {
		var err error
		at, err = time.Parse("2006-01-02", req.At)
		if err != nil || at.Year() < 1800 || at.Year() > 2100 {
			chartFactsError(w, http.StatusBadRequest, "Invalid at: want YYYY-MM-DD")
			return false
		}
	}
	if len(req.Yogas) > radioMaxYogas {
		chartFactsError(w, http.StatusBadRequest, "Invalid yogas")
		return false
	}
	for _, y := range req.Yogas {
		if len(y) > radioMaxYogaLen {
			chartFactsError(w, http.StatusBadRequest, "Invalid yogas")
			return false
		}
	}

	// The birth date (optional with facts) gives the age for the Sade Sati ordinal.
	var birth *time.Time
	if req.Date != "" {
		date, err := sanitizeDate(req.Date)
		if err != nil {
			chartFactsError(w, http.StatusBadRequest, "Invalid date: "+err.Error())
			return false
		}
		bt, err := time.Parse("1 2 2006", date)
		if err != nil {
			chartFactsError(w, http.StatusBadRequest, "Invalid date: not a calendar date")
			return false
		}
		birth = &bt
	}
	facts := req.Facts
	if facts != nil {
		if err := validateRadioFacts(facts); err != nil {
			chartFactsError(w, http.StatusBadRequest, "Invalid facts: "+err.Error())
			return false
		}
	} else {
		fr := req.chartFactsRequest
		fr.Lang, fr.At = lang, at.Format("2006-01-02")
		var status int
		var msg string
		if facts, status, msg = s.facts.compute(&fr, who); facts == nil {
			chartFactsError(w, status, msg)
			return false
		}
	}

	dir := s.dir()
	libV, err := s.cache.load(filepath.Join(dir, "lib", "index.json"), parseRadioLib)
	if err != nil {
		log.Printf("radio-you: library index unavailable %s: %v", who, err)
		chartFactsError(w, http.StatusServiceUnavailable, "Radio library unavailable")
		return false
	}
	catV, err := s.cache.load(filepath.Join(dir, "cat", "index.json"), parseRadioCat)
	if err != nil {
		log.Printf("radio-you: catalog index unavailable %s: %v", who, err)
		chartFactsError(w, http.StatusServiceUnavailable, "Radio library unavailable")
		return false
	}
	day := at.Format("2006-01-02")
	schedules := map[string]*radioSchedule{}
	schedule := func(station string) *radioSchedule {
		if sc, ok := schedules[station]; ok {
			return sc
		}
		v, err := s.cache.load(filepath.Join(dir, station, day, "schedule.json"), parseRadioSchedule)
		var sc *radioSchedule
		if err != nil {
			log.Printf("radio-you: schedule %s/%s unavailable: %v", station, day, err)
		} else {
			sc = v.(*radioSchedule)
		}
		schedules[station] = sc
		return sc
	}

	pl := buildRadioPlaylist(radioInputs{facts: facts, extraYogas: req.Yogas, birth: birth, lang: lang, at: at,
		lib: libV.(*radioLib), cat: catV.(*radioCat), schedule: schedule})
	if len(pl.missingMusic) > 0 {
		log.Printf("radio-you: no music bed for stations %v on %s %s", pl.missingMusic, day, who)
	}
	chartFactsJSON(w, http.StatusOK, pl)
	return true
}

// handleCat serves GET /api/radio/cat/{sha1}: only 40-hex keys named in
// cat/index.json, from the TTS cache, with Range support.
func (s *radioService) handleCat(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/radio/cat/")
	if !radioCatKeyRe.MatchString(key) {
		chartFactsError(w, http.StatusBadRequest, "bad key")
		return
	}
	catV, err := s.cache.load(filepath.Join(s.dir(), "cat", "index.json"), parseRadioCat)
	if err != nil {
		log.Printf("radio-cat: catalog index unavailable: %v", err)
		chartFactsError(w, http.StatusServiceUnavailable, "catalog unavailable")
		return
	}
	if !catV.(*radioCat).keys[key] {
		chartFactsError(w, http.StatusNotFound, "not found")
		return
	}
	f, err := os.Open(filepath.Join(s.ttsDir(), key+".mp3"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("radio-cat: %s is in the catalog index but not in the TTS cache", key)
			chartFactsError(w, http.StatusNotFound, "not found")
			return
		}
		log.Printf("radio-cat: open %s: %v", key, err)
		chartFactsError(w, http.StatusInternalServerError, "read failed")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		log.Printf("radio-cat: stat %s: %v", key, err)
		chartFactsError(w, http.StatusInternalServerError, "read failed")
		return
	}
	w.Header().Set("Content-Type", "audio/mpeg")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, key+".mp3", st.ModTime(), f)
}
