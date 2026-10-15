package main

// Personal playlist of the «Your Chart» radio wave (owner 2026-10-13,
// insta-agent/docs/radio/YOUR-CHART.md §2, §4, §5).
//
//   POST /api/radio/your-chart
//   {facts:<chart-facts response>, date?:"M D Y"} or the birth data of
//   /api/chart-facts; plus lang? (16 languages, default en),
//   at?:"YYYY-MM-DD" (default today UTC), yogas?:[names from the app's detector],
//   heard?:[block ids already heard, ≤ 200], last_first?:block id, nonce?:string ≤ 64
//
//   GET /api/radio/cat/{sha1}   — public: a catalog insert from the TTS cache
//
// Nothing is recorded for the wave: the playlist is assembled from files
// already on this box under RADIO_DIR (default /var/www/html/radio):
// lib/index.json (the Kokoro library of spec readings), cat/index.json (the
// app's 16-language catalog, audio in TTS_CACHE_DIR/<sha1>.mp3), the
// station-of-the-day schedule.json (sky news, yesterday's releases, music) and
// <station>/ever/loops.json (the music loops, each played once).
// The answer has the item fields of a station schedule.json, so engine.js and
// the app play it without a new player.
//
// Access and limits are exactly those of /api/chart-facts (chartAccess).
// Lead variants are deterministic: seed = sha1(facts + at). The ORDER of the
// rubric blocks is a shuffle bag (owner 2026-10-15): the ident first, the
// closing last, between them the blocks not yet heard in an order seeded by
// (facts, at, nonce), then the heard ones (see radioBuilder.order). Every item
// carries its block id; without a nonce the server draws a fresh one, so each
// start sounds in a new order.

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	mrand "math/rand"
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
	radioMaxBody      = 32768 // facts (~1.5 KB) + the app's yoga list + heard block ids
	radioMaxHeard     = 200   // request cap on heard[]
	radioMaxNonce     = 64    // request cap on nonce (bytes)
	radioMaxYogas     = 64    // request cap on yogas[]
	radioMaxYogaLen   = 64
	radioYogasPlayed  = 5    // at most this many yoga inserts
	radioSpeechGap    = 10.0 // seconds of pure music between speech tracks
	radioLeadGap      = 2.0  // between a rubric's lead and its first topic
	radioEventWindow  = 14   // days ahead for the «event of the week»
	radioMusicDuck    = 0.15
	radioMusicXfade   = 8
	radioNoteGap      = 1.0 // after a yoga name / the language note, before what it announces
	radioGenreRun     = 3   // at most this many music loops of one genre (or one station) in a row
	radioMinLoopDur   = 1.0 // shorter loops.json entries are ignored
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

// radioMusicStations: the stations whose loops make up the music deck (see
// musicDeck).
var radioMusicStations = []string{"sun", "moon", "mars", "mercury", "jupiter", "venus", "saturn", "rahu", "ketu"}

// radioHouseTopic: the house holding most planets -> topics/<topic>.
var radioHouseTopic = map[int]string{
	1: "self", 2: "wealth", 3: "courage", 4: "home", 5: "children", 6: "health",
	7: "love", 8: "depth", 9: "luck", 10: "career", 11: "friends", 12: "freedom",
}

var radioCatKeyRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// radioBlockReqRe validates block ids sent back by clients (heard,
// last_first). Looser than what blockID emits so a later format change does
// not turn ids stored by old clients into 400s; unknown ids are ignored.
var radioBlockReqRe = regexp.MustCompile(`^[a-z0-9_:-]{1,64}$`)

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
	Yoga      string   `json:"yoga"` // yoga-name/<slug>: the name as in the catalog slug yoga_<Name>
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

// radioLoop is one entry of <station>/ever/loops.json; src is relative to ever/.
type radioLoop struct {
	Src   string  `json:"src"`
	Dur   float64 `json:"dur"`
	Genre string  `json:"genre"`
}

func parseRadioLoops(b []byte) (interface{}, error) {
	var loops []radioLoop
	if err := json.Unmarshal(b, &loops); err != nil {
		return nil, err
	}
	return loops, nil
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
	Srcs   map[string]string  `json:"srcs,omitempty"` // per-language audio URL (catalog inserts; the site/app prefer it)
	Rubric string             `json:"rubric"`
	Block  string             `json:"block"` // the shuffle unit: "ident", "closing" or "<rubric>:<12 hex of its content ids>"

	span    float64 // time on the timeline (a catalog insert in the listener's language may be longer than en)
	station string  // music under this item
	pause   float64 // > 0: silence before the next item of the rubric (instead of the lead/speech gap)
}

type radioMusicTrack struct {
	From    float64 `json:"from"`
	Src     string  `json:"src"`
	Dur     float64 `json:"dur"`
	Station string  `json:"station"`
	Genre   string  `json:"genre"`
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
	loops      func(station string) []radioLoop    // <station>/ever/loops.json; nil when absent
	heard      map[string]bool                     // block ids the listener has heard: they go after the unheard ones
	lastFirst  string                              // first block after the ident at the previous start
	nonce      string                              // order seed salt ("" in tests: a fixed order)
}

// radioBuilder accumulates rubric groups.
type radioBuilder struct {
	in     radioInputs
	atStr  string
	seed   [20]byte
	groups [][]radioItem
	day    string                 // station of the day
	music  map[string][]radioLoop // stationLoops cache
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
var radioDefaultTitles = map[string]string{"ident": "Your Chart", "lead": "Coming up", "closing": "Your Chart",
	"lang_note": "Your Chart"}

// you returns one active `you/*` track (ident, closing, lang_note or the lead of a rubric).
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

// catItem is a catalog insert: src is the en audio (the listener's language
// when the slug has no en voice), durs every language.
func (b *radioBuilder) catItem(slug, title, rubric, station string) (radioItem, bool) {
	langs, ok := b.in.cat.slugs[slug]
	if !ok {
		return radioItem{}, false
	}
	en, ok := langs["en"]
	if !ok {
		en, ok = langs[b.in.lang]
	}
	if !ok || !radioCatKeyRe.MatchString(en.Key) {
		return radioItem{}, false
	}
	durs := map[string]float64{}
	srcs := map[string]string{} // 13.10.2026: /radio/cat/<lang>/<slug>.m4a exists only for the few slugs the live
	// stations happened to encode (no yogas); the TTS cache has every voice, so hand out those URLs per language
	for l, e := range langs {
		durs[l] = e.Dur
		if radioCatKeyRe.MatchString(e.Key) {
			srcs[l] = "/api/radio/cat/" + e.Key
		}
	}
	span := en.Dur
	if d, ok := langs[b.in.lang]; ok && d.Dur > span {
		span = d.Dur
	}
	return radioItem{Dur: en.Dur, span: span, Kind: "insert", ID: "insert_" + slug, Title: title,
		Src: "/api/radio/cat/" + en.Key, Cat: slug, Durs: durs, Srcs: srcs, Rubric: rubric, station: station}, true
}

// yogaName announces yoga y before its insert: the catalog slug
// yoganame_<y> when it is voiced in the listener's language, else the
// active English `yoga-name/*` library track.
func (b *radioBuilder) yogaName(y, station string) (radioItem, bool) {
	slug := "yoganame_" + y
	if e, ok := b.in.cat.slugs[slug][b.in.lang]; ok && radioCatKeyRe.MatchString(e.Key) {
		if it, ok := b.catItem(slug, y, rubYogas, station); ok {
			it.pause = radioNoteGap
			return it, true
		}
	}
	for i := range b.in.lib.Tracks {
		t := &b.in.lib.Tracks[i]
		if t.Tags.You == "yoga_name" && t.Tags.Yoga == y && b.active(t) {
			it, ok := b.libItem(t, "yoga_name", rubYogas, station)
			if it.Title == "" {
				it.Title = y
			}
			it.pause = radioNoteGap
			return it, ok
		}
	}
	log.Printf("radio-you: no yoga-name track for %q (%s)", y, b.in.lang)
	return radioItem{}, false
}

// langNote is the «what follows is in your language» line, played after the
// lead of a rubric that has a catalog insert voiced in the listener's
// language (never for en).
func (b *radioBuilder) langNote(rubric string, topics []radioItem) (radioItem, bool) {
	if b.in.lang == "en" {
		return radioItem{}, false
	}
	localized := false
	for _, it := range topics {
		if _, ok := it.Durs[b.in.lang]; ok && it.Kind == "insert" {
			localized = true
			break
		}
	}
	if !localized {
		return radioItem{}, false
	}
	t := b.you("lang_note", rubric)
	if t == nil {
		return radioItem{}, false
	}
	it, ok := b.libItem(t, "lang_note", rubric, topics[0].station)
	it.pause = radioNoteGap
	return it, ok
}

// add appends a rubric: its lead (when rubric != ""), the language note and
// the topic items. Nothing is added when there is nothing to play.
func (b *radioBuilder) add(rubric string, topics []radioItem) {
	if len(topics) == 0 {
		return
	}
	if note, ok := b.langNote(rubric, topics); ok {
		topics = append([]radioItem{note}, topics...)
	}
	group := topics
	if lead := b.you("lead", rubric); lead != nil {
		if li, ok := b.libItem(lead, "lead", rubric, topics[0].station); ok {
			group = append([]radioItem{li}, topics...)
		}
	}
	id := radioBlockID(rubric, group)
	for i := range group {
		group[i].Block = id
	}
	b.groups = append(b.groups, group)
}

// radioBlockID names a rubric block by its content: the rubric plus a hash of
// the ids of its content items. Leads, language notes and yoga names are left
// out (their variant or language changes from day to day while the content
// stays), so the id is stable for as long as the same texts play, and a new
// sky_news / release / month text is a new, unheard block.
func radioBlockID(rubric string, items []radioItem) string {
	h := sha1.New()
	for _, it := range items {
		switch it.Kind {
		case "lead", "lang_note", "yoga_name":
			continue
		}
		h.Write([]byte(it.ID))
		h.Write([]byte{'\n'})
	}
	return rubric + ":" + hex.EncodeToString(h.Sum(nil))[:12]
}

// order shuffles the rubric blocks between the ident (first) and the closing
// (last): the blocks not in heard first, then the heard ones, each part in a
// random order seeded by (facts, at, nonce). Two blocks under the same music
// station do not follow each other when that can be avoided (one block per
// rubric, so the rubric itself never repeats), and the first block after the
// ident is not lastFirst when another unheard block can open.
func (b *radioBuilder) order() {
	head, tail := 0, len(b.groups)
	for head < tail && b.groups[head][0].Rubric == rubIdent {
		head++
	}
	for tail > head && b.groups[tail-1][0].Rubric == rubClosing {
		tail--
	}
	h := sha1.Sum(append(append(b.seed[:], "|order|"...), b.in.nonce...))
	rng := mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(h[:8]))))
	var unheard, heard [][]radioItem
	for _, g := range b.groups[head:tail] {
		if b.in.heard[g[0].Block] {
			heard = append(heard, g)
		} else {
			unheard = append(unheard, g)
		}
	}
	for _, part := range [][][]radioItem{unheard, heard} {
		rng.Shuffle(len(part), func(i, j int) { part[i], part[j] = part[j], part[i] })
	}
	prev := ""
	if head > 0 {
		prev = b.groups[head-1][0].station
	}
	out := append([][]radioItem{}, b.groups[:head]...)
	avoid := b.in.lastFirst
	for _, part := range [][][]radioItem{unheard, heard} {
		if len(part) == 0 {
			continue
		}
		part = radioArrange(part, prev, avoid)
		avoid = ""
		prev = part[len(part)-1][0].station
		out = append(out, part...)
	}
	b.groups = append(out, b.groups[tail:]...)
}

// radioArrange reorders blocks (already shuffled) so that no two neighbours
// share a station (the block's first item; prev is the station before the
// first block) whenever such an order exists, and the first block is not
// avoid when another can open. Greedy in the shuffled order: at every step the
// first block that differs from the previous station AND leaves the rest
// arrangeable; failing that, the first that differs; failing that, the first.
func radioArrange(blocks [][]radioItem, prev, avoid string) [][]radioItem {
	rest := append([][]radioItem{}, blocks...)
	out := make([][]radioItem, 0, len(rest))
	key := func(g []radioItem) string { return g[0].station }
	// arrangeable: rest without i can follow key(rest[i]) with no equal neighbours.
	arrangeable := func(i int) bool {
		n := len(rest) - 1
		count := map[string]int{}
		for j, g := range rest {
			if j != i {
				count[key(g)]++
			}
		}
		for k, c := range count {
			limit := (n + 1) / 2
			if k == key(rest[i]) {
				limit = n / 2
			}
			if c > limit {
				return false
			}
		}
		return true
	}
	for len(rest) > 0 {
		allowed := func(i int) bool {
			return len(out) > 0 || avoid == "" || len(rest) == 1 || rest[i][0].Block != avoid
		}
		pick := -1
		for tier := 0; tier < 3 && pick < 0; tier++ {
			for i, g := range rest {
				if !allowed(i) {
					continue
				}
				if tier < 2 && key(g) == prev {
					continue
				}
				if tier < 1 && !arrangeable(i) {
					continue
				}
				pick = i
				break
			}
		}
		if pick < 0 {
			pick = 0
		}
		prev = key(rest[pick])
		out = append(out, rest[pick])
		rest = append(rest[:pick:pick], rest[pick+1:]...)
	}
	return out
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
			it.Block = rubIdent
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
			if len(pl.FactsUsed.Yogas) >= radioYogasPlayed || seen[y] {
				continue
			}
			seen[y] = true
			if it, ok := b.catItem("yoga_"+y, y, rubYogas, day); ok {
				if ni, ok := b.yogaName(y, day); ok {
					items = append(items, ni)
				}
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
			it.Block = rubClosing
			b.groups = append(b.groups, []radioItem{it})
		}
	}

	b.order()
	b.layout(pl)
	return pl
}

// layout sets start times (10 s between speech, 2 s after a lead, 1 s after
// a yoga name or the language note) and lays the music bed.
func (b *radioBuilder) layout(pl *radioPlaylist) {
	pl.Items = []radioItem{}
	t := 0.0
	for gi, g := range b.groups {
		for i, it := range g {
			if gi > 0 || i > 0 {
				switch {
				case i > 0 && g[i-1].pause > 0:
					t += g[i-1].pause
				case i > 0 && g[i-1].Kind == "lead":
					t += radioLeadGap
				default:
					t += radioSpeechGap
				}
			}
			it.Start = radioRound(t)
			t += it.span
			pl.Items = append(pl.Items, it)
		}
	}
	b.layoutMusic(pl, t)
}

func radioRound(x float64) float64 { return math.Round(x*10) / 10 }

// stationLoops: the station's ever/loops.json, else its music.m4a from the
// day's schedule.json (genre = the station id); nil when it has no music.
func (b *radioBuilder) stationLoops(station string) []radioLoop {
	if l, ok := b.music[station]; ok {
		return l
	}
	var out []radioLoop
	if b.in.loops != nil {
		for _, l := range b.in.loops(station) {
			u, ok := radioLoopURL(station, l.Src)
			if !ok || l.Dur < radioMinLoopDur {
				log.Printf("radio-you: %s/ever/loops.json: bad entry %+v", station, l)
				continue
			}
			if l.Genre == "" {
				l.Genre = station
			}
			l.Src = u
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		if s := b.in.schedule(station); s != nil && s.Music.Dur >= radioMinLoopDur {
			out = []radioLoop{{Src: "/radio/" + station + "/ever/music.m4a", Dur: s.Music.Dur, Genre: station}}
		}
	}
	if b.music == nil {
		b.music = map[string][]radioLoop{}
	}
	b.music[station] = out
	return out
}

// radioLoopURL resolves a loops.json src (relative to ever/) to /radio/<st>/ever/<src>.
func radioLoopURL(station, src string) (string, bool) {
	if src == "" || strings.HasPrefix(src, "/") || strings.Contains(src, "://") || strings.Contains(src, "\\") {
		return "", false
	}
	base := "/radio/" + station + "/ever/"
	u := path.Join(base, src)
	return u, strings.HasPrefix(u, base)
}

// radioDeckLoop is one loop of the music deck.
type radioDeckLoop struct {
	radioLoop
	station string
	round   int // the loop's place among its station's loops in this pass
}

// musicDeck is one pass of the deck: every loop of every station of
// radioMusicStations exactly once, in a seeded order. A station's loops are
// shuffled (once for all passes, so they take turns) and dealt into rounds
// (round k = the k-th loop of each station that has one), and the stations
// are shuffled inside each round anew every pass, so all stations with music
// sound before any of them plays its second loop.
func (b *radioBuilder) musicDeck(pass int) []radioDeckLoop {
	shuffle := func(n int, salt string) []int {
		p := make([]int, n)
		for i := range p {
			p[i] = i
		}
		for i := n - 1; i > 0; i-- {
			j := b.pick(i+1, fmt.Sprintf("%s/%d", salt, i))
			p[i], p[j] = p[j], p[i]
		}
		return p
	}
	var rounds [][]radioDeckLoop
	for _, st := range radioMusicStations {
		loops := b.stationLoops(st)
		for k, i := range shuffle(len(loops), "deck/"+st) { // the same in every pass: a station's loops take turns
			if k == len(rounds) {
				rounds = append(rounds, nil)
			}
			rounds[k] = append(rounds[k], radioDeckLoop{radioLoop: loops[i], station: st, round: k})
		}
	}
	var deck []radioDeckLoop
	for k, r := range rounds {
		for _, i := range shuffle(len(r), fmt.Sprintf("deck/%d/round/%d", pass, k)) {
			deck = append(deck, r[i])
		}
	}
	return deck
}

// layoutMusic fills [0, end) with music loops, each played ONCE (dur = the
// loop length), back to back; the last one may run past the end (the client
// fades out). The loops come from the deck (musicDeck): a loop plays once per
// pass and the next pass starts only when every loop has played. Among the
// loops not yet played in the pass, the earliest round goes first; inside
// it the station of the item playing at the loop's start goes first, then
// deck order. A candidate is skipped when it is the loop just played, when
// it already played in the current run of its station, or when its station
// or its genre has played radioGenreRun times in a row (all of this holds
// across the seam of two passes too); when every unplayed loop breaks a run
// rule, the first one that is not the loop just played is taken.
func (b *radioBuilder) layoutMusic(pl *radioPlaylist, end float64) {
	pl.Music = radioMusic{Duck: radioMusicDuck, Xfade: radioMusicXfade, Tracks: []radioMusicTrack{}}
	if len(pl.Items) == 0 {
		return
	}
	pass := 0
	deck := b.musicDeck(pass)
	missing := map[string]bool{}
	var lastSrc, lastGenre, lastStation string
	genreRun, stationRun, item := 0, 0, 0
	runSrcs := map[string]bool{} // loops played in the current run of lastStation
	for t := 0.0; t < end; {
		for item+1 < len(pl.Items) && pl.Items[item+1].Start <= t {
			item++
		}
		st := pl.Items[item].station
		if len(b.stationLoops(st)) == 0 && !missing[st] {
			missing[st] = true
			pl.missingMusic = append(pl.missingMusic, st)
		}
		if len(deck) == 0 && lastSrc == "" {
			return // no music anywhere
		}
		if len(deck) == 0 {
			pass++
			deck = b.musicDeck(pass)
		}
		order := make([]int, len(deck))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(x, y int) bool {
			a, c := deck[order[x]], deck[order[y]]
			if a.round != c.round {
				return a.round < c.round
			}
			return a.station == st && c.station != st
		})
		chosen, fallback := -1, -1
		for _, i := range order {
			l := deck[i]
			if l.Src == lastSrc {
				continue
			}
			if fallback < 0 {
				fallback = i
			}
			if l.station == lastStation && (stationRun >= radioGenreRun || runSrcs[l.Src]) {
				continue
			}
			if l.Genre == lastGenre && genreRun >= radioGenreRun {
				continue
			}
			chosen = i
			break
		}
		if chosen < 0 {
			chosen = fallback
		}
		if chosen < 0 {
			chosen = 0 // the only loop there is
		}
		l := deck[chosen]
		deck = append(deck[:chosen:chosen], deck[chosen+1:]...)
		if l.Genre == lastGenre {
			genreRun++
		} else {
			lastGenre, genreRun = l.Genre, 1
		}
		if l.station == lastStation {
			stationRun++
		} else {
			lastStation, stationRun, runSrcs = l.station, 1, map[string]bool{}
		}
		runSrcs[l.Src] = true
		lastSrc = l.Src
		pl.Music.Tracks = append(pl.Music.Tracks, radioMusicTrack{From: radioRound(t), Src: l.Src, Dur: l.Dur,
			Station: l.station, Genre: l.Genre})
		t += l.Dur
	}
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

type radioYourChartRequest struct {
	chartFactsRequest             // birth data (date also serves the Sade Sati ordinal with facts), lang, at
	Facts             *chartFacts `json:"facts"`
	Yogas             []string    `json:"yogas"`
	Heard             []string    `json:"heard"`      // block ids the listener has heard (shuffle bag)
	LastFirst         string      `json:"last_first"` // first block after the ident at the previous start
	Nonce             string      `json:"nonce"`      // order seed; empty = a fresh random one
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

	if len(req.Heard) > radioMaxHeard {
		chartFactsError(w, http.StatusBadRequest, "Invalid heard")
		return false
	}
	heard := make(map[string]bool, len(req.Heard))
	for _, id := range req.Heard {
		if !radioBlockReqRe.MatchString(id) {
			chartFactsError(w, http.StatusBadRequest, "Invalid heard")
			return false
		}
		heard[id] = true
	}
	if req.LastFirst != "" && !radioBlockReqRe.MatchString(req.LastFirst) {
		chartFactsError(w, http.StatusBadRequest, "Invalid last_first")
		return false
	}
	if len(req.Nonce) > radioMaxNonce {
		chartFactsError(w, http.StatusBadRequest, "Invalid nonce")
		return false
	}
	nonce := req.Nonce
	if nonce == "" {
		nonce = radioFreshNonce()
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

	loops := func(station string) []radioLoop {
		v, err := s.cache.load(filepath.Join(dir, station, "ever", "loops.json"), parseRadioLoops)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Printf("radio-you: loops %s unavailable: %v", station, err)
			}
			return nil
		}
		return v.([]radioLoop)
	}

	pl := buildRadioPlaylist(radioInputs{facts: facts, extraYogas: req.Yogas, birth: birth, lang: lang, at: at,
		lib: libV.(*radioLib), cat: catV.(*radioCat), schedule: schedule, loops: loops,
		heard: heard, lastFirst: req.LastFirst, nonce: nonce})
	if len(pl.missingMusic) > 0 {
		log.Printf("radio-you: no music bed for stations %v on %s %s", pl.missingMusic, day, who)
	}
	chartFactsJSON(w, http.StatusOK, pl)
	return true
}

// radioFreshNonce: a random order seed for a request without one (the site's
// /you/ sends none and still gets a new order on every start).
func radioFreshNonce() string {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		log.Printf("radio-you: crypto/rand failed, nonce from the clock: %v", err)
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(r[:])
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
