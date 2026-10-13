package main

// Natal chart facts for the «Your Chart» radio wave (owner 2026-10-13,
// insta-agent/docs/radio/YOUR-CHART.md).
//
//   POST /api/chart-facts
//   {date:"M D Y", time:"HH:MM", timezone, longitude, latitude, lang?, at?:"YYYY-MM-DD"}
//
// Runs the SAME natal astrolog call as /api/astrolog (astrologChartArgs) and
// returns structured facts instead of the raw text, so the site and the
// playlist builder do not need the Dart parser:
// lagna, planets by sign/house, conjunctions, Moon nakshatra, Vimshottari
// maha/antar dasha, Sade Sati and today's tithi at `at`, and a deterministic
// subset of benefic yogas. The rules are ports of the app code
// (my_first_app/lib/services: chart_parser, mahadasa_service,
// sade_sati_service, yoga_calculator) — keep them in step.
//
// Access: either a Bearer JWT (the app; same jwtAuthMiddleware and limiters
// as /api/astrolog), or no Authorization header from the website — then the
// Origin must be astrolytix.com (webChatAllowedOrigins) and per-IP sliding
// windows apply (10/hour, 30/day) on top of ipLimiter. No name or e-mail.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	chartFactsPerIPHourLimit = 10
	chartFactsPerIPDayLimit  = 30
	chartFactsMaxBody        = 4096

	// Vimshottari: the app uses the solar year (MahadasaService, useSavanaYear=false).
	vimshottariDaysPerYear = 365.2425
	vimshottariMaxAgeYears = 120.0
)

var chartFactsSigns = []string{"aries", "taurus", "gemini", "cancer", "leo", "virgo",
	"libra", "scorpio", "sagittarius", "capricorn", "aquarius", "pisces"}

// chartFactsPlanetOrder is the output order of planets[].
var chartFactsPlanetOrder = []string{"sun", "moon", "mercury", "venus", "mars", "jupiter", "saturn", "rahu", "ketu"}

// astrolog row prefix -> our key. Asce is the lagna.
var chartFactsRowNames = map[string]string{
	"Sun ": "sun", "Moon": "moon", "Merc": "mercury", "Venu": "venus", "Mars": "mars",
	"Jupi": "jupiter", "Satu": "saturn", "Nort": "rahu", "Asce": "lagna",
}

// A natal row: "Merc: 14Ari18 R - 2:29' (-) [10th house] [-] -0.131  -  House cusp …".
// The (x) column is dignity and the optional R is ignored: retrograde is the
// signed speed (chart_parser.dart). Asce has neither the dignity nor the
// ruler bracket, so both are optional. Anything after the speed is ignored.
var chartFactsRowRe = regexp.MustCompile(`^(Sun |Moon|Merc|Venu|Mars|Jupi|Satu|Nort|Asce):\s*(\d{1,2})([A-Z][a-z]{2})(\d{2})(?:\s+R)?\s+[+-]\s*\d+:\d+'\s*(?:\([^)]*\)\s*)?\[\s*(\d{1,2})[a-z]{2}\s+house\]\s*(?:\[.\]\s*)?([+-]?\d+(?:\.\d+)?)`)

// natalBody is one parsed body of the natal chart.
type natalBody struct {
	sign  int // 0 = aries
	deg   int // whole degrees in the sign
	min   int // arc minutes
	house int // 1..12 (whole signs from the lagna)
	speed float64
}

// arcmin is the exact longitude in arc minutes (0..21599).
func (b natalBody) arcmin() int { return (b.sign*30+b.deg)*60 + b.min }

// degInSign is the in-sign position rounded to 0.01° (the minute stays
// recoverable: round(frac*60)).
func (b natalBody) degInSign() float64 {
	return math.Round((float64(b.deg)+float64(b.min)/60)*100) / 100
}

// parseNatalChart reads the bodies from astrolog's natal output. Every body
// of chartFactsRowNames must be present; Ketu is derived (Rahu + 180°,
// house + 6), exactly like YogaCalculator.fromChartData.
func parseNatalChart(out string) (map[string]natalBody, error) {
	res := map[string]natalBody{}
	for _, line := range strings.Split(out, "\n") {
		m := chartFactsRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := chartFactsRowNames[m[1]]
		sign, ok := signAbbrIndex[m[3]]
		if !ok {
			return nil, fmt.Errorf("%s: unknown sign %q", name, m[3])
		}
		deg, err := strconv.Atoi(m[2])
		if err != nil {
			return nil, fmt.Errorf("%s: degrees: %w", name, err)
		}
		min, err := strconv.Atoi(m[4])
		if err != nil {
			return nil, fmt.Errorf("%s: minutes: %w", name, err)
		}
		house, err := strconv.Atoi(m[5])
		if err != nil {
			return nil, fmt.Errorf("%s: house: %w", name, err)
		}
		speed, err := strconv.ParseFloat(m[6], 64)
		if err != nil {
			return nil, fmt.Errorf("%s: speed: %w", name, err)
		}
		if deg > 29 || min > 59 || house < 1 || house > 12 {
			return nil, fmt.Errorf("%s: value out of range in %q", name, strings.TrimSpace(line))
		}
		res[name] = natalBody{sign: sign, deg: deg, min: min, house: house, speed: speed}
	}
	for _, name := range chartFactsRowNames {
		if _, ok := res[name]; !ok {
			return nil, fmt.Errorf("natal output lacks %s", name)
		}
	}
	rahu := res["rahu"]
	ketuHouse := (rahu.house + 6) % 12
	if ketuHouse == 0 {
		ketuHouse = 12
	}
	res["ketu"] = natalBody{sign: (rahu.sign + 6) % 12, deg: rahu.deg, min: rahu.min, house: ketuHouse, speed: rahu.speed}
	return res, nil
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

type chartFactsSignDeg struct {
	Sign string  `json:"sign"`
	Deg  float64 `json:"deg"`
}

type chartFactsPlanet struct {
	Planet string  `json:"planet"`
	Sign   string  `json:"sign"`
	Deg    float64 `json:"deg"`
	House  int     `json:"house"`
	Retro  bool    `json:"retro"`
}

type chartFactsMoon struct {
	Sign      string `json:"sign"`
	Nakshatra string `json:"nakshatra"` // slug of the English name, e.g. "uttara-ashadha"
	Pada      int    `json:"pada"`
}

type chartFactsDasha struct {
	Maha       string `json:"maha"`
	Antar      string `json:"antar"`
	MahaUntil  string `json:"maha_until"`  // YYYY-MM-DD, first day of the next mahadasha
	AntarUntil string `json:"antar_until"` // YYYY-MM-DD, first day of the next antardasha
}

type chartFactsSadeSati struct {
	Active bool    `json:"active"`
	Phase  *string `json:"phase"` // rising | peak | setting | null
}

type chartFactsTithi struct {
	Paksha string `json:"paksha"` // sukla | krishna (as TithiInfo / catalog tithi:<paksha>:<n>)
	N      int    `json:"n"`      // 1..15 within the paksha
}

type chartFacts struct {
	Lagna        chartFactsSignDeg  `json:"lagna"`
	Planets      []chartFactsPlanet `json:"planets"`
	Conjunctions [][2]string        `json:"conjunctions"`
	Moon         chartFactsMoon     `json:"moon"`
	Dasha        *chartFactsDasha   `json:"dasha"` // null outside the 120-year span
	SadeSati     chartFactsSadeSati `json:"sade_sati"`
	TithiToday   chartFactsTithi    `json:"tithi_today"`
	Yogas        []string           `json:"yogas"`
	At           string             `json:"at"`
}

// buildChartFacts assembles the facts from the parsed natal chart, the birth
// date and the sidereal sky at `at` (siderealLongitudes keys).
func buildChartFacts(bodies map[string]natalBody, birth, at time.Time, sky map[string]float64) (*chartFacts, error) {
	for _, k := range []string{"Saturn", "Sun", "Moon"} {
		if _, ok := sky[k]; !ok {
			return nil, fmt.Errorf("sky at %s lacks %s", at.Format("2006-01-02"), k)
		}
	}
	lagna := bodies["lagna"]
	f := &chartFacts{
		Lagna:        chartFactsSignDeg{Sign: chartFactsSigns[lagna.sign], Deg: lagna.degInSign()},
		Conjunctions: [][2]string{},
		At:           at.Format("2006-01-02"),
	}
	for _, p := range chartFactsPlanetOrder {
		b := bodies[p]
		// Nodes are always retrograde by nature; the app (chart_parser.dart) reports them as not
		// retrograde, and the facts must match the app, so the flag is reserved for the planets.
		retro := b.speed < 0 && p != "rahu" && p != "ketu"
		f.Planets = append(f.Planets, chartFactsPlanet{
			Planet: p, Sign: chartFactsSigns[b.sign], Deg: b.degInSign(), House: b.house, Retro: retro,
		})
	}
	for i, a := range chartFactsPlanetOrder {
		for _, b := range chartFactsPlanetOrder[i+1:] {
			if a == "rahu" && b == "ketu" {
				continue
			}
			if bodies[a].sign == bodies[b].sign {
				f.Conjunctions = append(f.Conjunctions, [2]string{a, b})
			}
		}
	}

	moon := bodies["moon"]
	nak, pada := nakshatraOfArcmin(moon.arcmin())
	f.Moon = chartFactsMoon{
		Sign:      chartFactsSigns[moon.sign],
		Nakshatra: strings.ToLower(strings.ReplaceAll(seoNakshatraNames["en"][nak], " ", "-")),
		Pada:      pada,
	}

	f.Dasha = vimshottariAt(birth, moon.arcmin(), at)

	if ph := sadeSatiPhase(signOf(norm360(sky["Saturn"])), moon.sign); ph != "" {
		f.SadeSati = chartFactsSadeSati{Active: true, Phase: &ph}
	}

	t := tithiOf(sky["Moon"], sky["Sun"])
	if t <= 15 {
		f.TithiToday = chartFactsTithi{Paksha: "sukla", N: t}
	} else {
		f.TithiToday = chartFactsTithi{Paksha: "krishna", N: t - 15}
	}

	f.Yogas = chartFactsYogas(bodies)
	return f, nil
}

// ---------------------------------------------------------------------------
// Vimshottari (port of MahadasaService)
// ---------------------------------------------------------------------------

// vimshottariOrder is MahadasaService.planetSequence; it is also the order
// of the nakshatra lords from Ashwini (index % 9).
var vimshottariOrder = []string{"ketu", "venus", "sun", "moon", "mars", "rahu", "jupiter", "saturn", "mercury"}

var vimshottariYears = map[string]int{
	"ketu": 7, "venus": 20, "sun": 6, "moon": 10, "mars": 7,
	"rahu": 18, "jupiter": 16, "saturn": 19, "mercury": 17,
}

type dashaPeriod struct {
	lord       string
	start, end time.Time
}

func addDays(t time.Time, days int) time.Time { return t.AddDate(0, 0, days) }

func ageYears(birth, t time.Time) float64 {
	return float64(int(t.Sub(birth).Hours()/24)) / vimshottariDaysPerYear
}

// nakshatraOfArcmin is nakshatraOf on exact arc minutes, as the app's
// TithiCalculator.getNakshatraPada. The float nakshatraOf puts an exact
// boundary (e.g. 93°20′, arcmin 5600) into the previous nakshatra, which
// would disagree with the app and with the dasha lord computed below.
func nakshatraOfArcmin(am int) (idx, pada int) {
	am = ((am % 21600) + 21600) % 21600
	return am / 800, (am%800)/200 + 1
}

// mahadashas mirrors calculateMahadasaPeriods: the birth nakshatra lord's
// dasha started `elapsed` days before birth (exact arc-minute fraction, as
// TithiCalculator.getNakshatraPada), periods cover ages 0..120.
func mahadashas(birth time.Time, moonArcmin int) []dashaPeriod {
	moonArcmin = ((moonArcmin % 21600) + 21600) % 21600
	nak, _ := nakshatraOfArcmin(moonArcmin)
	traversed := float64(moonArcmin%800) / 800.0
	startIdx := nak % 9
	lord := vimshottariOrder[startIdx]
	elapsedDays := int(math.Round(float64(vimshottariYears[lord]) * traversed * vimshottariDaysPerYear))
	cur := addDays(birth, -elapsedDays)

	var out []dashaPeriod
	for i := startIdx; ; i++ {
		p := vimshottariOrder[i%9]
		end := addDays(cur, int(math.Round(float64(vimshottariYears[p])*vimshottariDaysPerYear)))
		startAge, endAge := ageYears(birth, cur), ageYears(birth, end)
		if endAge > 0 && startAge < vimshottariMaxAgeYears {
			out = append(out, dashaPeriod{lord: p, start: cur, end: end})
		}
		cur = end
		if startAge >= vimshottariMaxAgeYears {
			return out
		}
	}
}

// antardashas mirrors calculateAntardasaPeriods.
func antardashas(maha dashaPeriod) []dashaPeriod {
	var out []dashaPeriod
	start := 0
	for i, p := range vimshottariOrder {
		if p == maha.lord {
			start = i
		}
	}
	cur := maha.start
	for k := 0; k < 9; k++ {
		if !cur.Before(maha.end) {
			break
		}
		p := vimshottariOrder[(start+k)%9]
		years := float64(vimshottariYears[maha.lord]*vimshottariYears[p]) / 120.0
		end := addDays(cur, int(math.Round(years*vimshottariDaysPerYear)))
		if end.After(maha.end) {
			end = maha.end
		}
		out = append(out, dashaPeriod{lord: p, start: cur, end: end})
		cur = end
	}
	return out
}

func periodAt(ps []dashaPeriod, t time.Time) *dashaPeriod {
	for i := range ps {
		if t.After(ps[i].start) && t.Before(ps[i].end) {
			return &ps[i]
		}
	}
	return nil
}

// vimshottariAt returns the running maha/antar dasha at noon UTC of `at`
// (period boundaries are UTC midnights, so noon never sits on one).
// birth is the UTC calendar day of birth, as the app's profile date.
func vimshottariAt(birth time.Time, moonArcmin int, at time.Time) *chartFactsDasha {
	t := time.Date(at.Year(), at.Month(), at.Day(), 12, 0, 0, 0, time.UTC)
	maha := periodAt(mahadashas(birth, moonArcmin), t)
	if maha == nil {
		return nil
	}
	antar := periodAt(antardashas(*maha), t)
	if antar == nil {
		return nil
	}
	return &chartFactsDasha{
		Maha: maha.lord, Antar: antar.lord,
		MahaUntil: maha.end.Format("2006-01-02"), AntarUntil: antar.end.Format("2006-01-02"),
	}
}

// sadeSatiPhase mirrors SadeSatiService.getPhaseForDate: Saturn in the 12th,
// 1st or 2nd sign from the natal Moon.
func sadeSatiPhase(saturnSign, moonSign int) string {
	switch saturnSign {
	case (moonSign + 11) % 12:
		return "rising"
	case moonSign:
		return "peak"
	case (moonSign + 1) % 12:
		return "setting"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Yogas (ports of YogaCalculator.find*; names as PresenterSlots.beneficYogas)
// ---------------------------------------------------------------------------

var (
	yogaKendras  = map[int]bool{1: true, 4: true, 7: true, 10: true}
	yogaTrikonas = map[int]bool{1: true, 5: true, 9: true}
	// YogaCalculator.planetRulership / exaltationSigns (sign indices).
	yogaRulership = map[string][]int{
		"sun": {4}, "moon": {3}, "mars": {0, 7}, "mercury": {2, 5},
		"jupiter": {8, 11}, "venus": {1, 6}, "saturn": {9, 10},
	}
	yogaExaltation = map[string]int{
		"sun": 0, "moon": 1, "mars": 9, "mercury": 5, "jupiter": 3, "venus": 11, "saturn": 6,
	}
	// Mahapurusha yogas in calculateAllYogas order.
	yogaMahapurusha = []struct{ planet, name string }{
		{"jupiter", "Hamsa Yoga"}, {"venus", "Malavya Yoga"}, {"mars", "Ruchaka Yoga"},
		{"mercury", "Bhadra Yoga"}, {"saturn", "Sasha Yoga"},
	}
)

func yogaOwnSign(planet string, sign int) bool {
	for _, s := range yogaRulership[planet] {
		if s == sign {
			return true
		}
	}
	return false
}

func yogaExalted(planet string, sign int) bool {
	s, ok := yogaExaltation[planet]
	return ok && s == sign
}

// yogaRelPos is YogaCalculator.getRelativePosition (1 = same house).
func yogaRelPos(from, to int) int {
	d := to - from + 1
	if d <= 0 {
		d += 12
	}
	return d
}

// chartFactsYogas returns the found yogas in calculateAllYogas order.
func chartFactsYogas(b map[string]natalBody) []string {
	out := []string{}
	moon := b["moon"]

	// findGajaKesariYoga: Jupiter in a kendra OR trikona from the Moon.
	if rel := yogaRelPos(moon.house, b["jupiter"].house); yogaKendras[rel] || yogaTrikonas[rel] {
		out = append(out, "Gaja Kesari Yoga")
	}
	// findBudhadityaYoga: Sun and Mercury in the same house.
	if b["sun"].house == b["mercury"].house {
		out = append(out, "Budhaditya Raja Yoga")
	}
	// find{Hamsa,Malavya,Ruchaka,Bhadra,Sasha}Yoga: kendra from the lagna and
	// own sign or exalted.
	for _, m := range yogaMahapurusha {
		p := b[m.planet]
		if yogaKendras[p.house] && (yogaOwnSign(m.planet, p.sign) || yogaExalted(m.planet, p.sign)) {
			out = append(out, m.name)
		}
	}
	// findAdhiYoga: any of Jupiter, Venus, Mercury 6th/7th/8th from the Moon.
	for _, p := range []string{"jupiter", "venus", "mercury"} {
		if rel := yogaRelPos(moon.house, b[p].house); rel >= 6 && rel <= 8 {
			out = append(out, "Adhi Yoga")
			break
		}
	}
	// findChandraMangalaYoga: Moon and Mars in the same house.
	if moon.house == b["mars"].house {
		out = append(out, "Chandra Mangala Yoga")
	}
	// findParivartanaYoga: two of the seven planets in each other's signs
	// (nodes skipped).
	seven := []string{"sun", "moon", "mercury", "venus", "mars", "jupiter", "saturn"}
exchange:
	for i, p1 := range seven {
		for _, p2 := range seven[i+1:] {
			if yogaOwnSign(p1, b[p2].sign) && yogaOwnSign(p2, b[p1].sign) {
				out = append(out, "Parivartana Yoga")
				break exchange
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

type chartFactsRequest struct {
	Date      string `json:"date"`
	Time      string `json:"time"`
	Timezone  string `json:"timezone"`
	Longitude string `json:"longitude"`
	Latitude  string `json:"latitude"`
	Lang      string `json:"lang"` // optional; facts are language-neutral, validated for the playlist builder
	At        string `json:"at"`   // optional "YYYY-MM-DD", default today UTC
}

// chartFactsService holds the site limiter state and the astrolog hooks;
// tests swap astrolog/sky/now for fakes.
type chartFactsService struct {
	mu       sync.Mutex // makes check-all-then-record atomic across windows
	ipHour   *slidingWindow
	ipDay    *slidingWindow
	astrolog func(args []string) ([]byte, error)
	sky      func(date time.Time) (map[string]float64, error)
	now      func() time.Time
}

func newChartFactsService() *chartFactsService {
	return &chartFactsService{
		ipHour:   newSlidingWindow(chartFactsPerIPHourLimit, time.Hour),
		ipDay:    newSlidingWindow(chartFactsPerIPDayLimit, 24*time.Hour),
		astrolog: runAstrolog,
		sky:      siderealLongitudes,
		now:      time.Now,
	}
}

var chartFactsSvc = newChartFactsService()

func chartFactsJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("chart-facts: write response: %v", err)
	}
}

func chartFactsError(w http.ResponseWriter, status int, msg string) {
	chartFactsJSON(w, status, map[string]string{"error": msg})
}

// handle serves POST /api/chart-facts. With an Authorization header the
// request goes through jwtAuthMiddleware (an invalid token is a 401, never a
// fallback to the site path); without one it is a site request.
func (s *chartFactsService) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		jwtAuthMiddleware(s.handleApp)(w, r)
		return
	}
	s.handleSite(w, r)
}

func (s *chartFactsService) handleApp(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		chartFactsError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if !ipLimiter.GetLimiter(getClientIP(r)).Allow() {
		chartFactsError(w, http.StatusTooManyRequests, "Too many requests from your network. Please wait.")
		return
	}
	if !deviceLimiter.GetLimiter(claims.DeviceID).Allow() {
		chartFactsError(w, http.StatusTooManyRequests, "Rate limit exceeded. Please try again.")
		return
	}
	var req chartFactsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, chartFactsMaxBody)).Decode(&req); err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	if s.serve(w, &req, "device="+claims.DeviceID) {
		logAPICall(claims.DeviceID, "astrolog", "chart_facts")
	}
}

func (s *chartFactsService) handleSite(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	ipHash := webChatIPHash(ip)
	if !webChatAllowedOrigins[r.Header.Get("Origin")] {
		log.Printf("chart-facts: reject status=403 reason=origin ip_hash=%s", ipHash)
		chartFactsError(w, http.StatusForbidden, "origin")
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		chartFactsError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, chartFactsMaxBody))
	if err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	var req chartFactsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	if !ipLimiter.GetLimiter(ip).Allow() {
		chartFactsError(w, http.StatusTooManyRequests, "Too many requests from your network. Please wait.")
		return
	}
	if wait := s.allow(s.now(), ip); wait > 0 {
		secs := int(math.Ceil(wait.Seconds()))
		if secs < 1 {
			secs = 1
		}
		log.Printf("chart-facts: reject status=429 reason=ip_limit ip_hash=%s retry_after=%d", ipHash, secs)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		chartFactsJSON(w, http.StatusTooManyRequests, map[string]interface{}{"error": "rate", "retry_after": secs})
		return
	}
	s.serve(w, &req, "ip_hash="+ipHash)
}

// allow records one site request for ip if both windows have room, else
// returns the longest wait.
func (s *chartFactsService) allow(now time.Time, ip string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	longest := s.ipHour.wait(ip, now)
	if d := s.ipDay.wait(ip, now); d > longest {
		longest = d
	}
	if longest > 0 {
		return longest
	}
	s.ipHour.add(ip, now)
	s.ipDay.add(ip, now)
	return 0
}

// serve validates the input, runs astrolog and writes the facts. Returns
// true when a 200 was written.
func (s *chartFactsService) serve(w http.ResponseWriter, req *chartFactsRequest, who string) bool {
	date, err := sanitizeDate(req.Date)
	if err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid date: "+err.Error())
		return false
	}
	timeStr, err := sanitizeTime(req.Time)
	if err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid time: "+err.Error())
		return false
	}
	timezone, err := sanitizeTimezone(req.Timezone)
	if err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid timezone: "+err.Error())
		return false
	}
	longitude, err := sanitizeCoordinate(req.Longitude, false)
	if err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid longitude: "+err.Error())
		return false
	}
	latitude, err := sanitizeCoordinate(req.Latitude, true)
	if err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid latitude: "+err.Error())
		return false
	}
	if req.Lang != "" && !webChatLangRe.MatchString(req.Lang) {
		chartFactsError(w, http.StatusBadRequest, "Invalid lang")
		return false
	}
	birth, err := time.Parse("1 2 2006", date)
	if err != nil {
		chartFactsError(w, http.StatusBadRequest, "Invalid date: not a calendar date")
		return false
	}
	at := s.now().UTC()
	at = time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
	if req.At != "" {
		at, err = time.Parse("2006-01-02", req.At)
		if err != nil || at.Year() < 1800 || at.Year() > 2100 {
			chartFactsError(w, http.StatusBadRequest, "Invalid at: want YYYY-MM-DD")
			return false
		}
	}

	out, err := s.astrolog(astrologChartArgs(date, timeStr, timezone, longitude, latitude, false))
	if err != nil {
		log.Printf("chart-facts: astrolog natal failed %s: %v", who, err)
		chartFactsError(w, http.StatusBadGateway, "Failed to calculate chart")
		return false
	}
	bodies, err := parseNatalChart(string(out))
	if err != nil {
		log.Printf("chart-facts: parse natal failed %s: %v", who, err)
		chartFactsError(w, http.StatusBadGateway, "Failed to calculate chart")
		return false
	}
	sky, err := s.sky(at)
	if err != nil {
		log.Printf("chart-facts: sky at %s failed %s: %v", at.Format("2006-01-02"), who, err)
		chartFactsError(w, http.StatusBadGateway, "Failed to calculate chart")
		return false
	}
	facts, err := buildChartFacts(bodies, birth, at, sky)
	if err != nil {
		log.Printf("chart-facts: build failed %s: %v", who, err)
		chartFactsError(w, http.StatusBadGateway, "Failed to calculate chart")
		return false
	}
	chartFactsJSON(w, http.StatusOK, facts)
	return true
}
