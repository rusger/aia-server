package main

// Server-driven UNIVERSAL astrological event pushes (same for everyone, no
// natal chart needed): New/Full Moon, slow-planet sign ingresses, eclipses.
//
// Personalised events (birthday, power periods, dashas, natal aspects) stay
// in the app as local notifications — they need the user's chart.
//
// Pipeline:
//   refreshPushEvents()  — computes upcoming events, upserts into push_events.
//   pushEventLoop()      — every 15 min delivers events whose per-device local
//                          delivery time has arrived (timezone-aware), once per
//                          (event, device) via push_event_deliveries.
//
// Moon phases + eclipses are computed in pure Go (ported from the app so the
// numbers match what users see). Ingresses use the ./astrolog binary (sidereal
// positions) via runAstrolog().

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ===========================================================================
// Schema
// ===========================================================================

func migratePushEvents() {
	// Per-device language + timezone (sent by the app when it registers its
	// push token). Needed to localise text and deliver at local morning.
	for _, stmt := range []string{
		`ALTER TABLE devices ADD COLUMN language TEXT`,
		`ALTER TABLE devices ADD COLUMN tz_offset_minutes INTEGER`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("ℹ️ devices migration note: %v", err)
		}
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS push_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ekey TEXT UNIQUE NOT NULL,      -- stable id, dedupes recompute
			kind TEXT NOT NULL,             -- lunar_new|lunar_full|slow_ingress|eclipse_solar|eclipse_lunar
			event_date DATETIME NOT NULL,   -- UTC instant of the actual event
			lead_days INTEGER NOT NULL DEFAULT 1,
			local_hour INTEGER NOT NULL DEFAULT 10,
			params TEXT,                    -- JSON: planet/sign/etc.
			payload TEXT,                   -- deep-link for the app tap handler
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		log.Printf("⚠️ push_events table: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS push_event_deliveries (
			event_id INTEGER NOT NULL,
			device_id TEXT NOT NULL,
			sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (event_id, device_id)
		);`); err != nil {
		log.Printf("⚠️ push_event_deliveries table: %v", err)
	}
}

// ===========================================================================
// Moon phase (ported from app MoonPhaseService — same simple synodic method)
// ===========================================================================

func julianDay(t time.Time) float64 {
	t = t.UTC()
	y, mo, d := t.Year(), int(t.Month()), t.Day()
	a := int(math.Floor(float64(14-mo) / 12.0))
	yy := y + 4800 - a
	m := mo + 12*a - 3
	jdn := d + (153*m+2)/5 + 365*yy + yy/4 - yy/100 + yy/400 - 32045
	return float64(jdn) + (float64(t.Hour())-12)/24.0 + float64(t.Minute())/1440.0 + float64(t.Second())/86400.0
}

func sinDeg(deg float64) float64 { return math.Sin(deg * math.Pi / 180.0) }

// moonPhase returns 0..1 (0/1 = new moon, 0.5 = full moon).
func moonPhase(jd float64) float64 {
	d := jd - 2451545.0
	L := math.Mod(218.316+13.176396*d, 360)
	M := math.Mod(134.963+13.064993*d, 360)
	Ls := math.Mod(280.466+0.9856474*d, 360)
	lambda := L + 6.289*sinDeg(M)
	D := math.Mod(lambda-Ls, 360)
	if D < 0 {
		D += 360
	}
	return D / 360.0
}

// findNextPhase finds the next New (target 0.0) or Full (0.5) moon after start.
func findNextPhase(start time.Time, target float64) time.Time {
	start = start.UTC()
	prev := moonPhase(julianDay(start))
	for day := 1; day <= 60; day++ {
		cur := start.AddDate(0, 0, day)
		ph := moonPhase(julianDay(cur))
		crossed := false
		if target == 0.0 {
			crossed = prev > 0.9 && ph < 0.1
		} else {
			crossed = prev < target && ph >= target
		}
		if crossed {
			return refinePhase(cur.AddDate(0, 0, -1), target)
		}
		prev = ph
	}
	return time.Time{}
}

func refinePhase(approx time.Time, target float64) time.Time {
	best := approx
	bestDiff := math.Inf(1)
	for h := 0; h < 48; h++ {
		tt := approx.Add(time.Duration(h) * time.Hour)
		ph := moonPhase(julianDay(tt))
		var diff float64
		if target == 0.0 {
			diff = math.Min(math.Abs(ph-target), math.Abs(ph-1.0))
		} else {
			diff = math.Abs(ph - target)
		}
		if diff < bestDiff {
			bestDiff = diff
			best = tt
		}
	}
	return best
}

// ===========================================================================
// Slow-planet ingresses (sidereal sign changes) via ./astrolog
// ===========================================================================

var signAbbr = []string{"Ari", "Tau", "Gem", "Can", "Leo", "Vir", "Lib", "Sco", "Sag", "Cap", "Aqu", "Pis"}
var signAbbrIndex = func() map[string]int {
	m := map[string]int{}
	for i, s := range signAbbr {
		m[s] = i
	}
	return m
}()

var posRe = regexp.MustCompile(`(\d{1,2})([A-Za-z]{3})(\d{2})`)

// siderealLongitudes returns planet -> ecliptic longitude (0..360, sidereal)
// at the given date (noon UTC, geocentric so location is irrelevant).
// Planet keys use the app's names: Jupiter, Saturn, Rahu, Ketu, Sun, Moon.
func siderealLongitudes(date time.Time) (map[string]float64, error) {
	date = date.UTC()
	args := []string{
		"-qa",
		strconv.Itoa(int(date.Month())), strconv.Itoa(date.Day()), strconv.Itoa(date.Year()),
		"12:00", "0", "0", "0",
		"-s", "0.883208", "-R", "8", "9", "10", "-c", "14", "-C", "-RC", "22", "31",
	}
	out, err := runAstrolog(args)
	if err != nil {
		return nil, err
	}
	// Map astrolog row prefixes -> our planet names.
	prefix := map[string]string{
		"Jupi": "Jupiter", "Satu": "Saturn", "Nort": "Rahu",
		"Sun ": "Sun", "Moon": "Moon",
	}
	res := map[string]float64{}
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 4 {
			continue
		}
		name, ok := prefix[line[:4]]
		if !ok {
			continue
		}
		m := posRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		deg, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[3])
		idx, ok := signAbbrIndex[m[2]]
		if !ok {
			continue
		}
		res[name] = float64(idx)*30 + float64(deg) + float64(min)/60.0
	}
	if r, ok := res["Rahu"]; ok {
		res["Ketu"] = math.Mod(r+180, 360) // Ketu is always opposite Rahu
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no positions parsed from astrolog output")
	}
	return res, nil
}

func signOf(lon float64) int { return int(math.Floor(lon/30.0)) % 12 }

type ingressEvt struct {
	planet  string
	signIdx int
	date    time.Time
}

// findIngresses scans [from, to] for slow-planet sidereal sign changes,
// bisecting each to ~1-day precision.
func findIngresses(from, to time.Time) []ingressEvt {
	planets := []string{"Jupiter", "Saturn", "Rahu", "Ketu"}
	step := 10 * 24 * time.Hour

	prev, err := siderealLongitudes(from)
	if err != nil {
		log.Printf("⚠️ ingress scan start failed: %v", err)
		return nil
	}
	prevSign := map[string]int{}
	for _, p := range planets {
		if l, ok := prev[p]; ok {
			prevSign[p] = signOf(l)
		}
	}

	var out []ingressEvt
	for t := from.Add(step); t.Before(to); t = t.Add(step) {
		cur, err := siderealLongitudes(t)
		if err != nil {
			continue
		}
		for _, p := range planets {
			cl, ok := cur[p]
			if !ok {
				continue
			}
			ns := signOf(cl)
			os, had := prevSign[p]
			if had && ns != os {
				// Sign changed between t-step and t — bisect for the day.
				d := bisectIngress(p, os, t.Add(-step), t)
				if !d.IsZero() {
					out = append(out, ingressEvt{planet: p, signIdx: ns, date: d})
				}
			}
			prevSign[p] = ns
		}
	}
	return out
}

// bisectIngress finds the first day on which planet is no longer in oldSign.
func bisectIngress(planet string, oldSign int, lo, hi time.Time) time.Time {
	for i := 0; i < 8 && hi.Sub(lo) > 24*time.Hour; i++ {
		mid := lo.Add(hi.Sub(lo) / 2)
		l, err := siderealLongitudes(mid)
		if err != nil {
			return time.Time{}
		}
		cl, ok := l[planet]
		if !ok {
			return time.Time{}
		}
		if signOf(cl) == oldSign {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi
}

// ===========================================================================
// Eclipses (ported from app EclipseService — NASA data)
// ===========================================================================

type eclipseRec struct {
	date  time.Time
	solar bool
}

var eclipses = []eclipseRec{
	// Lunar
	{time.Date(2026, 3, 3, 11, 33, 0, 0, time.UTC), false},
	{time.Date(2026, 8, 28, 4, 13, 0, 0, time.UTC), false},
	{time.Date(2027, 2, 20, 23, 13, 0, 0, time.UTC), false},
	{time.Date(2027, 7, 18, 16, 3, 0, 0, time.UTC), false},
	{time.Date(2027, 8, 17, 7, 13, 0, 0, time.UTC), false},
	{time.Date(2028, 1, 12, 4, 13, 0, 0, time.UTC), false},
	{time.Date(2028, 7, 6, 18, 20, 0, 0, time.UTC), false},
	{time.Date(2028, 12, 31, 16, 52, 0, 0, time.UTC), false},
	{time.Date(2029, 6, 26, 3, 22, 0, 0, time.UTC), false},
	{time.Date(2029, 12, 20, 22, 43, 0, 0, time.UTC), false},
	{time.Date(2030, 6, 15, 18, 23, 0, 0, time.UTC), false},
	// Solar
	{time.Date(2026, 2, 17, 12, 13, 0, 0, time.UTC), true},
	{time.Date(2026, 8, 12, 17, 47, 0, 0, time.UTC), true},
	{time.Date(2027, 2, 6, 16, 0, 0, 0, time.UTC), true},
	{time.Date(2027, 8, 2, 10, 7, 0, 0, time.UTC), true},
	{time.Date(2028, 1, 26, 15, 8, 0, 0, time.UTC), true},
	{time.Date(2028, 7, 22, 2, 57, 0, 0, time.UTC), true},
	{time.Date(2028, 12, 16, 0, 56, 0, 0, time.UTC), true},
	{time.Date(2029, 1, 14, 17, 13, 0, 0, time.UTC), true},
	{time.Date(2029, 6, 12, 4, 6, 0, 0, time.UTC), true},
	{time.Date(2029, 7, 11, 15, 37, 0, 0, time.UTC), true},
	{time.Date(2029, 12, 5, 15, 3, 0, 0, time.UTC), true},
	{time.Date(2030, 6, 1, 6, 29, 0, 0, time.UTC), true},
	{time.Date(2030, 11, 25, 6, 51, 0, 0, time.UTC), true},
}

// ===========================================================================
// Refresh: compute upcoming events and upsert into push_events
// ===========================================================================

func refreshPushEvents() {
	now := time.Now().UTC()

	insert := func(ekey, kind string, eventDate time.Time, params map[string]interface{}, payload string) {
		pj, _ := json.Marshal(params)
		_, err := db.Exec(`INSERT OR IGNORE INTO push_events
			(ekey, kind, event_date, lead_days, local_hour, params, payload)
			VALUES (?, ?, ?, 1, 10, ?, ?)`,
			ekey, kind, eventDate.UTC(), string(pj), payload)
		if err != nil {
			log.Printf("⚠️ push_events insert %s: %v", ekey, err)
		}
	}

	// Moon phases — next ~150 days.
	moonHorizon := now.AddDate(0, 0, 150)
	for _, mp := range []struct {
		target float64
		isNew  bool
	}{{0.0, true}, {0.5, false}} {
		cursor := now
		for i := 0; i < 6; i++ {
			d := findNextPhase(cursor, mp.target)
			if d.IsZero() || d.After(moonHorizon) {
				break
			}
			kind := "lunar_full"
			if mp.isNew {
				kind = "lunar_new"
			}
			day := d.Format("2006-01-02")
			ekey := kind + ":" + day
			payload := fmt.Sprintf("astro:lunar_phase:lunar_phase:%s:%s", map[bool]string{true: "new", false: "full"}[mp.isNew], day)
			insert(ekey, kind, d, map[string]interface{}{"isNew": mp.isNew}, payload)
			cursor = d.AddDate(0, 0, 1)
		}
	}

	// Eclipses — next ~150 days.
	eclipseHorizon := now.AddDate(0, 0, 150)
	for _, e := range eclipses {
		if e.date.After(now) && e.date.Before(eclipseHorizon) {
			kind := "eclipse_lunar"
			tag := "lunar"
			if e.solar {
				kind = "eclipse_solar"
				tag = "solar"
			}
			day := e.date.Format("2006-01-02")
			ekey := kind + ":" + day
			payload := fmt.Sprintf("astro:eclipse:eclipse:%s:%s", tag, day)
			insert(ekey, kind, e.date, map[string]interface{}{"solar": e.solar}, payload)
		}
	}

	// Slow ingresses — next ~400 days (rare events; one scan covers a year+).
	for _, ig := range findIngresses(now, now.AddDate(0, 0, 400)) {
		day := ig.date.Format("2006-01-02")
		ekey := fmt.Sprintf("slow_ingress:%s:%s", ig.planet, day)
		payload := fmt.Sprintf("astro:slow_ingress:slow_ingress:%s:%s", ig.planet, day)
		insert(ekey, "slow_ingress", ig.date,
			map[string]interface{}{"planet": ig.planet, "signIdx": ig.signIdx}, payload)
	}

	log.Printf("✓ refreshPushEvents done")
}

// ===========================================================================
// Delivery: timezone-aware, once per (event, device)
// ===========================================================================

func deliverDueEvents() {
	now := time.Now().UTC()

	// Only events whose delivery window (≈ nominal day across all timezones)
	// is around now: event within [now-1d, now+2d].
	rows, err := db.Query(`SELECT id, kind, event_date, lead_days, local_hour, params, payload
		FROM push_events WHERE event_date >= ? AND event_date <= ?`,
		now.AddDate(0, 0, -1), now.AddDate(0, 0, 2))
	if err != nil {
		log.Printf("⚠️ deliverDueEvents query: %v", err)
		return
	}
	type ev struct {
		id                  int64
		kind, params, payld string
		eventDate           time.Time
		leadDays, localHour int
	}
	var evs []ev
	for rows.Next() {
		var e ev
		var params, payld sql.NullString
		if err := rows.Scan(&e.id, &e.kind, &e.eventDate, &e.leadDays, &e.localHour, &params, &payld); err != nil {
			continue
		}
		e.params = params.String
		e.payld = payld.String
		evs = append(evs, e)
	}
	rows.Close()
	if len(evs) == 0 {
		return
	}

	// All deliverable devices (iOS with a token).
	drows, err := db.Query(`SELECT device_id, push_token, COALESCE(language,'en'), COALESCE(tz_offset_minutes,0)
		FROM devices WHERE push_token IS NOT NULL AND push_token != '' AND revoked = 0
		AND (platform = 'iOS' OR platform IS NULL OR platform = '')`)
	if err != nil {
		log.Printf("⚠️ deliverDueEvents devices: %v", err)
		return
	}
	type dev struct {
		id, token, lang string
		tzMin           int
	}
	var devs []dev
	for drows.Next() {
		var d dev
		if err := drows.Scan(&d.id, &d.token, &d.lang, &d.tzMin); err == nil {
			devs = append(devs, d)
		}
	}
	drows.Close()

	for _, e := range evs {
		// Nominal local target = (event date - lead) at local_hour, wall-clock.
		nominal := time.Date(e.eventDate.Year(), e.eventDate.Month(), e.eventDate.Day(),
			e.localHour, 0, 0, 0, time.UTC).AddDate(0, 0, -e.leadDays)
		for _, d := range devs {
			// Device reaches that wall-clock at UTC = nominal - offset.
			deliverUTC := nominal.Add(-time.Duration(d.tzMin) * time.Minute)
			if now.Before(deliverUTC) || now.After(deliverUTC.Add(24*time.Hour)) {
				continue
			}
			// Claim (event, device) atomically; skip if already delivered.
			res, err := db.Exec(`INSERT OR IGNORE INTO push_event_deliveries (event_id, device_id) VALUES (?, ?)`, e.id, d.id)
			if err != nil {
				continue
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue // already sent
			}
			title, body := eventText(e.kind, e.params, d.lang)
			if err := sendAPNs(d.token, title, body, e.payld); err != nil {
				log.Printf("⚠️ event push to %s failed: %v", d.id, err)
				// Roll back the claim so a later tick can retry.
				db.Exec(`DELETE FROM push_event_deliveries WHERE event_id = ? AND device_id = ?`, e.id, d.id)
			}
		}
	}
}

func pushEventLoop() {
	// Initial compute, then refresh daily and deliver every 15 min.
	refreshPushEvents()
	refreshTick := time.NewTicker(24 * time.Hour)
	deliverTick := time.NewTicker(15 * time.Minute)
	deliverDueEvents()
	for {
		select {
		case <-refreshTick.C:
			refreshPushEvents()
		case <-deliverTick.C:
			deliverDueEvents()
		}
	}
}

// ===========================================================================
// Localised text (planet/sign names ported from the app; phrases standard)
// ===========================================================================

func eventText(kind, paramsJSON, lang string) (string, string) {
	var p map[string]interface{}
	_ = json.Unmarshal([]byte(paramsJSON), &p)

	switch kind {
	case "lunar_new":
		return tr(lunarNewTitle, lang), tr(lunarNewBody, lang)
	case "lunar_full":
		return tr(lunarFullTitle, lang), tr(lunarFullBody, lang)
	case "eclipse_solar":
		return tr(solarEclipseTitle, lang), tr(solarEclipseBody, lang)
	case "eclipse_lunar":
		return tr(lunarEclipseTitle, lang), tr(lunarEclipseBody, lang)
	case "slow_ingress":
		planet, _ := p["planet"].(string)
		signIdx := 0
		if f, ok := p["signIdx"].(float64); ok {
			signIdx = int(f)
		}
		pn := planetName(planet, lang)
		sn := signName(signIdx, lang)
		return fmt.Sprintf(tr(ingressTitleTmpl, lang), pn, sn),
			fmt.Sprintf(tr(ingressBodyTmpl, lang), pn, sn)
	}
	return "Astrolytix", ""
}

func tr(m map[string]string, lang string) string {
	if v, ok := m[lang]; ok {
		return v
	}
	return m["en"]
}

func planetName(planet, lang string) string {
	if m, ok := planetNames[planet]; ok {
		if v, ok := m[lang]; ok {
			return v
		}
		return m["en"]
	}
	return planet
}

func signName(idx int, lang string) string {
	if idx < 0 || idx >= len(signNames) {
		return ""
	}
	m := signNames[idx]
	if v, ok := m[lang]; ok {
		return v
	}
	return m["en"]
}

var lunarNewTitle = map[string]string{
	"en": "New Moon 🌑", "ru": "Новолуние 🌑", "es": "Luna Nueva 🌑", "fr": "Nouvelle Lune 🌑",
	"de": "Neumond 🌑", "it": "Luna Nuova 🌑", "pt": "Lua Nova 🌑", "zh": "新月 🌑",
	"ja": "新月 🌑", "ko": "신월 🌑", "hi": "अमावस्या 🌑", "ar": "القمر الجديد 🌑",
}
var lunarNewBody = map[string]string{
	"en": "A New Moon rises today — a moment for fresh starts and intentions.",
	"ru": "Сегодня новолуние — время новых начинаний и намерений.",
	"es": "Hoy llega la Luna Nueva — momento para nuevos comienzos.",
	"fr": "Nouvelle Lune aujourd'hui — un moment pour de nouveaux départs.",
	"de": "Heute ist Neumond — Zeit für einen Neuanfang.",
	"it": "Oggi è Luna Nuova — momento per nuovi inizi.",
	"pt": "Hoje é Lua Nova — momento para novos começos.",
	"zh": "今天是新月——适合开启新的意图。",
	"ja": "今日は新月——新しい始まりの時。",
	"ko": "오늘은 신월입니다 — 새로운 시작의 순간.",
	"hi": "आज अमावस्या है — नई शुरुआत का समय।",
	"ar": "اليوم قمر جديد — وقت للبدايات الجديدة.",
}
var lunarFullTitle = map[string]string{
	"en": "Full Moon 🌕", "ru": "Полнолуние 🌕", "es": "Luna Llena 🌕", "fr": "Pleine Lune 🌕",
	"de": "Vollmond 🌕", "it": "Luna Piena 🌕", "pt": "Lua Cheia 🌕", "zh": "满月 🌕",
	"ja": "満月 🌕", "ko": "보름달 🌕", "hi": "पूर्णिमा 🌕", "ar": "اكتمال القمر 🌕",
}
var lunarFullBody = map[string]string{
	"en": "A Full Moon rises today — a time of culmination and release.",
	"ru": "Сегодня полнолуние — время кульминации и завершения.",
	"es": "Hoy llega la Luna Llena — tiempo de culminación.",
	"fr": "Pleine Lune aujourd'hui — un temps de culmination.",
	"de": "Heute ist Vollmond — Zeit der Vollendung.",
	"it": "Oggi è Luna Piena — tempo di culmine.",
	"pt": "Hoje é Lua Cheia — tempo de culminação.",
	"zh": "今天是满月——圆满与释放的时刻。",
	"ja": "今日は満月——結実と解放の時。",
	"ko": "오늘은 보름달입니다 — 절정과 비움의 시간.",
	"hi": "आज पूर्णिमा है — पूर्णता और मुक्ति का समय।",
	"ar": "اليوم اكتمال القمر — وقت الذروة والتحرر.",
}
var solarEclipseTitle = map[string]string{
	"en": "Solar Eclipse ☀️", "ru": "Солнечное затмение ☀️", "es": "Eclipse Solar ☀️", "fr": "Éclipse Solaire ☀️",
	"de": "Sonnenfinsternis ☀️", "it": "Eclissi Solare ☀️", "pt": "Eclipse Solar ☀️", "zh": "日食 ☀️",
	"ja": "日食 ☀️", "ko": "일식 ☀️", "hi": "सूर्य ग्रहण ☀️", "ar": "كسوف الشمس ☀️",
}
var solarEclipseBody = map[string]string{
	"en": "A Solar Eclipse occurs around now — a powerful window for new beginnings.",
	"ru": "Сейчас солнечное затмение — мощное окно для новых начал.",
	"es": "Ocurre un Eclipse Solar — una ventana poderosa para empezar de nuevo.",
	"fr": "Une Éclipse Solaire se produit — une fenêtre puissante de renouveau.",
	"de": "Eine Sonnenfinsternis findet statt — ein kraftvolles Fenster für Neuanfänge.",
	"it": "Avviene un'Eclissi Solare — una finestra potente per ricominciare.",
	"pt": "Ocorre um Eclipse Solar — uma janela poderosa para recomeços.",
	"zh": "日食临近——开启新篇章的有力时机。",
	"ja": "日食の頃です——新たな始まりの強力な節目。",
	"ko": "일식이 일어납니다 — 새로운 시작의 강력한 시기.",
	"hi": "सूर्य ग्रहण हो रहा है — नई शुरुआत का शक्तिशाली अवसर।",
	"ar": "يحدث كسوف للشمس — نافذة قوية للبدايات الجديدة.",
}
var lunarEclipseTitle = map[string]string{
	"en": "Lunar Eclipse 🌙", "ru": "Лунное затмение 🌙", "es": "Eclipse Lunar 🌙", "fr": "Éclipse Lunaire 🌙",
	"de": "Mondfinsternis 🌙", "it": "Eclissi Lunare 🌙", "pt": "Eclipse Lunar 🌙", "zh": "月食 🌙",
	"ja": "月食 🌙", "ko": "월식 🌙", "hi": "चंद्र ग्रहण 🌙", "ar": "خسوف القمر 🌙",
}
var lunarEclipseBody = map[string]string{
	"en": "A Lunar Eclipse occurs around now — a time of culmination and release.",
	"ru": "Сейчас лунное затмение — время кульминации и завершения.",
	"es": "Ocurre un Eclipse Lunar — tiempo de culminación y liberación.",
	"fr": "Une Éclipse Lunaire se produit — un temps de culmination.",
	"de": "Eine Mondfinsternis findet statt — Zeit der Vollendung.",
	"it": "Avviene un'Eclissi Lunare — tempo di culmine e rilascio.",
	"pt": "Ocorre um Eclipse Lunar — tempo de culminação.",
	"zh": "月食临近——圆满与释放的时刻。",
	"ja": "月食の頃です——結実と解放の時。",
	"ko": "월식이 일어납니다 — 절정과 비움의 시간.",
	"hi": "चंद्र ग्रहण हो रहा है — पूर्णता और मुक्ति का समय।",
	"ar": "يحدث خسوف للقمر — وقت الذروة والتحرر.",
}
var ingressTitleTmpl = map[string]string{
	"en": "%s enters %s", "ru": "%s переходит в %s", "es": "%s entra en %s", "fr": "%s entre en %s",
	"de": "%s tritt in %s ein", "it": "%s entra in %s", "pt": "%s entra em %s", "zh": "%s 进入 %s",
	"ja": "%s が %s に入る", "ko": "%s, %s 입성", "hi": "%s का %s में प्रवेश", "ar": "%s يدخل %s",
}
var ingressBodyTmpl = map[string]string{
	"en": "%s moves into %s — a slow, long-lasting shift in its themes.",
	"ru": "%s входит в знак %s — медленный, долгий сдвиг в его темах.",
	"es": "%s entra en %s — un cambio lento y duradero en sus temas.",
	"fr": "%s entre en %s — un changement lent et durable.",
	"de": "%s wechselt in %s — eine langsame, lang anhaltende Verschiebung.",
	"it": "%s entra in %s — un cambiamento lento e duraturo.",
	"pt": "%s entra em %s — uma mudança lenta e duradoura.",
	"zh": "%s 进入 %s——主题上缓慢而持久的转变。",
	"ja": "%s が %s へ——ゆっくりと長く続く変化。",
	"ko": "%s가 %s로 이동 — 느리고 오래 지속되는 변화.",
	"hi": "%s %s में प्रवेश करता है — धीमा, दीर्घकालिक बदलाव।",
	"ar": "%s ينتقل إلى %s — تحول بطيء وطويل الأمد.",
}

var planetNames = map[string]map[string]string{
	"Sun":     {"en": "Sun", "es": "Sol", "fr": "Soleil", "de": "Sonne", "it": "Sole", "pt": "Sol", "ru": "Солнце", "zh": "太阳", "ja": "太陽", "ko": "태양", "hi": "सूर्य", "ar": "الشمس"},
	"Moon":    {"en": "Moon", "es": "Luna", "fr": "Lune", "de": "Mond", "it": "Luna", "pt": "Lua", "ru": "Луна", "zh": "月亮", "ja": "月", "ko": "달", "hi": "चंद्रमा", "ar": "القمر"},
	"Jupiter": {"en": "Jupiter", "es": "Júpiter", "fr": "Jupiter", "de": "Jupiter", "it": "Giove", "pt": "Júpiter", "ru": "Юпитер", "zh": "木星", "ja": "木星", "ko": "목성", "hi": "बृहस्पति", "ar": "المشتري"},
	"Saturn":  {"en": "Saturn", "es": "Saturno", "fr": "Saturne", "de": "Saturn", "it": "Saturno", "pt": "Saturno", "ru": "Сатурн", "zh": "土星", "ja": "土星", "ko": "토성", "hi": "शनि", "ar": "زحل"},
	"Rahu":    {"en": "Rahu", "es": "Rahu", "fr": "Rahu", "de": "Rahu", "it": "Rahu", "pt": "Rahu", "ru": "Раху", "zh": "罗睺", "ja": "ラーフ", "ko": "라후", "hi": "राहु", "ar": "راهو"},
	"Ketu":    {"en": "Ketu", "es": "Ketu", "fr": "Ketu", "de": "Ketu", "it": "Ketu", "pt": "Ketu", "ru": "Кету", "zh": "计都", "ja": "ケートゥ", "ko": "케투", "hi": "केतु", "ar": "كيتو"},
}

var signNames = []map[string]string{
	{"en": "Aries", "es": "Aries", "fr": "Bélier", "de": "Widder", "it": "Ariete", "pt": "Áries", "ru": "Овен", "zh": "白羊座", "ja": "牡羊座", "ko": "양자리", "hi": "मेष", "ar": "الحمل"},
	{"en": "Taurus", "es": "Tauro", "fr": "Taureau", "de": "Stier", "it": "Toro", "pt": "Touro", "ru": "Телец", "zh": "金牛座", "ja": "牡牛座", "ko": "황소자리", "hi": "वृषभ", "ar": "الثور"},
	{"en": "Gemini", "es": "Géminis", "fr": "Gémeaux", "de": "Zwillinge", "it": "Gemelli", "pt": "Gêmeos", "ru": "Близнецы", "zh": "双子座", "ja": "双子座", "ko": "쌍둥이자리", "hi": "मिथुन", "ar": "الجوزاء"},
	{"en": "Cancer", "es": "Cáncer", "fr": "Cancer", "de": "Krebs", "it": "Cancro", "pt": "Câncer", "ru": "Рак", "zh": "巨蟹座", "ja": "蟹座", "ko": "게자리", "hi": "कर्क", "ar": "السرطان"},
	{"en": "Leo", "es": "Leo", "fr": "Lion", "de": "Löwe", "it": "Leone", "pt": "Leão", "ru": "Лев", "zh": "狮子座", "ja": "獅子座", "ko": "사자자리", "hi": "सिंह", "ar": "الأسد"},
	{"en": "Virgo", "es": "Virgo", "fr": "Vierge", "de": "Jungfrau", "it": "Vergine", "pt": "Virgem", "ru": "Дева", "zh": "处女座", "ja": "乙女座", "ko": "처녀자리", "hi": "कन्या", "ar": "العذراء"},
	{"en": "Libra", "es": "Libra", "fr": "Balance", "de": "Waage", "it": "Bilancia", "pt": "Libra", "ru": "Весы", "zh": "天秤座", "ja": "天秤座", "ko": "천칭자리", "hi": "तुला", "ar": "الميزان"},
	{"en": "Scorpio", "es": "Escorpio", "fr": "Scorpion", "de": "Skorpion", "it": "Scorpione", "pt": "Escorpião", "ru": "Скорпион", "zh": "天蝎座", "ja": "蠍座", "ko": "전갈자리", "hi": "वृश्चिक", "ar": "العقرب"},
	{"en": "Sagittarius", "es": "Sagitario", "fr": "Sagittaire", "de": "Schütze", "it": "Sagittario", "pt": "Sagitário", "ru": "Стрелец", "zh": "射手座", "ja": "射手座", "ko": "궁수자리", "hi": "धनु", "ar": "القوس"},
	{"en": "Capricorn", "es": "Capricornio", "fr": "Capricorne", "de": "Steinbock", "it": "Capricorno", "pt": "Capricórnio", "ru": "Козерог", "zh": "摩羯座", "ja": "山羊座", "ko": "염소자리", "hi": "मकर", "ar": "الجدي"},
	{"en": "Aquarius", "es": "Acuario", "fr": "Verseau", "de": "Wassermann", "it": "Acquario", "pt": "Aquário", "ru": "Водолей", "zh": "水瓶座", "ja": "水瓶座", "ko": "물병자리", "hi": "कुंभ", "ar": "الدلو"},
	{"en": "Pisces", "es": "Piscis", "fr": "Poissons", "de": "Fische", "it": "Pesci", "pt": "Peixes", "ru": "Рыбы", "zh": "双鱼座", "ja": "魚座", "ko": "물고기자리", "hi": "मीन", "ar": "الحوت"},
}
