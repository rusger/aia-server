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
		// Comma-separated event groups the user muted in the app's
		// notification settings: lunar,eclipse,ingress,station.
		`ALTER TABLE devices ADD COLUMN disabled_push_kinds TEXT`,
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
// Planet keys use the app's names: Jupiter, Saturn, Rahu, Ketu, Sun, Moon,
// Mercury, Venus, Mars.
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
		"Merc": "Mercury", "Venu": "Venus", "Mars": "Mars",
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

type stationEvt struct {
	planet string
	retro  bool // true = turns retrograde, false = turns direct
	date   time.Time
}

// findStations scans [from, to] for planetary stations (retrograde/direct
// turns). Astrolog exposes longitudes only, so motion direction is the sign
// of the longitude difference between noon samples: a station lies where
// that sign flips. Coarse 5-day spans bracket the flip (the shortest retro
// arc, Mercury's ~21 days, spans 4+ samples), then a day-by-day scan pins
// the turn to a calendar day. The refinement is anchored to calendar days,
// not to the scan grid, so recomputing on a later date yields the same
// event day and INSERT OR IGNORE dedup holds. Rahu/Ketu (mean nodes,
// always retrograde) and the luminaries never station.
func findStations(from, to time.Time) []stationEvt {
	planets := []string{"Mercury", "Venus", "Mars", "Jupiter", "Saturn"}
	const stepDays = 5

	// Memoized noon longitudes — one astrolog exec serves all planets and
	// the day-scan refinement revisits dates.
	memo := map[string]map[string]float64{}
	lonsAt := func(t time.Time) map[string]float64 {
		k := t.Format("2006-01-02")
		if v, ok := memo[k]; ok {
			return v
		}
		v, err := siderealLongitudes(t)
		if err != nil {
			return nil
		}
		memo[k] = v
		return v
	}
	// Signed motion of planet across [t, t+days], normalized to (-180,180].
	motion := func(p string, t time.Time, days int) (float64, bool) {
		a := lonsAt(t)
		b := lonsAt(t.AddDate(0, 0, days))
		if a == nil || b == nil {
			return 0, false
		}
		la, ok1 := a[p]
		lb, ok2 := b[p]
		if !ok1 || !ok2 {
			return 0, false
		}
		return math.Mod(lb-la+540, 360) - 180, true
	}

	var out []stationEvt
	for _, p := range planets {
		prev := math.NaN()
		for t := from; !t.AddDate(0, 0, stepDays).After(to); t = t.AddDate(0, 0, stepDays) {
			d, ok := motion(p, t, stepDays)
			if !ok || d == 0 {
				continue
			}
			if !math.IsNaN(prev) && (d > 0) != (prev > 0) {
				// Direction flipped inside (t-step, t+step) — find the first
				// calendar day whose noon-to-noon motion has the new sign.
				for dt := t.AddDate(0, 0, -stepDays); dt.Before(t.AddDate(0, 0, stepDays)); dt = dt.AddDate(0, 0, 1) {
					dd, ok := motion(p, dt, 1)
					if !ok || dd == 0 {
						continue
					}
					if (dd > 0) != (prev > 0) {
						out = append(out, stationEvt{planet: p, retro: dd < 0, date: dt})
						break
					}
				}
			}
			prev = d
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

	// Stations (retrograde/direct turns) — next ~200 days. Frequent enough
	// (Mercury alone turns ~8×/year) that a shorter horizon keeps the
	// daily refresh cheap; delivery only looks a couple of days ahead.
	for _, st := range findStations(now, now.AddDate(0, 0, 200)) {
		day := st.date.Format("2006-01-02")
		dir := "direct"
		if st.retro {
			dir = "retro"
		}
		ekey := fmt.Sprintf("station:%s:%s:%s", st.planet, dir, day)
		payload := fmt.Sprintf("astro:station:station:%s:%s:%s", st.planet, dir, day)
		insert(ekey, "station", st.date,
			map[string]interface{}{"planet": st.planet, "retro": st.retro}, payload)
	}

	log.Printf("✓ refreshPushEvents done")
}

// ===========================================================================
// Delivery: timezone-aware, once per (event, device)
// ===========================================================================

// eventPushTTL bounds how long APNs/FCM may hold an astro-event push for an
// unreachable device (off / no network). "New Moon today" delivered days
// later is noise, so the message expires instead of being queued — unlike
// admin/organizational pushes, which are sent without expiry. 12h keeps
// delivery within the event's own day (sends go out at local morning).
const eventPushTTL = 12 * time.Hour

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

	// All deliverable devices with a token (iOS → APNs, Android → FCM).
	// email is needed to record sends into notification_history (the app
	// fetches that history to show server pushes in Settings → Notifications).
	drows, err := db.Query(`SELECT device_id, push_token, COALESCE(platform,''), COALESCE(language,'en'), COALESCE(tz_offset_minutes,0), COALESCE(email,''), COALESCE(disabled_push_kinds,'')
		FROM devices WHERE push_token IS NOT NULL AND push_token != '' AND revoked = 0`)
	if err != nil {
		log.Printf("⚠️ deliverDueEvents devices: %v", err)
		return
	}
	type dev struct {
		id, token, platform, lang, email, disabledKinds string
		tzMin                                           int
	}
	// One physical device can appear under several account rows (real email +
	// <device_id>@device.astrolytix.app placeholder). The delivery claim is
	// keyed by device_id so duplicates never double-send, but WHICH row wins
	// decides the history attribution — dedupe preferring the real email.
	isPlaceholder := func(email string) bool {
		return email == "" || strings.HasSuffix(email, "@device.astrolytix.app")
	}
	var devs []dev
	byDevice := map[string]int{}
	for drows.Next() {
		var d dev
		if err := drows.Scan(&d.id, &d.token, &d.platform, &d.lang, &d.tzMin, &d.email, &d.disabledKinds); err != nil {
			continue
		}
		if i, ok := byDevice[d.id]; ok {
			if isPlaceholder(devs[i].email) && !isPlaceholder(d.email) {
				devs[i] = d
			}
			continue
		}
		byDevice[d.id] = len(devs)
		devs = append(devs, d)
	}
	drows.Close()

	for _, e := range evs {
		// Nominal local target = (event date - lead) at local_hour, wall-clock.
		nominal := time.Date(e.eventDate.Year(), e.eventDate.Month(), e.eventDate.Day(),
			e.localHour, 0, 0, 0, time.UTC).AddDate(0, 0, -e.leadDays)
		group := eventKindGroup(e.kind)
		sent, failed := 0, 0
		for _, d := range devs {
			// Honor the app's per-category notification settings: skip
			// devices that muted this event group (lunar/eclipse/ingress/station).
			if d.disabledKinds != "" && kindDisabled(d.disabledKinds, group) {
				continue
			}
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
			if err := sendPushToToken(d.platform, d.token, title, body, e.payld, eventPushTTL); err != nil {
				failed++
				if isDeadPushToken(err) {
					// Token permanently invalid (app uninstalled / token rotated):
					// clear it so the device drops out of the eligible set instead
					// of failing again every 15-minute tick, and KEEP the claim —
					// retrying the same dead token can never succeed.
					log.Printf("🗑 clearing dead push token for %s (%s): %v", d.id, d.platform, err)
					db.Exec(`UPDATE devices SET push_token = '' WHERE device_id = ? AND push_token = ?`, d.id, d.token)
					continue
				}
				log.Printf("⚠️ event push to %s failed: %v", d.id, err)
				// Transient failure — roll back the claim so a later tick retries.
				db.Exec(`DELETE FROM push_event_deliveries WHERE event_id = ? AND device_id = ?`, e.id, d.id)
				continue
			}
			sent++
			// Mirror admin/CLI sends: persist to notification_history so the
			// app's Settings → Notifications → History (which merges this
			// endpoint) shows scheduled event pushes too. Without this the
			// scheduled pushes were invisible in history even when delivered.
			recordNotificationHistory(d.email, d.id, title, body, e.payld)
		}
		if sent > 0 || failed > 0 {
			log.Printf("📅 event %d (%s): sent=%d failed=%d", e.id, e.kind, sent, failed)
		}
	}
}

// eventKindGroup maps a push_events kind to the app's notification-settings
// category group (what the app sends as disabled_kinds entries).
func eventKindGroup(kind string) string {
	switch kind {
	case "lunar_new", "lunar_full":
		return "lunar"
	case "eclipse_solar", "eclipse_lunar":
		return "eclipse"
	case "slow_ingress":
		return "ingress"
	case "station":
		return "station"
	}
	return kind
}

// kindDisabled reports whether group appears in the comma-separated
// disabled_push_kinds list stored on the device row.
func kindDisabled(disabledCSV, group string) bool {
	for _, k := range strings.Split(disabledCSV, ",") {
		if strings.TrimSpace(k) == group {
			return true
		}
	}
	return false
}

// isDeadPushToken reports whether a push send error means the device token is
// permanently invalid (as opposed to a transient network/service failure).
// APNs: 410 Unregistered, or BadDeviceToken on BOTH environments (sendAPNs
// already retried the other host before returning). FCM: 404 UNREGISTERED.
func isDeadPushToken(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "Unregistered") || // APNs 410 / FCM "UNREGISTERED"
		strings.Contains(s, "UNREGISTERED") ||
		strings.Contains(s, "BadDeviceToken") ||
		strings.Contains(s, "DeviceTokenNotForTopic")
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
	case "station":
		planet, _ := p["planet"].(string)
		retro, _ := p["retro"].(bool)
		pn := planetName(planet, lang)
		if retro {
			return fmt.Sprintf(tr(stationRetroTitleTmpl, lang), pn),
				fmt.Sprintf(tr(stationRetroBodyTmpl, lang), pn)
		}
		return fmt.Sprintf(tr(stationDirectTitleTmpl, lang), pn),
			fmt.Sprintf(tr(stationDirectBodyTmpl, lang), pn)
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
	"mr": "अमावस्या 🌑", "te": "అమావాస్య 🌑", "ta": "அமாவாசை 🌑", "kn": "ಅಮಾವಾಸ್ಯೆ 🌑",
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
	"mr": "आज अमावस्या आहे — नव्या सुरुवातीची वेळ.",
	"te": "ఈరోజు అమావాస్య — కొత్త ఆరంభాలకు తగిన సమయం.",
	"ta": "இன்று அமாவாசை — புதிய தொடக்கங்களுக்கான நேரம்.",
	"kn": "ಇಂದು ಅಮಾವಾಸ್ಯೆ — ಹೊಸ ಆರಂಭಗಳ ಸಮಯ.",
}
var lunarFullTitle = map[string]string{
	"en": "Full Moon 🌕", "ru": "Полнолуние 🌕", "es": "Luna Llena 🌕", "fr": "Pleine Lune 🌕",
	"de": "Vollmond 🌕", "it": "Luna Piena 🌕", "pt": "Lua Cheia 🌕", "zh": "满月 🌕",
	"ja": "満月 🌕", "ko": "보름달 🌕", "hi": "पूर्णिमा 🌕", "ar": "اكتمال القمر 🌕",
	"mr": "पौर्णिमा 🌕", "te": "పౌర్ణమి 🌕", "ta": "பௌர்ணமி 🌕", "kn": "ಹುಣ್ಣಿಮೆ 🌕",
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
	"mr": "आज पौर्णिमा आहे — पूर्णत्व आणि मुक्तीची वेळ.",
	"te": "ఈరోజు పౌర్ణమి — పరిపూర్ణత మరియు విముక్తికి సమయం.",
	"ta": "இன்று பௌர்ணமி — நிறைவுக்கும் விடுதலைக்குமான நேரம்.",
	"kn": "ಇಂದು ಹುಣ್ಣಿಮೆ — ಪೂರ್ಣತೆ ಮತ್ತು ಬಿಡುಗಡೆಯ ಸಮಯ.",
}
var solarEclipseTitle = map[string]string{
	"en": "Solar Eclipse ☀️", "ru": "Солнечное затмение ☀️", "es": "Eclipse Solar ☀️", "fr": "Éclipse Solaire ☀️",
	"de": "Sonnenfinsternis ☀️", "it": "Eclissi Solare ☀️", "pt": "Eclipse Solar ☀️", "zh": "日食 ☀️",
	"ja": "日食 ☀️", "ko": "일식 ☀️", "hi": "सूर्य ग्रहण ☀️", "ar": "كسوف الشمس ☀️",
	"mr": "सूर्यग्रहण ☀️", "te": "సూర్యగ్రహణం ☀️", "ta": "சூரிய கிரகணம் ☀️", "kn": "ಸೂರ್ಯಗ್ರಹಣ ☀️",
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
	"mr": "सूर्यग्रहण होत आहे — नव्या सुरुवातीची शक्तिशाली संधी.",
	"te": "సూర్యగ్రహణం జరుగుతోంది — కొత్త ఆరంభాలకు శక్తివంతమైన అవకాశం.",
	"ta": "சூரிய கிரகணம் நிகழ்கிறது — புதிய தொடக்கங்களுக்கான வலிமையான தருணம்.",
	"kn": "ಸೂರ್ಯಗ್ರಹಣ ನಡೆಯುತ್ತಿದೆ — ಹೊಸ ಆರಂಭಗಳಿಗೆ ಶಕ್ತಿಶಾಲಿ ಅವಕಾಶ.",
}
var lunarEclipseTitle = map[string]string{
	"en": "Lunar Eclipse 🌙", "ru": "Лунное затмение 🌙", "es": "Eclipse Lunar 🌙", "fr": "Éclipse Lunaire 🌙",
	"de": "Mondfinsternis 🌙", "it": "Eclissi Lunare 🌙", "pt": "Eclipse Lunar 🌙", "zh": "月食 🌙",
	"ja": "月食 🌙", "ko": "월식 🌙", "hi": "चंद्र ग्रहण 🌙", "ar": "خسوف القمر 🌙",
	"mr": "चंद्रग्रहण 🌙", "te": "చంద్రగ్రహణం 🌙", "ta": "சந்திர கிரகணம் 🌙", "kn": "ಚಂದ್ರಗ್ರಹಣ 🌙",
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
	"mr": "चंद्रग्रहण होत आहे — पूर्णत्व आणि मुक्तीची वेळ.",
	"te": "చంద్రగ్రహణం జరుగుతోంది — పరిపూర్ణత మరియు విముక్తికి సమయం.",
	"ta": "சந்திர கிரகணம் நிகழ்கிறது — நிறைவுக்கும் விடுதலைக்குமான நேரம்.",
	"kn": "ಚಂದ್ರಗ್ರಹಣ ನಡೆಯುತ್ತಿದೆ — ಪೂರ್ಣತೆ ಮತ್ತು ಬಿಡುಗಡೆಯ ಸಮಯ.",
}
var ingressTitleTmpl = map[string]string{
	"en": "%s enters %s", "ru": "%s переходит в %s", "es": "%s entra en %s", "fr": "%s entre en %s",
	"de": "%s tritt in %s ein", "it": "%s entra in %s", "pt": "%s entra em %s", "zh": "%s 进入 %s",
	"ja": "%s が %s に入る", "ko": "%s, %s 입성", "hi": "%s का %s में प्रवेश", "ar": "%s يدخل %s",
	"mr": "%s चा %s राशीत प्रवेश", "te": "%s %s రాశిలో ప్రవేశం", "ta": "%s %s ராசியில் பிரவேசம்", "kn": "%s %s ರಾಶಿಗೆ ಪ್ರವೇಶ",
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
	"mr": "%s %s राशीत प्रवेश करतो — संथ, दीर्घकालीन बदल.",
	"te": "%s %s రాశిలోకి ప్రవేశిస్తుంది — నెమ్మదైన, దీర్ఘకాలిక మార్పు.",
	"ta": "%s %s ராசியில் நுழைகிறது — மெதுவான, நீண்டகால மாற்றம்.",
	"kn": "%s %s ರಾಶಿಯನ್ನು ಪ್ರವೇಶಿಸುತ್ತದೆ — ನಿಧಾನ, ದೀರ್ಘಕಾಲೀನ ಬದಲಾವಣೆ.",
}

var stationRetroTitleTmpl = map[string]string{
	"en": "%s turns retrograde", "ru": "%s разворачивается вспять", "es": "%s entra en retrogradación", "fr": "%s devient rétrograde",
	"de": "%s wird rückläufig", "it": "%s inizia il moto retrogrado", "pt": "%s inicia o movimento retrógrado", "zh": "%s 开始逆行",
	"ja": "%s が逆行を開始", "ko": "%s 역행 시작", "hi": "%s वक्री हो रहा है", "ar": "%s يبدأ التراجع",
	"mr": "%s वक्री होत आहे", "te": "%s వక్ర గమనం ప్రారంభం", "ta": "%s வக்கிர நடை தொடக்கம்", "kn": "%s ವಕ್ರ ಗತಿ ಆರಂಭ",
}
var stationRetroBodyTmpl = map[string]string{
	"en": "%s stands still and turns retrograde — a weeks-long phase of review and rework begins.",
	"ru": "%s замирает и начинает попятное движение — начинается многонедельная фаза пересмотра.",
	"es": "%s se detiene e inicia la retrogradación — comienza una fase de revisión de varias semanas.",
	"fr": "%s s'arrête et rétrograde — une phase de révision de plusieurs semaines commence.",
	"de": "%s steht still und wird rückläufig — eine wochenlange Phase der Überprüfung beginnt.",
	"it": "%s si ferma e inizia il moto retrogrado — comincia una fase di revisione di settimane.",
	"pt": "%s para e inicia o movimento retrógrado — começa uma fase de revisão de semanas.",
	"zh": "%s 停滞并开始逆行——为期数周的回顾与调整阶段开始。",
	"ja": "%s が留まり逆行へ——数週間の見直し期間が始まります。",
	"ko": "%s가 멈추고 역행을 시작합니다 — 몇 주간의 재검토 시기가 시작됩니다.",
	"hi": "%s ठहरकर वक्री होता है — कई हफ्तों का पुनर्विचार काल शुरू होता है।",
	"ar": "%s يتوقف ويبدأ التراجع — تبدأ مرحلة مراجعة تمتد لأسابيع.",
	"mr": "%s थांबून वक्री होतो — अनेक आठवड्यांचा पुनर्विचाराचा काळ सुरू होतो.",
	"te": "%s నిలిచి వక్రగతిలోకి మారుతుంది — వారాల పాటు సమీక్షా దశ మొదలవుతుంది.",
	"ta": "%s நின்று வக்கிர நடைக்கு மாறுகிறது — பல வார மறுஆய்வு காலம் தொடங்குகிறது.",
	"kn": "%s ನಿಂತು ವಕ್ರ ಗತಿಗೆ ತಿರುಗುತ್ತದೆ — ಹಲವು ವಾರಗಳ ಪುನರ್ ಪರಿಶೀಲನೆಯ ಹಂತ ಆರಂಭ.",
}
var stationDirectTitleTmpl = map[string]string{
	"en": "%s turns direct", "ru": "%s снова в прямом движении", "es": "%s retoma el movimiento directo", "fr": "%s reprend sa marche directe",
	"de": "%s wird wieder direktläufig", "it": "%s riprende il moto diretto", "pt": "%s retoma o movimento direto", "zh": "%s 恢复顺行",
	"ja": "%s が順行に戻る", "ko": "%s 순행 복귀", "hi": "%s मार्गी हो रहा है", "ar": "%s يعود إلى المسار المباشر",
	"mr": "%s मार्गी होत आहे", "te": "%s ఋజు గమనానికి తిరిగి", "ta": "%s நேர்நடைக்கு திரும்புகிறது", "kn": "%s ನೇರ ಗತಿಗೆ ಮರಳುತ್ತದೆ",
}
var stationDirectBodyTmpl = map[string]string{
	"en": "%s stations and resumes direct motion — stalled matters can finally move forward.",
	"ru": "%s останавливается и возобновляет прямое движение — застопорившиеся дела снова идут вперёд.",
	"es": "%s se detiene y retoma el movimiento directo — lo estancado vuelve a avanzar.",
	"fr": "%s marque une pause puis reprend sa marche directe — ce qui stagnait repart de l'avant.",
	"de": "%s steht still und läuft wieder direkt — Blockiertes kommt wieder in Bewegung.",
	"it": "%s si ferma e riprende il moto diretto — ciò che era in stallo torna a muoversi.",
	"pt": "%s para e retoma o movimento direto — o que estava travado volta a andar.",
	"zh": "%s 停滞后恢复顺行——停滞的事务重新向前推进。",
	"ja": "%s が留まり順行へ——停滞していた物事が再び動き出します。",
	"ko": "%s가 멈춘 뒤 순행으로 돌아섭니다 — 정체됐던 일들이 다시 움직입니다.",
	"hi": "%s ठहरकर मार्गी होता है — रुके हुए काम फिर आगे बढ़ते हैं।",
	"ar": "%s يتوقف ثم يستأنف مساره المباشر — ما كان متعثرًا يتحرك من جديد.",
	"mr": "%s थांबून मार्गी होतो — रखडलेली कामे पुन्हा पुढे सरकतात.",
	"te": "%s నిలిచి ఋజుగతికి మారుతుంది — ఆగిపోయిన పనులు మళ్లీ ముందుకు సాగుతాయి.",
	"ta": "%s நின்று நேர்நடைக்கு திரும்புகிறது — தேங்கிய காரியங்கள் மீண்டும் முன்னேறுகின்றன.",
	"kn": "%s ನಿಂತು ನೇರ ಗತಿಗೆ ಮರಳುತ್ತದೆ — ಸ್ಥಗಿತಗೊಂಡ ಕೆಲಸಗಳು ಮತ್ತೆ ಮುಂದುವರಿಯುತ್ತವೆ.",
}

var planetNames = map[string]map[string]string{
	"Sun":     {"en": "Sun", "es": "Sol", "fr": "Soleil", "de": "Sonne", "it": "Sole", "pt": "Sol", "ru": "Солнце", "zh": "太阳", "ja": "太陽", "ko": "태양", "hi": "सूर्य", "ar": "الشمس", "mr": "सूर्य", "te": "సూర్యుడు", "ta": "சூரியன்", "kn": "ಸೂರ್ಯ"},
	"Mercury": {"en": "Mercury", "es": "Mercurio", "fr": "Mercure", "de": "Merkur", "it": "Mercurio", "pt": "Mercúrio", "ru": "Меркурий", "zh": "水星", "ja": "水星", "ko": "수성", "hi": "बुध", "ar": "عطارد", "mr": "बुध", "te": "బుధుడు", "ta": "புதன்", "kn": "ಬುಧ"},
	"Venus":   {"en": "Venus", "es": "Venus", "fr": "Vénus", "de": "Venus", "it": "Venere", "pt": "Vênus", "ru": "Венера", "zh": "金星", "ja": "金星", "ko": "금성", "hi": "शुक्र", "ar": "الزهرة", "mr": "शुक्र", "te": "శుక్రుడు", "ta": "சுக்கிரன்", "kn": "ಶುಕ್ರ"},
	"Mars":    {"en": "Mars", "es": "Marte", "fr": "Mars", "de": "Mars", "it": "Marte", "pt": "Marte", "ru": "Марс", "zh": "火星", "ja": "火星", "ko": "화성", "hi": "मंगल", "ar": "المريخ", "mr": "मंगळ", "te": "కుజుడు", "ta": "செவ்வாய்", "kn": "ಮಂಗಳ"},
	"Moon":    {"en": "Moon", "es": "Luna", "fr": "Lune", "de": "Mond", "it": "Luna", "pt": "Lua", "ru": "Луна", "zh": "月亮", "ja": "月", "ko": "달", "hi": "चंद्रमा", "ar": "القمر", "mr": "चंद्र", "te": "చంద్రుడు", "ta": "சந்திரன்", "kn": "ಚಂದ್ರ"},
	"Jupiter": {"en": "Jupiter", "es": "Júpiter", "fr": "Jupiter", "de": "Jupiter", "it": "Giove", "pt": "Júpiter", "ru": "Юпитер", "zh": "木星", "ja": "木星", "ko": "목성", "hi": "बृहस्पति", "ar": "المشتري", "mr": "गुरु", "te": "గురువు", "ta": "குரு", "kn": "ಗುರು"},
	"Saturn":  {"en": "Saturn", "es": "Saturno", "fr": "Saturne", "de": "Saturn", "it": "Saturno", "pt": "Saturno", "ru": "Сатурн", "zh": "土星", "ja": "土星", "ko": "토성", "hi": "शनि", "ar": "زحل", "mr": "शनि", "te": "శని", "ta": "சனி", "kn": "ಶನಿ"},
	"Rahu":    {"en": "Rahu", "es": "Rahu", "fr": "Rahu", "de": "Rahu", "it": "Rahu", "pt": "Rahu", "ru": "Раху", "zh": "罗睺", "ja": "ラーフ", "ko": "라후", "hi": "राहु", "ar": "راهو", "mr": "राहू", "te": "రాహువు", "ta": "ராகு", "kn": "ರಾಹು"},
	"Ketu":    {"en": "Ketu", "es": "Ketu", "fr": "Ketu", "de": "Ketu", "it": "Ketu", "pt": "Ketu", "ru": "Кету", "zh": "计都", "ja": "ケートゥ", "ko": "케투", "hi": "केतु", "ar": "كيتو", "mr": "केतू", "te": "కేతువు", "ta": "கேது", "kn": "ಕೇತು"},
}

var signNames = []map[string]string{
	{"en": "Aries", "es": "Aries", "fr": "Bélier", "de": "Widder", "it": "Ariete", "pt": "Áries", "ru": "Овен", "zh": "白羊座", "ja": "牡羊座", "ko": "양자리", "hi": "मेष", "ar": "الحمل", "mr": "मेष", "te": "మేషం", "ta": "மேஷம்", "kn": "ಮೇಷ"},
	{"en": "Taurus", "es": "Tauro", "fr": "Taureau", "de": "Stier", "it": "Toro", "pt": "Touro", "ru": "Телец", "zh": "金牛座", "ja": "牡牛座", "ko": "황소자리", "hi": "वृषभ", "ar": "الثور", "mr": "वृषभ", "te": "వృషభం", "ta": "ரிஷபம்", "kn": "ವೃಷಭ"},
	{"en": "Gemini", "es": "Géminis", "fr": "Gémeaux", "de": "Zwillinge", "it": "Gemelli", "pt": "Gêmeos", "ru": "Близнецы", "zh": "双子座", "ja": "双子座", "ko": "쌍둥이자리", "hi": "मिथुन", "ar": "الجوزاء", "mr": "मिथुन", "te": "మిథునం", "ta": "மிதுனம்", "kn": "ಮಿಥುನ"},
	{"en": "Cancer", "es": "Cáncer", "fr": "Cancer", "de": "Krebs", "it": "Cancro", "pt": "Câncer", "ru": "Рак", "zh": "巨蟹座", "ja": "蟹座", "ko": "게자리", "hi": "कर्क", "ar": "السرطان", "mr": "कर्क", "te": "కర్కాటకం", "ta": "கடகம்", "kn": "ಕರ್ಕಾಟಕ"},
	{"en": "Leo", "es": "Leo", "fr": "Lion", "de": "Löwe", "it": "Leone", "pt": "Leão", "ru": "Лев", "zh": "狮子座", "ja": "獅子座", "ko": "사자자리", "hi": "सिंह", "ar": "الأسد", "mr": "सिंह", "te": "సింహం", "ta": "சிம்மம்", "kn": "ಸಿಂಹ"},
	{"en": "Virgo", "es": "Virgo", "fr": "Vierge", "de": "Jungfrau", "it": "Vergine", "pt": "Virgem", "ru": "Дева", "zh": "处女座", "ja": "乙女座", "ko": "처녀자리", "hi": "कन्या", "ar": "العذراء", "mr": "कन्या", "te": "కన్య", "ta": "கன்னி", "kn": "ಕನ್ಯಾ"},
	{"en": "Libra", "es": "Libra", "fr": "Balance", "de": "Waage", "it": "Bilancia", "pt": "Libra", "ru": "Весы", "zh": "天秤座", "ja": "天秤座", "ko": "천칭자리", "hi": "तुला", "ar": "الميزان", "mr": "तूळ", "te": "తుల", "ta": "துலாம்", "kn": "ತುಲಾ"},
	{"en": "Scorpio", "es": "Escorpio", "fr": "Scorpion", "de": "Skorpion", "it": "Scorpione", "pt": "Escorpião", "ru": "Скорпион", "zh": "天蝎座", "ja": "蠍座", "ko": "전갈자리", "hi": "वृश्चिक", "ar": "العقرب", "mr": "वृश्चिक", "te": "వృశ్చికం", "ta": "விருச்சிகம்", "kn": "ವೃಶ್ಚಿಕ"},
	{"en": "Sagittarius", "es": "Sagitario", "fr": "Sagittaire", "de": "Schütze", "it": "Sagittario", "pt": "Sagitário", "ru": "Стрелец", "zh": "射手座", "ja": "射手座", "ko": "궁수자리", "hi": "धनु", "ar": "القوس", "mr": "धनु", "te": "ధనుస్సు", "ta": "தனுசு", "kn": "ಧನು"},
	{"en": "Capricorn", "es": "Capricornio", "fr": "Capricorne", "de": "Steinbock", "it": "Capricorno", "pt": "Capricórnio", "ru": "Козерог", "zh": "摩羯座", "ja": "山羊座", "ko": "염소자리", "hi": "मकर", "ar": "الجدي", "mr": "मकर", "te": "మకరం", "ta": "மகரம்", "kn": "ಮಕರ"},
	{"en": "Aquarius", "es": "Acuario", "fr": "Verseau", "de": "Wassermann", "it": "Acquario", "pt": "Aquário", "ru": "Водолей", "zh": "水瓶座", "ja": "水瓶座", "ko": "물병자리", "hi": "कुंभ", "ar": "الدلو", "mr": "कुंभ", "te": "కుంభం", "ta": "கும்பம்", "kn": "ಕುಂಭ"},
	{"en": "Pisces", "es": "Piscis", "fr": "Poissons", "de": "Fische", "it": "Pesci", "pt": "Peixes", "ru": "Рыбы", "zh": "双鱼座", "ja": "魚座", "ko": "물고기자리", "hi": "मीन", "ar": "الحوت", "mr": "मीन", "te": "మీనం", "ta": "மீனம்", "kn": "ಮೀನ"},
}
