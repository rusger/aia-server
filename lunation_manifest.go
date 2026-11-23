package main

// lunation_manifest.go — the New/Full Moon rows of GET /api/events/ingresses
// (A177, owner 23.11.2026). A lunation push carries only phase + day
// (astro:lunar_phase:lunar_phase:<new|full>:<day>); the app looks the clip up
// here by phase + day. A row is listed ONLY when its clip is in the bank, so
// the app keeps its old card for every other lunation, and a clip rendered
// later for another sign is picked up with no app release: put
// moon_<sign>_<full|new>.mp4 (+ _idle.mp4, .jpg, _first.jpg, _flash.jpg) into
// the bank and the next manifest lists it.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type lunationEntry struct {
	Date string `json:"date"` // the push payload's day
	Kind string `json:"kind"` // new | full, as in the push payload
	Sign string `json:"sign"` // the Moon's sidereal sign at the lunation moment
	Key  string `json:"key"`  // moon_<sign>_<kind>, names the lunation video
}

// lunationBankDir is where /tv/ingress/ is served from (nginx); override with
// TV_INGRESS_DIR.
func lunationBankDir() string {
	if d := os.Getenv("TV_INGRESS_DIR"); d != "" {
		return d
	}
	return "/mnt/HC_Volume_107049376/tv/ingress"
}

var (
	// moonLongitudeAt is the Moon's sidereal longitude at a moment; a var so tests
	// need no astrolog binary.
	moonLongitudeAt = func(at time.Time) (float64, error) {
		lons, err := siderealLongitudesAt(at)
		if err != nil {
			return 0, err
		}
		lon, ok := lons["Moon"]
		if !ok {
			return 0, fmt.Errorf("no Moon longitude")
		}
		return lon, nil
	}
	lunationSignMu    sync.Mutex
	lunationSignCache = map[string]int{} // ekey → sign index; a lunation's moment never changes
)

func lunationSign(ekey string, at time.Time) (int, error) {
	lunationSignMu.Lock()
	defer lunationSignMu.Unlock()
	if s, ok := lunationSignCache[ekey]; ok {
		return s, nil
	}
	lon, err := moonLongitudeAt(at)
	if err != nil {
		return 0, err
	}
	s := signOf(lon)
	lunationSignCache[ekey] = s
	return s, nil
}

func loadLunationManifest() ([]lunationEntry, error) {
	rows, err := db.Query(`SELECT ekey, kind, event_date FROM push_events
		WHERE kind IN ('lunar_full', 'lunar_new') ORDER BY event_date`)
	if err != nil {
		return nil, err
	}
	type row struct {
		ekey, kind string
		at         time.Time
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ekey, &r.kind, &r.at); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	dir := lunationBankDir()
	out := []lunationEntry{}
	for _, r := range list {
		day, ok := strings.CutPrefix(r.ekey, r.kind+":")
		if !ok || len(day) != len("2006-01-02") {
			log.Printf("⚠️ lunation manifest: skipping %s: unexpected ekey", r.ekey)
			continue
		}
		kind := strings.TrimPrefix(r.kind, "lunar_")
		sign, err := lunationSign(r.ekey, r.at)
		if err != nil {
			log.Printf("⚠️ lunation manifest: skipping %s: sign: %v", r.ekey, err)
			continue // no sign → no clip; the card stays as before
		}
		key := fmt.Sprintf("moon_%s_%s", signSlug(sign), kind)
		if _, err := os.Stat(filepath.Join(dir, key+".mp4")); err != nil {
			// Not rendered yet is the normal case: the app keeps its old card.
			// Anything else (bank volume unmounted, I/O, permissions) is logged.
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("⚠️ lunation manifest: bank stat %s: %v", key, err)
			}
			continue
		}
		out = append(out, lunationEntry{Date: day, Kind: kind, Sign: signSlug(sign), Key: key})
	}
	return out, nil
}
