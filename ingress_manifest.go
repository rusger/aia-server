package main

// ingress_manifest.go — GET /api/events/ingresses: planet sign changes the
// server knows about, for the transit push overlay. A push payload carries
// only planet + date; the app looks the signs up here, so payloads stay the
// same and installed versions keep matching their local records and history.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type ingressParams struct {
	Planet  string `json:"planet"`
	FromIdx *int   `json:"fromIdx"`
	SignIdx *int   `json:"signIdx"`
}

// ingressEntry is one manifest row. From and Key are absent for a row whose
// left sign is unknown; To alone is enough for the natal house.
type ingressEntry struct {
	Planet string `json:"planet"`
	Date   string `json:"date"`
	From   string `json:"from,omitempty"`
	To     string `json:"to"`
	Key    string `json:"key,omitempty"` // <planet>_<from>_<to>, names the transition video
}

// ingressDay extracts the calendar day from a slow_ingress:<Planet>:<day> ekey.
func ingressDay(ekey string) (string, bool) {
	parts := strings.Split(ekey, ":")
	if len(parts) != 3 {
		return "", false
	}
	return parts[2], true
}

// backfillIngressFrom adds fromIdx to slow_ingress rows stored without it.
// The event day is the first whose noon sign is new, so the noon before it
// still holds the sign being left. Only that key is added; a row is skipped
// when the two signs agree, because then the date does not fit the rule.
func backfillIngressFrom(longitudes func(time.Time) (map[string]float64, error)) {
	rows, err := db.Query(`SELECT id, ekey, params FROM push_events
		WHERE kind = 'slow_ingress' AND json_extract(params, '$.fromIdx') IS NULL`)
	if err != nil {
		log.Printf("⚠️ ingress backfill query: %v", err)
		return
	}
	type pending struct {
		id           int64
		ekey, params string
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.ekey, &p.params); err != nil {
			log.Printf("⚠️ ingress backfill scan: %v", err)
			continue
		}
		todo = append(todo, p)
	}
	if err := rows.Err(); err != nil {
		log.Printf("⚠️ ingress backfill rows: %v", err)
	}
	rows.Close()

	for _, p := range todo {
		var fields map[string]interface{}
		var known ingressParams
		day, ok := ingressDay(p.ekey)
		if !ok {
			log.Printf("⚠️ ingress backfill %s: unexpected ekey", p.ekey)
			continue
		}
		date, err := time.Parse("2006-01-02", day)
		if err != nil {
			log.Printf("⚠️ ingress backfill %s: %v", p.ekey, err)
			continue
		}
		if err := json.Unmarshal([]byte(p.params), &fields); err != nil {
			log.Printf("⚠️ ingress backfill %s: %v", p.ekey, err)
			continue
		}
		if err := json.Unmarshal([]byte(p.params), &known); err != nil || known.SignIdx == nil {
			log.Printf("⚠️ ingress backfill %s: no signIdx (%v)", p.ekey, err)
			continue
		}
		lons, err := longitudes(date.AddDate(0, 0, -1))
		if err != nil {
			log.Printf("⚠️ ingress backfill %s: %v", p.ekey, err)
			continue
		}
		lon, ok := lons[known.Planet]
		if !ok {
			log.Printf("⚠️ ingress backfill %s: no longitude", p.ekey)
			continue
		}
		from := signOf(lon)
		if from == *known.SignIdx {
			log.Printf("⚠️ ingress backfill %s: same sign the day before", p.ekey)
			continue
		}
		fields["fromIdx"] = from
		pj, err := json.Marshal(fields)
		if err != nil {
			log.Printf("⚠️ ingress backfill %s: %v", p.ekey, err)
			continue
		}
		if _, err := db.Exec(`UPDATE push_events SET params = ? WHERE id = ?`, string(pj), p.id); err != nil {
			log.Printf("⚠️ ingress backfill %s: %v", p.ekey, err)
		}
	}
}

func loadIngressManifest() ([]ingressEntry, error) {
	rows, err := db.Query(`SELECT ekey, params FROM push_events
		WHERE kind = 'slow_ingress' ORDER BY event_date`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ingressEntry{}
	for rows.Next() {
		var ekey, params string
		if err := rows.Scan(&ekey, &params); err != nil {
			return nil, err
		}
		var p ingressParams
		day, ok := ingressDay(ekey)
		if err := json.Unmarshal([]byte(params), &p); err != nil || !ok || p.SignIdx == nil {
			log.Printf("⚠️ ingress manifest: skipping %s (%v)", ekey, err)
			continue
		}
		e := ingressEntry{Planet: p.Planet, Date: day, To: signSlug(*p.SignIdx)}
		if p.FromIdx != nil {
			e.From = signSlug(*p.FromIdx)
			e.Key = fmt.Sprintf("%s_%s_%s", strings.ToLower(p.Planet), e.From, e.To)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GET /api/events/ingresses → {ingresses: [{planet, date, from, to, key}]}.
func ingressManifestHandler(w http.ResponseWriter, r *http.Request) {
	entries, err := loadIngressManifest()
	if err != nil {
		log.Printf("⚠️ ingress manifest: %v", err)
		http.Error(w, `{"error":"unavailable"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"ingresses": entries}); err != nil {
		log.Printf("⚠️ ingress manifest write: %v", err)
	}
}
