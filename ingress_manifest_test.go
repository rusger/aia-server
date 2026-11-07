package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func setupIngressDB(t *testing.T) {
	t.Helper()
	prev := db
	mem, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	mem.SetMaxOpenConns(1)
	db = mem
	t.Cleanup(func() {
		mem.Close()
		db = prev
	})
	if _, err := db.Exec(`CREATE TABLE push_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, ekey TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
		event_date DATETIME NOT NULL, params TEXT, payload TEXT)`); err != nil {
		t.Fatal(err)
	}
}

func addEvent(t *testing.T, ekey, kind, date, params string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO push_events (ekey, kind, event_date, params, payload) VALUES (?, ?, ?, ?, 'p')`,
		ekey, kind, date, params); err != nil {
		t.Fatal(err)
	}
}

func eventParams(t *testing.T, ekey string) string {
	t.Helper()
	var p string
	if err := db.QueryRow(`SELECT params FROM push_events WHERE ekey = ?`, ekey).Scan(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBackfillAddsFromFromTheDayBefore(t *testing.T) {
	setupIngressDB(t)
	addEvent(t, "slow_ingress:Venus:2026-11-22", "slow_ingress", "2026-11-22", `{"planet":"Venus","signIdx":6}`)
	addEvent(t, "lunar_new:2026-11-22", "lunar_new", "2026-11-22", `{"isNew":true}`)

	var asked []string
	lons := func(d time.Time) (map[string]float64, error) {
		asked = append(asked, d.Format("2006-01-02"))
		return map[string]float64{"Venus": 175}, nil // Virgo
	}
	backfillIngressFrom(lons)

	if len(asked) != 1 || asked[0] != "2026-11-21" {
		t.Fatalf("must sample only the day before, asked %v", asked)
	}
	if got := eventParams(t, "slow_ingress:Venus:2026-11-22"); got != `{"fromIdx":5,"planet":"Venus","signIdx":6}` {
		t.Fatalf("params = %s", got)
	}
	if got := eventParams(t, "lunar_new:2026-11-22"); got != `{"isNew":true}` {
		t.Fatalf("other kinds must stay untouched, got %s", got)
	}

	backfillIngressFrom(lons)
	if len(asked) != 1 {
		t.Fatalf("a filled row must not be recomputed, asked %v", asked)
	}
}

func TestBackfillSkipsRowItCannotProve(t *testing.T) {
	setupIngressDB(t)
	same := `{"planet":"Mars","signIdx":4}`
	failed := `{"planet":"Sun","signIdx":7}`
	addEvent(t, "slow_ingress:Mars:2026-11-13", "slow_ingress", "2026-11-13", same)
	addEvent(t, "slow_ingress:Sun:2026-11-17", "slow_ingress", "2026-11-17", failed)

	backfillIngressFrom(func(d time.Time) (map[string]float64, error) {
		if d.Day() == 16 {
			return nil, errors.New("astrolog down")
		}
		return map[string]float64{"Mars": 125}, nil // still Leo the day before
	})

	if got := eventParams(t, "slow_ingress:Mars:2026-11-13"); got != same {
		t.Fatalf("same sign must not be written, got %s", got)
	}
	if got := eventParams(t, "slow_ingress:Sun:2026-11-17"); got != failed {
		t.Fatalf("failed lookup must not be written, got %s", got)
	}
}

func TestIngressManifestResponse(t *testing.T) {
	setupIngressDB(t)
	addEvent(t, "slow_ingress:Rahu:2026-12-06", "slow_ingress", "2026-12-06", `{"fromIdx":10,"planet":"Rahu","signIdx":9}`)
	addEvent(t, "slow_ingress:Mars:2026-11-13", "slow_ingress", "2026-11-13", `{"planet":"Mars","signIdx":4}`)
	addEvent(t, "slow_ingress:Sun:2026-11-17", "slow_ingress", "2026-11-17", `not json`)
	addEvent(t, "station:Mars:retro:2026-11-14", "station", "2026-11-14", `{"planet":"Mars","retro":true}`)

	w := httptest.NewRecorder()
	ingressManifestHandler(w, httptest.NewRequest("GET", "/api/events/ingresses", nil))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var doc struct {
		Ingresses []ingressEntry `json:"ingresses"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := []ingressEntry{
		{Planet: "Mars", Date: "2026-11-13", To: "leo"},
		{Planet: "Rahu", Date: "2026-12-06", From: "aquarius", To: "capricorn", Key: "rahu_aquarius_capricorn"},
	}
	if len(doc.Ingresses) != len(want) {
		t.Fatalf("entries = %+v", doc.Ingresses)
	}
	for i := range want {
		if doc.Ingresses[i] != want[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, doc.Ingresses[i], want[i])
		}
	}
}

func TestFromIdxLeavesPushTextAlone(t *testing.T) {
	plainTitle, plainBody := eventText("slow_ingress", `{"planet":"Mars","signIdx":3}`, "ru")
	title, body := eventText("slow_ingress", `{"planet":"Mars","fromIdx":4,"signIdx":3}`, "ru")
	if title != plainTitle || body != plainBody {
		t.Fatalf("fromIdx changed the push: %q / %q", title, body)
	}
}
