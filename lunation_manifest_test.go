package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stubMoon fixes the Moon's longitude and the bank folder for one test.
func stubMoon(t *testing.T, lon func(time.Time) (float64, error)) string {
	t.Helper()
	prev := moonLongitudeAt
	moonLongitudeAt = lon
	lunationSignMu.Lock()
	lunationSignCache = map[string]int{}
	lunationSignMu.Unlock()
	dir := t.TempDir()
	t.Setenv("TV_INGRESS_DIR", dir)
	t.Cleanup(func() { moonLongitudeAt = prev })
	return dir
}

func touch(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLunationListedOnlyWhenItsClipIsInTheBank(t *testing.T) {
	setupIngressDB(t)
	addEvent(t, "lunar_full:2026-11-24", "lunar_full", "2026-11-24 19:07:09", `{"isNew":false}`)
	addEvent(t, "lunar_new:2026-12-09", "lunar_new", "2026-12-09 10:00:00", `{"isNew":true}`)
	addEvent(t, "lunar_full:2026-12-24", "lunar_full", "2026-12-24 01:00:00", `{"isNew":false}`)
	var asked []string
	dir := stubMoon(t, func(at time.Time) (float64, error) {
		asked = append(asked, at.UTC().Format("2006-01-02 15:04"))
		switch at.UTC().Format("2006-01-02") {
		case "2026-11-24":
			return 40.7, nil // Taurus
		case "2026-12-09":
			return 225, nil // Scorpio
		}
		return 70, nil // Gemini
	})
	touch(t, dir, "moon_taurus_full.mp4") // only Taurus full is rendered

	got, err := loadLunationManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (lunationEntry{Date: "2026-11-24", Kind: "full", Sign: "taurus", Key: "moon_taurus_full"}) {
		t.Fatalf("manifest = %+v, want only Taurus full", got)
	}
	// The sign is taken at the lunation's minute, not at noon.
	if asked[0] != "2026-11-24 19:07" {
		t.Fatalf("Moon asked at %v", asked)
	}

	// A clip rendered later is picked up with no code change; signs are cached.
	touch(t, dir, "moon_scorpio_new.mp4")
	n := len(asked)
	got, _ = loadLunationManifest()
	if len(got) != 2 || got[1].Key != "moon_scorpio_new" || got[1].Kind != "new" || got[1].Date != "2026-12-09" {
		t.Fatalf("manifest = %+v, want Taurus full + Scorpio new", got)
	}
	if len(asked) != n {
		t.Fatalf("signs recomputed: asked %d times, want %d", len(asked), n)
	}
}

func TestLunationWithoutSignIsLeftOut(t *testing.T) {
	setupIngressDB(t)
	addEvent(t, "lunar_full:2026-11-24", "lunar_full", "2026-11-24 19:07:09", `{"isNew":false}`)
	dir := stubMoon(t, func(time.Time) (float64, error) { return 0, errors.New("astrolog down") })
	touch(t, dir, "moon_aries_full.mp4")
	got, err := loadLunationManifest()
	if err != nil || len(got) != 0 {
		t.Fatalf("manifest = %+v, %v; want empty", got, err)
	}
}

func TestManifestCarriesLunations(t *testing.T) {
	setupIngressDB(t)
	addEvent(t, "lunar_full:2026-11-24", "lunar_full", "2026-11-24 19:07:09", `{"isNew":false}`)
	dir := stubMoon(t, func(time.Time) (float64, error) { return 40.7, nil })
	touch(t, dir, "moon_taurus_full.mp4")
	w := httptest.NewRecorder()
	ingressManifestHandler(w, httptest.NewRequest("GET", "/api/events/ingresses", nil))
	var doc struct {
		Lunations []lunationEntry `json:"lunations"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(doc.Lunations) != 1 || doc.Lunations[0].Key != "moon_taurus_full" {
		t.Fatalf("HTTP %d, lunations %+v", w.Code, doc.Lunations)
	}
}
