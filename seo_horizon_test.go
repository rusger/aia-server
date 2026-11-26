package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A246: the horizon never releases a month past current+seoSignMonthsAhead,
// but a month already on disk keeps its place (losing .seo-state.json
// must not narrow the window).
func TestSeoHorizonHighWater(t *testing.T) {
	data := []*seoYearData{{year: 2026}, {year: 2027}}
	now := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)

	empty := t.TempDir()
	if got := seoSignMonths(data, now, empty); len(got) != 3 || got[2] != [2]int{2027, 1} {
		t.Errorf("empty out: months %v, want Nov..Jan", got)
	}
	if end := seoDayWindowEnd(data, now, empty); !end.Equal(time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("empty out: day window ends %s, want 2027-01-31", fmtDay(end))
	}

	// Production on 26.11.2026: February 2027 already published (day pages
	// and facts), no state file.
	pub := t.TempDir()
	os.MkdirAll(filepath.Join(pub, "en", "2027", "02"), 0o755)
	os.MkdirAll(filepath.Join(pub, seoFactsDir), 0o755)
	os.WriteFile(filepath.Join(pub, seoFactsDir, "2027-02-aries.json"), []byte("{}"), 0o644)
	got := seoSignMonths(data, now, pub)
	if len(got) != 4 || got[3] != [2]int{2027, 2} {
		t.Errorf("published Feb: months %v, want Nov..Feb", got)
	}
	if end := seoDayWindowEnd(data, now, pub); !end.Equal(time.Date(2027, 2, 28, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("published Feb: day window ends %s, want 2027-02-28 (no March)", fmtDay(end))
	}
	// Facts alone (folders lost) still hold the mark.
	factsOnly := t.TempDir()
	os.MkdirAll(filepath.Join(factsOnly, seoFactsDir), 0o755)
	os.WriteFile(filepath.Join(factsOnly, seoFactsDir, "2027-02-libra.json"), []byte("{}"), 0o644)
	if end := seoDayWindowEnd(data, now, factsOnly); !end.Equal(time.Date(2027, 2, 28, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("facts only: day window ends %s, want 2027-02-28", fmtDay(end))
	}

	// 31.12: today+60 = 01.03 must not spill into March.
	dec31 := time.Date(2026, 12, 31, 9, 0, 0, 0, time.UTC)
	if end := seoDayWindowEnd(data, dec31, empty); !end.Equal(time.Date(2027, 2, 28, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("31.12: day window ends %s, want 2027-02-28", fmtDay(end))
	}
	// Past months still leave the window as before.
	if got := seoSignMonths(data, time.Date(2027, 3, 2, 0, 0, 0, 0, time.UTC), pub); got[0] != [2]int{2027, 3} {
		t.Errorf("March run starts at %v, want 2027-03", got[0])
	}
}

// Full run: a month already published stays in the sitemap and in the
// language hub links even when the horizon alone would not reach it.
func TestSeoHorizonKeepsPublishedInSitemap(t *testing.T) {
	old := seoSignMonthsAhead
	seoSignMonthsAhead = 0 // horizon = current month only
	defer func() { seoSignMonthsAhead = old }()
	data := fixtureWithRetro(t)
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

	fresh := t.TempDir()
	if _, err := writeSeoSiteAt(fresh, data, now); err != nil {
		t.Fatal(err)
	}
	sm, _ := os.ReadFile(filepath.Join(fresh, "sitemap.xml"))
	if strings.Contains(string(sm), "/2026/11/") || strings.Contains(string(sm), "/2026/12/") {
		t.Error("horizon 0 on a fresh dir must not release November/December")
	}

	pub := t.TempDir()
	os.MkdirAll(filepath.Join(pub, "ru", "2026", "12"), 0o755) // December already published
	if _, err := writeSeoSiteAt(pub, data, now); err != nil {
		t.Fatal(err)
	}
	sm, _ = os.ReadFile(filepath.Join(pub, "sitemap.xml"))
	for _, want := range []string{
		"<loc>https://astrolytix.com/astro/ru/2026/12/</loc>",
		"<loc>https://astrolytix.com/astro/en/2026/12/31.html</loc>",
	} {
		if !strings.Contains(string(sm), want) {
			t.Errorf("sitemap lost published %s", want)
		}
	}
	if strings.Contains(string(sm), "/2027/01/") {
		t.Error("nothing past the published December")
	}
	hub, _ := os.ReadFile(filepath.Join(pub, "en", "index.html"))
	if !strings.Contains(string(hub), `href="https://astrolytix.com/astro/en/2026/12/"`) {
		t.Error("language hub must still link the published December hub")
	}
}
