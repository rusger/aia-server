package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHouseFrom(t *testing.T) {
	if houseFrom(6, 6) != 1 || houseFrom(6, 7) != 2 || houseFrom(6, 5) != 12 || houseFrom(0, 11) != 12 {
		t.Error("houses count from the Moon sign as house 1")
	}
}

func fixtureWithRetro(t *testing.T) []*seoYearData {
	d := fixtureYear(t)
	d.retro["Venus"] = []seoRetroPeriod{{planet: "Venus", start: day(2026, 10, 3), end: day(2026, 11, 13), startSign: 6, endSign: 5}}
	return []*seoYearData{d}
}

func TestComputeSignFacts(t *testing.T) {
	f, err := computeSignFacts(fixtureWithRetro(t), 2026, 10, 6) // Libra
	if err != nil {
		t.Fatal(err)
	}
	if f.Sign != "Libra" || f.MonthStart != "2026-10-01" || f.MonthEnd != "2026-10-31" {
		t.Errorf("header: %+v", f)
	}
	byName := map[string]seoFactPlanet{}
	for _, p := range f.Planets {
		byName[p.Planet] = p
	}
	sun := byName["Sun"]
	// fixture Sun: 167° on Oct 1 (Virgo, house 12 from Libra) → 197° on Oct 31 (Libra, house 1)
	if sun.SignStart != "Virgo" || sun.HouseStart != 12 || sun.SignEnd != "Libra" || sun.HouseEnd != 1 {
		t.Errorf("sun: %+v", sun)
	}
	if len(sun.Ingresses) != 1 || sun.Ingresses[0].Date != "2026-10-17" || sun.Ingresses[0].House != 1 {
		t.Errorf("sun ingress: %+v", sun.Ingresses)
	}
	if len(byName["Mercury"].Stations) != 1 || byName["Mercury"].Stations[0].Turns != "retrograde" {
		t.Errorf("mercury station: %+v", byName["Mercury"].Stations)
	}
	if v := byName["Venus"]; v.RetroStart || !v.RetroEnd {
		t.Errorf("venus retro flags: start=%v end=%v", v.RetroStart, v.RetroEnd)
	}
	if !byName["Rahu"].RetroStart || byName["Sun"].RetroEnd {
		t.Error("nodes always retro, Sun never")
	}
	if len(f.MoonEvents) != 1 || f.MoonEvents[0].Kind != "new_moon" || f.MoonEvents[0].House != 12 {
		t.Errorf("moon events: %+v", f.MoonEvents)
	}
	if f.Names["ru"].Sign != "Весы" || f.Names["ru"].Signs["Aries"] != "Овен" || f.Names["ru"].Planets["Jupiter"] != "Юпитер" || f.Names["en"].Month != "October" {
		t.Errorf("names: %+v", f.Names["ru"])
	}
	if len(f.Names) != len(seoDayLangs) {
		t.Errorf("names for %d languages, want %d (seoDayLangs)", len(f.Names), len(seoDayLangs))
	}
}

func writeText(t *testing.T, out, lang, key, lead string) {
	t.Helper()
	dir := filepath.Join(out, seoTextDir, lang)
	os.MkdirAll(dir, 0o755)
	raw, _ := json.Marshal(map[string]any{
		"lead": lead,
		"sections": []map[string]string{
			{"key": "overview", "h": "Обзор", "p": "Юпитер в 10-м доме <b>не</b> тег."},
			{"key": "advice", "h": "Совет", "p": "Планируйте."},
		},
		"model": "sonnet", "provider": "claude",
	})
	if err := os.WriteFile(filepath.Join(dir, key+".json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSignPagesRenderOnlyWithText(t *testing.T) {
	out := t.TempDir()
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	data := fixtureWithRetro(t)
	key := factsKey(2026, 10, "libra")
	writeText(t, out, "ru", key, "Месяц для Весов.")
	// A sign page two months ahead must also have its month hub (review r1).
	writeText(t, out, "ru", factsKey(2026, 12, "aries"), "Декабрь для Овна.")
	n1, err := writeSeoSiteAt(out, data, now)
	if err != nil {
		t.Fatal(err)
	}
	// Facts for 12 signs × the months inside 2026 data (Oct..Dec = 3; Jan 2027 has no data).
	if files, _ := filepath.Glob(filepath.Join(out, seoFactsDir, "*.json")); len(files) != 36 {
		t.Errorf("%d facts files, want 36", len(files))
	}
	var facts seoSignFacts
	raw, _ := os.ReadFile(filepath.Join(out, seoFactsDir, key+".json"))
	if err := json.Unmarshal(raw, &facts); err != nil || facts.Sign != "Libra" {
		t.Fatalf("facts file: %v %+v", err, facts.Sign)
	}
	page, err := os.ReadFile(filepath.Join(out, "ru", "2026", "10", "libra.html"))
	if err != nil {
		t.Fatal("ru page must exist:", err)
	}
	html := string(page)
	for _, want := range []string{
		`<link rel="canonical" href="https://astrolytix.com/astro/ru/2026/10/libra.html">`,
		`<link rel="alternate" hreflang="ru" href="https://astrolytix.com/astro/ru/2026/10/libra.html">`,
		`<link rel="alternate" hreflang="x-default" href="https://astrolytix.com/astro/ru/2026/10/libra.html">`,
		"<h1>Весы: октябрь 2026 по лунному знаку</h1>",
		`<p class="lead">Месяц для Весов.</p>`,
		"Дом от Луны", "<td>Солнце</td><td>12 → 1</td><td>Дева → Весы</td>", "<td>Венера (R)</td>",
		"Ключевые даты", "Солнце входит в Весы (дом 1)", "Новолуние (Амавасья) · Дева (дом 12)",
		"<h2>Обзор</h2>\n<p>Юпитер в 10-м доме &lt;b&gt;не&lt;/b&gt; тег.</p>",
		`class="btn ios" rel="noopener" href="https://astrolytix.com/go/ios/"`,
		"Прогноз по лунному знаку",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("sign page lacks %s", want)
		}
	}
	if strings.Contains(html, `hreflang="en"`) {
		t.Error("hreflang must not promise an English page that does not exist")
	}
	if _, err := os.Stat(filepath.Join(out, "en", "2026", "10", "libra.html")); err == nil {
		t.Error("no text → no page")
	}
	hub, _ := os.ReadFile(filepath.Join(out, "ru", "2026", "10", "index.html"))
	if !strings.Contains(string(hub), "По лунному знаку") || !strings.Contains(string(hub), `href="https://astrolytix.com/astro/ru/2026/10/libra.html">Весы</a>`) {
		t.Error("ru month hub must link the Libra page")
	}
	enHub, _ := os.ReadFile(filepath.Join(out, "en", "2026", "10", "index.html"))
	if strings.Contains(string(enHub), "By Moon sign") {
		t.Error("en month hub must not list sign pages it does not have")
	}
	// Every rendered sign page links a month hub that exists and is listed by it.
	for _, rel := range []string{"2026/10/libra.html", "2026/12/aries.html"} {
		pg, err := os.ReadFile(filepath.Join(out, "ru", rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		hubRel := filepath.Dir(rel) + "/index.html"
		if !strings.Contains(string(pg), `href="https://astrolytix.com/astro/ru/`+filepath.Dir(rel)+`/"`) {
			t.Errorf("%s lacks its month link", rel)
		}
		hubHTML, err := os.ReadFile(filepath.Join(out, "ru", hubRel))
		if err != nil {
			t.Fatalf("month hub for %s missing: %v", rel, err)
		}
		if !strings.Contains(string(hubHTML), `href="https://astrolytix.com/astro/ru/`+rel+`"`) {
			t.Errorf("hub %s does not list %s", hubRel, rel)
		}
	}
	sm, _ := os.ReadFile(filepath.Join(out, "sitemap.xml"))
	if !strings.Contains(string(sm), "<loc>https://astrolytix.com/astro/ru/2026/10/libra.html</loc>") || strings.Contains(string(sm), "/astro/en/2026/10/libra.html") {
		t.Error("sitemap lists exactly the rendered sign pages")
	}
	// Corrupt text must fail loudly, not vanish.
	os.WriteFile(filepath.Join(out, seoTextDir, "ru", key+".json"), []byte("{"), 0o644)
	if _, err := writeSeoSiteAt(out, data, now); err == nil {
		t.Error("corrupt text file must fail the run")
	}
	writeText(t, out, "ru", key, "Месяц для Весов.")
	// Unchanged text on a later day keeps the page's lastmod.
	n2, err := writeSeoSiteAt(out, data, now.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if n2 != n1 { // the day window ends at the sign-facts horizon: nothing new on day 2
		t.Errorf("file count changed %d → %d", n1, n2)
	}
	sm2, _ := os.ReadFile(filepath.Join(out, "sitemap.xml"))
	if !strings.Contains(string(sm2), "<loc>https://astrolytix.com/astro/ru/2026/10/libra.html</loc><lastmod>2026-10-12</lastmod>") {
		t.Error("sign page lastmod must stay at its first date")
	}
}
