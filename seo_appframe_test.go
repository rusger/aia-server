package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A212 canon: every generated content page — whatever its type — has the
// read-more link at the end of its first paragraph, then the app frame, then
// the anchor; hubs (lists of links) have none. A new page type without a
// lead paragraph turns this red.
func TestSeoAppFrameOnEveryContentPage(t *testing.T) {
	out := t.TempDir()
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	data := fixtureWithRetro(t)
	writeText(t, out, "ru", factsKey(2026, 10, "libra"), "Месяц для Весов.")
	if _, err := writeSeoSiteAt(out, data, now); err != nil {
		t.Fatal(err)
	}
	pages, hubs := 0, 0
	kinds := map[string]bool{}
	err := filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		rel, _ := filepath.Rel(out, p)
		if rel == "index.html" { // root language list, not rendered by the layout
			return nil
		}
		raw, _ := os.ReadFile(p)
		s := string(raw)
		parts := strings.SplitN(rel, string(filepath.Separator), 2)
		isHub := parts[1] == "index.html" || (strings.HasSuffix(parts[1], "/index.html") && strings.Count(parts[1], "/") == 2)
		if isHub {
			hubs++
			if strings.Contains(s, `<section class="cta cta-top">`) || strings.Contains(s, `class="more"`) {
				t.Errorf("%s: hub got the app frame", rel)
			}
			return nil
		}
		pages++
		kinds[pageKind(parts[1])] = true
		lead := strings.Index(s, `<p class="lead">`)
		more := strings.Index(s, `<a class="more" href="#`+seoMoreAnchor+`">`)
		frame := strings.Index(s, `<section class="cta cta-top">`)
		anchor := strings.Index(s, `<div id="`+seoMoreAnchor+`"></div>`)
		leadEnd := -1
		if lead >= 0 {
			leadEnd = lead + strings.Index(s[lead:], "</p>")
		}
		if lead < 0 || !(lead < more && more < leadEnd && leadEnd < frame && frame < anchor) {
			t.Errorf("%s: want lead → read more → frame → anchor (lead %d more %d frame %d anchor %d)", rel, lead, more, frame, anchor)
		}
		if !strings.Contains(s, seoGoIOS+"?from=top") || !strings.Contains(s, seoGoAndroid+"?from=top") {
			t.Errorf("%s: frame store links must go through /go/ with from=top", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"year", "day", "today", "sign", "razbor"} {
		if !kinds[k] {
			t.Errorf("no %s page among %d checked — the test must see every type", k, pages)
		}
	}
	if hubs == 0 {
		t.Error("no hubs checked")
	}
}

func pageKind(rel string) string {
	switch {
	case strings.HasPrefix(rel, "today/"):
		return "today"
	case strings.Count(rel, "/") == 2 && strings.HasSuffix(rel, ".html") && len(filepath.Base(rel)) == len("01.html"):
		return "day"
	case strings.Count(rel, "/") == 2:
		return "sign"
	case strings.Count(rel, "/") == 1:
		for _, y := range []string{"transits", "retrograde-", "moon-phases", "eclipses"} {
			if strings.Contains(rel, y) {
				return "year"
			}
		}
		return "razbor"
	}
	return "other"
}

func TestSeoAppFrameLangs(t *testing.T) {
	for _, m := range []map[string]string{seoAppTitle, seoAppDesc, seoReadMore} {
		for _, l := range seoLangs {
			if m[l] == "" {
				t.Errorf("missing %s", l)
			}
		}
	}
	if seoReadMore["ru"] != "Читать далее ниже" {
		t.Error("ru must be the owner's words")
	}
	body, ok := withAppFrame("it", "<h1>x</h1>\n<p class=\"lead\">Primo.</p>\n<p class=\"lead\">Secondo.</p>")
	if !ok || strings.Count(body, `<section class="cta cta-top">`) != 1 || !strings.Contains(body, "Primo. <a class=\"more\"") {
		t.Errorf("frame must follow the FIRST lead only: %s", body)
	}
	if _, ok := withAppFrame("it", "<h1>x</h1><ul></ul>"); ok {
		t.Error("no lead, no frame")
	}
}

// The frame says what the site says: same strings as astrolytix/locales.
func TestSeoAppFrameStringsMatchSite(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, "aia", "astrolytix", "locales")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("astrolytix checkout not here")
	}
	for _, l := range seoLangs {
		raw, err := os.ReadFile(filepath.Join(dir, l+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var loc struct {
			FeatureDetails struct {
				Horoscopes struct{ Title, Desc string } `json:"horoscopes"`
			} `json:"featureDetails"`
		}
		if err := json.Unmarshal(raw, &loc); err != nil {
			t.Fatal(err)
		}
		if loc.FeatureDetails.Horoscopes.Title != seoAppTitle[l] || loc.FeatureDetails.Horoscopes.Desc != seoAppDesc[l] {
			t.Errorf("%s: frame text differs from the site's featureDetails.horoscopes", l)
		}
	}
}
