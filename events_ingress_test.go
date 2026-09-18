package main

import (
	"strings"
	"testing"
)

// Fast planets (Sun/Mercury/Venus/Mars) share the slow_ingress kind but must
// not be described as a "slow, long-lasting shift".

func TestIngressBodyFastVsSlow(t *testing.T) {
	_, fast := eventText("slow_ingress", `{"planet":"Mars","signIdx":3}`, "en")
	if fast != "Mars moves into Cancer — the accents shift for the coming weeks." {
		t.Fatalf("fast ingress body, got %q", fast)
	}
	title, slow := eventText("slow_ingress", `{"planet":"Jupiter","signIdx":3}`, "en")
	if title != "Jupiter enters Cancer" {
		t.Fatalf("ingress title, got %q", title)
	}
	if !strings.Contains(slow, "slow, long-lasting") {
		t.Fatalf("slow ingress must keep its body, got %q", slow)
	}
}

func TestIngressPlanetSetsAreDisjointAndNamed(t *testing.T) {
	for _, p := range slowIngressPlanets {
		if isFastIngressPlanet(p) {
			t.Fatalf("%s is both slow and fast", p)
		}
	}
	for _, p := range append(append([]string{}, slowIngressPlanets...), fastIngressPlanets...) {
		if _, ok := planetNames[p]; !ok {
			t.Fatalf("no localized name for %s", p)
		}
	}
}

func TestFastIngressBodyCoversAllLanguages(t *testing.T) {
	if len(fastIngressBodyTmpl) != len(ingressBodyTmpl) {
		t.Fatalf("fast body has %d languages, slow has %d", len(fastIngressBodyTmpl), len(ingressBodyTmpl))
	}
	for lang := range ingressBodyTmpl {
		v, ok := fastIngressBodyTmpl[lang]
		if !ok {
			t.Fatalf("fast body missing %s", lang)
		}
		if strings.Count(v, "%s") != 2 {
			t.Fatalf("fast body %s must carry planet+sign placeholders: %q", lang, v)
		}
	}
}
