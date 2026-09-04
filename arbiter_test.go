package main

import "testing"

func TestArbiterFeatureDisabled(t *testing.T) {
	cases := []struct {
		feature, list string
		want          bool
	}{
		{"ayurveda", "", false},
		{"ayurveda", "ayurveda", true},
		{"ayurveda", "predefined_question, Ayurveda ,horoscope", true},
		{"horoscope", "predefined_question,ayurveda", false},
		{"", "ayurveda", false},
		{"chat", "chats", false},
	}
	for _, c := range cases {
		if got := arbiterFeatureDisabled(c.feature, c.list); got != c.want {
			t.Errorf("arbiterFeatureDisabled(%q,%q)=%v want %v", c.feature, c.list, got, c.want)
		}
	}
}

func TestParseArbiterJSONToleratesFences(t *testing.T) {
	reply := "Sure.\n```json\n{\"changed\": true, \"changes\": [\"a\"], \"corrected\": \"text\"}\n```"
	changed, changes, corrected, ok := parseArbiterJSON(reply)
	if !ok || !changed || len(changes) != 1 || corrected != "text" {
		t.Fatalf("unexpected parse: %v %v %q %v", changed, changes, corrected, ok)
	}
	if _, _, _, ok := parseArbiterJSON("no json here"); ok {
		t.Fatal("expected !ok on prose without JSON")
	}
}

func TestLooksLikeRunaway(t *testing.T) {
	orig := "abcdefghij"
	if looksLikeRunaway(orig, "abcdefghijk") {
		t.Fatal("near-identical length must not be runaway")
	}
	if !looksLikeRunaway(orig, "abc") || !looksLikeRunaway(orig, orig+orig) {
		t.Fatal("halved or doubled length must be runaway")
	}
}

func TestParseArbiterJSONFullOmitted(t *testing.T) {
	reply := `{"changed": false, "changes": [], "omitted": ["Gaja Kesari yoga (Moon-Jupiter kendra) not mentioned", "Saturn retrograde in the 10th"], "corrected": "text"}`
	changed, changes, omitted, corrected, ok := parseArbiterJSONFull(reply)
	if !ok || changed || len(changes) != 0 || corrected != "text" {
		t.Fatalf("unexpected parse: %v %v %q %v", changed, changes, corrected, ok)
	}
	if len(omitted) != 2 || omitted[1] != "Saturn retrograde in the 10th" {
		t.Fatalf("omitted not parsed: %v", omitted)
	}
	// Absent / null "omitted" is an empty list, never an error.
	_, _, omitted, _, ok = parseArbiterJSONFull(`{"changed": true, "changes": ["x"], "corrected": "y"}`)
	if !ok || len(omitted) != 0 {
		t.Fatalf("absent omitted must be empty, ok: %v %v", omitted, ok)
	}
	_, _, omitted, _, ok = parseArbiterJSONFull(`{"changed": true, "changes": ["x"], "omitted": null, "corrected": "y"}`)
	if !ok || len(omitted) != 0 {
		t.Fatalf("null omitted must be empty, ok: %v %v", omitted, ok)
	}
}
