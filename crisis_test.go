package main

import (
	"strings"
	"testing"
)

func TestDetectCrisisHits(t *testing.T) {
	cases := map[string]string{ // input → expected lang
		"Я больше не хочу жить, всё бессмысленно":  "ru",
		"Иногда думаю про суицид":                  "ru",
		"sometimes I just want to die":             "en",
		"I've been thinking about suicide lately":  "en",
		"no quiero vivir más":                      "es",
		"je ne veux plus vivre comme ça":           "fr",
		"ich will sterben":                         "de",
		"voglio morire":                            "it",
		"não quero mais viver assim":               "pt",
		"我最近总是想死":                                  "zh",
		"もう死にたいです":                                 "ja",
		"요즘 죽고 싶다는 생각이 들어요":                        "ko",
		"لا أريد أن أعيش بعد الآن":                 "ar",
		"मैं अब जीना नहीं चाहता":                    "hi",
	}
	for input, wantLang := range cases {
		hit, lang := detectCrisis(input)
		if !hit {
			t.Errorf("expected crisis hit for %q", input)
			continue
		}
		if lang != wantLang {
			t.Errorf("input %q: lang = %q, want %q", input, lang, wantLang)
		}
	}
}

func TestDetectCrisisNegatives(t *testing.T) {
	for _, input := range []string{
		"",
		"Сегодня был тяжёлый день на работе, я очень устала",
		"What does Saturn in the 8th house mean for my career?",
		"Расскажи про мой лунный знак",
		"El tránsito de Marte me tiene con mucha energía",
	} {
		if hit, lang := detectCrisis(input); hit {
			t.Errorf("false positive for %q (lang=%s)", input, lang)
		}
	}
}

func TestLastUserMessage(t *testing.T) {
	msgs := []map[string]string{
		{"role": "system", "content": "you are an astrologer"},
		{"role": "user", "content": "old message"},
		{"role": "assistant", "content": "reply"},
		{"role": "user", "content": "current message"},
	}
	if got := lastUserMessage(msgs); got != "current message" {
		t.Errorf("lastUserMessage = %q, want %q", got, "current message")
	}
	if got := lastUserMessage(nil); got != "" {
		t.Errorf("lastUserMessage(nil) = %q, want empty", got)
	}
}

func TestCrisisNoticeContent(t *testing.T) {
	// Russian: own line first, standard roster present, no duplicate number.
	n := crisisNotice("ru")
	if !strings.Contains(n, "Похоже, вам сейчас очень тяжело") {
		t.Error("ru notice missing localized header")
	}
	if strings.Count(n, "8-800-2000-122") != 1 {
		t.Errorf("ru notice should contain its hotline exactly once:\n%s", n)
	}
	lines := strings.Split(n, "\n")
	if !strings.Contains(lines[2], "8-800-2000-122") {
		t.Errorf("ru hotline must be the first number line, got %q", lines[2])
	}
	for _, must := range []string{"988", "12356", "109", "13 11 14", "1737", "188", "800-4673", "920033360", "14416", "116 123"} {
		if !strings.Contains(n, must) {
			t.Errorf("ru notice missing standard hotline %q", must)
		}
	}
	// Unknown language falls back to the English header.
	if !strings.Contains(crisisNotice("xx"), "You don't have to face this alone") {
		t.Error("unknown lang must fall back to English header")
	}
	// Arabic shows both KSA and UAE first.
	ar := crisisNotice("ar")
	if strings.Count(ar, "920033360") != 1 || strings.Count(ar, "800-4673") != 1 {
		t.Errorf("ar notice must list KSA and UAE exactly once:\n%s", ar)
	}
}
