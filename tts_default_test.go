package main

import (
	"os"
	"testing"
)

// TestMain: the package's tests were written against the speech endpoint (fake ttsFetch, legacy nova/onyx voices,
// fixed cache keys). Since 28.11.2026 realtime is the production default (A119), so the suite pins
// TTS_BACKEND=speech unless the runner set it; the default itself is covered by TestTTSBackendDefaultRealtime.
func TestMain(m *testing.M) {
	if _, ok := os.LookupEnv("TTS_BACKEND"); !ok {
		os.Setenv("TTS_BACKEND", "speech")
	}
	os.Exit(m.Run())
}

// Unset/empty TTS_BACKEND → realtime with the owner's voices (25.11.2026); only an explicit "speech" keeps the
// endpoint whose model gpt-4o-mini-tts shuts down on 06.01.2027.
func TestTTSBackendDefaultRealtime(t *testing.T) {
	t.Setenv("TTS_VOICE_MAP", "")
	for _, c := range []struct {
		env  string
		want bool
	}{{"", true}, {"realtime", true}, {"REALTIME", true}, {"typo", true}, {"speech", false}, {" Speech ", false}} {
		t.Setenv("TTS_BACKEND", c.env)
		if got := ttsBackendRealtime(); got != c.want {
			t.Fatalf("TTS_BACKEND=%q: realtime=%v, want %v", c.env, got, c.want)
		}
	}
	t.Setenv("TTS_BACKEND", "")
	for _, c := range []struct{ g, lang, want string }{{"f", "ru", "marin"}, {"m", "ru", "cedar"}, {"f", "en", "shimmer"}, {"m", "en", "ash"}, {"m", "hi", "cedar"}} {
		if got := ttsVoiceFor(c.g, c.lang); got != c.want {
			t.Fatalf("default realtime voice %s/%s = %s, want %s", c.g, c.lang, got, c.want)
		}
	}
	t.Setenv("TTS_BACKEND", "speech")
	if got := ttsVoiceFor("f", "ru"); got != "nova" {
		t.Fatalf("speech backend without map must keep legacy nova, got %s", got)
	}
}
