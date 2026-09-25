package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestTTSVoiceAndKey(t *testing.T) {
	if v := ttsVoiceFor("f", "ru"); v != "nova" {
		t.Fatalf("ru female: %s", v)
	}
	if v := ttsVoiceFor("m", "ru-RU"); v != "onyx" {
		t.Fatalf("ru male: %s", v)
	}
	if v := ttsVoiceFor("f", "en-US"); v != "shimmer" {
		t.Fatalf("en female: %s", v)
	}
	if v := ttsVoiceFor("male", "en"); v != "ash" {
		t.Fatalf("en male: %s", v)
	}
	if v := ttsVoiceFor("", ""); v != "nova" {
		t.Fatalf("default: %s", v)
	}
	k1 := ttsCacheKey(ttsModel, "nova", "ru", "Привет.  ")
	k2 := ttsCacheKey(ttsModel, "nova", "RU", "Привет.")
	if k1 != k2 {
		t.Fatal("key must ignore surrounding whitespace and lang case")
	}
	if ttsCacheKey(ttsModel, "onyx", "ru", "Привет.") == k1 {
		t.Fatal("another voice is another file")
	}
}

func TestTTSFinanceRate(t *testing.T) {
	// 520 chars ≈ $0.010 (measured); must NOT fall into the gpt-4o-mini text rate
	got := financeTokenCostUSD("gpt-4o-mini-tts", 520, 0, 0, true)
	if got < 0.009 || got > 0.011 {
		t.Fatalf("tts cost for 520 chars = %.5f, want ≈ 0.010", got)
	}
}

func TestTTSHandler(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("TTS_CACHE_DIR", dir)
	defer os.Unsetenv("TTS_CACHE_DIR")
	oldFetch, oldInjected := ttsFetch, ttsFetchInjected
	defer func() { ttsFetch, ttsFetchInjected = oldFetch, oldInjected }()
	calls := 0
	ttsFetch = func(model, voice, instructions, text string) ([]byte, error) {
		calls++
		if model != ttsModel || voice != "onyx" {
			t.Fatalf("unexpected model/voice: %s %s", model, voice)
		}
		return []byte(strings.Repeat("x", 5000)), nil
	}
	ttsFetchInjected = true
	claims := &JWTClaims{Email: "a@x", DeviceID: "dev1"}
	call := func(body string, c *JWTClaims) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/tts", strings.NewReader(body))
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), "claims", c))
		}
		w := httptest.NewRecorder()
		ttsHandler(w, r)
		return w
	}
	if w := call(`{"text":"Привет"}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: %d", w.Code)
	}
	if w := call(`{"text":"   "}`, claims); w.Code != http.StatusBadRequest {
		t.Fatalf("empty: %d", w.Code)
	}
	if w := call(`{"text":"`+strings.Repeat("а", ttsMaxChars+1)+`"}`, claims); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too long: %d", w.Code)
	}
	w := call(`{"text":"Вы соединяете чуткость и стойкость.","gender":"m","lang":"ru"}`, claims)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "audio/mpeg" || w.Header().Get("X-TTS-Cache") != "miss" {
		t.Fatalf("first call: %d %s %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if w.Header().Get("X-TTS-Voice") != "onyx" {
		t.Fatalf("voice header: %s", w.Header().Get("X-TTS-Voice"))
	}
	w2 := call(`{"text":"Вы соединяете чуткость и стойкость.","gender":"m","lang":"ru"}`, claims)
	if w2.Code != http.StatusOK || w2.Header().Get("X-TTS-Cache") != "hit" {
		t.Fatalf("second call must be a cache hit: %d %s", w2.Code, w2.Header().Get("X-TTS-Cache"))
	}
	if calls != 1 {
		t.Fatalf("openai called %d times, want 1", calls)
	}
	if w2.Body.Len() != 5000 {
		t.Fatalf("cached bytes: %d", w2.Body.Len())
	}
}
