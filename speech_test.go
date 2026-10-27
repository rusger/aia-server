package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setupSpeechTest gives each test a fresh ledger, fresh breakers and fake
// Azure / Groq endpoints — no test ever reaches a real provider.
func setupSpeechTest(t *testing.T, azure, groq http.HandlerFunc) {
	t.Helper()
	var err error
	analyticsDB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	analyticsDB.SetMaxOpenConns(1)
	speechTableOnce = sync.Once{}
	speechTTSBreaker = &speechBreaker{}
	speechSTTBreaker = &speechBreaker{}
	speechSTTSlot = make(chan struct{}, 1)

	oldTTS, oldSTT, oldGroq, oldWav := speechAzureTTSURL, speechAzureSTTURL, speechGroqURL, speechToWav
	az := httptest.NewServer(azure)
	gq := httptest.NewServer(groq)
	speechAzureTTSURL = func(string) string { return az.URL + "/tts" }
	speechAzureSTTURL = func(string) string { return az.URL + "/stt" }
	speechGroqURL = gq.URL + "/groq"
	speechToWav = func(in []byte) ([]byte, error) { return in, nil }
	t.Cleanup(func() {
		az.Close()
		gq.Close()
		speechAzureTTSURL, speechAzureSTTURL, speechGroqURL, speechToWav = oldTTS, oldSTT, oldGroq, oldWav
		analyticsDB.Close()
		analyticsDB = nil
	})
}

func speechTestConfig() speechConfig {
	return speechConfig{key: "test-key", region: "germanywestcentral", tier: "F0",
		ttsMonth: 250000, ttsDevDay: 15000, sttMonth: 16200, sttDevDay: 600, groqMonth: 36000}
}

// wavOf returns a fake 16 kHz mono s16 wav of the given length.
func wavOf(seconds float64) []byte {
	return make([]byte, 44+int(seconds*32000))
}

func speechRows(t *testing.T, where string) (n, units int) {
	t.Helper()
	if err := analyticsDB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(units), 0) FROM speech_usage WHERE `+where).Scan(&n, &units); err != nil {
		t.Fatal(err)
	}
	return
}

func failHandler(t *testing.T, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("%s must not be called", name)
		w.WriteHeader(500)
	}
}

func TestSpeechLangAndVoices(t *testing.T) {
	for in, want := range map[string]string{"ru": "ru", "ru-RU": "ru", "pt_BR": "pt", " EN ": "en", "tr": "", "": ""} {
		if got := speechLang(in); got != want {
			t.Errorf("speechLang(%q) = %q, want %q", in, got, want)
		}
	}
	if len(speechVoices) != 16 {
		t.Fatalf("want a voice for each of the 16 app languages, got %d", len(speechVoices))
	}
	for l, v := range speechVoices {
		if !strings.HasPrefix(v.name, v.locale+"-") || !strings.HasSuffix(v.name, "Neural") {
			t.Errorf("%s: voice %q does not match locale %q", l, v.name, v.locale)
		}
	}
	if speechVoices["pt"].locale != "pt-BR" {
		t.Errorf("pt must use the Brazilian voice")
	}
}

func TestSpeechAzureOnlyOnF0(t *testing.T) {
	cfg := speechTestConfig()
	for tier, want := range map[string]string{"F0": "", "S0": "azure_not_f0", "": "azure_not_f0", "f0 ": "azure_not_f0"} {
		cfg.tier = tier
		if got := cfg.azureProblem(); got != want {
			t.Errorf("tier %q: got %q, want %q", tier, got, want)
		}
	}
	cfg = speechTestConfig()
	cfg.key = ""
	if cfg.azureProblem() != "azure_no_key" {
		t.Error("no key must switch Azure off")
	}
	cfg = speechTestConfig()
	cfg.region = "evil.com/x"
	if cfg.azureProblem() != "azure_bad_region" {
		t.Error("a region that is not a plain name must switch Azure off")
	}
}

func TestSpeechEnvCeilings(t *testing.T) {
	t.Setenv("APP_TTS_MONTH_CHARS", "900000")
	t.Setenv("APP_STT_MONTH_SECONDS", "99999")
	t.Setenv("APP_TTS_DEVICE_DAY_CHARS", "-5")
	cfg := speechConfigFromEnv()
	if cfg.ttsMonth != speechTTSMonthCeiling || cfg.sttMonth != speechSTTMonthCeiling {
		t.Errorf("ceilings not applied: tts %d stt %d", cfg.ttsMonth, cfg.sttMonth)
	}
	if cfg.ttsDevDay != speechTTSDeviceDay {
		t.Errorf("negative env must fall back to default, got %d", cfg.ttsDevDay)
	}
}

func TestSpeechTTSSuccessBooksChars(t *testing.T) {
	var gotSSML, gotFormat, gotKey string
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSSML, gotFormat, gotKey = string(b), r.Header.Get("X-Microsoft-OutputFormat"), r.Header.Get("Ocp-Apim-Subscription-Key")
		w.Write([]byte("MP3DATA"))
	}, failHandler(t, "groq"))
	audio, why := speechSynthesize("dev1", "  Привет <мир> &  ", "ru-RU", speechTestConfig(), time.Now())
	if why != "" || string(audio) != "MP3DATA" {
		t.Fatalf("got %q / %q", audio, why)
	}
	if !strings.Contains(gotSSML, "ru-RU-SvetlanaNeural") || !strings.Contains(gotSSML, "Привет &lt;мир&gt; &amp;") {
		t.Errorf("SSML not built/escaped: %s", gotSSML)
	}
	if gotFormat != speechTTSOutputFormat || gotKey != "test-key" {
		t.Errorf("headers: format %q key %q", gotFormat, gotKey)
	}
	n, units := speechRows(t, `kind='tts' AND provider='azure' AND ok=1 AND source='app' AND device_id='dev1'`)
	if n != 1 || units != len([]rune("Привет <мир> &")) {
		t.Errorf("ledger: %d rows, %d units", n, units)
	}
}

func TestSpeechTTSRefusalsNeverCallAzure(t *testing.T) {
	setupSpeechTest(t, failHandler(t, "azure"), failHandler(t, "groq"))
	cfg := speechTestConfig()
	now := time.Now()
	if _, why := speechSynthesize("", "hi", "en", cfg, now); why != "no_device" {
		t.Errorf("no device: %q", why)
	}
	if _, why := speechSynthesize("d", "hi", "tr", cfg, now); why != "unsupported_lang" {
		t.Errorf("lang: %q", why)
	}
	if _, why := speechSynthesize("d", "   ", "en", cfg, now); why != "empty_text" {
		t.Errorf("empty: %q", why)
	}
	if _, why := speechSynthesize("d", strings.Repeat("я", speechTTSMaxRunes+1), "ru", cfg, now); why != "text_too_long" {
		t.Errorf("long: %q", why)
	}
	s0 := cfg
	s0.tier = "S0"
	if _, why := speechSynthesize("d", "hi", "en", s0, now); why != "azure_not_f0" {
		t.Errorf("S0: %q", why)
	}
	small := cfg
	small.ttsDevDay = 3
	if _, why := speechSynthesize("d", "hello", "en", small, now); why != "device_day_limit" {
		t.Errorf("device day: %q", why)
	}
	small = cfg
	small.ttsMonth = 3
	if _, why := speechSynthesize("d", "hello", "en", small, now); why != "azure_month_limit" {
		t.Errorf("month: %q", why)
	}
	if n, _ := speechRows(t, "1=1"); n != 0 {
		t.Errorf("refusals must not book anything, got %d rows", n)
	}
}

func TestSpeechTTSMonthCapCountsAllDevices(t *testing.T) {
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("A")) }, failHandler(t, "groq"))
	cfg := speechTestConfig()
	cfg.ttsMonth = 8
	now := time.Now()
	if _, why := speechSynthesize("a", "hello", "en", cfg, now); why != "" {
		t.Fatal(why)
	}
	if _, why := speechSynthesize("b", "hello", "en", cfg, now); why != "azure_month_limit" {
		t.Errorf("second device must hit the shared month cap, got %q", why)
	}
}

func TestSpeechTTS429PausesAndAuthErrorSwitchesOff(t *testing.T) {
	var calls int32
	status := int32(http.StatusTooManyRequests)
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(int(atomic.LoadInt32(&status)))
	}, failHandler(t, "groq"))
	cfg := speechTestConfig()
	now := time.Now()
	if _, why := speechSynthesize("d", "hi", "en", cfg, now); why != "azure_http_429" {
		t.Fatalf("got %q", why)
	}
	if _, why := speechSynthesize("d", "hi", "en", cfg, now.Add(time.Minute)); why != "azure_cooldown" {
		t.Errorf("must pause after 429, got %q", why)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("no retry allowed: %d calls", calls)
	}
	// After the pause Azure is tried again; a 401 then switches it off for good.
	atomic.StoreInt32(&status, http.StatusUnauthorized)
	later := now.Add(speechCooldown + time.Minute)
	if _, why := speechSynthesize("d", "hi", "en", cfg, later); why != "azure_http_401" {
		t.Fatalf("got %q", why)
	}
	if _, why := speechSynthesize("d", "hi", "en", cfg, later.Add(24*time.Hour)); why != "azure_auth_off" {
		t.Errorf("401 must switch off until restart, got %q", why)
	}
	// Failed calls keep their reservation (over-count is the safe side).
	if n, _ := speechRows(t, "ok=0"); n != 2 {
		t.Errorf("want 2 failed booked rows, got %d", n)
	}
}

func TestSpeechTTSRateWindow(t *testing.T) {
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("A")) }, failHandler(t, "groq"))
	cfg := speechTestConfig()
	now := time.Now()
	for i := 0; i < speechTTSPerMinute; i++ {
		if _, why := speechSynthesize("d", "hi", "en", cfg, now); why != "" {
			t.Fatalf("call %d: %q", i, why)
		}
	}
	if _, why := speechSynthesize("d", "hi", "en", cfg, now); why != "rate_limited" {
		t.Errorf("11th call in a minute: %q", why)
	}
	if _, why := speechSynthesize("d", "hi", "en", cfg, now.Add(61*time.Second)); why != "" {
		t.Errorf("window must slide: %q", why)
	}
}

func TestSpeechSTTAzureSuccessAndNoMatch(t *testing.T) {
	var lang, ctype string
	reply := `{"RecognitionStatus":"Success","DisplayText":"Какой у меня асцендент?"}`
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) {
		lang, ctype = r.URL.Query().Get("language"), r.Header.Get("Content-Type")
		w.Write([]byte(reply))
	}, failHandler(t, "groq"))
	cfg := speechTestConfig()
	res := speechTranscribe("d", "ru", wavOf(4.2), cfg, time.Now())
	if !res.Success || res.Text != "Какой у меня асцендент?" || res.Provider != "azure" {
		t.Fatalf("got %+v", res)
	}
	if lang != "ru-RU" || !strings.HasPrefix(ctype, "audio/wav") {
		t.Errorf("request: lang %q type %q", lang, ctype)
	}
	if _, units := speechRows(t, "kind='stt' AND provider='azure' AND ok=1"); units != 5 {
		t.Errorf("4.2 s must book 5 s, got %d", units)
	}
	reply = `{"RecognitionStatus":"NoMatch"}`
	res = speechTranscribe("d", "ru", wavOf(2), cfg, time.Now())
	if !res.Success || res.Text != "" {
		t.Errorf("NoMatch must be an empty success, got %+v", res)
	}
	if len(speechSTTSlot) != 0 {
		t.Error("STT slot leaked")
	}
}

func TestSpeechSTTFallsBackToGroq(t *testing.T) {
	var groqCalls int32
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&groqCalls, 1)
		if r.Header.Get("Authorization") != "Bearer groq-key" {
			t.Errorf("groq auth header missing")
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil || r.FormValue("model") != speechGroqModel || r.FormValue("language") != "en" {
			t.Errorf("groq form: %v model=%q lang=%q", err, r.FormValue("model"), r.FormValue("language"))
		}
		w.Write([]byte(`{"text":" when is my next dasha? "}`))
	})
	cfg := speechTestConfig()
	cfg.groqKey = "groq-key"
	now := time.Now()
	res := speechTranscribe("d", "en", wavOf(3), cfg, now)
	if !res.Success || res.Text != "when is my next dasha?" || res.Provider != "groq" {
		t.Fatalf("got %+v", res)
	}
	// Azure is now paused: the next clip goes straight to Groq.
	res = speechTranscribe("d", "en", wavOf(3), cfg, now.Add(time.Minute))
	if res.Provider != "groq" || atomic.LoadInt32(&groqCalls) != 2 {
		t.Errorf("got %+v, groq calls %d", res, groqCalls)
	}
	if n, _ := speechRows(t, "provider='azure'"); n != 1 {
		t.Errorf("Azure must be called once (no retry during pause), rows %d", n)
	}
	if len(speechSTTSlot) != 0 {
		t.Error("STT slot leaked")
	}
}

func TestSpeechSTTWithoutGroqKeyFailsCleanly(t *testing.T) {
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, failHandler(t, "groq"))
	res := speechTranscribe("d", "en", wavOf(2), speechTestConfig(), time.Now())
	if res.Success || res.Reason != "azure_http_500" {
		t.Errorf("got %+v", res)
	}
}

func TestSpeechSTTLimits(t *testing.T) {
	setupSpeechTest(t, failHandler(t, "azure"), failHandler(t, "groq"))
	cfg := speechTestConfig()
	cfg.groqKey = "groq-key"
	now := time.Now()
	if res := speechTranscribe("", "en", wavOf(5), cfg, now); res.Success || res.Reason != "no_device" {
		t.Errorf("no device: %+v", res)
	}
	if res := speechTranscribe("d", "en", wavOf(0.1), cfg, now); !res.Success || res.Reason != "too_short" {
		t.Errorf("short: %+v", res)
	}
	if res := speechTranscribe("d", "en", wavOf(70), cfg, now); res.Success || res.Reason != "too_long" {
		t.Errorf("long: %+v", res)
	}
	cfg.sttDevDay = 2
	// The device's own day is spent: no paid Groq call either.
	if res := speechTranscribe("d", "en", wavOf(5), cfg, now); res.Reason != "device_day_limit" {
		t.Errorf("device day: %+v", res)
	}
	if len(speechSTTSlot) != 0 {
		t.Error("STT slot leaked")
	}
}

func TestSpeechSTTBusySlotGoesToGroq(t *testing.T) {
	setupSpeechTest(t, failHandler(t, "azure"), func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"text":"ok"}`))
	})
	cfg := speechTestConfig()
	cfg.groqKey = "groq-key"
	speechSTTSlot <- struct{}{} // another request holds Azure
	defer func() { <-speechSTTSlot }()
	start := time.Now()
	res := speechTranscribe("d", "en", wavOf(2), cfg, start)
	if res.Provider != "groq" {
		t.Errorf("got %+v", res)
	}
	if time.Since(start) < speechSTTBusyWait {
		t.Errorf("must wait for the slot before falling back")
	}
}

func TestSpeechHandlers(t *testing.T) {
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tts") {
			w.Write([]byte("MP3"))
			return
		}
		w.Write([]byte(`{"RecognitionStatus":"Success","DisplayText":"hello"}`))
	}, failHandler(t, "groq"))
	t.Setenv("AZURE_SPEECH_KEY", "k")
	t.Setenv("AZURE_SPEECH_REGION", "germanywestcentral")
	t.Setenv("AZURE_SPEECH_TIER", "F0")
	ctx := context.WithValue(context.Background(), "claims", &JWTClaims{DeviceID: "dev"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/speech/tts", strings.NewReader(`{"text":"hi","lang":"en"}`)).WithContext(ctx)
	speechTTSHandler(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "audio/mpeg" || rec.Body.String() != "MP3" {
		t.Errorf("tts: %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/speech/tts", strings.NewReader(`{"text":"hi","lang":"tr"}`)).WithContext(ctx)
	speechTTSHandler(rec, req)
	var refusal map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &refusal)
	if rec.Code != 503 || refusal["fallback"] != true || refusal["reason"] != "unsupported_lang" {
		t.Errorf("tts refusal: %d %v", rec.Code, refusal)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/speech/stt?lang=en", bytes.NewReader(wavOf(2))).WithContext(ctx)
	speechSTTHandler(rec, req)
	var res speechSTTResult
	json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != 200 || !res.Success || res.Text != "hello" {
		t.Errorf("stt: %d %+v", rec.Code, res)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/speech/stt?lang=en", bytes.NewReader(make([]byte, speechSTTMaxBytes+1))).WithContext(ctx)
	speechSTTHandler(rec, req)
	if rec.Code != 400 {
		t.Errorf("oversized upload: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	speechTTSHandler(rec, httptest.NewRequest("POST", "/api/speech/tts", strings.NewReader(`{}`)))
	if rec.Code != 401 {
		t.Errorf("no claims: %d", rec.Code)
	}
}

func TestAdminSpeechUsage(t *testing.T) {
	setupSpeechTest(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("A")) }, failHandler(t, "groq"))
	old := ADMIN_SECRET_KEY
	ADMIN_SECRET_KEY = "s3cret"
	t.Cleanup(func() { ADMIN_SECRET_KEY = old })
	speechSynthesize("a", "hello", "en", speechTestConfig(), time.Now())
	speechSynthesize("b", "hey", "en", speechTestConfig(), time.Now())

	rec := httptest.NewRecorder()
	adminGetSpeechUsage(rec, httptest.NewRequest("GET", "/api/admin/speech-usage?admin_secret=wrong", nil))
	if rec.Code != 403 {
		t.Errorf("bad secret: %d", rec.Code)
	}
	oldEmails := ADMIN_EMAILS
	ADMIN_EMAILS = []string{"admin@example.com"}
	t.Cleanup(func() { ADMIN_EMAILS = oldEmails })
	email := "admin@example.com"
	rec = httptest.NewRecorder()
	adminGetSpeechUsage(rec, httptest.NewRequest("GET", "/api/admin/speech-usage?days=7&admin_secret=s3cret&admin_email="+email, nil))
	var out struct {
		Success bool
		Rows    []struct {
			Kind, Provider        string
			Calls, Units, Devices int
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || !out.Success || len(out.Rows) != 1 || out.Rows[0].Units != 8 || out.Rows[0].Devices != 2 {
		t.Errorf("summary: %d %s", rec.Code, rec.Body.String())
	}
}

// The real converter: a 3 s 44.1 kHz stereo m4a (what the phone records is
// similar) must come out as 16 kHz mono s16 wav of the same length.
func TestSpeechFFmpegToWav16k(t *testing.T) {
	radioNeedFFmpeg(t)
	src := filepath.Join(t.TempDir(), "clip.m4a")
	if out, err := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi",
		"-i", "sine=frequency=440:duration=3:sample_rate=44100", "-ac", "2", "-c:a", "aac", src).CombinedOutput(); err != nil {
		t.Fatalf("make m4a: %v %s", err, out)
	}
	in, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	wav, err := ffmpegToWav16k(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(wav[:4]) != "RIFF" || binary.LittleEndian.Uint16(wav[22:]) != 1 || binary.LittleEndian.Uint32(wav[24:]) != 16000 {
		t.Fatalf("not 16 kHz mono wav: % x", wav[:28])
	}
	if s := speechWavSeconds(wav); s < 2.9 || s > 3.1 {
		t.Errorf("duration %.2f s, want ≈ 3", s)
	}
	long := filepath.Join(t.TempDir(), "long.m4a")
	if out, err := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi",
		"-i", "sine=frequency=440:duration=64:sample_rate=16000", "-c:a", "aac", long).CombinedOutput(); err != nil {
		t.Fatalf("make long m4a: %v %s", err, out)
	}
	in, _ = os.ReadFile(long)
	if wav, err = ffmpegToWav16k(in); err != nil || speechWavSeconds(wav) > speechSTTMaxSeconds {
		t.Errorf("64 s clip must be cut under the limit: err %v, %.2f s", err, speechWavSeconds(wav))
	}
	if _, err := ffmpegToWav16k([]byte("not audio")); err == nil {
		t.Error("garbage must fail to convert")
	}
}
