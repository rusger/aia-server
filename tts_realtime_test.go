package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
)

// The key names /api/tts cache files AND the presenter video catalogue: it must
// not move when the backend changes (A119). Values computed from the code
// before A119 (25.11.2026).
func TestTTSCacheKeyPinned(t *testing.T) {
	if got := ttsCacheKey(ttsModel, "nova", "ru", "Сегодня Луна переходит в знак Рака."); got != "a87d6343d89aa06ec9cf495b8cdaefb4ceaaaeb6" {
		t.Fatalf("ru key moved: %s", got)
	}
	if got := ttsCacheKey(ttsModel, "ash", "en", "Hello from Astrolytix."); got != "c99ef964837afbd43157959a61e384f2b2cf9cc0" {
		t.Fatalf("en key moved: %s", got)
	}
}

// TTS_BACKEND unset → the /v1/audio/speech request is byte for byte the one
// sent before A119.
func TestTTSSpeechRequestUnchanged(t *testing.T) {
	t.Setenv("TTS_BACKEND", "")
	var body []byte
	var authz, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		authz, ctype = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		w.Write([]byte("ID3mp3"))
	}))
	defer srv.Close()
	oldURL, oldKey := ttsEndpoint, OPENAI_API_KEY
	ttsEndpoint, OPENAI_API_KEY = srv.URL, "sk-test-fake"
	defer func() { ttsEndpoint, OPENAI_API_KEY = oldURL, oldKey }()

	data, err := ttsFetch(ttsModel, "nova", "Calm.", "Привет, мир.")
	if err != nil || string(data) != "ID3mp3" {
		t.Fatalf("fetch: %q %v", data, err)
	}
	want := `{"input":"Привет, мир.","instructions":"Calm.","model":"gpt-4o-mini-tts","response_format":"mp3","voice":"nova"}`
	if string(body) != want {
		t.Fatalf("speech body changed:\n got %s\nwant %s", body, want)
	}
	if authz != "Bearer sk-test-fake" || ctype != "application/json" {
		t.Fatalf("headers: %q %q", authz, ctype)
	}
}

// rtFake — a Realtime API stand-in: records each session's events and answers
// with two audio deltas, the transcript in two deltas and response.done.
type rtFake struct {
	conns      atomic.Int32
	transcript string
	pcm        []byte
	mu         sync.Mutex
	sessions   [][]map[string]interface{}
	authz      string
}

func (f *rtFake) serve(t *testing.T) *httptest.Server {
	up := websocket.Upgrader{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.conns.Add(1)
		f.mu.Lock()
		f.authz = r.Header.Get("Authorization")
		f.mu.Unlock()
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer c.Close()
		var got []map[string]interface{}
		for i := 0; i < 3; i++ {
			var ev map[string]interface{}
			if err := c.ReadJSON(&ev); err != nil {
				t.Errorf("read: %v", err)
				return
			}
			got = append(got, ev)
		}
		f.mu.Lock()
		f.sessions = append(f.sessions, got)
		f.mu.Unlock()
		half, tr := len(f.pcm)/2, []rune(f.transcript)
		send := []map[string]interface{}{
			{"type": "session.updated"},
			{"type": "response.output_audio.delta", "delta": base64.StdEncoding.EncodeToString(f.pcm[:half])},
			{"type": "response.output_audio_transcript.delta", "delta": string(tr[:len(tr)/2])},
			{"type": "response.output_audio.delta", "delta": base64.StdEncoding.EncodeToString(f.pcm[half:])},
			{"type": "response.output_audio_transcript.delta", "delta": string(tr[len(tr)/2:])},
			{"type": "response.done", "response": map[string]interface{}{"status": "completed", "usage": map[string]interface{}{
				"input_tokens": 120, "output_tokens": 288, "total_tokens": 408,
				"input_token_details": map[string]interface{}{"cached_tokens": 64},
			}}},
		}
		for _, ev := range send {
			if err := c.WriteJSON(ev); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
		c.ReadMessage() // until the client hangs up after response.done
	}))
}

// setupRealtime: TTS_BACKEND=realtime against the fake, a fake encoder, a
// captured api_calls logger.
func setupRealtime(t *testing.T, f *rtFake) *[]string {
	t.Setenv("TTS_BACKEND", "realtime")
	t.Setenv("TTS_REALTIME_RETRY_ON_MISMATCH", "")
	t.Setenv("TTS_VOICE_MAP", "")
	srv := f.serve(t)
	oldURL, oldEnc, oldLog, oldKey, oldInj := ttsRealtimeURL, ttsPCMToMP3, ttsLogAPICall, OPENAI_API_KEY, ttsFetchInjected
	ttsRealtimeURL = "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/realtime?model=" + ttsRealtimeModel
	OPENAI_API_KEY = "sk-test-fake"
	ttsFetchInjected = true
	ttsPCMToMP3 = func(pcm []byte) ([]byte, error) { return append([]byte("MP3:"), pcm...), nil }
	var mu sync.Mutex
	logged := &[]string{}
	ttsLogAPICall = func(deviceID, callType, model string, p, c, tot, cached int) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal([]interface{}{deviceID, callType, model, p, c, tot, cached})
		*logged = append(*logged, string(b))
	}
	t.Cleanup(func() {
		srv.Close()
		ttsRealtimeURL, ttsPCMToMP3, ttsLogAPICall, OPENAI_API_KEY, ttsFetchInjected = oldURL, oldEnc, oldLog, oldKey, oldInj
	})
	return logged
}

func TestTTSRealtimeFetch(t *testing.T) {
	text := "Сегодня Луна переходит в знак Рака, и вечер располагает к спокойным разговорам."
	f := &rtFake{transcript: "сегодня луна переходит в знак рака и вечер располагает к спокойным разговорам", pcm: []byte(strings.Repeat("pcm!", 600))}
	setupRealtime(t, f)

	data, u, err := ttsFetchMetered(ttsFetch, ttsModel, "marin", "Calm narrator.", text)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(data) != "MP3:"+string(f.pcm) {
		t.Fatalf("audio not collected in order: %d bytes", len(data))
	}
	if u == nil || *u != (ttsUsage{Input: 120, Output: 288, Total: 408, Cached: 64}) {
		t.Fatalf("usage: %+v", u)
	}
	if f.authz != "Bearer sk-test-fake" {
		t.Fatalf("auth header: %q", f.authz)
	}
	if len(f.sessions) != 1 {
		t.Fatalf("sessions: %d", len(f.sessions))
	}
	ev := f.sessions[0]
	if ev[0]["type"] != "session.update" || ev[1]["type"] != "conversation.item.create" || ev[2]["type"] != "response.create" {
		t.Fatalf("event order: %v %v %v", ev[0]["type"], ev[1]["type"], ev[2]["type"])
	}
	sess := ev[0]["session"].(map[string]interface{})
	out := sess["audio"].(map[string]interface{})["output"].(map[string]interface{})
	format := out["format"].(map[string]interface{})
	mods := sess["output_modalities"].([]interface{})
	if sess["type"] != "realtime" || len(mods) != 1 || mods[0] != "audio" || out["voice"] != "marin" ||
		format["type"] != "audio/pcm" || format["rate"] != float64(24000) {
		t.Fatalf("session.update: %v", sess)
	}
	instr, _ := sess["instructions"].(string)
	if !strings.Contains(instr, "exactly, word for word") || !strings.HasSuffix(instr, "Voice style: Calm narrator.") {
		t.Fatalf("instructions: %q", instr)
	}
	item := ev[1]["item"].(map[string]interface{})
	content := item["content"].([]interface{})[0].(map[string]interface{})
	if item["role"] != "user" || content["type"] != "input_text" || content["text"] != text {
		t.Fatalf("item: %v", item)
	}

	// the plain ttsFetch (no usage) goes the same way in realtime mode
	if d, err := ttsFetch(ttsModel, "marin", "x", text); err != nil || string(d) != "MP3:"+string(f.pcm) {
		t.Fatalf("ttsFetch realtime: %v", err)
	}
}

// /api/tts in realtime mode: mp3 cached under the unchanged key, api_calls row
// with the realtime model and its tokens.
func TestTTSEnsureRealtimeLogsTokens(t *testing.T) {
	text := "Hello from Astrolytix."
	f := &rtFake{transcript: "Hello from Astrolytix!", pcm: []byte(strings.Repeat("p", 400))}
	logged := setupRealtime(t, f)
	dir := t.TempDir()
	t.Setenv("TTS_CACHE_DIR", dir)

	data, voice, hit, status, msg := ttsEnsure("dev1", "203.0.113.7", text, "f", "en")
	if status != http.StatusOK || hit || voice != "shimmer" || !strings.HasPrefix(string(data), "MP3:") {
		t.Fatalf("ensure: %d %q voice=%s hit=%v", status, msg, voice, hit)
	}
	if _, err := os.Stat(dir + "/" + ttsCacheKey(ttsModel, "shimmer", "en", text) + ".mp3"); err != nil {
		t.Fatalf("not cached under the unchanged key: %v", err)
	}
	if len(*logged) != 1 || (*logged)[0] != `["dev1","tts","gpt-realtime-2.1-mini",120,288,408,64]` {
		t.Fatalf("api_calls: %v", *logged)
	}
}

// A transcript that is not the text → error, nothing cached, no retry by
// default; TTS_REALTIME_RETRY_ON_MISMATCH=1 → exactly one retry.
func TestTTSRealtimeMismatch(t *testing.T) {
	text := "Не торопитесь с важными решениями."
	f := &rtFake{transcript: "Не торопитесь с важными решениями. Хорошего вечера!", pcm: []byte(strings.Repeat("p", 400))}
	logged := setupRealtime(t, f)
	dir := t.TempDir()
	t.Setenv("TTS_CACHE_DIR", dir)
	t.Setenv("TTS_VOICE_MAP", "*:f=marin,*:m=cedar")

	_, _, _, status, _ := ttsEnsure("dev1", "203.0.113.7", text, "f", "ru")
	if status != http.StatusBadGateway {
		t.Fatalf("mismatch must fail: %d", status)
	}
	if n := f.conns.Load(); n != 1 {
		t.Fatalf("flag 0: %d sessions, want 1 (no retry)", n)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("mismatch must not be cached: %v", entries)
	}
	// the billed reply is still on the books
	if len(*logged) != 1 || (*logged)[0] != `["dev1","tts","gpt-realtime-2.1-mini",120,288,408,64]` {
		t.Fatalf("api_calls: %v", *logged)
	}

	t.Setenv("TTS_REALTIME_RETRY_ON_MISMATCH", "1")
	_, _, _, status, _ = ttsEnsure("dev1", "203.0.113.7", text, "f", "ru")
	if status != http.StatusBadGateway {
		t.Fatalf("mismatch twice must fail: %d", status)
	}
	if n := f.conns.Load() - 1; n != 2 {
		t.Fatalf("flag 1: %d sessions, want exactly 2", n)
	}
	if len(*logged) != 2 || (*logged)[1] != `["dev1","tts","gpt-realtime-2.1-mini",240,576,816,128]` {
		t.Fatalf("usage of both attempts: %v", *logged)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("still nothing cached: %v", entries)
	}
}

// A voice the Realtime API does not have → error before any network call.
func TestTTSRealtimeVoiceNotAllowed(t *testing.T) {
	f := &rtFake{transcript: "x", pcm: []byte("pp")}
	logged := setupRealtime(t, f)
	for _, v := range []string{"nova", "onyx", "fable", ""} {
		_, u, err := ttsRealtimeFetch(v, "x", "Привет.")
		if !errors.Is(err, errTTSVoiceNotRealtime) || u != nil {
			t.Fatalf("%q: %v %v", v, err, u)
		}
		if _, err := ttsFetch(ttsModel, v, "x", "Привет."); !errors.Is(err, errTTSVoiceNotRealtime) {
			t.Fatalf("ttsFetch %q: %v", v, err)
		}
	}
	t.Setenv("TTS_CACHE_DIR", t.TempDir())
	_, voice, _, status, msg := ttsEnsure("dev1", "203.0.113.7", "Привет.", "m", "ru")
	if voice != "onyx" || status != http.StatusServiceUnavailable || msg != "tts unavailable" {
		t.Fatalf("ensure onyx: %s %d %q", voice, status, msg)
	}
	if n := f.conns.Load(); n != 0 {
		t.Fatalf("network used: %d sessions", n)
	}
	if len(*logged) != 0 {
		t.Fatalf("nothing billed, nothing logged: %v", *logged)
	}
}

func TestTTSRealtimeErrorEvent(t *testing.T) {
	up := websocket.Upgrader{}
	var conns atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conns.Add(1)
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		c.WriteJSON(map[string]interface{}{"type": "error", "error": map[string]interface{}{
			"type": "invalid_request_error", "code": "invalid_value", "message": "bad voice"}})
		c.ReadMessage()
	}))
	defer srv.Close()
	t.Setenv("TTS_REALTIME_RETRY_ON_MISMATCH", "1") // only a mismatch may be retried, never an API error
	old := ttsRealtimeURL
	ttsRealtimeURL = "ws" + strings.TrimPrefix(srv.URL, "http")
	defer func() { ttsRealtimeURL = old }()
	if _, _, err := ttsRealtimeFetch("ash", "x", "Hi."); err == nil || !strings.Contains(err.Error(), "bad voice") {
		t.Fatalf("error event: %v", err)
	}
	if conns.Load() != 1 {
		t.Fatalf("API error retried: %d sessions", conns.Load())
	}
}

func TestTTSTranscriptNorm(t *testing.T) {
	cases := [][2]string{
		{"Всё  хорошо, — правда?!", "все хорошо правда"},
		{"  Hello,\nWorld… ", "hello world"},
		{"Ёлка", "елка"},
	}
	for _, c := range cases {
		if got := ttsTranscriptNorm(c[0]); got != c[1] {
			t.Fatalf("%q → %q, want %q", c[0], got, c[1])
		}
	}
	if ttsTranscriptNorm("Не торопитесь.") == ttsTranscriptNorm("Не торопитесь. Хорошего вечера!") {
		t.Fatal("an added sentence must not normalise away")
	}
}

func TestTTSVoiceMap(t *testing.T) {
	t.Setenv("TTS_VOICE_MAP", "")
	if ttsVoiceFor("f", "ru") != "nova" || ttsVoiceFor("m", "en-US") != "ash" {
		t.Fatal("unset map must keep today's voices")
	}
	t.Setenv("TTS_VOICE_MAP", "en:f=shimmer, en:m=ash ,*:f=marin,*:m=cedar,broken,xx:q=alloy")
	for _, c := range [][3]string{
		{"f", "en-US", "shimmer"}, {"m", "en", "ash"}, {"f", "ru", "marin"}, {"m", "ru-RU", "cedar"}, {"", "", "marin"},
	} {
		if got := ttsVoiceFor(c[0], c[1]); got != c[2] {
			t.Fatalf("%s/%s → %s, want %s", c[0], c[1], got, c[2])
		}
	}
	// a map without «*» keeps today's voice for the other languages
	t.Setenv("TTS_VOICE_MAP", "en:f=coral")
	if ttsVoiceFor("f", "en") != "coral" || ttsVoiceFor("f", "ru") != "nova" {
		t.Fatal("partial map")
	}
}

// The real encoder: 1 s of PCM silence → an mp3 (skipped where ffmpeg is absent).
func TestTTSPCMToMP3(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("no ffmpeg")
	}
	mp3, err := ttsPCMToMP3(make([]byte, 2*ttsRealtimeRate))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(mp3) < 1000 || !(strings.HasPrefix(string(mp3), "ID3") || mp3[0] == 0xFF) {
		t.Fatalf("not an mp3: %d bytes %x", len(mp3), mp3[:4])
	}
}
