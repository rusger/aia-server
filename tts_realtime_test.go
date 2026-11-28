package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// TTS_BACKEND=speech → the /v1/audio/speech request is byte for byte the one
// sent before A119.
func TestTTSSpeechRequestUnchanged(t *testing.T) {
	t.Setenv("TTS_BACKEND", "speech")
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
			// the shape measured 25.11 (80 text in, 204 audio + 84 text out), here with 64 of the input cached
			{"type": "response.done", "response": map[string]interface{}{"status": "completed", "usage": map[string]interface{}{
				"input_tokens": 80, "output_tokens": 288, "total_tokens": 368,
				"input_token_details": map[string]interface{}{"text_tokens": 80, "audio_tokens": 0, "cached_tokens": 64,
					"cached_tokens_details": map[string]interface{}{"text_tokens": 64, "audio_tokens": 0}},
				"output_token_details": map[string]interface{}{"text_tokens": 84, "audio_tokens": 204},
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
	if u == nil || *u != (ttsUsage{TextIn: 16, CachedText: 64, TextOut: 84, AudioOut: 204}) {
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
	prevA := analyticsDB
	var err error
	if analyticsDB, err = sql.Open("sqlite", ":memory:"); err != nil {
		t.Fatal(err)
	}
	analyticsDB.SetMaxOpenConns(1) // every :memory: connection is its own database
	t.Cleanup(func() { analyticsDB.Close(); analyticsDB = prevA })
	if _, err := analyticsDB.Exec(`CREATE TABLE api_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
		call_type TEXT NOT NULL, model TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, prompt_tokens INTEGER DEFAULT 0,
		completion_tokens INTEGER DEFAULT 0, total_tokens INTEGER DEFAULT 0, cached_tokens INTEGER DEFAULT 0,
		answer_id TEXT DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	capture := ttsLogAPICall
	ttsLogAPICall = func(deviceID, callType, model string, p, c, tot, cached int) {
		capture(deviceID, callType, model, p, c, tot, cached)
		logAPICallWithTokens(deviceID, callType, model, p, c, tot, cached)
	}

	data, voice, hit, status, msg := ttsEnsure("dev1", "203.0.113.7", text, "f", "en")
	if status != http.StatusOK || hit || voice != "shimmer" || !strings.HasPrefix(string(data), "MP3:") {
		t.Fatalf("ensure: %d %q voice=%s hit=%v", status, msg, voice, hit)
	}
	if _, err := os.Stat(dir + "/" + ttsCacheKey(ttsModel, "shimmer", "en", text) + ".mp3"); err != nil {
		t.Fatalf("not cached under the unchanged key: %v", err)
	}
	wantRows := `["dev1","tts","gpt-realtime-2.1-mini",0,204,204,0]` + "\n" +
		`["dev1","tts_text","gpt-realtime-2.1-mini-text",80,84,164,64]`
	if strings.Join(*logged, "\n") != wantRows {
		t.Fatalf("api_calls: %v", *logged)
	}
	// the daily cap counts call_type 'tts' only: still one per synthesis
	waitRows := func(n int) {
		for i := 0; i < 200; i++ {
			var c int
			if analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls`).Scan(&c) == nil && c >= n {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("api_calls rows never reached %d", n)
	}
	waitRows(2)
	if n := ttsUsedToday("dev1"); n != 1 {
		t.Fatalf("ttsUsedToday after one realtime synthesis = %d, want 1", n)
	}
}

// Finance prices the two rows at the gpt-realtime-2.1-mini list rates (audio out $20/M, text in $0.60/M,
// text out $2.40/M — voiceRatesFor) for the usage measured 25.11.
func TestTTSRealtimeFinanceCost(t *testing.T) {
	var cost float64
	rows := 0
	ttsLogRealtimeRows(func(_, _, model string, p, c, tot, cached int) {
		rows++
		if tot > 0 {
			cost += financeTokenCostUSD(model, int64(p), int64(c), int64(cached), false)
		}
	}, "dev1", "tts", ttsUsage{TextIn: 80, TextOut: 84, AudioOut: 204})
	want := 80*0.60e-6 + 204*20e-6 + 84*2.40e-6
	if rows != 2 || cost < want-1e-9 || cost > want+1e-9 {
		t.Fatalf("cost %.10f over %d rows, want %.10f", cost, rows, want)
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
	if len(*logged) != 2 || (*logged)[0] != `["dev1","tts","gpt-realtime-2.1-mini",0,204,204,0]` ||
		(*logged)[1] != `["dev1","tts_text","gpt-realtime-2.1-mini-text",80,84,164,64]` {
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
	if len(*logged) != 4 || (*logged)[2] != `["dev1","tts","gpt-realtime-2.1-mini",0,408,408,0]` ||
		(*logged)[3] != `["dev1","tts_text","gpt-realtime-2.1-mini-text",160,168,328,128]` {
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
	// unset map → the owner's realtime voices (default since 28.11.2026); a map naming a non-Realtime voice is still refused
	t.Setenv("TTS_VOICE_MAP", "*:m=onyx")
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

// A119 27.11.2026, journal astrolog-api: the same Chinese words a line break / a space apart were a mismatch and
// blocked one reading. Japanese with changed word forms (13:12) stays a mismatch.
func TestTTSTranscriptKeyCJKSpaces(t *testing.T) {
	same := [][2]string{
		{"时期总体描述：\n\n金星大运带来愉悦、创造力。\n\n预期经历：\n\n人际关系改善。", "时期总体描述：金星大运带来愉悦、创造力。\n\n预期经历：人际关系改善。"},
		{"主要优势是 Ashtakoota 得分达到28/36，Nadi、Bhakut 与 Graha Maitri 均表现突出", "主要优势是 Ashtakoota 得分达到 28/36，Nadi、Bhakut 与 Graha Maitri 均表现突出"},
		{"結婚生活では、\n相手の気持ちを聞いてから", "結婚生活では、相手の気持ちを聞いてから"},
	}
	for _, c := range same {
		if ttsTranscriptKey(c[0]) != ttsTranscriptKey(c[1]) {
			t.Fatalf("same words must match:\n%q\n%q", ttsTranscriptKey(c[0]), ttsTranscriptKey(c[1]))
		}
	}
	differ := [][2]string{
		{"感情の表し方と親密さへの期待が異なり、衝突時に誇りや批判が前面に出やすいことです。", "感情の表し方と親密さへの期待が異なることで、衝突時に誇りや批判が前面に出やすい点です。"},
		{"graha maitri 均表现突出", "grahamaitri 均表现突出"},
		{"Не торопитесь.", "Не торопитесь. Хорошего вечера!"},
		{"안녕 하세요", "안녕하세요"},
	}
	for _, c := range differ {
		if ttsTranscriptKey(c[0]) == ttsTranscriptKey(c[1]) {
			t.Fatalf("must stay a mismatch: %q vs %q", c[0], c[1])
		}
	}
	if !strings.Contains(ttsMismatchLog(1, 1, "marin", "达到28", "达到 28", true), "runes want=4 got=4") {
		t.Fatal("the log must compare the same key form")
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

// A mismatch line carries both strings whole and the point where the normalized forms part (25.11: the
// 120-byte cut hid the cause of a Korean failure).
func TestTTSMismatchLogFull(t *testing.T) {
	want := "이 커플의 가장 큰 강점은 그라하 마이트리 5/5점에 나타난 대화와 이해의 잠재력, 그리고 서로를 존중하는 태도입니다. 끝까지 함께하세요."
	got := "이 커플의 가장 큰 강점은 그라하 마이트리 5점 만점에 5점에 나타난 대화와 이해의 잠재력, 그리고 서로를 존중하는 태도입니다. 끝까지 함께하세요."
	line := ttsMismatchLog(1, 1, "cedar", want, got, true)
	for _, s := range []string{fmt.Sprintf("%q", want), fmt.Sprintf("%q", got), "attempt 1/1", "voice=cedar", "mismatch served", "runes want="} {
		if !strings.Contains(line, s) {
			t.Fatalf("line lacks %s:\n%s", s, line)
		}
	}
	if !strings.Contains(line, "differ at rune 25:") {
		t.Fatalf("divergence point:\n%s", line)
	}
	if strings.Contains(line, `\x`) {
		t.Fatalf("broken rune in the line:\n%s", line)
	}
	// equal prefix, one string longer → the point is the end of the shorter one
	if l := ttsMismatchLog(2, 2, "marin", "Да.", "Да. Хорошего вечера!", false); !strings.Contains(l, "differ at rune 2:") {
		t.Fatalf("longer transcript:\n%s", l)
	}
}

// A119 26.11 (owner: learn from live calls, no paid re-tests): a reading that differs inside but starts and ends
// where the text does is served and cached, once, with usage.Mismatch and the device line; cut short → error.
func TestTTSRealtimeMismatchServed(t *testing.T) {
	text := "이 커플의 강점은 그라하 마이트리 5/5점입니다. 함께하세요."
	f := &rtFake{transcript: "이 커플의 강점은 그라하 마이트리 5점 만점에 5점입니다. 함께하세요.", pcm: []byte(strings.Repeat("p", 400))}
	logged := setupRealtime(t, f)
	dir := t.TempDir()
	t.Setenv("TTS_CACHE_DIR", dir)
	t.Setenv("TTS_VOICE_MAP", "*:f=marin,*:m=cedar")
	t.Setenv("TTS_REALTIME_RETRY_ON_MISMATCH", "1") // a served reading is never retried
	var jb bytes.Buffer
	log.SetOutput(&jb)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	data, _, hit, status, _ := ttsEnsure("dev1", "203.0.113.7", text, "m", "ko")
	if status != http.StatusOK || hit || !strings.HasPrefix(string(data), "MP3:") {
		t.Fatalf("served mismatch: %d hit=%v", status, hit)
	}
	if n := f.conns.Load(); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
	if _, err := os.Stat(dir + "/" + ttsCacheKey(ttsModel, "cedar", "ko", text) + ".mp3"); err != nil {
		t.Fatalf("served audio not cached: %v", err)
	}
	if len(*logged) != 2 {
		t.Fatalf("api_calls: %v", *logged)
	}
	j := jb.String()
	for _, s := range []string{"transcript mismatch served", "mismatch served: device=dev1 call=tts", "lang=ko", "mismatch=true"} {
		if !strings.Contains(j, s) {
			t.Fatalf("journal lacks %q:\n%s", s, j)
		}
	}

	// cut short: the end of the text is missing → error, retried once with the flag, nothing cached
	f.transcript = "이 커플의 강점은 그라하 마이트리"
	text2 := text + " 끝."
	if _, _, _, status, _ = ttsEnsure("dev1", "203.0.113.7", text2, "m", "ko"); status != http.StatusBadGateway {
		t.Fatalf("cut short must fail: %d", status)
	}
	if n := f.conns.Load() - 1; n != 2 {
		t.Fatalf("cut short: %d sessions, want 2 (flag 1)", n)
	}
	if !strings.Contains(jb.String(), "transcript mismatch blocked") {
		t.Fatalf("blocked line missing:\n%s", jb.String())
	}
	if _, err := os.Stat(dir + "/" + ttsCacheKey(ttsModel, "cedar", "ko", text2) + ".mp3"); err == nil {
		t.Fatal("blocked audio cached")
	}

	// a direct fetch: served → Mismatch true; exact → false
	f.transcript = "이 커플의 강점은 그라하 마이트리 5점 만점에 5점입니다. 함께하세요."
	if _, u, err := ttsRealtimeFetch("cedar", "x", text); err != nil || u == nil || !u.Mismatch {
		t.Fatalf("fetch served: %v %+v", err, u)
	}
	f.transcript = text
	if _, u, err := ttsRealtimeFetch("cedar", "x", text); err != nil || u == nil || u.Mismatch {
		t.Fatalf("fetch exact: %v %+v", err, u)
	}
}

func TestTTSRealtimeServable(t *testing.T) {
	for _, c := range []struct {
		text, got string
		ok        bool
	}{
		{"Не торопитесь с решениями.", "Не торопитесь с важными решениями.", true}, // a word inside
		{"Не торопитесь с решениями.", "Не торопитесь с", false},                   // cut short
		{"Не торопитесь.", "Не торопитесь. Хорошего вечера!", false},               // added after
		{"Не торопитесь.", "Конечно: не торопитесь.", false},                       // added before
		{"Не торопитесь.", "Take your time.", false},                               // another language
		{"Привет.", "", false},
	} {
		if got := ttsRealtimeServable(c.text, c.got); got != c.ok {
			t.Fatalf("%q / %q → %v, want %v", c.text, c.got, got, c.ok)
		}
	}
}

func TestTTSRealtimeInstructionsKeepWordForms(t *testing.T) {
	got := ttsRealtimeInstructions("calm, warm")
	for _, want := range []string{"word for word", "Do not change word forms, cases or grammar; keep every word exactly as written."} {
		if !strings.Contains(got, want) {
			t.Fatalf("instructions miss %q: %q", want, got)
		}
	}
	if !strings.HasSuffix(got, "Voice style: calm, warm") {
		t.Fatalf("voice style must stay at the end: %q", got)
	}
}
