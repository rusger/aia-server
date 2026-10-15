package main

// radio_call.go — listener calls on Astrolytix Radio (owner 14.10.2026, insta-agent/docs/radio/CALL-IN.md).
//
// The phone app records two short clips: the intro («what's your name, what would you like to ask?») and
// the question (≤ 60 s). Each clip is transcribed, moderated and checked for topic; only then anything goes
// on air. The air itself is Liquidsoap + insta-agent/scripts/radio_feeder.py on this box: we write
// <RADIO_ROOT>/call/now.json, and the feeder of every station queues our segments after its current line,
// filling the waits with the station's hold phrases (hold_set "day") or «thinking» phrases (hold_set "think").
//
// Host lines are voiced by the station hosts (Kokoro, 9 voices) on the Mac render node: we queue a job, the
// Mac worker long-polls /api/radio/call/jobs and uploads one file per station. A reply in a language other
// than English is voiced here with OpenAI TTS (one shared file) and followed by the English translation in the
// station voices. One call on air at a time for all stations; stage 1 — only VOICE_ALLOWED_EMAILS.
//
// Money: an aired call costs radioCallMinutes from the same balance as the in-app phone (voice.go); a call
// rejected by the checks is free. Our cost (transcription + moderation + two small LLM calls + TTS) is
// logged in api_calls under radio_call_* call types.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

const (
	radioCallConsentVersion = "2026-10-14"
	radioCallMinutes        = 2.0 // owner 14.10.2026: fixed price of an aired call, from the voice balance
	radioCallDailyLimit     = 2
	radioCallMaxAudioBytes  = 8 << 20
	radioCallIdleTimeout    = 4 * time.Minute // a call nobody moves on is dropped and the line freed
	radioCallJobTimeout     = 45 * time.Second
	radioCallTranscribe     = "gpt-4o-mini-transcribe"
	radioCallModerationURL  = "https://api.openai.com/v1/moderations"
	radioCallLLM            = "gpt-4.1-mini"
)

var radioCallStations = []string{"moon", "sun", "mars", "mercury", "jupiter", "venus", "saturn", "rahu", "ketu"}

func radioRoot() string { return envDefault("RADIO_ROOT", "/var/www/html/radio") }

// ---------------------------------------------------------------------------
// Injectable externals (tests replace them)

// radioCallTranscribeFn: audio → text (+ audio seconds for the books).
var radioCallTranscribeFn = func(ctx context.Context, audio []byte, filename, lang string) (string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("model", radioCallTranscribe)
	if lang != "" && len(lang) <= 3 {
		_ = mw.WriteField("language", lang)
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(audio); err != nil {
		return "", err
	}
	mw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(envDefault("OPENAI_BASE_URL", "https://api.openai.com/v1"), "/")+"/audio/transcriptions", &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("transcribe %d: %s", resp.StatusCode, truncateForLog(string(raw), 200))
	}
	var out struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.Text), nil
}

// radioCallModerateFn: true = flagged (insults, harassment, scams with violence, sexual content…).
var radioCallModerateFn = func(ctx context.Context, text string) (bool, error) {
	body, _ := json.Marshal(map[string]string{"model": "omni-moderation-latest", "input": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, radioCallModerationURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("moderation %d: %s", resp.StatusCode, truncateForLog(string(raw), 200))
	}
	var out struct {
		Results []struct {
			Flagged bool `json:"flagged"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Results) == 0 {
		return false, fmt.Errorf("moderation: bad reply")
	}
	return out.Results[0].Flagged, nil
}

// radioCallChatFn: one JSON-mode chat completion; returns the content and token usage.
var radioCallChatFn = func(ctx context.Context, system, user string) (string, int, int, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":           radioCallLLM,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openaiChatURL(), bytes.NewReader(body))
	if err != nil {
		return "", 0, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		return "", 0, 0, fmt.Errorf("chat %d: %s", resp.StatusCode, truncateForLog(string(raw), 200))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return "", 0, 0, fmt.Errorf("chat: bad reply")
	}
	return out.Choices[0].Message.Content, out.Usage.Prompt, out.Usage.Completion, nil
}

// radioCallPhoneFn: the caller's clip → phone-sounding m4a (300–3400 Hz, compressed, 8 kHz), returns seconds.
var radioCallPhoneFn = func(in, out string) (float64, error) {
	af := "highpass=f=300,lowpass=f=3400,acompressor=threshold=-20dB:ratio=4:attack=5:release=60," +
		"aresample=8000,aresample=48000,loudnorm=I=-17:TP=-2"
	cmd := exec.Command("ffmpeg", "-y", "-loglevel", "error", "-i", in, "-af", af, "-ar", "48000", "-ac", "2",
		"-c:a", "aac", "-b:a", "96k", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("ffmpeg: %v %s", err, truncateForLog(string(b), 200))
	}
	return radioCallDurFn(out)
}

// radioCallDurFn: media duration in seconds (ffprobe).
var radioCallDurFn = func(path string) (float64, error) {
	b, err := exec.Command("ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path).Output()
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
}

// radioCallLocalTTSFn: a non-English reply voiced once for all stations (OpenAI TTS, same voices as /api/tts).
var radioCallLocalTTSFn = func(text, lang, gender string) ([]byte, error) {
	return ttsFetch(ttsModel, ttsVoiceFor(gender, lang), ttsInstructions, text)
}

// radioCallKokoroFn: the free last-resort voice — Kokoro on this box (tools/kokoro_say.py, RADIO_KOKORO_DIR with the
// venv and the model). One voice, niced, one thread: the 9 Liquidsoap stations on 2 cores come first.
var radioCallKokoroFn = func(text, out string) error {
	dir := os.Getenv("RADIO_KOKORO_DIR")
	if dir == "" {
		return errors.New("RADIO_KOKORO_DIR not set")
	}
	script := envDefault("RADIO_KOKORO_SCRIPT", "tools/kokoro_say.py")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nice", "-n", "19", filepath.Join(dir, "venv", "bin", "python"), script, dir,
		envDefault("RADIO_KOKORO_VOICE", "af_heart"), out)
	cmd.Stdin = strings.NewReader(text)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kokoro: %v %s", err, truncateForLog(string(b), 300))
	}
	return nil
}

var radioCallNow = time.Now

// ---------------------------------------------------------------------------
// Schema

var radioCallSchemaReady atomic.Bool

func ensureRadioCallSchema() {
	if radioCallSchemaReady.Load() {
		return
	}
	func() {
		for _, s := range []string{
			`CREATE TABLE IF NOT EXISTS radio_call_consent (
				email TEXT NOT NULL, version TEXT NOT NULL, device_id TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (email, version))`,
			`CREATE TABLE IF NOT EXISTS radio_calls (
				id TEXT PRIMARY KEY, email TEXT NOT NULL, device_id TEXT, lang TEXT,
				name TEXT, intro_text TEXT, question_text TEXT, answer_text TEXT,
				state TEXT NOT NULL, reason TEXT, aired INTEGER NOT NULL DEFAULT 0, charged_usd_micro INTEGER NOT NULL DEFAULT 0,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP, ended_at DATETIME)`,
			`CREATE INDEX IF NOT EXISTS idx_radio_calls_email ON radio_calls(email, created_at)`,
		} {
			if _, err := db.Exec(s); err != nil {
				log.Printf("⚠️ radio call schema: %v — will retry on next request", err)
				return
			}
		}
		radioCallSchemaReady.Store(true)
	}()
}

// ---------------------------------------------------------------------------
// The line (one call on air at a time, all stations)

type radioSegment struct {
	N    int                `json:"n"`
	Src  string             `json:"src"`
	Dur  float64            `json:"dur,omitempty"`
	Durs map[string]float64 `json:"durs,omitempty"`
	Kind string             `json:"kind"`
}

type radioCall struct {
	ID       string
	Email    string
	DeviceID string
	Lang     string
	Name     string
	TopicEN  string
	State    string // intro → connecting → question → answering → done
	OnAir    bool   // a segment has been sent to the stations
	Aired    bool   // the caller's voice went on air
	HoldSet  string
	Segments []radioSegment
	Touched  time.Time
	Live     bool // now.json state "live" (feeders fill the waits)
	jobs     map[string]*radioJob
	// «<имя> на линии…»: задание Маку и признак, что реплика уже в эфире (её ждёт «вы в эфире», владелец 14.10.2026)
	introJob   *radioJob
	introAired bool
	introText  string
}

type radioJob struct {
	ID     string              `json:"id"`
	CallID string              `json:"call_id"`
	Kind   string              `json:"kind"`
	Lines  []map[string]string `json:"lines"` // [{host, text}]
	Taken  bool                `json:"-"`
	Done   chan struct{}       `json:"-"`
	Durs   map[string]float64  `json:"-"`
}

var radioLine struct {
	sync.Mutex
	call *radioCall
	jobs []*radioJob
	wake chan struct{}
}

func radioNewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// radioWriteNow publishes the call for the feeders (atomic rename); call with the line locked.
func radioWriteNow(c *radioCall) {
	state := "live"
	if !c.Live {
		state = "done"
	}
	doc := map[string]interface{}{
		"id": c.ID, "state": state, "hold": c.Live, "hold_set": c.HoldSet,
		"updated": float64(radioCallNow().UnixNano()) / 1e9, "segments": c.Segments,
	}
	b, _ := json.MarshalIndent(doc, "", " ")
	dir := filepath.Join(radioRoot(), "call")
	_ = os.MkdirAll(dir, 0o755)
	tmp := filepath.Join(dir, "now.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Printf("⚠️ radio call now.json: %v", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, "now.json")); err != nil {
		log.Printf("⚠️ radio call now.json rename: %v", err)
	}
}

// radioCue: a random prerendered cue of [kind] (announce / onair / dropped / think) as a per-station segment.
// The cue files share a name across stations (hash of host+text), durations differ per voice.
func radioCue(kind string) (src string, durs map[string]float64, ok bool) {
	type cue struct {
		Src string  `json:"src"`
		Dur float64 `json:"dur"`
	}
	var names []string
	perCh := map[string]map[string]float64{}
	for _, ch := range radioCallStations {
		raw, err := os.ReadFile(filepath.Join(radioRoot(), ch, "call", "cues.json"))
		if err != nil {
			continue
		}
		var all map[string][]cue
		if json.Unmarshal(raw, &all) != nil {
			continue
		}
		for _, c := range all[kind] {
			base := filepath.Base(c.Src)
			if perCh[base] == nil {
				perCh[base] = map[string]float64{}
				names = append(names, base)
			}
			perCh[base][ch] = c.Dur
		}
	}
	sort.Strings(names)
	var full []string
	for _, n := range names {
		if len(perCh[n]) == len(radioCallStations) {
			full = append(full, n)
		}
	}
	if len(full) == 0 {
		return "", nil, false
	}
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	n := full[int(b[0])%len(full)]
	return "{ch}/call/" + n, perCh[n], true
}

// radioAppend adds a segment to the call (line locked) and republishes now.json.
func radioAppend(c *radioCall, seg radioSegment) {
	seg.N = len(c.Segments)
	c.Segments = append(c.Segments, seg)
	c.OnAir = true
	radioWriteNow(c)
}

func radioAppendCue(c *radioCall, kind string) {
	if src, durs, ok := radioCue(kind); ok {
		radioAppend(c, radioSegment{Src: src, Durs: durs, Kind: kind})
	} else {
		log.Printf("⚠️ radio call %s: no %q cues on disk", c.ID, kind)
	}
}

// radioEnd closes the call on air (line locked): a «line dropped» cue when something already went out but
// the caller never aired, then state done for the feeders and the line is free.
func radioEnd(c *radioCall, state, reason string) {
	if c.OnAir && !c.Aired && state != "aired" {
		radioAppendCue(c, "dropped")
	}
	c.Live = false
	c.State = "done"
	if c.OnAir {
		radioWriteNow(c)
	}
	for _, j := range c.jobs {
		select {
		case <-j.Done:
		default:
			close(j.Done)
		}
	}
	if radioLine.call == c {
		radioLine.call = nil
	}
	var kept []*radioJob
	for _, j := range radioLine.jobs {
		if j.CallID != c.ID {
			kept = append(kept, j)
		}
	}
	radioLine.jobs = kept
	if _, err := db.Exec(`UPDATE radio_calls SET state = ?, reason = ?, aired = ?, ended_at = CURRENT_TIMESTAMP WHERE id = ?`,
		state, reason, boolToInt(c.Aired), c.ID); err != nil {
		log.Printf("⚠️ radio call %s end: %v", c.ID, err)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// radioReapIdle frees a line nobody moved on for radioCallIdleTimeout (line locked).
func radioReapIdle() {
	if c := radioLine.call; c != nil && radioCallNow().Sub(c.Touched) > radioCallIdleTimeout {
		log.Printf("radio call %s idle — dropped", c.ID)
		radioEnd(c, "dropped", "idle")
	}
}

// radioQueueJob asks the Mac worker to voice host lines in all station voices (line locked).
func radioQueueJob(c *radioCall, kind string, lines []map[string]string) *radioJob {
	j := &radioJob{ID: radioNewID(), CallID: c.ID, Kind: kind, Lines: lines, Done: make(chan struct{})}
	if c.jobs == nil {
		c.jobs = map[string]*radioJob{}
	}
	c.jobs[j.ID] = j
	radioLine.jobs = append(radioLine.jobs, j)
	if radioLine.wake != nil {
		select {
		case radioLine.wake <- struct{}{}:
		default:
		}
	}
	return j
}

// ---------------------------------------------------------------------------
// Access

func radioCallPublic() bool { return os.Getenv("RADIO_CALL_PUBLIC") == "1" }

func radioCallAllowed(email string) (bool, string) {
	if voiceAllowed(email) {
		return true, ""
	}
	if !radioCallPublic() {
		return false, "not_available"
	}
	ensureVoiceSchema()
	if voiceRemainingMicro(email) < int64(radioCallMinutes*voiceMinuteUSD*1e6) {
		return false, "no_minutes"
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM radio_calls WHERE email = ? AND created_at >= date('now')`, email).Scan(&n)
	if n >= radioCallDailyLimit {
		return false, "daily_limit"
	}
	return true, ""
}

func radioConsented(email string) bool {
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM radio_call_consent WHERE email = ? AND version = ?`, email, radioCallConsentVersion).Scan(&n)
	return n > 0
}

func radioJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// GET /api/radio/call/status
func radioCallStatusHandler(w http.ResponseWriter, r *http.Request) {
	_, email, ok := voiceClaims(w, r)
	if !ok {
		return
	}
	ensureRadioCallSchema()
	allowed, why := radioCallAllowed(email)
	radioLine.Lock()
	radioReapIdle()
	busy := radioLine.call != nil
	radioLine.Unlock()
	radioJSON(w, 200, map[string]interface{}{
		"success": true, "available": allowed, "reason": why, "consent_version": radioCallConsentVersion,
		"consented": radioConsented(email), "line_busy": busy, "minutes": radioCallMinutes,
	})
}

// POST /api/radio/call/consent {version}
func radioCallConsentHandler(w http.ResponseWriter, r *http.Request) {
	claims, email, ok := voiceClaims(w, r)
	if !ok {
		return
	}
	ensureRadioCallSchema()
	var req struct {
		Version string `json:"version"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) != nil || req.Version != radioCallConsentVersion {
		voiceError(w, http.StatusBadRequest, "consent version mismatch")
		return
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO radio_call_consent (email, version, device_id) VALUES (?, ?, ?)`,
		email, req.Version, claims.DeviceID); err != nil {
		voiceError(w, http.StatusInternalServerError, "db")
		return
	}
	radioJSON(w, 200, map[string]interface{}{"success": true})
}

// POST /api/radio/call/start {lang}
func radioCallStartHandler(w http.ResponseWriter, r *http.Request) {
	claims, email, ok := voiceClaims(w, r)
	if !ok {
		return
	}
	ensureRadioCallSchema()
	var req struct {
		Lang string `json:"lang"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
	lang := strings.ToLower(strings.TrimSpace(req.Lang))
	if len(lang) < 2 || len(lang) > 3 {
		lang = "en"
	}
	if !radioConsented(email) {
		radioJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "error": "consent_required"})
		return
	}
	if allowed, why := radioCallAllowed(email); !allowed {
		radioJSON(w, http.StatusForbidden, map[string]interface{}{"success": false, "error": why})
		return
	}
	radioLine.Lock()
	defer radioLine.Unlock()
	radioReapIdle()
	if radioLine.call != nil {
		radioJSON(w, http.StatusConflict, map[string]interface{}{"success": false, "error": "line_busy"})
		return
	}
	c := &radioCall{ID: radioNewID(), Email: email, DeviceID: claims.DeviceID, Lang: lang, State: "intro",
		HoldSet: "day", Touched: radioCallNow()}
	if _, err := db.Exec(`INSERT INTO radio_calls (id, email, device_id, lang, state) VALUES (?, ?, ?, ?, 'intro')`,
		c.ID, email, claims.DeviceID, lang); err != nil {
		voiceError(w, http.StatusInternalServerError, "db")
		return
	}
	radioLine.call = c
	radioJSON(w, 200, map[string]interface{}{"success": true, "call_id": c.ID, "max_question_sec": 60})
}

// radioCallFor: the caller's own active call by id (line locked by the caller of this func).
func radioCallFor(w http.ResponseWriter, r *http.Request, email string) *radioCall {
	id := mux.Vars(r)["id"]
	c := radioLine.call
	if c == nil || c.ID != id || c.Email != email {
		radioJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "no_call"})
		return nil
	}
	return c
}

// radioReadAudio: the multipart "audio" field.
func radioReadAudio(w http.ResponseWriter, r *http.Request) ([]byte, string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, radioCallMaxAudioBytes+1<<16)
	if err := r.ParseMultipartForm(radioCallMaxAudioBytes); err != nil {
		voiceError(w, http.StatusBadRequest, "audio too large or bad form")
		return nil, "", false
	}
	f, hdr, err := r.FormFile("audio")
	if err != nil {
		voiceError(w, http.StatusBadRequest, "no audio")
		return nil, "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, radioCallMaxAudioBytes))
	if err != nil || len(b) < 1000 {
		voiceError(w, http.StatusBadRequest, "audio empty")
		return nil, "", false
	}
	name := filepath.Base(hdr.Filename)
	if filepath.Ext(name) == "" {
		name += ".m4a"
	}
	return b, name, true
}

// ---------------------------------------------------------------------------
// Checks

const radioCheckSystem = `You screen phone calls to an astrology radio show (Vedic astrology / Jyotish, planets, sky,
life questions that an astrologer could talk about). You get the transcript of what a caller said.
Reply JSON: {"ok": bool, "reason": "short English reason if not ok", "name": "caller's first name or empty",
"topic_en": "the question/topic paraphrased in English, 3-12 words, neutral, without the name",
"language": "ISO 639-1 code of the language the caller spoke"}.
ok=false for: insults, hate, harassment, sexual content, threats; scams, ads, links, phone numbers, selling;
politics and news debates; medical emergencies or requests for medical/legal/financial decisions as a must;
strong off-topic with no astrology or life-question angle; empty, unintelligible or test noise.
ok=true for polite questions about planets, zodiac, birth charts, transits, Jyotish, the sky, or life
(love, work, family, timing) that a radio astrologer can answer in general terms. Never output full surnames.`

type radioCheck struct {
	OK       bool   `json:"ok"`
	Reason   string `json:"reason"`
	Name     string `json:"name"`
	TopicEN  string `json:"topic_en"`
	Language string `json:"language"`
}

var radioNameRe = regexp.MustCompile(`^[\p{L}][\p{L}\-' ]{0,30}$`)

// radioScreen: transcript → moderation → topic check. Costs go to api_calls.
func radioScreen(ctx context.Context, c *radioCall, stage string, audio []byte, fname string) (string, radioCheck, error) {
	// transcription is billed per audio minute: logged as milliseconds of audio (finance.go «transcribe»)
	ms := 0
	tmp := filepath.Join(os.TempDir(), "radio_call_"+c.ID+"_"+stage[:1]+filepath.Ext(fname))
	if os.WriteFile(tmp, audio, 0o600) == nil {
		if d, err := radioCallDurFn(tmp); err == nil {
			ms = int(d * 1000)
		}
		os.Remove(tmp)
	}
	text, err := radioCallTranscribeFn(ctx, audio, fname, c.Lang)
	if err != nil {
		return "", radioCheck{}, err
	}
	logAPICallWithTokens(c.DeviceID, "radio_call_transcribe", radioCallTranscribe, ms, 0, ms, 0)
	if len([]rune(text)) < 3 {
		return text, radioCheck{OK: false, Reason: "empty"}, nil
	}
	flagged, err := radioCallModerateFn(ctx, text)
	if err != nil {
		return text, radioCheck{}, err
	}
	if flagged {
		return text, radioCheck{OK: false, Reason: "moderation"}, nil
	}
	raw, in, out, err := radioCallChatFn(ctx, radioCheckSystem, fmt.Sprintf("Stage: %s.\nTranscript:\n%s", stage, text))
	logAPICallWithTokens(c.DeviceID, "radio_call_check", radioCallLLM, in, out, in+out, 0)
	if err != nil {
		return text, radioCheck{}, err
	}
	var chk radioCheck
	if json.Unmarshal([]byte(raw), &chk) != nil {
		return text, radioCheck{}, errors.New("check: bad JSON")
	}
	chk.Name = strings.TrimSpace(chk.Name)
	if !radioNameRe.MatchString(chk.Name) {
		chk.Name = ""
	}
	if f := strings.Fields(chk.Name); len(f) > 1 {
		chk.Name = f[0] // first name only on air
	}
	return text, chk, nil
}

// ---------------------------------------------------------------------------
// POST /api/radio/call/{id}/intro

func radioCallIntroHandler(w http.ResponseWriter, r *http.Request) {
	_, email, ok := voiceClaims(w, r)
	if !ok {
		return
	}
	audio, fname, ok := radioReadAudio(w, r)
	if !ok {
		return
	}
	radioLine.Lock()
	c := radioCallFor(w, r, email)
	if c == nil {
		radioLine.Unlock()
		return
	}
	if c.State != "intro" {
		radioLine.Unlock()
		voiceError(w, http.StatusConflict, "wrong state")
		return
	}
	c.State = "checking_intro"
	c.Touched = radioCallNow()
	radioLine.Unlock()

	text, chk, err := radioScreen(r.Context(), c, "intro (name and what they want to ask)", audio, fname)

	radioLine.Lock()
	defer radioLine.Unlock()
	if radioLine.call != c {
		voiceError(w, http.StatusGone, "call ended")
		return
	}
	c.Touched = radioCallNow()
	_, _ = db.Exec(`UPDATE radio_calls SET intro_text = ?, name = ? WHERE id = ?`, text, chk.Name, c.ID)
	if err != nil {
		log.Printf("⚠️ radio call %s intro: %v", c.ID, err)
		radioEnd(c, "error", "intro: "+err.Error())
		radioJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": "check_failed"})
		return
	}
	if !chk.OK {
		radioEnd(c, "rejected", "intro: "+chk.Reason)
		radioJSON(w, 200, map[string]interface{}{"success": true, "ok": false, "reason": chk.Reason})
		return
	}
	c.Name, c.TopicEN, c.State, c.Live = chk.Name, chk.TopicEN, "question", true
	if chk.Language != "" && len(chk.Language) <= 3 {
		c.Lang = strings.ToLower(chk.Language)
	}
	radioAppendCue(c, "announce") // «looks like we have a caller» — queued after each station's current line
	who := "Our caller"
	if c.Name != "" {
		who = c.Name
	}
	line := fmt.Sprintf("With us on the line is %s, who wants to ask about %s.", who, strings.TrimSuffix(c.TopicEN, "."))
	j := radioQueueJob(c, "intro_line", []map[string]string{{"host": "A", "text": line}})
	c.introJob, c.introText = j, line
	go radioAwaitIntroLine(c, j)
	radioJSON(w, 200, map[string]interface{}{"success": true, "ok": true, "name": c.Name})
}

// radioAwaitIntroLine appends the voiced «With us on the line is <name>…» as soon as the Mac delivers it.
func radioAwaitIntroLine(c *radioCall, j *radioJob) {
	select {
	case <-j.Done:
	case <-time.After(radioCallJobTimeout):
	}
	radioLine.Lock()
	defer radioLine.Unlock()
	radioAppendIntro(c, j)
}

// radioAppendIntro puts the intro line on air once (line locked); never after the caller is on air.
func radioAppendIntro(c *radioCall, j *radioJob) {
	if radioLine.call != c || j == nil || j.Durs == nil || c.introAired || c.Aired {
		return
	}
	c.introAired = true
	radioAppend(c, radioSegment{Src: "call/" + c.ID + "/{ch}/intro_line.m4a", Durs: j.Durs, Kind: "intro_line"})
}

// radioIntroWait: how long the question waits for the intro line (the listener must hear who is calling first);
// radioAnswerWait: how long the reply waits for the station voices. Late Mac → the server voices it itself.
// (atomic: tests shorten them while goroutines of earlier calls may still be waiting)
var radioIntroWait, radioAnswerWait atomic.Int64

func init() {
	radioIntroWait.Store(int64(45 * time.Second))
	radioAnswerWait.Store(int64(45 * time.Second))
}

// radioFallbackSeg voices a host line on the server (OpenAI TTS, one shared file) when the Mac is late — the listener
// must never lose the intro or the reply (owner 14.10.2026). Called WITHOUT the line lock.
// Tiers (owner 14.10.2026): the Mac with the 9 station voices → OpenAI TTS, one voice (fast) → Kokoro on this
// box, one voice (free: no OpenAI balance, outage).
func radioFallbackSeg(c *radioCall, kind, text string) (radioSegment, error) {
	dir := filepath.Join(radioRoot(), "call", c.ID)
	_ = os.MkdirAll(dir, 0o755)
	name := kind + "_fb.mp3"
	data, err := radioCallLocalTTSFn(text, "en", "f")
	if err == nil {
		logAPICallWithTokens(c.DeviceID, "radio_call_tts", ttsModel, len([]rune(text)), 0, 0, 0)
		err = os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
	if err != nil {
		log.Printf("⚠️ radio call %s: %s via OpenAI failed (%v) — Kokoro on the server", c.ID, kind, err)
		name = kind + "_kokoro.wav"
		if err = radioCallKokoroFn(text, filepath.Join(dir, name)); err != nil {
			return radioSegment{}, err
		}
	}
	d, err := radioCallDurFn(filepath.Join(dir, name))
	if err != nil {
		return radioSegment{}, err
	}
	return radioSegment{Src: "call/" + c.ID + "/" + name, Dur: math.Round(d*100) / 100, Kind: kind}, nil
}

// radioMacGrace: the Mac worker must PICK UP a job this fast, else it is offline and the server voices the line
// at once instead of waiting the full radioIntroWait/radioAnswerWait (owner 14.10.2026: «Мак недоступен 5 секунд»).
// A Mac that polled within radioMacAlive is busy with the previous line, not offline — then the full wait applies.
var radioMacGrace, radioMacAlive, radioWorkerSeen atomic.Int64

func init() {
	radioMacGrace.Store(int64(5 * time.Second))
	radioMacAlive.Store(int64(30 * time.Second))
}

// radioWaitJob waits for the Mac: done → true; not taken within radioMacGrace or not done within max → false.
func radioWaitJob(j *radioJob, max time.Duration) bool {
	grace := time.After(time.Duration(radioMacGrace.Load()))
	limit := time.After(max)
	for {
		select {
		case <-j.Done:
			radioLine.Lock()
			ok := j.Durs != nil
			radioLine.Unlock()
			return ok
		case <-limit:
			return false
		case <-grace:
			radioLine.Lock()
			taken := j.Taken
			radioLine.Unlock()
			seen := time.Since(time.Unix(0, radioWorkerSeen.Load()))
			if !taken && seen > time.Duration(radioMacAlive.Load()) {
				return false // Мак офлайн: задание не взято, на связь не выходил
			}
		}
	}
}

// ---------------------------------------------------------------------------
// POST /api/radio/call/{id}/question

const radioAnswerSystem = `You are the warm, witty host of Astrolytix Radio, an internet radio about Vedic astrology
(Jyotish). A listener called in. Answer on air like a real radio host: thank them by first name, answer the question
in general Jyotish terms (planets, signs, houses, transits, dashas, nakshatras), practical and kind, no fear,
no fatalism, no medical/legal/financial instructions, no promises. 60-110 words. End with a light, good-natured joke
about the topic and "Thank you for calling, stay with us on Astrolytix Radio!" (in the reply language).
If chart notes are given, you may use them in general words, never reading out birth date, time or place.
Reply JSON: {"answer": "the reply in LANGUAGE", "answer_en": "the same reply in English (if LANGUAGE is English, repeat it)"}.`

func radioCallQuestionHandler(w http.ResponseWriter, r *http.Request) {
	_, email, ok := voiceClaims(w, r)
	if !ok {
		return
	}
	audio, fname, ok := radioReadAudio(w, r)
	if !ok {
		return
	}
	chart := ""
	if r.MultipartForm != nil {
		if v := r.MultipartForm.Value["chart_context"]; len(v) > 0 {
			chart = truncateForLog(v[0], 4000)
		}
	}
	radioLine.Lock()
	c := radioCallFor(w, r, email)
	if c == nil {
		radioLine.Unlock()
		return
	}
	if c.State != "question" {
		radioLine.Unlock()
		voiceError(w, http.StatusConflict, "wrong state")
		return
	}
	c.State = "checking_question"
	c.Touched = radioCallNow()
	radioLine.Unlock()

	ctx := context.Background() // the caller may hang up; the air must finish cleanly
	text, chk, err := radioScreen(ctx, c, "question", audio, fname)
	raw := filepath.Join(radioRoot(), "call", c.ID, "caller_raw"+filepath.Ext(fname))
	phone := filepath.Join(radioRoot(), "call", c.ID, "caller.m4a")
	var callerDur float64
	if err == nil && chk.OK {
		_ = os.MkdirAll(filepath.Dir(raw), 0o755)
		if err = os.WriteFile(raw, audio, 0o644); err == nil {
			callerDur, err = radioCallPhoneFn(raw, phone)
			_ = os.Remove(raw) // сырая запись вопроса не хранится (политика конфиденциальности, 15.10.2026)
		}
	}

	radioLine.Lock()
	if radioLine.call != c {
		radioLine.Unlock()
		voiceError(w, http.StatusGone, "call ended")
		return
	}
	c.Touched = radioCallNow()
	_, _ = db.Exec(`UPDATE radio_calls SET question_text = ? WHERE id = ?`, text, c.ID)
	if err != nil {
		log.Printf("⚠️ radio call %s question: %v", c.ID, err)
		radioEnd(c, "error", "question: "+err.Error())
		radioLine.Unlock()
		radioJSON(w, http.StatusBadGateway, map[string]interface{}{"success": false, "error": "check_failed"})
		return
	}
	if !chk.OK {
		radioEnd(c, "rejected", "question: "+chk.Reason)
		radioLine.Unlock()
		radioJSON(w, 200, map[string]interface{}{"success": true, "ok": false, "reason": chk.Reason})
		return
	}
	// The intro line («With us on the line is <name>…») must go first: wait for the Mac (unlocked), up to radioIntroWait.
	if j := c.introJob; j != nil && !c.introAired {
		radioLine.Unlock()
		if !radioWaitJob(j, time.Duration(radioIntroWait.Load())) {
			log.Printf("⚠️ radio call %s: the Mac did not voice the intro (offline or late) — server TTS", c.ID)
		}
		radioLine.Lock()
		if radioLine.call != c {
			radioLine.Unlock()
			voiceError(w, http.StatusGone, "call ended")
			return
		}
		if j.Durs == nil && !c.introAired { // Мак не успел — представление озвучивает сервер, без него нельзя
			c.introAired = true // опоздавший файл Мака уже не нужен
			text := c.introText
			radioLine.Unlock()
			seg, ferr := radioFallbackSeg(c, "intro_line", text)
			radioLine.Lock()
			if radioLine.call != c {
				radioLine.Unlock()
				voiceError(w, http.StatusGone, "call ended")
				return
			}
			if ferr == nil {
				radioAppend(c, seg)
			} else {
				log.Printf("⚠️ radio call %s: intro fallback TTS: %v", c.ID, ferr)
			}
		}
		radioAppendIntro(c, j)
	}
	// On air now: «yes, yes, we hear you» + the caller's voice; while the reply is voiced — thinking phrases.
	radioAppendCue(c, "onair")
	radioAppend(c, radioSegment{Src: "call/" + c.ID + "/caller.m4a", Dur: math.Round(callerDur*100) / 100, Kind: "caller"})
	c.Aired, c.State, c.HoldSet = true, "answering", "think"
	radioWriteNow(c)
	lang, name := c.Lang, c.Name
	radioLine.Unlock()

	radioJSON(w, 200, map[string]interface{}{"success": true, "ok": true})
	go radioAnswer(c, text, chart, lang, name)
}

// radioAnswer writes the host's reply, voices it and closes the call; charges the aired call.
func radioAnswer(c *radioCall, question, chart, lang, name string) {
	user := fmt.Sprintf("LANGUAGE: %s\nCaller first name: %s\nQuestion (transcript):\n%s", lang, name, question)
	if chart != "" {
		user += "\n\nChart notes (do not read birth data aloud):\n" + chart
	}
	raw, in, out, err := radioCallChatFn(context.Background(), radioAnswerSystem, user)
	logAPICallWithTokens(c.DeviceID, "radio_call_answer", radioCallLLM, in, out, in+out, 0)
	var ans struct {
		Answer   string `json:"answer"`
		AnswerEN string `json:"answer_en"`
	}
	if err == nil && (json.Unmarshal([]byte(raw), &ans) != nil || strings.TrimSpace(ans.AnswerEN) == "") {
		err = errors.New("answer: bad JSON")
	}
	var local []byte
	if err == nil && lang != "en" && strings.TrimSpace(ans.Answer) != "" {
		local, err = radioCallLocalTTSFn(ans.Answer, lang, "f")
		logAPICallWithTokens(c.DeviceID, "radio_call_tts", ttsModel, len([]rune(ans.Answer)), 0, 0, 0)
	}
	var j *radioJob
	radioLine.Lock()
	if radioLine.call != c {
		radioLine.Unlock()
		return
	}
	_, _ = db.Exec(`UPDATE radio_calls SET answer_text = ? WHERE id = ?`, ans.Answer+"\n---\n"+ans.AnswerEN, c.ID)
	if err != nil {
		log.Printf("⚠️ radio call %s answer: %v", c.ID, err)
		radioEnd(c, "error", "answer: "+err.Error()) // caller aired: no «dropped» cue; the feeders resume
		radioLine.Unlock()
		return
	}
	if local != nil {
		p := filepath.Join(radioRoot(), "call", c.ID, "answer_local.mp3")
		if werr := os.WriteFile(p, local, 0o644); werr != nil {
			log.Printf("⚠️ radio call %s: local reply not written: %v", c.ID, werr)
		} else if d, derr := radioCallDurFn(p); derr != nil {
			log.Printf("⚠️ radio call %s: local reply duration: %v — not on air", c.ID, derr)
		} else {
			radioAppend(c, radioSegment{Src: "call/" + c.ID + "/answer_local.mp3", Dur: math.Round(d*100) / 100, Kind: "answer_local"})
		}
	}
	en := ans.AnswerEN
	if local != nil {
		en = "For our listeners in English: " + en
	}
	j = radioQueueJob(c, "answer_en", []map[string]string{{"host": "A", "text": en}})
	radioLine.Unlock()

	radioWaitJob(j, time.Duration(radioAnswerWait.Load()))
	radioLine.Lock()
	if radioLine.call != c {
		radioLine.Unlock()
		return
	}
	if j.Durs != nil {
		radioAppend(c, radioSegment{Src: "call/" + c.ID + "/{ch}/answer_en.m4a", Durs: j.Durs, Kind: "answer_en"})
	} else { // Мак опоздал — ответ озвучивает сервер: ответ слушателю не теряется никогда
		log.Printf("⚠️ radio call %s: the Mac did not voice the reply in time — server TTS", c.ID)
		radioLine.Unlock()
		seg, ferr := radioFallbackSeg(c, "answer_en", en)
		radioLine.Lock()
		if radioLine.call != c {
			radioLine.Unlock()
			return
		}
		if ferr == nil {
			radioAppend(c, seg)
		} else {
			log.Printf("⚠️ radio call %s: reply fallback TTS: %v", c.ID, ferr)
		}
	}
	defer radioLine.Unlock()
	if !voiceAllowed(c.Email) {
		ensureVoiceSchema()
		micro := int64(math.Round(radioCallMinutes * voiceMinuteUSD * 1e6))
		if _, err := db.Exec(`INSERT INTO voice_balance (email, spent_usd_micro, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(email) DO UPDATE SET spent_usd_micro = spent_usd_micro + excluded.spent_usd_micro, updated_at = CURRENT_TIMESTAMP`,
			c.Email, micro); err == nil {
			_, _ = db.Exec(`UPDATE radio_calls SET charged_usd_micro = ? WHERE id = ?`, micro, c.ID)
		} else {
			log.Printf("⚠️ radio call %s charge: %v", c.ID, err)
		}
	}
	radioEnd(c, "aired", "")
}

// POST /api/radio/call/{id}/hangup
func radioCallHangupHandler(w http.ResponseWriter, r *http.Request) {
	_, email, ok := voiceClaims(w, r)
	if !ok {
		return
	}
	radioLine.Lock()
	defer radioLine.Unlock()
	c := radioCallFor(w, r, email)
	if c == nil {
		return
	}
	if c.Aired {
		// the caller is already on air: the reply still goes out, only the phone hangs up
		radioJSON(w, 200, map[string]interface{}{"success": true, "aired": true})
		return
	}
	radioEnd(c, "hangup", "caller hung up")
	radioJSON(w, 200, map[string]interface{}{"success": true, "aired": false})
}

// GET /api/radio/call/{id}
func radioCallGetHandler(w http.ResponseWriter, r *http.Request) {
	_, email, ok := voiceClaims(w, r)
	if !ok {
		return
	}
	id := mux.Vars(r)["id"]
	radioLine.Lock()
	if c := radioLine.call; c != nil && c.ID == id && c.Email == email {
		st, aired := c.State, c.Aired
		radioLine.Unlock()
		radioJSON(w, 200, map[string]interface{}{"success": true, "state": st, "aired": aired, "active": true})
		return
	}
	radioLine.Unlock()
	var state string
	var aired int
	if err := db.QueryRow(`SELECT state, aired FROM radio_calls WHERE id = ? AND email = ?`, id, email).Scan(&state, &aired); err != nil {
		radioJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "no_call"})
		return
	}
	radioJSON(w, 200, map[string]interface{}{"success": true, "state": state, "aired": aired == 1, "active": false})
}

// ---------------------------------------------------------------------------
// The Mac worker

func radioWorkerOK(r *http.Request) bool {
	want := os.Getenv("RADIO_CALL_WORKER_TOKEN")
	got := r.Header.Get("X-Radio-Worker")
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// GET /api/radio/call/jobs?wait=25 — pending voicing jobs (long-poll).
func radioCallJobsHandler(w http.ResponseWriter, r *http.Request) {
	if !radioWorkerOK(r) {
		voiceError(w, http.StatusForbidden, "forbidden")
		return
	}
	radioWorkerSeen.Store(radioCallNow().UnixNano())
	defer func() { radioWorkerSeen.Store(radioCallNow().UnixNano()) }()
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait < 0 || wait > 25 {
		wait = 25
	}
	deadline := time.After(time.Duration(wait) * time.Second)
	for {
		radioLine.Lock()
		radioReapIdle()
		var out []*radioJob
		for _, j := range radioLine.jobs {
			if !j.Taken {
				j.Taken = true
				out = append(out, j)
			}
		}
		if radioLine.wake == nil {
			radioLine.wake = make(chan struct{}, 1)
		}
		wake := radioLine.wake
		radioLine.Unlock()
		if len(out) > 0 || wait == 0 {
			radioJSON(w, 200, map[string]interface{}{"success": true, "stations": radioCallStations, "jobs": out})
			return
		}
		select {
		case <-wake:
		case <-deadline:
			radioJSON(w, 200, map[string]interface{}{"success": true, "stations": radioCallStations, "jobs": []*radioJob{}})
			return
		case <-r.Context().Done():
			return
		}
	}
}

var radioStationRe = regexp.MustCompile(`^[a-z]{3,8}$`)

// POST /api/radio/call/jobs/{job} — multipart: one m4a per station (field = station id) + "durs" JSON.
func radioCallJobDoneHandler(w http.ResponseWriter, r *http.Request) {
	if !radioWorkerOK(r) {
		voiceError(w, http.StatusForbidden, "forbidden")
		return
	}
	jobID := mux.Vars(r)["job"]
	radioLine.Lock()
	var j *radioJob
	var c *radioCall
	if radioLine.call != nil {
		c = radioLine.call
		j = c.jobs[jobID]
	}
	radioLine.Unlock()
	if j == nil {
		voiceError(w, http.StatusGone, "job gone")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 40<<20)
	if err := r.ParseMultipartForm(40 << 20); err != nil {
		voiceError(w, http.StatusBadRequest, "bad form")
		return
	}
	var durs map[string]float64
	if json.Unmarshal([]byte(r.FormValue("durs")), &durs) != nil {
		voiceError(w, http.StatusBadRequest, "durs")
		return
	}
	dir := filepath.Join(radioRoot(), "call", c.ID)
	for _, ch := range radioCallStations {
		f, _, err := r.FormFile(ch)
		if err != nil || durs[ch] <= 0 {
			voiceError(w, http.StatusBadRequest, "missing station "+ch)
			return
		}
		b, err := io.ReadAll(io.LimitReader(f, 8<<20))
		f.Close()
		if err != nil || !radioStationRe.MatchString(ch) {
			voiceError(w, http.StatusBadRequest, "read "+ch)
			return
		}
		_ = os.MkdirAll(filepath.Join(dir, ch), 0o755)
		if err := os.WriteFile(filepath.Join(dir, ch, j.Kind+".m4a"), b, 0o644); err != nil {
			voiceError(w, http.StatusInternalServerError, "write")
			return
		}
	}
	radioLine.Lock()
	if c.jobs[jobID] == j {
		j.Durs = map[string]float64{}
		for _, ch := range radioCallStations {
			j.Durs[ch] = math.Round(durs[ch]*100) / 100
		}
		select {
		case <-j.Done:
		default:
			close(j.Done)
		}
	}
	radioLine.Unlock()
	radioJSON(w, 200, map[string]interface{}{"success": true})
}

// ---------------------------------------------------------------------------
// Retention (privacy policy, owner 15.10.2026): call audio — 30 days; transcripts and texts — 12 months; the call row
// (time, state, charge) and the consent stay for billing and proof of consent.

const (
	radioCallAudioDays = 30
	radioCallTextDays  = 365
)

// radioCallCleanup removes call audio older than 30 days (never the call on air) and clears texts older than 12 months.
func radioCallCleanup(now time.Time) {
	radioLine.Lock()
	live := ""
	if radioLine.call != nil {
		live = radioLine.call.ID
	}
	radioLine.Unlock()
	dir := filepath.Join(radioRoot(), "call")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() || e.Name() == live {
			continue
		}
		info, err := e.Info()
		if err == nil && now.Sub(info.ModTime()) > radioCallAudioDays*24*time.Hour {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				log.Printf("⚠️ radio call cleanup %s: %v", e.Name(), err)
			}
		}
	}
	cut := now.Add(-radioCallTextDays * 24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	if _, err := db.Exec(`UPDATE radio_calls SET name = NULL, intro_text = NULL, question_text = NULL, answer_text = NULL
		WHERE created_at < ? AND (name IS NOT NULL OR intro_text IS NOT NULL OR question_text IS NOT NULL OR answer_text IS NOT NULL)`, cut); err != nil {
		log.Printf("⚠️ radio call text cleanup: %v", err)
	}
}

// startRadioCallCleanup runs the cleanup at start and then daily.
func startRadioCallCleanup() {
	go func() {
		ensureRadioCallSchema()
		for {
			radioCallCleanup(time.Now())
			time.Sleep(24 * time.Hour)
		}
	}()
}
