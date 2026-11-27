package main

// tts_realtime.go — the second TTS backend (A119, 25.11.2026).
//
// OpenAI shuts gpt-4o-mini-tts down on 06.01.2027 (developers.openai.com/api/docs/deprecations) and names
// gpt-realtime-2.1-mini as the replacement; that model is not served by /v1/audio/speech, only by the Realtime API
// (WebSocket). One session per text: session.update (audio out, PCM 24 kHz) → conversation.item.create
// (input_text) → response.create; the reply streams as response.output_audio.delta (base64 PCM s16le 24 kHz mono)
// plus response.output_audio_transcript.delta and ends with response.done (usage). Protocol measured against the
// live API 25.11.2026 (~/aia/staging/a119/probe/voices.py).
//
// TTS_BACKEND=speech (default) keeps /v1/audio/speech exactly as before; TTS_BACKEND=realtime switches every
// ttsFetch consumer here. The model READS the text, so its own transcript is compared with the input: a mismatch
// is an error, nothing is cached and — by default — nothing is retried (runtime LLM retries need the owner's
// explicit yes, server rules 2026-08-01); TTS_REALTIME_RETRY_ON_MISMATCH=1 allows exactly one retry.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/websocket"
)

const (
	ttsRealtimeModel   = "gpt-realtime-2.1-mini"
	ttsRealtimeTimeout = 90 * time.Second // as ttsSpeechFetch's http.Client
	ttsRealtimeMaxPCM  = 20 << 20         // as ttsSpeechFetch's response limit
	ttsRealtimeRate    = 24000
)

// ttsRealtimeURL — package var so tests point it at an httptest server.
var ttsRealtimeURL = "wss://api.openai.com/v1/realtime?model=" + ttsRealtimeModel

// ttsRealtimeVoices: the Realtime API's voice list (guides/realtime-conversations «Voice options», 25.11.2026) —
// nova, onyx and fable are NOT in it.
var ttsRealtimeVoices = map[string]bool{
	"alloy": true, "ash": true, "ballad": true, "coral": true, "echo": true,
	"sage": true, "shimmer": true, "verse": true, "marin": true, "cedar": true,
}

// errTTSVoiceNotRealtime: the configured voice does not exist in the Realtime API. Never swapped silently for
// another one — picking the voice is the owner's decision (samples ~/aia/staging/a119/voices).
var errTTSVoiceNotRealtime = errors.New("tts voice not available in realtime")

// ttsUsage — what one realtime synthesis cost, in the billable buckets of voiceUsage.split (response.done
// usage; summed over a mismatch retry). TextIn/AudioIn are UNCACHED input; cached tokens are separate.
// Mismatch: the audio was served although its transcript differs from the text (ttsRealtimeServable).
type ttsUsage struct {
	TextIn, AudioIn, CachedText, CachedAudio, TextOut, AudioOut int
	Mismatch                                                    bool
}

func (u *ttsUsage) add(o ttsUsage) {
	u.TextIn += o.TextIn
	u.AudioIn += o.AudioIn
	u.CachedText += o.CachedText
	u.CachedAudio += o.CachedAudio
	u.TextOut += o.TextOut
	u.AudioOut += o.AudioOut
	u.Mismatch = u.Mismatch || o.Mismatch
}

// ttsLogRealtimeRows writes one realtime synthesis as two api_calls rows, the voice.go convention, so finance.go
// prices audio and text at their own rates: callType under the model (audio tokens) and callType+"_text" under
// model+"-text" (text tokens). The base row stays one per synthesis, so ttsUsedToday's call_type='tts' count —
// the daily cap — is unchanged.
func ttsLogRealtimeRows(logf func(deviceID, callType, model string, p, c, tot, cached int), deviceID, callType string, u ttsUsage) {
	audioIn := u.AudioIn + u.CachedAudio
	logf(deviceID, callType, ttsRealtimeModel, audioIn, u.AudioOut, audioIn+u.AudioOut, u.CachedAudio)
	textIn := u.TextIn + u.CachedText
	logf(deviceID, callType+"_text", ttsRealtimeModel+"-text", textIn, u.TextOut, textIn+u.TextOut, u.CachedText)
}

// ttsBackendRealtime: TTS_BACKEND=realtime. Anything else (unset, "speech", a typo) is the speech endpoint.
func ttsBackendRealtime() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("TTS_BACKEND")), "realtime")
}

func ttsRealtimeRetryOnMismatch() bool {
	return strings.TrimSpace(os.Getenv("TTS_REALTIME_RETRY_ON_MISMATCH")) == "1"
}

// ttsFetchMetered: one synthesis plus the realtime usage for api_calls. In speech mode it calls the caller's own
// (swappable) speech fetch and returns no usage — the caller logs characters as before. In realtime mode it goes
// to ttsRealtimeFetchFn and returns its usage, also on error when the API already billed the reply.
func ttsFetchMetered(fetch func(model, voice, instructions, text string) ([]byte, error),
	model, voice, instructions, text string) ([]byte, *ttsUsage, error) {
	if ttsBackendRealtime() {
		return ttsRealtimeFetchFn(voice, instructions, text)
	}
	data, err := fetch(model, voice, instructions, text)
	return data, nil, err
}

// ttsLogUsage writes the api_calls rows of one synthesis: the two realtime rows when u is set,
// otherwise the speech row exactly as the caller logged it before A119 (characters as tokens).
func ttsLogUsage(deviceID, callType string, u *ttsUsage, speechPrompt, speechTotal int) {
	if u != nil {
		if u.Mismatch { // joins the full ttsMismatchLog line just before it with the device (A119 live check)
			log.Printf("⚠️ tts realtime mismatch served: device=%s call=%s", deviceID, callType)
		}
		ttsLogRealtimeRows(ttsLogAPICall, deviceID, callType, *u)
		return
	}
	ttsLogAPICall(deviceID, callType, ttsModel, speechPrompt, 0, speechTotal, 0)
}

// ttsLogAPICall — the api_calls logger; tests swap it.
var ttsLogAPICall = logAPICallWithTokens

// ttsRealtimeFetchFn — the realtime backend with its mismatch policy; tests of consumers may swap it.
var ttsRealtimeFetchFn = ttsRealtimeFetch

// ttsRealtimeFetch voices text with the Realtime API and returns mp3 bytes. The voice is checked before any
// network call. A transcript mismatch whose reading still starts and ends where the text does is served (the audio
// is already paid for; owner 26.11.2026: learn the cause from live calls, no paid re-tests) with usage.Mismatch and
// a full journal line. Any other mismatch — cut short, extra words before or after, another text or language — is
// an error, retried at most once and only with TTS_REALTIME_RETRY_ON_MISMATCH=1.
func ttsRealtimeFetch(voice, instructions, text string) ([]byte, *ttsUsage, error) {
	if !ttsRealtimeVoices[voice] {
		return nil, nil, fmt.Errorf("%w: %q", errTTSVoiceNotRealtime, voice)
	}
	attempts := 1
	if ttsRealtimeRetryOnMismatch() {
		attempts = 2
	}
	var total *ttsUsage
	for i := 0; i < attempts; i++ {
		pcm, transcript, u, err := ttsRealtimeSession(voice, instructions, text)
		if u != nil {
			if total == nil {
				total = &ttsUsage{}
			}
			total.add(*u)
		}
		if err != nil {
			return nil, total, err
		}
		mismatch := ttsTranscriptKey(transcript) != ttsTranscriptKey(text)
		if mismatch {
			serve := ttsRealtimeServable(text, transcript)
			log.Print(ttsMismatchLog(i+1, attempts, voice, text, transcript, serve))
			if !serve {
				continue
			}
		}
		mp3, err := ttsPCMToMP3(pcm)
		if err != nil {
			return nil, total, fmt.Errorf("tts realtime: mp3: %w", err)
		}
		if mismatch {
			if total == nil {
				total = &ttsUsage{}
			}
			total.Mismatch = true
		}
		return mp3, total, nil
	}
	return nil, total, errors.New("tts realtime: transcript does not match the text")
}

// ttsRealtimeEvent — the fields of a server event this client reads.
type ttsRealtimeEvent struct {
	Type  string `json:"type"`
	Delta string `json:"delta"`
	Error *struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Response *struct {
		Status        string          `json:"status"`
		StatusDetails json.RawMessage `json:"status_details"`
		Usage         *voiceUsage     `json:"usage"`
	} `json:"response"`
}

// ttsRealtimeSession: one WebSocket session for one text → raw PCM, the model's transcript and usage.
// ttsRealtimeInstructions is the session prompt. A119 27.11.2026: live calls showed the model "correcting" Russian
// cases while reading («неожиданные возможности» → «неожиданных возможностей»), hence the word-forms sentence. It only
// asks for exact reading in the same single call: no retry, and serving on mismatch stays ttsRealtimeServable.
func ttsRealtimeInstructions(style string) string {
	return "You are a text-to-speech engine. Read the user's message aloud exactly, word for word, " +
		"in its language. Do not change word forms, cases or grammar; keep every word exactly as written. " +
		"Do not add, answer or comment. Voice style: " + style
}

func ttsRealtimeSession(voice, instructions, text string) (pcm []byte, transcript string, usage *ttsUsage, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), ttsRealtimeTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+OPENAI_API_KEY)
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, ttsRealtimeURL, hdr)
	if err != nil {
		if resp != nil {
			return nil, "", nil, fmt.Errorf("openai realtime dial %d: %v", resp.StatusCode, err)
		}
		return nil, "", nil, fmt.Errorf("openai realtime dial: %v", err)
	}
	defer conn.Close()
	// One deadline for the whole session, as the speech client's 90 s timeout.
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, "", nil, err
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return nil, "", nil, err
	}
	conn.SetReadLimit(ttsRealtimeMaxPCM) // per event, as the whole-audio cap

	events := []interface{}{
		map[string]interface{}{"type": "session.update", "session": map[string]interface{}{
			"type": "realtime", "output_modalities": []string{"audio"},
			"instructions": ttsRealtimeInstructions(instructions),
			"audio": map[string]interface{}{"output": map[string]interface{}{
				"voice": voice, "format": map[string]interface{}{"type": "audio/pcm", "rate": ttsRealtimeRate},
			}},
		}},
		map[string]interface{}{"type": "conversation.item.create", "item": map[string]interface{}{
			"type": "message", "role": "user",
			"content": []interface{}{map[string]interface{}{"type": "input_text", "text": text}},
		}},
		map[string]interface{}{"type": "response.create"},
	}
	for _, e := range events {
		if err := conn.WriteJSON(e); err != nil {
			return nil, "", nil, fmt.Errorf("openai realtime send: %v", err)
		}
	}

	var audio bytes.Buffer
	var tr strings.Builder
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return nil, "", nil, fmt.Errorf("openai realtime read: %v", err)
		}
		var ev ttsRealtimeEvent
		if err := json.Unmarshal(msg, &ev); err != nil {
			return nil, "", nil, fmt.Errorf("openai realtime event: %v", err)
		}
		switch ev.Type {
		case "response.output_audio.delta":
			chunk, err := base64.StdEncoding.DecodeString(ev.Delta)
			if err != nil {
				return nil, "", nil, fmt.Errorf("openai realtime audio delta: %v", err)
			}
			if audio.Len()+len(chunk) > ttsRealtimeMaxPCM {
				return nil, "", nil, fmt.Errorf("openai realtime: audio over %d bytes", ttsRealtimeMaxPCM)
			}
			audio.Write(chunk)
		case "response.output_audio_transcript.delta":
			tr.WriteString(ev.Delta)
		case "error":
			if ev.Error != nil {
				return nil, "", nil, fmt.Errorf("openai realtime error %s/%s: %s", ev.Error.Type, ev.Error.Code,
					truncateForLog(ev.Error.Message, 200))
			}
			return nil, "", nil, fmt.Errorf("openai realtime error: %s", truncateForLog(string(msg), 200))
		case "response.done":
			if ev.Response == nil {
				return nil, "", nil, errors.New("openai realtime: response.done without response")
			}
			if u := ev.Response.Usage; u != nil {
				ti, ai, ct, ca, to, ao := u.split()
				usage = &ttsUsage{TextIn: ti, AudioIn: ai, CachedText: ct, CachedAudio: ca, TextOut: to, AudioOut: ao}
			}
			if st := ev.Response.Status; st != "" && st != "completed" {
				return nil, "", usage, fmt.Errorf("openai realtime: response %s %s", st,
					truncateForLog(string(ev.Response.StatusDetails), 200))
			}
			if audio.Len() == 0 {
				return nil, "", usage, errors.New("openai realtime: no audio")
			}
			return audio.Bytes(), tr.String(), usage, nil
		}
	}
}

// ttsMismatchLog: the journal line of a transcript mismatch — both strings in full (a truncated pair hid the cause
// on 25.11: the first 120 bytes matched) and where the normalized forms part, so the cause is readable from the line.
func ttsMismatchLog(attempt, attempts int, voice, text, transcript string, served bool) string {
	wn, gn := []rune(ttsTranscriptKey(text)), []rune(ttsTranscriptKey(transcript))
	at := 0
	for at < len(wn) && at < len(gn) && wn[at] == gn[at] {
		at++
	}
	ctx := func(r []rune) string {
		lo, hi := at-20, at+40
		if lo < 0 {
			lo = 0
		}
		if hi > len(r) {
			hi = len(r)
		}
		if lo > hi {
			lo = hi
		}
		return string(r[lo:hi])
	}
	verdict := "blocked"
	if served {
		verdict = "served"
	}
	return fmt.Sprintf("⚠️ tts realtime: transcript mismatch %s (attempt %d/%d, voice=%s, runes want=%d got=%d): normalized differ at rune %d: want …%q… got …%q…; want full %q; got full %q",
		verdict, attempt, attempts, voice, len(wn), len(gn), at, ctx(wn), ctx(gn), text, transcript)
}

// ttsRealtimeServable: a mismatching reading is still served when its first and last normalized words are the
// text's — it began and finished where the text does. A reading cut short, with words added before or after
// (a greeting, an answer), or in another text or language, fails this and stays an error. Structural, no ratio.
func ttsRealtimeServable(text, transcript string) bool {
	w, g := strings.Fields(ttsTranscriptNorm(text)), strings.Fields(ttsTranscriptNorm(transcript))
	if len(w) == 0 || len(g) == 0 {
		return false
	}
	return w[0] == g[0] && w[len(w)-1] == g[len(g)-1]
}

// ttsTranscriptKey: the form compared for a mismatch — ttsTranscriptNorm without the spaces that touch a Han, Hiragana
// or Katakana rune. Chinese and Japanese write no spaces between words; the norm's spaces there come from line
// breaks and «：», which the model reads as one sentence (A119, 27.11.2026: zh 12:50 blocked and zh 14:28 «达到28» vs
// «达到 28» — same words, a space apart). Korean and the Latin/Cyrillic words around CJK keep their own spaces.
func ttsTranscriptKey(s string) string {
	r := []rune(ttsTranscriptNorm(s))
	var b strings.Builder
	for i, c := range r {
		if c == ' ' && i > 0 && i+1 < len(r) && (ttsNoSpaceScript(r[i-1]) || ttsNoSpaceScript(r[i+1])) {
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func ttsNoSpaceScript(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana)
}

// ttsTranscriptNorm: lower case, ё = е, punctuation and symbols dropped, whitespace collapsed — the comparison
// must catch added or missing words, not the model's choice of commas.
func ttsTranscriptNorm(s string) string {
	var b strings.Builder
	space := true
	for _, r := range strings.ToLower(s) {
		if r == 'ё' {
			r = 'е'
		}
		switch {
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			continue
		case unicode.IsSpace(r):
			if !space {
				b.WriteByte(' ')
				space = true
			}
		default:
			b.WriteRune(r)
			space = false
		}
	}
	return strings.TrimSpace(b.String())
}

// ttsPCMToMP3 encodes PCM s16le 24 kHz mono to mp3 (ffmpeg stdin → stdout); every consumer expects mp3, as from
// /v1/audio/speech. Tests swap it.
var ttsPCMToMP3 = func(pcm []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-nostdin", "-loglevel", "error",
		"-f", "s16le", "-ar", fmt.Sprint(ttsRealtimeRate), "-ac", "1", "-i", "pipe:0",
		"-c:a", "libmp3lame", "-b:a", "128k", "-f", "mp3", "pipe:1")
	cmd.Stdin = bytes.NewReader(pcm)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg: %v: %s", err, truncateForLog(stderr.String(), 200))
	}
	if out.Len() == 0 {
		return nil, errors.New("ffmpeg: empty mp3")
	}
	return out.Bytes(), nil
}

// ttsVoiceMap parses TTS_VOICE_MAP («en:f=shimmer,en:m=ash,*:f=marin,*:m=cedar»): key «<lang>:<f|m>», lang the
// 2-letter code or «*». Malformed entries are skipped and logged once per distinct setting.
func ttsVoiceMap() map[string]string {
	raw := strings.TrimSpace(os.Getenv("TTS_VOICE_MAP"))
	if raw == "" {
		return nil
	}
	m := map[string]string{}
	var bad []string
	for _, ent := range strings.Split(raw, ",") {
		ent = strings.TrimSpace(ent)
		if ent == "" {
			continue
		}
		k, v, ok := strings.Cut(ent, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.ToLower(strings.TrimSpace(v))
		lang, g, ok2 := strings.Cut(k, ":")
		if !ok || !ok2 || v == "" || lang == "" || (g != "f" && g != "m") {
			bad = append(bad, ent)
			continue
		}
		m[lang+":"+g] = v
	}
	if len(bad) > 0 {
		if _, seen := ttsVoiceMapWarned.LoadOrStore(raw, true); !seen {
			log.Printf("⚠️ TTS_VOICE_MAP: skipped malformed entries %q", bad)
		}
	}
	return m
}

var ttsVoiceMapWarned sync.Map
