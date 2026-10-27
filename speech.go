package main

// speech.go — voice in the Astrolytix chats (owner 27.10.2026): Azure neural
// voices read the guru / astrologer / psychologist answers aloud, and a voice
// message the user records is transcribed here and sent on as typed text.
//
// Money rules (the Azure account sits on the owner's PERSONAL card):
//   - Azure is called only while AZURE_SPEECH_TIER=F0 (free tier). Any other
//     value switches it off — never a paid S0 call from this code.
//   - The F0 text-to-speech quota (500k chars/month) is SHARED with the
//     Ramsider bot; the owner gave the app 250k (APP_TTS_MONTH_CHARS, hard
//     ceiling below) and the bot 200k. Speech to text F0 = 5 audio hours a
//     month, used only by the app (APP_STT_MONTH_SECONDS, 4.5 h default).
//   - Units are reserved in speech_usage BEFORE the request (one mutex, so
//     two requests can't both squeeze under a cap); a failed request keeps
//     its reservation — over-counting is safe, under-counting is not.
//   - No retries: 429 → pause 15 min, 401/403 → off until restart, anything
//     else → this request fails. Every failure tells the app to fall back
//     (TTS: the phone's own voice; STT: Groq below).
//   - STT fallback is Groq whisper-large-v3-turbo (~$0.04/audio hour, owner
//     decision 27.10.2026). Runs only with GROQ_API_KEY set and under its own
//     monthly ceiling (APP_GROQ_MONTH_SECONDS).
//
// The key never leaves the server and is never logged. speech_usage (source
// 'app') is the app's ledger; the bot keeps its own (tts_usage) and the
// weekly report adds the two up.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
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
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	speechTTSMonthDefault  = 250000
	speechTTSMonthCeiling  = 250000 // owner's split of the shared F0 500k
	speechTTSDeviceDay     = 15000
	speechSTTMonthDefault  = 16200 // 4.5 h of the 5 free hours
	speechSTTMonthCeiling  = 17000
	speechSTTDeviceDay     = 600
	speechGroqMonthDefault = 36000 // 10 h ≈ $0.40 at the list price
	speechTTSMaxRunes      = 5000
	speechTTSPerMinute     = 10 // F0 = 20 transactions/min per resource, shared with the bot
	speechSTTMaxBytes      = 2 << 20
	speechSTTMaxSeconds    = 61.0
	speechSTTMinSeconds    = 0.3
	speechHTTPTimeout      = 25 * time.Second
	speechTTSTimeout       = 55 * time.Second // a 4800-char answer can take a while; app waits 60 s, nginx 60 s
	speechSTTBusyWait      = 10 * time.Second
	speechCooldown         = 15 * time.Minute
	speechMaxAudioBytes    = 16 << 20
	speechTTSOutputFormat  = "audio-24khz-48kbitrate-mono-mp3"
	speechGroqModel        = "whisper-large-v3-turbo"
	speechUserAgent        = "astrolytix-server/1.0"
	speechSource           = "app"
	speechKindTTS          = "tts"
	speechKindSTT          = "stt"
	speechProviderAzure    = "azure"
	speechProviderGroq     = "groq"
)

// Endpoints — package vars so tests can point them at httptest servers.
var (
	speechAzureTTSURL = func(region string) string {
		return "https://" + region + ".tts.speech.microsoft.com/cognitiveservices/v1"
	}
	speechAzureSTTURL = func(region string) string {
		return "https://" + region + ".stt.speech.microsoft.com/speech/recognition/conversation/cognitiveservices/v1"
	}
	speechGroqURL = "https://api.groq.com/openai/v1/audio/transcriptions"
	// speechToWav converts an uploaded clip to 16 kHz mono PCM WAV (ffmpeg).
	speechToWav = ffmpegToWav16k
)

// speechVoices — one female neural voice per app language (owner 27.10.2026;
// every name checked against /voices/list in germanywestcentral). pt is the
// Brazilian voice: the app's Portuguese audience is mostly Brazil.
var speechVoices = map[string]struct{ locale, name string }{
	"en": {"en-US", "en-US-JennyNeural"},
	"es": {"es-ES", "es-ES-ElviraNeural"},
	"fr": {"fr-FR", "fr-FR-DeniseNeural"},
	"de": {"de-DE", "de-DE-KatjaNeural"},
	"it": {"it-IT", "it-IT-ElsaNeural"},
	"pt": {"pt-BR", "pt-BR-FranciscaNeural"},
	"ru": {"ru-RU", "ru-RU-SvetlanaNeural"},
	"zh": {"zh-CN", "zh-CN-XiaoxiaoNeural"},
	"ja": {"ja-JP", "ja-JP-NanamiNeural"},
	"ko": {"ko-KR", "ko-KR-SunHiNeural"},
	"hi": {"hi-IN", "hi-IN-SwaraNeural"},
	"ar": {"ar-SA", "ar-SA-ZariyahNeural"},
	"mr": {"mr-IN", "mr-IN-AarohiNeural"},
	"te": {"te-IN", "te-IN-ShrutiNeural"},
	"ta": {"ta-IN", "ta-IN-PallaviNeural"},
	"kn": {"kn-IN", "kn-IN-SapnaNeural"},
}

// speechLang normalises "ru", "ru-RU", "ru_RU" → "ru"; "" when unsupported.
func speechLang(lang string) string {
	l := strings.ToLower(strings.TrimSpace(lang))
	if i := strings.IndexAny(l, "-_"); i > 0 {
		l = l[:i]
	}
	if _, ok := speechVoices[l]; ok {
		return l
	}
	return ""
}

// --- config ---

type speechConfig struct {
	key, region, tier, groqKey               string
	ttsMonth, ttsDevDay, sttMonth, sttDevDay int
	groqMonth                                int
}

var speechRegionRe = regexp.MustCompile(`^[a-z0-9]{2,40}$`)

func speechEnvInt(name string, def, ceiling int) int {
	v := def
	if s := strings.TrimSpace(os.Getenv(name)); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			v = n
		}
	}
	if ceiling > 0 && v > ceiling {
		v = ceiling
	}
	return v
}

func speechConfigFromEnv() speechConfig {
	return speechConfig{
		key:       strings.TrimSpace(os.Getenv("AZURE_SPEECH_KEY")),
		region:    strings.ToLower(strings.TrimSpace(os.Getenv("AZURE_SPEECH_REGION"))),
		tier:      strings.TrimSpace(os.Getenv("AZURE_SPEECH_TIER")),
		groqKey:   strings.TrimSpace(os.Getenv("GROQ_API_KEY")),
		ttsMonth:  speechEnvInt("APP_TTS_MONTH_CHARS", speechTTSMonthDefault, speechTTSMonthCeiling),
		ttsDevDay: speechEnvInt("APP_TTS_DEVICE_DAY_CHARS", speechTTSDeviceDay, 0),
		sttMonth:  speechEnvInt("APP_STT_MONTH_SECONDS", speechSTTMonthDefault, speechSTTMonthCeiling),
		sttDevDay: speechEnvInt("APP_STT_DEVICE_DAY_SECONDS", speechSTTDeviceDay, 0),
		groqMonth: speechEnvInt("APP_GROQ_MONTH_SECONDS", speechGroqMonthDefault, 0),
	}
}

// azureProblem — why Azure must not be called ("" = it may).
func (c speechConfig) azureProblem() string {
	switch {
	case c.tier != "F0":
		return "azure_not_f0"
	case c.key == "":
		return "azure_no_key"
	case !speechRegionRe.MatchString(c.region):
		return "azure_bad_region"
	}
	return ""
}

// --- breaker: 429 pause / 401-403 off, per Azure service ---

type speechBreaker struct {
	mu            sync.Mutex
	cooldownUntil time.Time
	disabled      bool
	recent        []time.Time // TTS rate window
}

var (
	speechTTSBreaker = &speechBreaker{}
	speechSTTBreaker = &speechBreaker{}
	// F0 speech to text allows ONE concurrent request per resource.
	speechSTTSlot = make(chan struct{}, 1)
)

func (b *speechBreaker) blocked(now time.Time) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.disabled:
		return "azure_auth_off"
	case now.Before(b.cooldownUntil):
		return "azure_cooldown"
	}
	return ""
}

// takeRate admits at most perMinute calls in any 60 s window.
func (b *speechBreaker) takeRate(now time.Time, perMinute int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := b.recent[:0]
	for _, t := range b.recent {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	b.recent = keep
	if len(b.recent) >= perMinute {
		return false
	}
	b.recent = append(b.recent, now)
	return true
}

// onStatus records what an Azure HTTP status means for the next calls.
func (b *speechBreaker) onStatus(status int, now time.Time, what string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch status {
	case http.StatusTooManyRequests:
		b.cooldownUntil = now.Add(speechCooldown)
		log.Printf("⏸ speech: Azure %s 429 — paused until %s UTC", what, b.cooldownUntil.UTC().Format("15:04"))
	case http.StatusUnauthorized, http.StatusForbidden:
		b.disabled = true
		log.Printf("⛔ speech: Azure %s %d — switched off until restart", what, status)
	}
}

// --- ledger ---

var (
	speechTableOnce sync.Once
	speechTableErr  error
	speechLedgerMu  sync.Mutex
)

func ensureSpeechUsageTable() error {
	speechTableOnce.Do(func() {
		if analyticsDB == nil {
			speechTableErr = errors.New("analytics DB not initialized")
			return
		}
		_, speechTableErr = analyticsDB.Exec(`
        CREATE TABLE IF NOT EXISTS speech_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            device_id TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL,
            provider TEXT NOT NULL,
            units INTEGER NOT NULL DEFAULT 0,
            ok INTEGER NOT NULL DEFAULT 0,
            reason TEXT DEFAULT '',
            lang TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_speech_usage_date ON speech_usage(created_at);
        CREATE INDEX IF NOT EXISTS idx_speech_usage_device ON speech_usage(device_id, created_at);
        `)
		if speechTableErr != nil {
			log.Printf("❌ speech_usage create failed: %v", speechTableErr)
		}
	})
	return speechTableErr
}

func speechMonthStart(now time.Time) string {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02 15:04:05")
}

func speechDayStart(now time.Time) string {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).Format("2006-01-02 15:04:05")
}

// speechReserve books units before a provider call. monthCap counts this
// kind+provider for the whole app; devDayCap counts this kind on this device
// across providers. over = "" when booked (id = the row to settle).
func speechReserve(deviceID, kind, provider, lang string, units, monthCap, devDayCap int, now time.Time) (id int64, over string, err error) {
	if err = ensureSpeechUsageTable(); err != nil {
		return 0, "", err
	}
	speechLedgerMu.Lock()
	defer speechLedgerMu.Unlock()
	var month, day int
	if err = analyticsDB.QueryRow(`SELECT COALESCE(SUM(units), 0) FROM speech_usage
        WHERE source = ? AND kind = ? AND provider = ? AND created_at >= ?`,
		speechSource, kind, provider, speechMonthStart(now)).Scan(&month); err != nil {
		return 0, "", err
	}
	if month+units > monthCap {
		return 0, provider + "_month_limit", nil
	}
	if err = analyticsDB.QueryRow(`SELECT COALESCE(SUM(units), 0) FROM speech_usage
        WHERE source = ? AND kind = ? AND device_id = ? AND created_at >= ?`,
		speechSource, kind, deviceID, speechDayStart(now)).Scan(&day); err != nil {
		return 0, "", err
	}
	if day+units > devDayCap {
		return 0, "device_day_limit", nil
	}
	res, err := analyticsDB.Exec(`INSERT INTO speech_usage (source, device_id, kind, provider, units, ok, reason, lang, created_at)
        VALUES (?, ?, ?, ?, ?, 0, 'reserved', ?, ?)`,
		speechSource, deviceID, kind, provider, units, lang, now.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, "", err
	}
	id, err = res.LastInsertId()
	return id, "", err
}

// speechSettle records the outcome of a reserved call (units stay booked).
func speechSettle(id int64, ok bool, reason string) {
	if id == 0 || analyticsDB == nil {
		return
	}
	okInt := 0
	if ok {
		okInt = 1
	}
	if _, err := analyticsDB.Exec(`UPDATE speech_usage SET ok = ?, reason = ? WHERE id = ?`, okInt, trimForLog(reason), id); err != nil {
		log.Printf("⚠️ speech_usage settle %d: %v", id, err)
	}
}

// --- text to speech ---

var speechSpaceRe = regexp.MustCompile(`\s+`)

// speechSSML wraps already-plain text in SSML for one voice (XML-escaped).
func speechSSML(locale, voice, text string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(text))
	return fmt.Sprintf(`<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="%s"><voice name="%s">%s</voice></speak>`,
		locale, voice, b.String())
}

type speechTTSRequest struct {
	Text string `json:"text"`
	Lang string `json:"lang"`
}

func speechFail(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "fallback": true, "reason": reason})
}

// speechTTSHandler — POST /api/speech/tts {text, lang} → audio/mpeg, or a
// JSON refusal telling the app to use the phone's voice.
func speechTTSHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		speechFail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req speechTTSRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		speechFail(w, http.StatusBadRequest, "bad_request")
		return
	}
	audio, reason := speechSynthesize(claims.DeviceID, req.Text, req.Lang, speechConfigFromEnv(), time.Now())
	if reason != "" {
		speechFail(w, http.StatusServiceUnavailable, reason)
		return
	}
	w.Header().Set("Content-Type", "audio/mpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(audio)))
	w.Write(audio)
}

// speechSynthesize returns mp3 bytes or the refusal reason.
func speechSynthesize(deviceID, text, lang string, cfg speechConfig, now time.Time) ([]byte, string) {
	if deviceID == "" {
		// The day caps are per device: a token without one would share a
		// single '' bucket with every other such token.
		return nil, "no_device"
	}
	l := speechLang(lang)
	if l == "" {
		return nil, "unsupported_lang"
	}
	text = strings.TrimSpace(speechSpaceRe.ReplaceAllString(text, " "))
	n := utf8.RuneCountInString(text)
	switch {
	case n == 0:
		return nil, "empty_text"
	case n > speechTTSMaxRunes:
		return nil, "text_too_long"
	}
	if p := cfg.azureProblem(); p != "" {
		return nil, p
	}
	if b := speechTTSBreaker.blocked(now); b != "" {
		return nil, b
	}
	if !speechTTSBreaker.takeRate(now, speechTTSPerMinute) {
		return nil, "rate_limited"
	}
	id, over, err := speechReserve(deviceID, speechKindTTS, speechProviderAzure, l, n, cfg.ttsMonth, cfg.ttsDevDay, now)
	if err != nil {
		log.Printf("⚠️ speech tts reserve: %v", err)
		return nil, "ledger_error"
	}
	if over != "" {
		return nil, over
	}
	v := speechVoices[l]
	ctx, cancel := context.WithTimeout(context.Background(), speechTTSTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, speechAzureTTSURL(cfg.region),
		strings.NewReader(speechSSML(v.locale, v.name, text)))
	if err != nil {
		speechSettle(id, false, "request_build")
		return nil, "azure_error"
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", cfg.key)
	req.Header.Set("Content-Type", "application/ssml+xml")
	req.Header.Set("X-Microsoft-OutputFormat", speechTTSOutputFormat)
	req.Header.Set("User-Agent", speechUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		speechSettle(id, false, "azure_transport")
		log.Printf("⚠️ speech tts: Azure transport error (%T)", err)
		return nil, "azure_error"
	}
	defer resp.Body.Close()
	speechTTSBreaker.onStatus(resp.StatusCode, now, "tts")
	if resp.StatusCode != http.StatusOK {
		speechSettle(id, false, fmt.Sprintf("azure_http_%d", resp.StatusCode))
		return nil, fmt.Sprintf("azure_http_%d", resp.StatusCode)
	}
	audio, err := io.ReadAll(io.LimitReader(resp.Body, speechMaxAudioBytes+1))
	if err != nil || len(audio) == 0 || len(audio) > speechMaxAudioBytes {
		speechSettle(id, false, "azure_bad_audio")
		return nil, "azure_error"
	}
	speechSettle(id, true, "ok")
	return audio, ""
}

// --- speech to text ---

// ffmpegToWav16k converts any clip ffmpeg reads to 16 kHz mono 16-bit WAV,
// cut at 60 s (the app stops recording at 60 s) so a clip near the limit
// still transcribes instead of failing as too long.
func ffmpegToWav16k(in []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "speech-stt-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	src, dst := filepath.Join(dir, "in"), filepath.Join(dir, "out.wav")
	if err := os.WriteFile(src, in, 0o600); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
		"-i", src, "-ac", "1", "-ar", "16000", "-sample_fmt", "s16", "-t", "60", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ffmpeg: %v: %s", err, trimForLog(string(out)))
	}
	return os.ReadFile(dst)
}

// speechWavSeconds — duration of a 16 kHz mono s16 WAV (44-byte header).
func speechWavSeconds(wav []byte) float64 {
	if len(wav) <= 44 {
		return 0
	}
	return float64(len(wav)-44) / 32000.0
}

// speechAzureSTTResult reads the short-audio REST reply (format=simple).
// ok=false means a failed recognition; ok with "" means silence / no match.
func speechAzureSTTResult(body []byte) (text string, ok bool) {
	var out struct {
		RecognitionStatus string `json:"RecognitionStatus"`
		DisplayText       string `json:"DisplayText"`
	}
	if json.Unmarshal(body, &out) != nil {
		return "", false
	}
	switch out.RecognitionStatus {
	case "Success":
		return strings.TrimSpace(out.DisplayText), true
	case "NoMatch", "InitialSilenceTimeout", "BabbleTimeout":
		return "", true
	}
	return "", false
}

// speechAzureRecognize — one Azure F0 short-audio call (slot already held).
func speechAzureRecognize(cfg speechConfig, wav []byte, locale string, now time.Time) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), speechHTTPTimeout)
	defer cancel()
	u := speechAzureSTTURL(cfg.region) + "?language=" + locale + "&format=simple"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(wav))
	if err != nil {
		return "", "azure_error"
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", cfg.key)
	req.Header.Set("Content-Type", "audio/wav; codecs=audio/pcm; samplerate=16000")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", speechUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("⚠️ speech stt: Azure transport error (%T)", err)
		return "", "azure_transport"
	}
	defer resp.Body.Close()
	speechSTTBreaker.onStatus(resp.StatusCode, now, "stt")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Sprintf("azure_http_%d", resp.StatusCode)
	}
	text, ok := speechAzureSTTResult(body)
	if !ok {
		return "", "azure_unrecognized"
	}
	return text, ""
}

// speechGroqRecognize — the paid fallback (owner-approved), one call.
func speechGroqRecognize(cfg speechConfig, wav []byte, lang string) (string, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "voice.wav")
	if err != nil {
		return "", "groq_error"
	}
	fw.Write(wav)
	mw.WriteField("model", speechGroqModel)
	mw.WriteField("language", lang)
	mw.WriteField("response_format", "json")
	mw.WriteField("temperature", "0")
	mw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), speechHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, speechGroqURL, &buf)
	if err != nil {
		return "", "groq_error"
	}
	req.Header.Set("Authorization", "Bearer "+cfg.groqKey)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("⚠️ speech stt: Groq transport error (%T)", err)
		return "", "groq_transport"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Sprintf("groq_http_%d", resp.StatusCode)
	}
	var out struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(body, &out) != nil {
		return "", "groq_bad_reply"
	}
	return strings.TrimSpace(out.Text), ""
}

type speechSTTResult struct {
	Success  bool   `json:"success"`
	Text     string `json:"text"`
	Provider string `json:"provider,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// speechTranscribe: Azure F0 first; on any Azure refusal Groq (if keyed).
func speechTranscribe(deviceID, lang string, wav []byte, cfg speechConfig, now time.Time) speechSTTResult {
	if deviceID == "" {
		return speechSTTResult{Reason: "no_device"}
	}
	l := speechLang(lang)
	if l == "" {
		return speechSTTResult{Reason: "unsupported_lang"}
	}
	secs := speechWavSeconds(wav)
	switch {
	case secs < speechSTTMinSeconds:
		return speechSTTResult{Success: true, Reason: "too_short"}
	case secs > speechSTTMaxSeconds:
		return speechSTTResult{Reason: "too_long"}
	}
	units := int(math.Ceil(secs))

	azureWhy := cfg.azureProblem()
	if azureWhy == "" {
		azureWhy = speechSTTBreaker.blocked(now)
	}
	if azureWhy == "" {
		select {
		case speechSTTSlot <- struct{}{}:
			id, over, err := speechReserve(deviceID, speechKindSTT, speechProviderAzure, l, units, cfg.sttMonth, cfg.sttDevDay, now)
			switch {
			case err != nil:
				log.Printf("⚠️ speech stt reserve: %v", err)
				azureWhy = "ledger_error"
			case over == "device_day_limit":
				<-speechSTTSlot
				// The device's own day is used up: no paid fallback for it.
				return speechSTTResult{Reason: over}
			case over != "":
				azureWhy = over
			default:
				text, why := speechAzureRecognize(cfg, wav, speechVoices[l].locale, now)
				speechSettle(id, why == "", firstNonEmpty(why, "ok"))
				if why == "" {
					<-speechSTTSlot
					return speechSTTResult{Success: true, Text: text, Provider: speechProviderAzure}
				}
				azureWhy = why
			}
			<-speechSTTSlot
		case <-time.After(speechSTTBusyWait):
			azureWhy = "azure_busy"
		}
	}

	if cfg.groqKey == "" {
		return speechSTTResult{Reason: azureWhy}
	}
	id, over, err := speechReserve(deviceID, speechKindSTT, speechProviderGroq, l, units, cfg.groqMonth, cfg.sttDevDay, now)
	if err != nil {
		log.Printf("⚠️ speech groq reserve: %v", err)
		return speechSTTResult{Reason: "ledger_error"}
	}
	if over != "" {
		return speechSTTResult{Reason: over}
	}
	text, why := speechGroqRecognize(cfg, wav, l)
	speechSettle(id, why == "", firstNonEmpty(why, "ok after "+azureWhy))
	if why != "" {
		return speechSTTResult{Reason: why}
	}
	return speechSTTResult{Success: true, Text: text, Provider: speechProviderGroq}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// speechSTTHandler — POST /api/speech/stt?lang=xx, body = the recorded clip.
func speechSTTHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		speechFail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	clip, err := io.ReadAll(http.MaxBytesReader(w, r.Body, speechSTTMaxBytes))
	if err != nil || len(clip) == 0 {
		speechFail(w, http.StatusBadRequest, "bad_audio")
		return
	}
	wav, err := speechToWav(clip)
	if err != nil {
		log.Printf("⚠️ speech stt: convert failed: %v", err)
		speechFail(w, http.StatusBadRequest, "bad_audio")
		return
	}
	res := speechTranscribe(claims.DeviceID, r.URL.Query().Get("lang"), wav, speechConfigFromEnv(), time.Now())
	w.Header().Set("Content-Type", "application/json")
	if !res.Success {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(res)
}

// adminGetSpeechUsage — GET /api/admin/speech-usage?days=N: the app's Azure /
// Groq spend by kind and provider, for the owner and the weekly report.
func adminGetSpeechUsage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !isAdminEmail(r.URL.Query().Get("admin_email")) || ADMIN_SECRET_KEY == "" ||
		r.URL.Query().Get("admin_secret") != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}
	days := 30
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 && d <= 400 {
		days = d
	}
	if err := ensureSpeechUsageTable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "speech usage unavailable"})
		return
	}
	rows, err := analyticsDB.Query(`SELECT kind, provider, COUNT(*), SUM(ok), COALESCE(SUM(units), 0), COUNT(DISTINCT device_id)
        FROM speech_usage WHERE created_at >= datetime('now', ?) GROUP BY kind, provider ORDER BY kind, provider`,
		fmt.Sprintf("-%d days", days))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var kind, provider string
		var calls, okCalls, units, devices int
		if err := rows.Scan(&kind, &provider, &calls, &okCalls, &units, &devices); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		out = append(out, map[string]interface{}{"kind": kind, "provider": provider, "calls": calls,
			"ok": okCalls, "units": units, "devices": devices})
	}
	if err := rows.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	cfg := speechConfigFromEnv()
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "days": days, "rows": out,
		"limits": map[string]int{"tts_month_chars": cfg.ttsMonth, "stt_month_seconds": cfg.sttMonth,
			"groq_month_seconds": cfg.groqMonth},
		"azure": firstNonEmpty(cfg.azureProblem(), "ok"), "groq_configured": cfg.groqKey != ""})
}
