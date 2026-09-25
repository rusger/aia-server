package main

// tts.go — POST /api/tts: OpenAI text-to-speech for the app (owner 25.09.2026).
//
// First user: the voice-over of the share «highlights» video; next: the in-app
// presenters (the iPhone system voice is the weak spot, and OpenAI gives a
// reliable male/female pair). Measured 24.09.2026: gpt-4o-mini-tts ≈ 35–47 s
// of speech for 9 sentences ≈ 1 ¢ at the list price.
//
// The API key never leaves the server. Every distinct (model, voice, lang,
// text) is synthesized once and kept on disk (TTS_CACHE_DIR), so a repeat —
// the same highlights shared again, the same reading re-rendered — costs
// nothing. Per-device daily cap TTS_DAILY_PER_DEVICE (default 40) counted in
// api_calls (call_type "tts"), which also feeds the usage / finance reports.

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	ttsModel    = "gpt-4o-mini-tts"
	ttsMaxChars = 4000 // presenters read up to ~3000 chars; OpenAI accepts 4096
	ttsEndpoint = "https://api.openai.com/v1/audio/speech"
)

// ttsInstructions: one calm narrator for every language — the model follows
// the text's own language.
const ttsInstructions = "Warm, calm, unhurried narrator reading a personal astrology reading to its owner. " +
	"Natural pace, clear diction, gentle confidence; no theatrics."

type ttsRequest struct {
	Text   string `json:"text"`
	Gender string `json:"gender"` // "f" | "m" (presenter pool convention); anything else → female
	Lang   string `json:"lang"`   // informational: part of the cache key
}

// ttsVoiceFor maps the presenter gender to the approved OpenAI voices
// (owner 25.09.2026: nova / onyx for Russian, shimmer / ash for English).
func ttsVoiceFor(gender, lang string) string {
	male := strings.HasPrefix(strings.ToLower(gender), "m")
	if strings.HasPrefix(strings.ToLower(lang), "en") {
		if male {
			return "ash"
		}
		return "shimmer"
	}
	if male {
		return "onyx"
	}
	return "nova"
}

// ttsCacheKey: sha1 of everything that changes the audio.
func ttsCacheKey(model, voice, lang, text string) string {
	h := sha1.Sum([]byte(model + "|" + voice + "|" + strings.ToLower(lang) + "|" + strings.TrimSpace(text)))
	return hex.EncodeToString(h[:])
}

func ttsCacheDir() string {
	if d := os.Getenv("TTS_CACHE_DIR"); d != "" {
		return d
	}
	return "./tts_cache"
}

func ttsDailyPerDevice() int {
	if v, err := strconv.Atoi(os.Getenv("TTS_DAILY_PER_DEVICE")); err == nil && v > 0 {
		return v
	}
	return 40
}

// ttsFetch calls OpenAI; a test injects its own.
var ttsFetch = func(model, voice, instructions, text string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"model": model, "voice": voice, "input": text,
		"instructions": instructions, "response_format": "mp3",
	})
	req, err := http.NewRequest("POST", ttsEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai tts %d: %s", resp.StatusCode, truncateForLog(string(data), 200))
	}
	return data, nil
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ttsUsedToday counts this device's paid syntheses today (cache hits are not logged).
func ttsUsedToday(deviceID string) int {
	if analyticsDB == nil {
		return 0
	}
	var n int
	err := analyticsDB.QueryRow(`SELECT COUNT(*) FROM api_calls WHERE device_id = ? AND call_type = 'tts' AND created_at >= date('now')`, deviceID).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

func ttsError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": msg})
}

// ttsHandler: POST /api/tts → audio/mpeg (X-TTS-Cache: hit|miss).
func ttsHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		ttsError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req ttsRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		ttsError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		ttsError(w, http.StatusBadRequest, "text is required")
		return
	}
	if len([]rune(text)) > ttsMaxChars {
		ttsError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("text longer than %d characters", ttsMaxChars))
		return
	}
	voice := ttsVoiceFor(req.Gender, req.Lang)
	key := ttsCacheKey(ttsModel, voice, req.Lang, text)
	dir := ttsCacheDir()
	path := filepath.Join(dir, key+".mp3")
	// A real mp3 from OpenAI is tens of KB; anything under 200 bytes is a
	// truncated write and is re-synthesized rather than served.
	if data, err := os.ReadFile(path); err == nil && len(data) > 200 {
		w.Header().Set("Content-Type", "audio/mpeg")
		w.Header().Set("X-TTS-Cache", "hit")
		w.Header().Set("X-TTS-Voice", voice)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	}
	deviceID := claims.DeviceID
	if OPENAI_API_KEY == "" && !ttsFetchInjected {
		ttsError(w, http.StatusServiceUnavailable, "TTS not configured on server")
		return
	}
	if ipLimiter != nil {
		if lim := ipLimiter.GetLimiter(getClientIP(r)); lim != nil && !lim.Allow() {
			ttsError(w, http.StatusTooManyRequests, "Too many requests from your network. Please wait.")
			return
		}
	}
	if deviceLimiter != nil {
		if lim := deviceLimiter.GetLimiter(deviceID); lim != nil && !lim.Allow() {
			ttsError(w, http.StatusTooManyRequests, "Rate limit exceeded. Please try again.")
			return
		}
	}
	if used, cap := ttsUsedToday(deviceID), ttsDailyPerDevice(); used >= cap {
		log.Printf("🔇 tts daily cap: device=%s used=%d cap=%d", deviceID, used, cap)
		ttsError(w, http.StatusTooManyRequests, "Daily voice limit reached")
		return
	}
	started := time.Now()
	data, err := ttsFetch(ttsModel, voice, ttsInstructions, text)
	if err != nil {
		log.Printf("❌ tts: device=%s voice=%s chars=%d: %v", deviceID, voice, len([]rune(text)), err)
		ttsError(w, http.StatusBadGateway, "voice synthesis failed")
		return
	}
	// Unique temp file + rename: two simultaneous misses for the same text
	// must never interleave into one corrupt cached mp3 (review r1).
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("⚠️ tts cache mkdir %s: %v", dir, err)
	} else if f, err := os.CreateTemp(dir, key+"-*.part"); err != nil {
		log.Printf("⚠️ tts cache temp %s: %v", dir, err)
	} else {
		tmp := f.Name()
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			log.Printf("⚠️ tts cache write %s: %v %v", tmp, werr, cerr)
			os.Remove(tmp)
		} else if rerr := os.Rename(tmp, path); rerr != nil {
			log.Printf("⚠️ tts cache rename %s: %v", path, rerr)
			os.Remove(tmp)
		}
	}
	chars := len([]rune(text))
	logAPICallWithTokens(deviceID, "tts", ttsModel, chars, 0, chars, 0)
	log.Printf("🔊 tts: device=%s voice=%s chars=%d bytes=%d in %dms", deviceID, voice, chars, len(data), time.Since(started).Milliseconds())
	w.Header().Set("Content-Type", "audio/mpeg")
	w.Header().Set("X-TTS-Cache", "miss")
	w.Header().Set("X-TTS-Voice", voice)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ttsFetchInjected lets tests run without an API key.
var ttsFetchInjected = false
