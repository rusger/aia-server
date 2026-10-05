package main

// presenter_video.go — ready-made presenter videos (owner 05.10.2026).
//
// The fixed readings (mahadasha, tithi, Sade Sati) are the same text for every
// user of a language, so their presenter videos are rendered once on the
// owner's Mac with the app's own renderer and served from here to both
// platforms: Android has no on-device renderer at all, and an iPhone gets the
// file in seconds instead of rendering for a minute.
//
// A video is named by the cache key of its voice (ttsCacheKey: model, voice,
// lang, text) and lives in <PRESENTER_VIDEO_DIR>/<render version>/<key>.mp4.
// Files are put there from the Mac over ssh; nothing here writes them.
//
//   POST /api/presenter/video/lookup  {text, gender, lang, version}
//        → {success, key, available, bytes}   the server computes the key with
//        the same code as /api/tts, so the client never has to.
//   GET  /api/presenter/video?key=<40 hex>&v=<vN>  → video/mp4 (Range supported)

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	presenterKeyRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	presenterVersionRe = regexp.MustCompile(`^v[0-9]{1,4}$`)
)

// A real video is megabytes; anything under 1 KB is a truncated copy.
const presenterVideoMinBytes = 1024

func presenterVideoDir() string {
	if d := os.Getenv("PRESENTER_VIDEO_DIR"); d != "" {
		return d
	}
	return "./presenter_videos"
}

// presenterVideoPath: where the video of (version, key) lives; ok is false for
// anything but a well-formed pair, so a path can never leave the directory.
func presenterVideoPath(version, key string) (string, bool) {
	if !presenterVersionRe.MatchString(version) || !presenterKeyRe.MatchString(key) {
		return "", false
	}
	return filepath.Join(presenterVideoDir(), version, key+".mp4"), true
}

// presenterVideoSize: size of a stored video, 0 when it is absent or truncated.
func presenterVideoSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() < presenterVideoMinBytes {
		return 0
	}
	return st.Size()
}

func presenterVideoError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": msg})
}

type presenterLookupRequest struct {
	Text    string `json:"text"`
	Gender  string `json:"gender"`
	Lang    string `json:"lang"`
	Version string `json:"version"`
}

// presenterVideoLookupHandler: is there a ready video for this text?
func presenterVideoLookupHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value("claims").(*JWTClaims); !ok {
		presenterVideoError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req presenterLookupRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		presenterVideoError(w, http.StatusBadRequest, "Invalid request format")
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		presenterVideoError(w, http.StatusBadRequest, "text is required")
		return
	}
	if len([]rune(text)) > ttsMaxChars {
		presenterVideoError(w, http.StatusBadRequest, fmt.Sprintf("text longer than %d characters", ttsMaxChars))
		return
	}
	// Same key as the voice of this text in /api/tts.
	key := ttsCacheKey(ttsModel, ttsVoiceFor(req.Gender, req.Lang), req.Lang, text)
	path, ok := presenterVideoPath(req.Version, key)
	if !ok {
		presenterVideoError(w, http.StatusBadRequest, "version must look like v17")
		return
	}
	size := presenterVideoSize(path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true, "key": key, "available": size > 0, "bytes": size,
	})
}

// presenterVideoHandler: the video file itself.
func presenterVideoHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value("claims").(*JWTClaims); !ok {
		presenterVideoError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	path, ok := presenterVideoPath(r.URL.Query().Get("v"), r.URL.Query().Get("key"))
	if !ok {
		presenterVideoError(w, http.StatusBadRequest, "key must be 40 hex characters and v like v17")
		return
	}
	if presenterVideoSize(path) == 0 {
		presenterVideoError(w, http.StatusNotFound, "no video for this key")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		presenterVideoError(w, http.StatusNotFound, "no video for this key")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		presenterVideoError(w, http.StatusNotFound, "no video for this key")
		return
	}
	// A (version, key) names one render for good: the file never changes under its name.
	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	http.ServeContent(w, r, "", st.ModTime(), f)
}
