package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPresenterVideoPath(t *testing.T) {
	os.Setenv("PRESENTER_VIDEO_DIR", "/srv/pv")
	defer os.Unsetenv("PRESENTER_VIDEO_DIR")
	key := strings.Repeat("a1", 20)
	if p, ok := presenterVideoPath("v17", key); !ok || p != "/srv/pv/v17/"+key+".mp4" {
		t.Fatalf("path: %q %v", p, ok)
	}
	for _, bad := range [][2]string{
		{"v17", "../../etc/passwd"}, {"v17", strings.Repeat("a", 39)}, {"v17", strings.Repeat("A", 40)},
		{"v17", strings.Repeat("g", 40)}, {"../v17", key}, {"17", key}, {"v", key}, {"v17/..", key}, {"", key}, {"v17", ""},
	} {
		if _, ok := presenterVideoPath(bad[0], bad[1]); ok {
			t.Fatalf("accepted version %q key %q", bad[0], bad[1])
		}
	}
}

func TestPresenterVideoLookupAndServe(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("PRESENTER_VIDEO_DIR", dir)
	defer os.Unsetenv("PRESENTER_VIDEO_DIR")
	claims := &JWTClaims{Email: "a@x", DeviceID: "dev1"}

	lookup := func(body string, c *JWTClaims) (*httptest.ResponseRecorder, map[string]interface{}) {
		r := httptest.NewRequest("POST", "/api/presenter/video/lookup", strings.NewReader(body))
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), "claims", c))
		}
		w := httptest.NewRecorder()
		presenterVideoLookupHandler(w, r)
		var out map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}
	get := func(query string, c *JWTClaims, rng string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/presenter/video?"+query, nil)
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), "claims", c))
		}
		if rng != "" {
			r.Header.Set("Range", rng)
		}
		w := httptest.NewRecorder()
		presenterVideoHandler(w, r)
		return w
	}

	const text = "Период Сатурна учит терпению."
	body := `{"text":"  ` + text + `  ","gender":"f","lang":"ru","version":"v17"}`
	if w, _ := lookup(body, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("lookup without claims: %d", w.Code)
	}
	for _, bad := range []string{
		`{"text":"   ","gender":"f","lang":"ru","version":"v17"}`,
		`{"text":"` + strings.Repeat("а", ttsMaxChars+1) + `","gender":"f","lang":"ru","version":"v17"}`,
		`{"text":"x","gender":"f","lang":"ru","version":"17"}`,
		`{"text":"x","gender":"f","lang":"ru","version":"../v17"}`,
		`{"text":"x","gender":"f","lang":"ru"}`,
		`not json`,
	} {
		if w, _ := lookup(bad, claims); w.Code != http.StatusBadRequest {
			t.Fatalf("lookup %q: %d", bad[:20], w.Code)
		}
	}

	// The key is the voice key of the same text in /api/tts: female Russian → nova.
	want := ttsCacheKey(ttsModel, "nova", "ru", text)
	w, out := lookup(body, claims)
	if w.Code != http.StatusOK || out["key"] != want || out["available"] != false || out["bytes"].(float64) != 0 {
		t.Fatalf("lookup before upload: %d %v (want key %s)", w.Code, out, want)
	}
	if _, m := lookup(`{"text":"`+text+`","gender":"m","lang":"ru","version":"v17"}`, claims); m["key"] == want {
		t.Fatal("another gender must be another key")
	}
	if g := get("key="+want+"&v=v17", claims, ""); g.Code != http.StatusNotFound {
		t.Fatalf("get before upload: %d", g.Code)
	}

	// A truncated file is not a video.
	os.MkdirAll(filepath.Join(dir, "v17"), 0o755)
	path := filepath.Join(dir, "v17", want+".mp4")
	os.WriteFile(path, []byte("short"), 0o644)
	if _, m := lookup(body, claims); m["available"] != false {
		t.Fatal("a truncated file must not be available")
	}
	if g := get("key="+want+"&v=v17", claims, ""); g.Code != http.StatusNotFound {
		t.Fatalf("get truncated: %d", g.Code)
	}

	video := []byte(strings.Repeat("0123456789", 500)) // 5000 bytes
	os.WriteFile(path, video, 0o644)
	if _, m := lookup(body, claims); m["available"] != true || m["bytes"].(float64) != 5000 {
		t.Fatalf("lookup after upload: %v", m)
	}
	// Another render version is another file.
	if _, m := lookup(strings.Replace(body, "v17", "v18", 1), claims); m["available"] != false {
		t.Fatal("v18 must not see the v17 file")
	}

	if g := get("key="+want+"&v=v17", nil, ""); g.Code != http.StatusUnauthorized {
		t.Fatalf("get without claims: %d", g.Code)
	}
	g := get("key="+want+"&v=v17", claims, "")
	if g.Code != http.StatusOK || g.Header().Get("Content-Type") != "video/mp4" || g.Body.Len() != 5000 {
		t.Fatalf("get: %d %s %d bytes", g.Code, g.Header().Get("Content-Type"), g.Body.Len())
	}
	part := get("key="+want+"&v=v17", claims, "bytes=10-19")
	if part.Code != http.StatusPartialContent || part.Body.String() != "0123456789" {
		t.Fatalf("range: %d %q", part.Code, part.Body.String())
	}
	for _, q := range []string{
		"key=" + want + "&v=17", "key=" + want, "key=..%2F..%2Fetc%2Fpasswd&v=v17",
		"key=" + strings.ToUpper(want) + "&v=v17", "key=" + want[:39] + "&v=v17", "v=v17",
	} {
		if b := get(q, claims, ""); b.Code != http.StatusBadRequest {
			t.Fatalf("get %q: %d", q, b.Code)
		}
	}
}
