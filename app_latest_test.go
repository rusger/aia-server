package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAppLatest(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app_latest.json")
	t.Setenv("APP_LATEST_FILE", f)
	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		appLatestHandler(w, httptest.NewRequest("GET", "/api/app/latest", nil))
		return w
	}
	if w := get(); w.Code != 404 {
		t.Fatalf("no file → 404, got %d", w.Code)
	}
	os.WriteFile(f, []byte("{bad"), 0o644)
	if w := get(); w.Code != 404 {
		t.Fatalf("bad JSON → 404, got %d", w.Code)
	}
	body := `{"version":"2.1.19","build":151,"released":"2026-10-15","android_url":"https://play.google.com/store/apps/details?id=com.astrolytix.app"}`
	os.WriteFile(f, []byte(body), 0o644)
	w := get()
	if w.Code != 200 || w.Body.String() != body || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("got %d %q cache=%q", w.Code, w.Body.String(), w.Header().Get("Cache-Control"))
	}
}
