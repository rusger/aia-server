package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func geocodeTestUpstream(t *testing.T, status int, body string, delay time.Duration) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("User-Agent") != geocodeUserAgent {
			t.Errorf("User-Agent %q", r.Header.Get("User-Agent"))
		}
		time.Sleep(delay)
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func geocodeTestSetup(t *testing.T, srv *httptest.Server) {
	t.Helper()
	oldUp, oldLim, oldCache, oldClient := geocodeUpstream, geocodeLimiter, geocodeCache, geocodeClient
	geocodeUpstream = srv.URL
	geocodeLimiter = rate.NewLimiter(rate.Inf, 1)
	geocodeCache = newGeocodeCache(3, time.Hour)
	geocodeClient = &http.Client{Timeout: 200 * time.Millisecond}
	t.Cleanup(func() {
		geocodeUpstream, geocodeLimiter, geocodeCache, geocodeClient = oldUp, oldLim, oldCache, oldClient
	})
}

func TestGeocodeSearchProxiesAndCaches(t *testing.T) {
	srv, calls := geocodeTestUpstream(t, 200, `[{"display_name":"Shanghai, China","lat":"31.23","lon":"121.47"}]`, 0)
	geocodeTestSetup(t, srv)
	do := func(q string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		geocodeSearchHandler(rec, httptest.NewRequest("GET", "/api/geocode/search?q="+q+"&lang=zh&limit=50", nil))
		return rec
	}
	rec := do("上海")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Shanghai") || rec.Header().Get("X-Geocode-Cache") != "miss" {
		t.Fatalf("first: %d %s %s", rec.Code, rec.Header().Get("X-Geocode-Cache"), rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("content type %q", rec.Header().Get("Content-Type"))
	}
	rec = do("上海")
	if rec.Code != 200 || rec.Header().Get("X-Geocode-Cache") != "hit" {
		t.Fatalf("second must be a cache hit: %d %s", rec.Code, rec.Header().Get("X-Geocode-Cache"))
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Errorf("upstream called %d times, want 1", *calls)
	}
}

func TestGeocodeSearchValidation(t *testing.T) {
	srv, calls := geocodeTestUpstream(t, 200, `[]`, 0)
	geocodeTestSetup(t, srv)
	for _, q := range []string{"", strings.Repeat("x", 201)} {
		rec := httptest.NewRecorder()
		geocodeSearchHandler(rec, httptest.NewRequest("GET", "/api/geocode/search?q="+q, nil))
		if rec.Code != 400 {
			t.Errorf("q=%q → %d, want 400", q, rec.Code)
		}
	}
	if *calls != 0 {
		t.Error("invalid queries must not reach upstream")
	}
	if geocodeLang("zh") != "zh" || geocodeLang("pt-BR") != "pt-BR" || geocodeLang("../x") != "en" || geocodeLang("") != "en" {
		t.Error("lang sanitising")
	}
}

func TestGeocodeUpstreamFailures(t *testing.T) {
	srv, _ := geocodeTestUpstream(t, 500, `oops`, 0)
	geocodeTestSetup(t, srv)
	rec := httptest.NewRecorder()
	geocodeSearchHandler(rec, httptest.NewRequest("GET", "/api/geocode/search?q=Paris", nil))
	if rec.Code != 502 {
		t.Errorf("upstream 500 → %d, want 502", rec.Code)
	}
	slow, _ := geocodeTestUpstream(t, 200, `[]`, 400*time.Millisecond)
	geocodeTestSetup(t, slow)
	rec = httptest.NewRecorder()
	geocodeSearchHandler(rec, httptest.NewRequest("GET", "/api/geocode/search?q=Paris", nil))
	if rec.Code != 502 {
		t.Errorf("upstream timeout → %d, want 502", rec.Code)
	}
	notJSON, _ := geocodeTestUpstream(t, 200, `<html>blocked</html>`, 0)
	geocodeTestSetup(t, notJSON)
	rec = httptest.NewRecorder()
	geocodeSearchHandler(rec, httptest.NewRequest("GET", "/api/geocode/search?q=Paris", nil))
	if rec.Code != 502 {
		t.Errorf("non-JSON upstream → %d, want 502 (never a 200 the client cannot parse)", rec.Code)
	}
}

func TestGeocodeReverse(t *testing.T) {
	srv, calls := geocodeTestUpstream(t, 200, `{"display_name":"Berlin, Germany"}`, 0)
	geocodeTestSetup(t, srv)
	rec := httptest.NewRecorder()
	geocodeReverseHandler(rec, httptest.NewRequest("GET", "/api/geocode/reverse?lat=52.52001&lon=13.40491&lang=de", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Berlin") {
		t.Fatalf("reverse: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder() // same spot within 11 m → cache
	geocodeReverseHandler(rec, httptest.NewRequest("GET", "/api/geocode/reverse?lat=52.52004&lon=13.40494&lang=de", nil))
	if rec.Header().Get("X-Geocode-Cache") != "hit" || *calls != 1 {
		t.Errorf("rounded coordinates must hit the cache (%s, %d calls)", rec.Header().Get("X-Geocode-Cache"), *calls)
	}
	for _, qs := range []string{"lat=91&lon=0", "lat=0&lon=181", "lat=x&lon=0", ""} {
		rec = httptest.NewRecorder()
		geocodeReverseHandler(rec, httptest.NewRequest("GET", "/api/geocode/reverse?"+qs, nil))
		if rec.Code != 400 {
			t.Errorf("%q → %d, want 400", qs, rec.Code)
		}
	}
}

func TestGeocodeCacheBound(t *testing.T) {
	c := newGeocodeCache(2, time.Hour)
	now := time.Now()
	c.put("a", []byte("1"), now)
	c.put("b", []byte("2"), now)
	c.put("c", []byte("3"), now)
	if _, ok := c.get("a", now); ok {
		t.Error("oldest entry must be evicted")
	}
	if v, ok := c.get("c", now); !ok || string(v) != "3" {
		t.Error("newest entry kept")
	}
	if _, ok := c.get("c", now.Add(2*time.Hour)); ok {
		t.Error("expired entry must miss")
	}
}
