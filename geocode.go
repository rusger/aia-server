package main

// Geocoding proxy (owner 13.10.2026): the app used to query
// nominatim.openstreetmap.org directly, which is unreachable from China —
// 31 iPhones in one week fell back to typing coordinates by hand (and hit
// the birth-info crash). astrolytix.com is reachable there, so the app asks
// us and we ask Nominatim: same JSON back, nothing to re-parse on the
// client.
//
// Nominatim's usage policy: an identifying User-Agent with a contact, at
// most one request per second, and results cached. Hence the global
// limiter, the 30-day in-memory cache keyed by the exact query, and the
// per-IP limiter the other public endpoints use. Upstream failures are
// 502/503 with a short text — never a 200 with an empty body, so the
// client can fall back to its own direct call.

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	geocodeUpstream  = "https://nominatim.openstreetmap.org"
	geocodeUserAgent = "Astrolytix/1.0 (support@astrolytix.com)"
	geocodeClient    = &http.Client{Timeout: 10 * time.Second}
	// Nominatim: max 1 request/s for the whole service.
	geocodeLimiter = rate.NewLimiter(rate.Every(time.Second), 1)
	geocodeCache   = newGeocodeCache(20000, 30*24*time.Hour)
)

const (
	geocodeMaxQuery   = 200
	geocodeMaxBody    = 1 << 20 // 1 MB
	geocodeLimiterMax = 5 * time.Second
)

type geocodeEntry struct {
	body    []byte
	expires time.Time
}

// geocodeCacheT is a bounded TTL cache; when full it drops the oldest
// insertions (good enough: the hot keys are big cities asked again and
// again, and they re-enter on the next miss).
type geocodeCacheT struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	items map[string]geocodeEntry
	order []string
}

func newGeocodeCache(max int, ttl time.Duration) *geocodeCacheT {
	return &geocodeCacheT{max: max, ttl: ttl, items: map[string]geocodeEntry{}}
}

func (c *geocodeCacheT) get(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok || now.After(e.expires) {
		return nil, false
	}
	return e.body, true
}

func (c *geocodeCacheT) put(key string, body []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[key]; !exists {
		c.order = append(c.order, key)
	}
	c.items[key] = geocodeEntry{body: body, expires: now.Add(c.ttl)}
	for len(c.order) > c.max {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
}

// geocodeLang keeps Accept-Language to what Nominatim understands: letters
// and dashes, short ("zh", "pt-BR"); anything else → English.
func geocodeLang(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 8 {
		return "en"
	}
	for _, r := range raw {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
			return "en"
		}
	}
	return raw
}

// geocodeSearchHandler: GET /api/geocode/search?q=<text>&limit=<1..10>&lang=<xx>
func geocodeSearchHandler(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) > geocodeMaxQuery {
		http.Error(w, "q required (1-200 chars)", http.StatusBadRequest)
		return
	}
	limit := 5
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
		limit = n
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 10 {
		limit = 10
	}
	lang := geocodeLang(r.URL.Query().Get("lang"))
	path := "/search?q=" + url.QueryEscape(q) + "&format=json&limit=" + strconv.Itoa(limit) + "&accept-language=" + url.QueryEscape(lang)
	geocodeProxy(w, r, path, lang)
}

// geocodeReverseHandler: GET /api/geocode/reverse?lat=&lon=&lang=<xx>
func geocodeReverseHandler(w http.ResponseWriter, r *http.Request) {
	lat, errLat := strconv.ParseFloat(r.URL.Query().Get("lat"), 64)
	lon, errLon := strconv.ParseFloat(r.URL.Query().Get("lon"), 64)
	if errLat != nil || errLon != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		http.Error(w, "lat/lon required", http.StatusBadRequest)
		return
	}
	lang := geocodeLang(r.URL.Query().Get("lang"))
	// 4 decimals ≈ 11 m: enough for a birth place, and it lets the cache
	// hit for the same spot tapped twice.
	path := "/reverse?lat=" + strconv.FormatFloat(lat, 'f', 4, 64) + "&lon=" + strconv.FormatFloat(lon, 'f', 4, 64) + "&format=json&zoom=10&accept-language=" + url.QueryEscape(lang)
	geocodeProxy(w, r, path, lang)
}

func geocodeProxy(w http.ResponseWriter, r *http.Request, path, lang string) {
	if !ipLimiter.GetLimiter(getClientIP(r)).Allow() {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	now := time.Now()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if body, ok := geocodeCache.get(path, now); ok {
		w.Header().Set("X-Geocode-Cache", "hit")
		w.Write(body)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), geocodeLimiterMax)
	defer cancel()
	if err := geocodeLimiter.Wait(ctx); err != nil {
		http.Error(w, "geocoder busy, retry", http.StatusServiceUnavailable)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, geocodeUpstream+path, nil)
	if err != nil {
		http.Error(w, "bad upstream request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", geocodeUserAgent)
	req.Header.Set("Accept-Language", lang)
	resp, err := geocodeClient.Do(req)
	if err != nil {
		log.Printf("geocode: upstream %s: %v", path, err)
		http.Error(w, "geocoder unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, geocodeMaxBody))
	if err != nil || resp.StatusCode != http.StatusOK || !json.Valid(body) {
		log.Printf("geocode: upstream %s: status %d, %d bytes, err %v", path, resp.StatusCode, len(body), err)
		http.Error(w, "geocoder unavailable", http.StatusBadGateway)
		return
	}
	geocodeCache.put(path, body, now)
	w.Header().Set("X-Geocode-Cache", "miss")
	w.Write(body)
}
