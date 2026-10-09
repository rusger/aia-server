package main

// Website consultant chat (astrolytix.com), owner 2026-10-10.
//
// Two PUBLIC routes (no JWT — the site visitor has no account):
//   POST /api/chat/message  -> POST {upstream}/web/chat/message
//   GET  /api/chat/history  -> GET  {upstream}/web/chat/history?session=…
// The upstream is the insta-agent Python service on the same box
// (WEB_CHAT_UPSTREAM, default http://127.0.0.1:8083), which relays the
// question to the owner's Telegram. This Go layer is the first line of
// defence: origin check, strict validation, honeypot, minimum fill time and
// per-IP / global sliding-window limits, so spam never reaches Telegram.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Limits (owner decision 2026-10-10). All are sliding windows over the
// timestamps of ACCEPTED requests, kept in memory (reset on restart).
const (
	webChatPerIPHourLimit  = 7   // messages per IP per rolling hour
	webChatPerIPDayLimit   = 21  // messages per IP per rolling 24 hours
	webChatGlobalHourLimit = 100 // messages per rolling hour across ALL IPs
	webChatHistoryPerMin   = 60  // history polls per IP per rolling minute

	webChatMaxBody      = 4096 // max POST body, bytes
	webChatMinTextRunes = 10   // text length after trim, runes
	webChatMaxTextRunes = 600
	webChatMaxPageRunes = 200
	webChatMinFillTime  = 5 * time.Second // opened_at must be at least this old
	webChatMaxFillTime  = 24 * time.Hour  // ...and at most this old

	webChatUpstreamTimeout = 25 * time.Second
	webChatMaxUpstreamBody = 1 << 20 // larger upstream replies are treated as broken

	webChatDefaultUpstream = "http://127.0.0.1:8083"
	webChatDefaultIPSalt   = "astrolytix"
)

var webChatAllowedOrigins = map[string]bool{
	"https://astrolytix.com":     true,
	"https://www.astrolytix.com": true,
}

var (
	webChatSessionRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	webChatLangRe    = regexp.MustCompile(`^[a-z-]{2,5}$`)
)

// slidingWindow counts events per key over a rolling window. Only events
// that were let through are recorded, so each key holds at most `limit`
// timestamps; empty keys are swept periodically so the map cannot grow
// without bound.
type slidingWindow struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	hits      map[string][]time.Time
	lastSweep time.Time
}

func newSlidingWindow(limit int, window time.Duration) *slidingWindow {
	return &slidingWindow{limit: limit, window: window, hits: make(map[string][]time.Time)}
}

// pruneLocked drops timestamps that have left the window for key.
func (s *slidingWindow) pruneLocked(key string, now time.Time) []time.Time {
	ts := s.hits[key]
	cut := now.Add(-s.window)
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(s.hits, key)
		return nil
	}
	s.hits[key] = ts
	return ts
}

func (s *slidingWindow) sweepLocked(now time.Time) {
	if now.Sub(s.lastSweep) < time.Minute {
		return
	}
	s.lastSweep = now
	for k := range s.hits {
		s.pruneLocked(k, now)
	}
}

// wait returns 0 if one more event for key fits into the window now,
// otherwise how long until the oldest blocking event leaves the window.
func (s *slidingWindow) wait(key string, now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	ts := s.pruneLocked(key, now)
	if len(ts) < s.limit {
		return 0
	}
	return ts[len(ts)-s.limit].Add(s.window).Sub(now)
}

func (s *slidingWindow) add(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits[key] = append(s.pruneLocked(key, now), now)
}

type webChatCheck struct {
	w   *slidingWindow
	key string
}

// webChatService holds the limiter state and upstream client. A package-level
// instance serves production; tests build their own with a fake clock.
type webChatService struct {
	mu      sync.Mutex // makes check-all-then-record atomic across windows
	ipHour  *slidingWindow
	ipDay   *slidingWindow
	global  *slidingWindow
	history *slidingWindow
	client  *http.Client
	now     func() time.Time
}

func newWebChatService() *webChatService {
	return &webChatService{
		ipHour:  newSlidingWindow(webChatPerIPHourLimit, time.Hour),
		ipDay:   newSlidingWindow(webChatPerIPDayLimit, 24*time.Hour),
		global:  newSlidingWindow(webChatGlobalHourLimit, time.Hour),
		history: newSlidingWindow(webChatHistoryPerMin, time.Minute),
		client:  &http.Client{Timeout: webChatUpstreamTimeout},
		now:     time.Now,
	}
}

var webChat = newWebChatService()

// allow checks every window and records the event in all of them only if all
// allow it. Otherwise returns the longest wait (every window must free up).
func (s *webChatService) allow(now time.Time, checks ...webChatCheck) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var longest time.Duration
	for _, c := range checks {
		if d := c.w.wait(c.key, now); d > longest {
			longest = d
		}
	}
	if longest > 0 {
		return longest
	}
	for _, c := range checks {
		c.w.add(c.key, now)
	}
	return 0
}

func webChatUpstream() string {
	if u := strings.TrimSpace(os.Getenv("WEB_CHAT_UPSTREAM")); u != "" {
		return strings.TrimRight(u, "/")
	}
	return webChatDefaultUpstream
}

func webChatIPHash(ip string) string {
	salt := os.Getenv("WEB_CHAT_IP_SALT")
	if salt == "" {
		salt = webChatDefaultIPSalt
	}
	sum := sha256.Sum256([]byte(ip + salt))
	return hex.EncodeToString(sum[:])[:12]
}

func webChatJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("web-chat: write response: %v", err)
	}
}

func webChatReject(w http.ResponseWriter, status int, code, reason, ipHash string) {
	log.Printf("web-chat: reject status=%d reason=%s ip_hash=%s", status, reason, ipHash)
	webChatJSON(w, status, map[string]string{"error": code})
}

func webChatRateLimited(w http.ResponseWriter, wait time.Duration, reason, ipHash string) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	log.Printf("web-chat: reject status=429 reason=%s ip_hash=%s retry_after=%d", reason, ipHash, secs)
	w.Header().Set("Retry-After", fmt.Sprint(secs))
	webChatJSON(w, http.StatusTooManyRequests, map[string]interface{}{"error": "rate", "retry_after": secs})
}

type webChatMessageReq struct {
	Session  string `json:"session"`
	Text     string `json:"text"`
	Lang     string `json:"lang"`
	Page     string `json:"page"`
	Website  string `json:"website"`
	OpenedAt int64  `json:"opened_at"`
}

// validateWebChatMessage returns "" if the message is acceptable, otherwise
// an internal reason for the log (never sent to the client). It normalises
// req.Text (trim) on success.
func validateWebChatMessage(req *webChatMessageReq, now time.Time) string {
	if !webChatSessionRe.MatchString(req.Session) {
		return "session"
	}
	if req.Website != "" {
		return "honeypot"
	}
	text := strings.TrimSpace(req.Text)
	if !utf8.ValidString(text) {
		return "text_utf8"
	}
	n := utf8.RuneCountInString(text)
	if n < webChatMinTextRunes || n > webChatMaxTextRunes {
		return "text_length"
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") || strings.Contains(lower, "www.") {
		return "text_link"
	}
	if !webChatLangRe.MatchString(req.Lang) {
		return "lang"
	}
	if utf8.RuneCountInString(req.Page) > webChatMaxPageRunes {
		return "page"
	}
	age := now.Sub(time.UnixMilli(req.OpenedAt))
	if age < webChatMinFillTime {
		return "too_fast"
	}
	if age > webChatMaxFillTime {
		return "opened_at_stale"
	}
	req.Text = text
	return ""
}

// handleMessage serves POST /api/chat/message.
func (s *webChatService) handleMessage(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	ipHash := webChatIPHash(ip)

	if !webChatAllowedOrigins[r.Header.Get("Origin")] {
		webChatReject(w, http.StatusForbidden, "origin", "origin", ipHash)
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		webChatReject(w, http.StatusBadRequest, "invalid", "content_type", ipHash)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webChatMaxBody))
	if err != nil {
		webChatReject(w, http.StatusBadRequest, "invalid", "body_size", ipHash)
		return
	}
	var req webChatMessageReq
	if err := json.Unmarshal(body, &req); err != nil {
		webChatReject(w, http.StatusBadRequest, "invalid", "json", ipHash)
		return
	}
	now := s.now()
	if reason := validateWebChatMessage(&req, now); reason != "" {
		webChatReject(w, http.StatusBadRequest, "invalid", reason, ipHash)
		return
	}
	if wait := s.allow(now,
		webChatCheck{s.ipHour, ip},
		webChatCheck{s.ipDay, ip},
		webChatCheck{s.global, ""},
	); wait > 0 {
		webChatRateLimited(w, wait, "message_limit", ipHash)
		return
	}

	out, err := json.Marshal(map[string]string{
		"session": req.Session,
		"text":    req.Text,
		"lang":    req.Lang,
		"page":    req.Page,
		"ip_hash": ipHash,
	})
	if err != nil {
		log.Printf("web-chat: marshal upstream body: %v", err)
		webChatJSON(w, http.StatusBadGateway, map[string]string{"error": "unavailable"})
		return
	}
	log.Printf("web-chat: accepted ip_hash=%s session=%s len=%d", ipHash, req.Session[:8], utf8.RuneCountInString(req.Text))
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, webChatUpstream()+"/web/chat/message", bytes.NewReader(out))
	if err != nil {
		log.Printf("web-chat: build upstream request: %v", err)
		webChatJSON(w, http.StatusBadGateway, map[string]string{"error": "unavailable"})
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	s.forward(w, upReq, ipHash)
}

// handleHistory serves GET /api/chat/history?session=<uuid>.
func (s *webChatService) handleHistory(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	ipHash := webChatIPHash(ip)

	if origin := r.Header.Get("Origin"); origin != "" && !webChatAllowedOrigins[origin] {
		webChatReject(w, http.StatusForbidden, "origin", "origin", ipHash)
		return
	}
	session := r.URL.Query().Get("session")
	if !webChatSessionRe.MatchString(session) {
		webChatReject(w, http.StatusBadRequest, "invalid", "session", ipHash)
		return
	}
	if wait := s.allow(s.now(), webChatCheck{s.history, ip}); wait > 0 {
		webChatRateLimited(w, wait, "history_limit", ipHash)
		return
	}
	q := url.Values{"session": {session}}
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, webChatUpstream()+"/web/chat/history?"+q.Encode(), nil)
	if err != nil {
		log.Printf("web-chat: build upstream request: %v", err)
		webChatJSON(w, http.StatusBadGateway, map[string]string{"error": "unavailable"})
		return
	}
	s.forward(w, upReq, ipHash)
}

// forward sends upReq upstream and relays status + body as is. Network
// errors, timeouts, oversized bodies and non-2xx/4xx statuses become 502.
func (s *webChatService) forward(w http.ResponseWriter, upReq *http.Request, ipHash string) {
	resp, err := s.client.Do(upReq)
	if err != nil {
		log.Printf("web-chat: upstream %s %s failed ip_hash=%s: %v", upReq.Method, upReq.URL.Path, ipHash, err)
		webChatJSON(w, http.StatusBadGateway, map[string]string{"error": "unavailable"})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, webChatMaxUpstreamBody+1))
	if err != nil || len(body) > webChatMaxUpstreamBody {
		log.Printf("web-chat: upstream %s body read failed ip_hash=%s size=%d err=%v", upReq.URL.Path, ipHash, len(body), err)
		webChatJSON(w, http.StatusBadGateway, map[string]string{"error": "unavailable"})
		return
	}
	if resp.StatusCode < 200 || (resp.StatusCode >= 300 && resp.StatusCode < 400) || resp.StatusCode >= 500 {
		log.Printf("web-chat: upstream %s status=%d ip_hash=%s", upReq.URL.Path, resp.StatusCode, ipHash)
		webChatJSON(w, http.StatusBadGateway, map[string]string{"error": "unavailable"})
		return
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(body); err != nil {
		log.Printf("web-chat: write relayed response: %v", err)
	}
}
