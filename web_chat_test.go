package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const webChatTestSession = "3f2b8c1e-9a4d-4e7f-8b2c-1d5e6f7a8b9c"

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestWebChat() (*webChatService, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	s := newWebChatService()
	s.now = clk.now
	return s, clk
}

func webChatBody(now time.Time, mutate func(m map[string]interface{})) string {
	m := map[string]interface{}{
		"session":   webChatTestSession,
		"text":      "When is a good time to start a new job?",
		"lang":      "de",
		"page":      "/",
		"website":   "",
		"opened_at": now.Add(-time.Minute).UnixMilli(),
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func postWebChat(s *webChatService, ip, origin, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/chat/message", strings.NewReader(body))
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.handleMessage(w, r)
	return w
}

// upstreamStub records what the Python side would receive.
type upstreamStub struct {
	mu     sync.Mutex
	bodies []map[string]string
	query  string
	status int
	reply  string
}

func startUpstream(t *testing.T, status int, reply string) *upstreamStub {
	t.Helper()
	u := &upstreamStub{status: status, reply: reply}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/web/chat/message":
			var m map[string]string
			if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
				t.Errorf("upstream decode: %v", err)
			}
			u.bodies = append(u.bodies, m)
		case r.Method == http.MethodGet && r.URL.Path == "/web/chat/history":
			u.query = r.URL.RawQuery
		default:
			t.Errorf("unexpected upstream call %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(u.status)
		io.WriteString(w, u.reply)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("WEB_CHAT_UPSTREAM", srv.URL)
	return u
}

func TestWebChatSlidingWindow(t *testing.T) {
	sw := newSlidingWindow(3, time.Hour)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		now := t0.Add(time.Duration(i) * 10 * time.Minute)
		if d := sw.wait("a", now); d != 0 {
			t.Fatalf("hit %d: want allowed, got wait %v", i, d)
		}
		sw.add("a", now)
	}
	// 4th at +30m: oldest (t0) frees at +60m -> wait 30m.
	if d := sw.wait("a", t0.Add(30*time.Minute)); d != 30*time.Minute {
		t.Fatalf("want wait 30m, got %v", d)
	}
	// Other keys are independent.
	if d := sw.wait("b", t0.Add(30*time.Minute)); d != 0 {
		t.Fatalf("key b should be free, got %v", d)
	}
	// Exactly when the oldest leaves the window, one slot is free.
	if d := sw.wait("a", t0.Add(time.Hour)); d != 0 {
		t.Fatalf("slot should free at +1h, got %v", d)
	}
	// Sweep drops keys whose hits all expired.
	sw.wait("zzz", t0.Add(5*time.Hour))
	sw.mu.Lock()
	n := len(sw.hits)
	sw.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected expired keys swept, %d left", n)
	}
}

func TestWebChatPerIPHourAndDayLimits(t *testing.T) {
	startUpstream(t, 200, `{"session":"x","status":"pending","message_id":1}`)
	s, clk := newTestWebChat()
	ip := "203.0.113.5"
	origin := "https://astrolytix.com"

	for i := 0; i < webChatPerIPHourLimit; i++ {
		if w := postWebChat(s, ip, origin, webChatBody(clk.t, nil)); w.Code != 200 {
			t.Fatalf("msg %d: want 200, got %d %s", i, w.Code, w.Body)
		}
		clk.advance(time.Minute)
	}
	// 8th within the hour -> 429 with retry_after until the first frees.
	w := postWebChat(s, ip, origin, webChatBody(clk.t, nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("8th/hour: want 429, got %d", w.Code)
	}
	var rl struct {
		Error      string `json:"error"`
		RetryAfter int    `json:"retry_after"`
	}
	json.Unmarshal(w.Body.Bytes(), &rl)
	if rl.Error != "rate" || rl.RetryAfter != 53*60 {
		t.Fatalf("want rate/3180s, got %+v", rl)
	}
	if got := w.Header().Get("Retry-After"); got != "3180" {
		t.Fatalf("Retry-After header = %q", got)
	}
	// Another IP is unaffected.
	if w := postWebChat(s, "203.0.113.6", origin, webChatBody(clk.t, nil)); w.Code != 200 {
		t.Fatalf("other IP: want 200, got %d", w.Code)
	}

	// Hours 2 and 3: 7 more each -> 21 total in the day.
	for h := 0; h < 2; h++ {
		clk.advance(time.Hour)
		for i := 0; i < webChatPerIPHourLimit; i++ {
			if w := postWebChat(s, ip, origin, webChatBody(clk.t, nil)); w.Code != 200 {
				t.Fatalf("hour %d msg %d: want 200, got %d", h+2, i, w.Code)
			}
		}
	}
	// Next hour: hourly window is free but the daily cap (21) blocks.
	clk.advance(2 * time.Hour)
	if w := postWebChat(s, ip, origin, webChatBody(clk.t, nil)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("22nd/day: want 429, got %d", w.Code)
	}
	// 24h after the very first message, the day window frees one slot.
	clk.t = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if w := postWebChat(s, ip, origin, webChatBody(clk.t, nil)); w.Code != 200 {
		t.Fatalf("after 24h: want 200, got %d", w.Code)
	}
}

func TestWebChatGlobalLimit(t *testing.T) {
	startUpstream(t, 200, `{"status":"pending"}`)
	s, clk := newTestWebChat()
	for i := 0; i < webChatGlobalHourLimit; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		if w := postWebChat(s, ip, "https://www.astrolytix.com", webChatBody(clk.t, nil)); w.Code != 200 {
			t.Fatalf("msg %d: want 200, got %d", i, w.Code)
		}
	}
	if w := postWebChat(s, "192.0.2.200", "https://astrolytix.com", webChatBody(clk.t, nil)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("101st global: want 429, got %d", w.Code)
	}
	clk.advance(time.Hour)
	if w := postWebChat(s, "192.0.2.200", "https://astrolytix.com", webChatBody(clk.t, nil)); w.Code != 200 {
		t.Fatalf("after window: want 200, got %d", w.Code)
	}
}

func TestWebChatRejectedDoNotConsumeLimit(t *testing.T) {
	startUpstream(t, 200, `{}`)
	s, clk := newTestWebChat()
	for i := 0; i < 20; i++ {
		postWebChat(s, "203.0.113.9", "https://astrolytix.com", webChatBody(clk.t, func(m map[string]interface{}) { m["website"] = "x" }))
	}
	if w := postWebChat(s, "203.0.113.9", "https://astrolytix.com", webChatBody(clk.t, nil)); w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestWebChatValidation(t *testing.T) {
	up := startUpstream(t, 200, `{}`)
	s, clk := newTestWebChat()
	cases := []struct {
		name   string
		mutate func(m map[string]interface{})
	}{
		{"honeypot", func(m map[string]interface{}) { m["website"] = "spam.com" }},
		{"link https", func(m map[string]interface{}) { m["text"] = "look at https://example.com now" }},
		{"link http", func(m map[string]interface{}) { m["text"] = "look at HTTP://example.com now" }},
		{"link www", func(m map[string]interface{}) { m["text"] = "visit www.example.com please" }},
		{"too short", func(m map[string]interface{}) { m["text"] = "   hi there   " }},
		{"too long", func(m map[string]interface{}) { m["text"] = strings.Repeat("я", 601) }},
		{"too fast", func(m map[string]interface{}) { m["opened_at"] = clk.t.Add(-2 * time.Second).UnixMilli() }},
		{"future opened_at", func(m map[string]interface{}) { m["opened_at"] = clk.t.Add(time.Minute).UnixMilli() }},
		{"stale opened_at", func(m map[string]interface{}) { m["opened_at"] = clk.t.Add(-25 * time.Hour).UnixMilli() }},
		{"missing opened_at", func(m map[string]interface{}) { delete(m, "opened_at") }},
		{"bad session", func(m map[string]interface{}) { m["session"] = "not-a-uuid" }},
		{"uuid v1", func(m map[string]interface{}) { m["session"] = "3f2b8c1e-9a4d-1e7f-8b2c-1d5e6f7a8b9c" }},
		{"bad lang", func(m map[string]interface{}) { m["lang"] = "DE" }},
		{"long lang", func(m map[string]interface{}) { m["lang"] = "abcdef" }},
		{"long page", func(m map[string]interface{}) { m["page"] = "/" + strings.Repeat("a", 200) }},
		{"wrong type", func(m map[string]interface{}) { m["website"] = 1 }},
	}
	for _, c := range cases {
		w := postWebChat(s, "203.0.113.20", "https://astrolytix.com", webChatBody(clk.t, c.mutate))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"invalid"`) {
			t.Errorf("%s: want 400 invalid, got %d %s", c.name, w.Code, w.Body)
		}
	}

	// Oversized body.
	big := webChatBody(clk.t, func(m map[string]interface{}) { m["page"] = strings.Repeat("a", 5000) })
	if w := postWebChat(s, "203.0.113.20", "https://astrolytix.com", big); w.Code != 400 {
		t.Errorf("oversized body: want 400, got %d", w.Code)
	}
	// Wrong content type.
	r := httptest.NewRequest(http.MethodPost, "/api/chat/message", strings.NewReader(webChatBody(clk.t, nil)))
	r.Header.Set("Origin", "https://astrolytix.com")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handleMessage(w, r)
	if w.Code != 400 {
		t.Errorf("text/plain: want 400, got %d", w.Code)
	}
	// Boundaries that must pass: 10 runes (after trim), 600 runes, exactly 5 s.
	okCases := []func(m map[string]interface{}){
		func(m map[string]interface{}) { m["text"] = "  " + strings.Repeat("я", 10) + "  " },
		func(m map[string]interface{}) { m["text"] = strings.Repeat("я", 600) },
		func(m map[string]interface{}) { m["opened_at"] = clk.t.Add(-5 * time.Second).UnixMilli() },
		func(m map[string]interface{}) { m["lang"] = "pt-br"; m["page"] = "" },
	}
	for i, mut := range okCases {
		w := postWebChat(s, fmt.Sprintf("203.0.113.%d", 100+i), "https://astrolytix.com", webChatBody(clk.t, mut))
		if w.Code != 200 {
			t.Errorf("ok case %d: want 200, got %d %s", i, w.Code, w.Body)
		}
	}
	if len(up.bodies) != len(okCases) {
		t.Fatalf("only valid messages may reach upstream: got %d, want %d", len(up.bodies), len(okCases))
	}
	if got := up.bodies[0]["text"]; got != strings.Repeat("я", 10) {
		t.Errorf("text must be forwarded trimmed, got %q", got)
	}
}

func TestWebChatOrigin(t *testing.T) {
	startUpstream(t, 200, `{"session":"x","pending":false,"messages":[]}`)
	s, clk := newTestWebChat()
	for _, o := range []string{"", "https://evil.com", "http://astrolytix.com", "https://astrolytix.com.evil.com"} {
		w := postWebChat(s, "203.0.113.30", o, webChatBody(clk.t, nil))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"origin"`) {
			t.Errorf("POST origin %q: want 403 origin, got %d %s", o, w.Code, w.Body)
		}
	}
	get := func(origin string) int {
		r := httptest.NewRequest(http.MethodGet, "/api/chat/history?session="+webChatTestSession, nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		s.handleHistory(w, r)
		return w.Code
	}
	if c := get(""); c != 200 {
		t.Errorf("GET without origin: want 200, got %d", c)
	}
	if c := get("https://www.astrolytix.com"); c != 200 {
		t.Errorf("GET allowed origin: want 200, got %d", c)
	}
	if c := get("https://evil.com"); c != 403 {
		t.Errorf("GET foreign origin: want 403, got %d", c)
	}
}

func TestWebChatForwardMessage(t *testing.T) {
	t.Setenv("WEB_CHAT_IP_SALT", "pepper")
	up := startUpstream(t, 200, `{"session":"`+webChatTestSession+`","status":"pending","message_id":42}`)
	s, clk := newTestWebChat()
	w := postWebChat(s, "203.0.113.40", "https://astrolytix.com", webChatBody(clk.t, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"message_id":42`) {
		t.Fatalf("want relayed 200 body, got %d %s", w.Code, w.Body)
	}
	if len(up.bodies) != 1 {
		t.Fatalf("upstream calls = %d", len(up.bodies))
	}
	got := up.bodies[0]
	want := map[string]string{
		"session": webChatTestSession,
		"text":    "When is a good time to start a new job?",
		"lang":    "de",
		"page":    "/",
		"ip_hash": webChatIPHash("203.0.113.40"),
	}
	if len(got) != len(want) {
		t.Errorf("upstream fields = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("upstream %s = %q, want %q", k, got[k], v)
		}
	}
	if h := got["ip_hash"]; h != webChatIPHashWithSalt("203.0.113.40", "pepper") {
		t.Errorf("ip_hash must be 12 hex using WEB_CHAT_IP_SALT, got %q", h)
	}

	// 409 from Python is relayed as is.
	up.status, up.reply = 409, `{"error":"pending"}`
	w = postWebChat(s, "203.0.113.41", "https://astrolytix.com", webChatBody(clk.t, nil))
	if w.Code != 409 || strings.TrimSpace(w.Body.String()) != `{"error":"pending"}` {
		t.Errorf("409 relay: got %d %s", w.Code, w.Body)
	}
	// 5xx from Python -> 502 unavailable.
	up.status, up.reply = 500, `boom`
	w = postWebChat(s, "203.0.113.42", "https://astrolytix.com", webChatBody(clk.t, nil))
	if w.Code != 502 || !strings.Contains(w.Body.String(), `"unavailable"`) {
		t.Errorf("5xx: want 502, got %d %s", w.Code, w.Body)
	}
}

func webChatIPHashWithSalt(ip, salt string) string {
	sum := sha256.Sum256([]byte(ip + salt))
	return hex.EncodeToString(sum[:])[:12]
}

func TestWebChatUpstreamDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens there now
	t.Setenv("WEB_CHAT_UPSTREAM", url)
	s, clk := newTestWebChat()
	w := postWebChat(s, "203.0.113.50", "https://astrolytix.com", webChatBody(clk.t, nil))
	if w.Code != 502 || !strings.Contains(w.Body.String(), `"unavailable"`) {
		t.Fatalf("want 502 unavailable, got %d %s", w.Code, w.Body)
	}
}

func TestWebChatHistory(t *testing.T) {
	reply := `{"session":"` + webChatTestSession + `","pending":true,"messages":[{"id":1,"dir":"in","text":"q","ts":1}]}`
	up := startUpstream(t, 200, reply)
	s, clk := newTestWebChat()
	get := func(q string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/chat/history"+q, nil)
		r.RemoteAddr = "203.0.113.60:1"
		w := httptest.NewRecorder()
		s.handleHistory(w, r)
		return w
	}
	w := get("?session=" + webChatTestSession)
	if w.Code != 200 || w.Body.String() != reply {
		t.Fatalf("history relay: got %d %s", w.Code, w.Body)
	}
	if up.query != "session="+webChatTestSession {
		t.Errorf("upstream query = %q", up.query)
	}
	if w := get("?session=bad"); w.Code != 400 {
		t.Errorf("bad session: want 400, got %d", w.Code)
	}
	for i := 1; i < webChatHistoryPerMin; i++ {
		if w := get("?session=" + webChatTestSession); w.Code != 200 {
			t.Fatalf("poll %d: want 200, got %d", i, w.Code)
		}
	}
	w = get("?session=" + webChatTestSession)
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("61st poll/min: want 429 Retry-After 60, got %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	clk.advance(time.Minute)
	if w := get("?session=" + webChatTestSession); w.Code != 200 {
		t.Fatalf("after a minute: want 200, got %d", w.Code)
	}
}
