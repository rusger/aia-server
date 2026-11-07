package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func sseEvents(body string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &v); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func TestStreamBufSequenceAndReplay(t *testing.T) {
	now := time.Now()
	b := newStreamBuf(now)
	b.append(map[string]interface{}{"c": "Hel"}, now)
	b.append(map[string]interface{}{"c": "lo"}, now)
	b.append(map[string]interface{}{"done": true}, now)
	b.append(map[string]interface{}{"c": "late"}, now) // after the terminal event — dropped

	rec := httptest.NewRecorder()
	streamFollow(context.Background(), rec, rec, b, -1, false)
	ev := sseEvents(rec.Body.String())
	if len(ev) != 3 || ev[0]["i"].(float64) != 0 || ev[0]["c"] != "Hel" || ev[2]["done"] != true || ev[2]["i"].(float64) != 2 {
		t.Fatalf("full replay: %v", ev)
	}

	rec = httptest.NewRecorder()
	streamFollow(context.Background(), rec, rec, b, 0, false)
	ev = sseEvents(rec.Body.String())
	if len(ev) != 2 || ev[0]["c"] != "lo" || ev[0]["i"].(float64) != 1 {
		t.Fatalf("after=0 must give events 1 and 2: %v", ev)
	}
	rec = httptest.NewRecorder()
	streamFollow(context.Background(), rec, rec, b, 99, false)
	if ev := sseEvents(rec.Body.String()); len(ev) != 0 {
		t.Fatalf("after beyond the end: nothing, got %v", ev)
	}
}

func TestStreamFollowLiveAndError(t *testing.T) {
	now := time.Now()
	b := newStreamBuf(now)
	b.append(map[string]interface{}{"c": "a"}, now)
	rec := httptest.NewRecorder()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamFollow(context.Background(), rec, rec, b, -1, false)
	}()
	time.Sleep(20 * time.Millisecond)
	b.append(map[string]interface{}{"c": "b"}, now)
	time.Sleep(20 * time.Millisecond)
	b.append(map[string]interface{}{"error": "stream interrupted"}, now)
	wg.Wait()
	ev := sseEvents(rec.Body.String())
	if len(ev) != 3 || ev[1]["c"] != "b" || ev[2]["error"] != "stream interrupted" {
		t.Fatalf("live follow must deliver later chunks and the buffered error: %v", ev)
	}
}

func TestStreamFollowStopsOnClientGone(t *testing.T) {
	b := newStreamBuf(time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		streamFollow(ctx, httptest.NewRecorder(), httptest.NewRecorder(), b, -1, false)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("follower must return when the client context is cancelled")
	}
}

func TestStreamRegistrySingleFlightAndExpiry(t *testing.T) {
	r := &streamRegistry{m: map[string]*streamBuf{}}
	now := time.Now()
	k := streamKey("dev1", "11111111-aaaa")
	b1, existed := r.register(k, now)
	if existed {
		t.Fatal("first register must create")
	}
	b2, existed := r.register(k, now)
	if !existed || b1 != b2 {
		t.Fatal("second register with the same id must return the same buffer (single-flight)")
	}
	if r.lookup(streamKey("dev2", "11111111-aaaa"), now) != nil {
		t.Fatal("another device must not see the stream")
	}
	// unfinished stream outlives streamBufMaxAge → gone
	if r.lookup(k, now.Add(streamBufMaxAge+time.Second)) != nil {
		t.Fatal("unfinished stream must expire after streamBufMaxAge")
	}
	b, _ := r.register(k, now)
	b.append(map[string]interface{}{"done": true}, now.Add(time.Minute))
	if r.lookup(k, now.Add(time.Minute+streamBufTTL-time.Second)) == nil {
		t.Fatal("finished stream must stay for streamBufTTL")
	}
	if r.lookup(k, now.Add(time.Minute+streamBufTTL+time.Second)) != nil {
		t.Fatal("finished stream must expire after streamBufTTL")
	}
	r.drop(k)
	if r.len() != 0 {
		t.Fatal("drop must remove")
	}
}

func TestStreamRegistryCapsAndOversize(t *testing.T) {
	r := &streamRegistry{m: map[string]*streamBuf{}}
	now := time.Now()
	for i := 0; i < streamRegistryMax+20; i++ {
		r.register(streamKey("dev", strings.Repeat("x", 8)+string(rune('a'+i%26))+string(rune('a'+i/26))), now.Add(time.Duration(i)*time.Millisecond))
	}
	if r.len() != streamRegistryMax {
		t.Fatalf("registry must hold at most %d, got %d", streamRegistryMax, r.len())
	}
	if r.lookup(streamKey("dev", strings.Repeat("x", 8)+"aa"), now.Add(time.Second)) != nil {
		t.Fatal("the oldest streams are the ones evicted")
	}
	big, _ := r.register(streamKey("dev", "bigbigbig1"), now)
	big.append(map[string]interface{}{"c": strings.Repeat("я", streamBufMaxBytes)}, now)
	if r.lookup(streamKey("dev", "bigbigbig1"), now) != nil {
		t.Fatal("over streamBufMaxBytes the stream is no longer resumable")
	}
	rec := httptest.NewRecorder()
	big.append(map[string]interface{}{"done": true}, now)
	streamFollow(context.Background(), rec, rec, big, -1, false)
	if len(sseEvents(rec.Body.String())) != 2 {
		t.Fatal("…but a live follower still gets everything")
	}
}

func resumeReq(t *testing.T, device, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/chatgpt-stream/resume?"+query, nil)
	req = req.WithContext(context.WithValue(req.Context(), "claims", &JWTClaims{DeviceID: device}))
	rec := httptest.NewRecorder()
	chatGPTStreamResume(rec, req)
	return rec
}

func TestResumeHandler(t *testing.T) {
	streams = &streamRegistry{m: map[string]*streamBuf{}}
	now := time.Now()
	if rec := resumeReq(t, "dev1", "stream_id=12345678-abcd&after=0"); rec.Code != http.StatusGone ||
		!strings.Contains(rec.Body.String(), `"code":"stream_expired"`) {
		t.Fatalf("unknown stream → 410 stream_expired, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := resumeReq(t, "dev1", "stream_id=bad!"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid id → 400, got %d", rec.Code)
	}
	if rec := resumeReq(t, "dev1", "stream_id=12345678-abcd&after=x"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad after → 400, got %d", rec.Code)
	}
	b, _ := streams.register(streamKey("dev1", "12345678-abcd"), now)
	b.append(map[string]interface{}{"c": "one"}, now)
	b.append(map[string]interface{}{"c": "two"}, now)
	b.append(map[string]interface{}{"done": true}, now)
	rec := resumeReq(t, "dev1", "stream_id=12345678-abcd&after=0")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("resume of a finished stream → 200 SSE, got %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	ev := sseEvents(rec.Body.String())
	if len(ev) != 2 || ev[0]["c"] != "two" || ev[1]["done"] != true {
		t.Fatalf("after=0 → events 1,2: %v", ev)
	}
	if rec := resumeReq(t, "dev2", "stream_id=12345678-abcd"); rec.Code != http.StatusGone {
		t.Fatalf("other device → 410, got %d", rec.Code)
	}
}

func TestStreamPingWhileWaiting(t *testing.T) {
	b := newStreamBuf(time.Now())
	pr, pw := io.Pipe()
	w := &pipeWriter{w: pw, h: http.Header{}}
	go func() {
		streamFollow(context.Background(), w, w, b, -1, true)
		pw.Close()
	}()
	// ping arrives without any event — read the first line
	type rd struct {
		s   string
		err error
	}
	got := make(chan rd, 1)
	go func() {
		buf := make([]byte, 64)
		n, err := pr.Read(buf)
		got <- rd{string(buf[:n]), err}
	}()
	select {
	case r := <-got:
		b.append(map[string]interface{}{"done": true}, time.Now())
		if r.err != nil || !strings.HasPrefix(r.s, ": ping") {
			t.Fatalf("expected a ping comment while idle, got %q %v", r.s, r.err)
		}
	case <-time.After(streamPingEvery + 2*time.Second):
		b.append(map[string]interface{}{"done": true}, time.Now())
		t.Fatal("no ping while idle")
	}
}

// pipeWriter: a ResponseWriter whose body is a pipe (recorder buffers cannot be
// read while the follower is still blocked).
type pipeWriter struct {
	w *io.PipeWriter
	h http.Header
}

func (p *pipeWriter) Header() http.Header         { return p.h }
func (p *pipeWriter) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeWriter) WriteHeader(int)             {}
func (p *pipeWriter) Flush()                      {}
