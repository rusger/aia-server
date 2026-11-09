package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return b.Bytes()
}

func TestDecodeAIRequestPlainAndGzip(t *testing.T) {
	body := `{"model":"gpt-4o-mini","stream_id":"abcdefgh-1","messages":[{"role":"user","content":"привет"}]}`
	for _, tc := range []struct {
		name string
		data []byte
		enc  string
	}{
		{"plain", []byte(body), ""},
		{"gzip", gz(t, body), "gzip"},
		{"gzip header case", gz(t, body), " GZIP "},
	} {
		r := httptest.NewRequest("POST", "/api/chatgpt", bytes.NewReader(tc.data))
		if tc.enc != "" {
			r.Header.Set("Content-Encoding", tc.enc)
		}
		var req ChatGPTProxyRequest
		if err := decodeAIRequest(httptest.NewRecorder(), r, &req); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if req.StreamID != "abcdefgh-1" || len(req.Messages) != 1 || req.Messages[0]["content"] != "привет" {
			t.Fatalf("%s: decoded %+v", tc.name, req)
		}
	}
}

func TestDecodeAIRequestCaps(t *testing.T) {
	big := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("a", aiRequestMaxBytes) + `"}]}`
	// raw over the cap
	r := httptest.NewRequest("POST", "/api/chatgpt", strings.NewReader(big))
	var req ChatGPTProxyRequest
	if err := decodeAIRequest(httptest.NewRecorder(), r, &req); err != errAIRequestTooLarge {
		t.Fatalf("raw over cap: want errAIRequestTooLarge, got %v", err)
	}
	// a small gzip that inflates over the cap (zip bomb) is refused too
	z := gz(t, big)
	if len(z) >= aiRequestMaxBytes {
		t.Fatalf("test setup: compressed %d must be under the cap", len(z))
	}
	r = httptest.NewRequest("POST", "/api/chatgpt", bytes.NewReader(z))
	r.Header.Set("Content-Encoding", "gzip")
	if err := decodeAIRequest(httptest.NewRecorder(), r, &req); err != errAIRequestTooLarge {
		t.Fatalf("inflated over cap: want errAIRequestTooLarge, got %v", err)
	}
	// compressed stream itself over the cap → 413 too, not a gzip error
	rnd := make([]byte, aiRequestMaxBytes+4096)
	for i := range rnd {
		rnd[i] = byte(i*7919 + i/13)
	}
	var zb bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&zb, gzip.NoCompression)
	zw.Write(rnd)
	zw.Close()
	r = httptest.NewRequest("POST", "/api/chatgpt", bytes.NewReader(zb.Bytes()))
	r.Header.Set("Content-Encoding", "gzip")
	if err := decodeAIRequest(httptest.NewRecorder(), r, &req); err != errAIRequestTooLarge {
		t.Fatalf("compressed over cap: want errAIRequestTooLarge, got %v", err)
	}
	// broken gzip → error, not a panic
	r = httptest.NewRequest("POST", "/api/chatgpt", strings.NewReader("not gzip"))
	r.Header.Set("Content-Encoding", "gzip")
	if err := decodeAIRequest(httptest.NewRecorder(), r, &req); err == nil {
		t.Fatal("broken gzip must fail")
	}
	// the measured real maximum (212 KB) passes with room to spare
	ok := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("я", 120_000) + `"}]}`
	r = httptest.NewRequest("POST", "/api/chatgpt", strings.NewReader(ok))
	if err := decodeAIRequest(httptest.NewRecorder(), r, &req); err != nil {
		t.Fatalf("240 KB body must pass: %v", err)
	}
}

func withFreshStreams(t *testing.T) {
	t.Helper()
	old := streams
	streams = &streamRegistry{m: map[string]*streamBuf{}}
	t.Cleanup(func() { streams = old })
}

// The repeat of an answered request gets that answer: the model is reached
// once (generated counts how many requests went past the gate).
func TestBufferedSingleFlightRepeatReplays(t *testing.T) {
	withFreshStreams(t)
	ctx := context.Background()
	generated := 0
	call := func() string {
		replay, finish, release := chatGPTBufferedSingleFlight(ctx, "dev1", "stream-0001")
		defer release()
		if replay != "" {
			return replay
		}
		generated++
		finish("ответ")
		return "ответ"
	}
	if got := call(); got != "ответ" {
		t.Fatal(got)
	}
	if got := call(); got != "ответ" || generated != 1 {
		t.Fatalf("repeat: got %q, generated %d (want 1)", got, generated)
	}
	// another device with the same id is a different request
	replay, _, release := chatGPTBufferedSingleFlight(ctx, "dev2", "stream-0001")
	release()
	if replay != "" {
		t.Fatal("another device must not get this answer")
	}
}

// A stream's buffer (crisis block + chunks) is what the buffered fallback
// with the same stream_id returns — the fallback never calls the model again.
func TestBufferedSingleFlightReplaysStream(t *testing.T) {
	withFreshStreams(t)
	now := time.Now()
	b, _ := streams.register(streamKey("dev1", "stream-0002"), now)
	b.append(map[string]interface{}{"c": "Часть 1. "}, now)
	b.append(map[string]interface{}{"c": "Часть 2."}, now)
	b.append(map[string]interface{}{"done": true}, now)
	replay, _, release := chatGPTBufferedSingleFlight(context.Background(), "dev1", "stream-0002")
	release()
	if replay != "Часть 1. Часть 2." {
		t.Fatalf("got %q", replay)
	}
}

// The fallback arriving while the stream is still generating waits for it.
func TestBufferedSingleFlightWaitsForInFlight(t *testing.T) {
	withFreshStreams(t)
	now := time.Now()
	b, _ := streams.register(streamKey("dev1", "stream-0003"), now)
	go func() {
		time.Sleep(30 * time.Millisecond)
		b.append(map[string]interface{}{"c": "готово"}, time.Now())
		b.append(map[string]interface{}{"done": true}, time.Now())
	}()
	replay, _, release := chatGPTBufferedSingleFlight(context.Background(), "dev1", "stream-0003")
	release()
	if replay != "готово" {
		t.Fatalf("got %q", replay)
	}
}

// Nothing booked → a retry generates: a failed first attempt (release without
// finish) or a stream that ended in error must not block the next request.
func TestBufferedSingleFlightFailureLetsRetryGenerate(t *testing.T) {
	withFreshStreams(t)
	ctx := context.Background()
	replay, _, release := chatGPTBufferedSingleFlight(ctx, "dev1", "stream-0004")
	if replay != "" {
		t.Fatal("first call must generate")
	}
	release() // e.g. OpenAI 5xx: returned without finish
	if streams.len() != 0 {
		t.Fatal("a failed attempt must drop its claim")
	}
	replay, finish, release := chatGPTBufferedSingleFlight(ctx, "dev1", "stream-0004")
	if replay != "" {
		t.Fatal("retry after failure must generate")
	}
	finish("ok")
	release()

	now := time.Now()
	b, _ := streams.register(streamKey("dev1", "stream-0005"), now)
	b.append(map[string]interface{}{"c": "half"}, now)
	b.append(map[string]interface{}{"error": "stream interrupted"}, now)
	replay, finish, release = chatGPTBufferedSingleFlight(ctx, "dev1", "stream-0005")
	if replay != "" {
		t.Fatal("an errored stream must not be replayed as an answer")
	}
	finish("fresh")
	release()
	if replay, _, _ = chatGPTBufferedSingleFlight(ctx, "dev1", "stream-0005"); replay != "fresh" {
		t.Fatalf("after regeneration the repeat must get the new answer, got %q", replay)
	}
}

// No stream_id (old clients) or a malformed one: no gate, old behaviour.
func TestBufferedSingleFlightWithoutStreamID(t *testing.T) {
	withFreshStreams(t)
	for _, id := range []string{"", "short", "bad id with spaces"} {
		replay, finish, release := chatGPTBufferedSingleFlight(context.Background(), "dev1", id)
		finish("x")
		release()
		if replay != "" || streams.len() != 0 {
			t.Fatalf("id %q must bypass the gate", id)
		}
	}
}

// The waiting repeat gives up with the client (or at bufferedReplayWait).
func TestBufferedAnswerStopsOnContext(t *testing.T) {
	b := newStreamBuf(time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, ok := bufferedAnswer(ctx, b); ok {
		t.Fatal("unfinished buffer must not yield an answer")
	}
}

// End to end through the HTTP handler's decode path: a gzip body reaches the
// stream handler's validation (bad stream_id → 400 proves it was decoded).
func TestStreamHandlerAcceptsGzip(t *testing.T) {
	body := gz(t, `{"model":"m","stream_id":"bad id","messages":[]}`)
	r := httptest.NewRequest("POST", "/api/chatgpt-stream", bytes.NewReader(body))
	r.Header.Set("Content-Encoding", "gzip")
	r = r.WithContext(context.WithValue(r.Context(), "claims", &JWTClaims{DeviceID: "dev1"}))
	old := OPENAI_API_KEY
	OPENAI_API_KEY = "test"
	defer func() { OPENAI_API_KEY = old }()
	w := httptest.NewRecorder()
	chatGPTStreamProxy(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Invalid stream_id") {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}
