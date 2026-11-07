package main

// Resumable AI stream (owner/coordinator 02–03.11.2026): a dropped connection
// used to cost a second OpenAI call (the app fell back to the buffered proxy)
// and on bad networks the user got nothing. Now every stream started with a
// stream_id is buffered in memory while it generates, and the client can pick
// it up again without the model being asked twice.
//
// Contract (client side: my_first_app, agreed 03.11.2026):
//   POST /api/chatgpt-stream  {…, "stream_id": "<uuid per attempt>"}
//     - every SSE event carries "i": 0,1,2… — {"i":0,"c":"…"}, {"i":N,"done":true},
//       {"i":N,"error":"…"}; the first chunk (crisis notice) is buffered too;
//     - idempotent: a repeat POST with a known stream_id replays the buffer and
//       follows the live generation — OpenAI is NOT called again, quota is NOT
//       charged again (it is charged once, at the end of the one generation);
//     - without stream_id the old protocol is unchanged (events still carry "i").
//   GET /api/chatgpt-stream/resume?stream_id=…&after=N  (same JWT)
//     - events with i > N as SSE; still generating → the connection stays open
//       and is fed live; finished → remainder + the terminal event;
//     - unknown / expired stream_id (or another device's) → 410 JSON
//       {"success":false,"error":"stream expired","code":"stream_expired"} —
//       the only answer on which the client regenerates;
//     - a mid-generation OpenAI failure is a buffered {"i":N,"error":…}
//       event, so a resume sees it instead of retrying forever.
//   Keep-alive: ": ping" SSE comment every streamPingEvery while waiting for
//   the model — on every stream; the app's parser skips non-"data:" lines
//   (chatgpt_service.dart `if (!line.startsWith('data: ')) continue`).
//
// Buffers live in process memory: TTL streamBufTTL after the terminal event,
// streamBufMaxAge for one that never finished; hard caps on entries and bytes
// (the box has 2 vCPU / 4 GB). A server restart forgets everything → 410.
// The upstream OpenAI request is deliberately not tied to r.Context(): the
// generation survives the client's disconnect, which is what makes resume work.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	streamBufTTL      = 20 * time.Minute // keep a finished stream this long
	streamBufMaxAge   = 15 * time.Minute // an unfinished one (OpenAI client timeout is 300 s)
	streamBufMaxBytes = 512 << 10        // per stream; beyond it resume is given up (live follow continues)
	streamRegistryMax = 300              // streams kept for resume at once
	streamPingEvery   = 10 * time.Second // ": ping" while the model is thinking
	streamIDMaxLen    = 64
)

var streamIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// streamBuf is one answer in flight or recently finished.
type streamBuf struct {
	mu       sync.Mutex
	events   [][]byte // marshalled SSE payloads, index == "i"
	size     int
	done     bool
	created  time.Time
	finished time.Time
	wake     chan struct{} // closed and replaced on every append (broadcast)
	evicted  bool          // over streamBufMaxBytes: no longer resumable
}

func newStreamBuf(now time.Time) *streamBuf {
	return &streamBuf{created: now, wake: make(chan struct{})}
}

// append stores one event with the next sequence number. done/error events
// close the stream; anything appended after that is dropped.
func (b *streamBuf) append(v map[string]interface{}, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return
	}
	v["i"] = len(b.events)
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	b.events = append(b.events, raw)
	b.size += len(raw)
	if b.size > streamBufMaxBytes {
		b.evicted = true
	}
	if _, ok := v["done"]; ok {
		b.done, b.finished = true, now
	} else if _, ok := v["error"]; ok {
		b.done, b.finished = true, now
	}
	close(b.wake)
	b.wake = make(chan struct{})
}

// snapshot → events after index `after`, whether the stream is closed, and a
// channel that closes on the next append.
func (b *streamBuf) snapshot(after int) ([][]byte, bool, chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	from := after + 1
	if from < 0 {
		from = 0
	}
	if from > len(b.events) {
		from = len(b.events)
	}
	out := make([][]byte, len(b.events)-from)
	copy(out, b.events[from:])
	return out, b.done, b.wake
}

func (b *streamBuf) expired(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return now.Sub(b.finished) > streamBufTTL
	}
	return now.Sub(b.created) > streamBufMaxAge
}

func (b *streamBuf) resumable() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.evicted
}

// streamRegistry maps device+stream_id → buffer; the single-flight point.
type streamRegistry struct {
	mu sync.Mutex
	m  map[string]*streamBuf
}

var streams = &streamRegistry{m: map[string]*streamBuf{}}

func streamKey(deviceID, streamID string) string { return deviceID + "\x00" + streamID }

// register returns the buffer for key and whether it already existed (then
// the caller must follow it, not start a second generation).
func (r *streamRegistry) register(key string, now time.Time) (*streamBuf, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.m[key]; ok && !b.expired(now) {
		return b, true
	}
	r.sweepLocked(now, streamRegistryMax-1) // make room for the new one
	b := newStreamBuf(now)
	r.m[key] = b
	return b, false
}

// lookup → the live/finished buffer or nil (unknown, expired, over size).
func (r *streamRegistry) lookup(key string, now time.Time) *streamBuf {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now, streamRegistryMax)
	b := r.m[key]
	if b == nil || !b.resumable() {
		return nil
	}
	return b
}

func (r *streamRegistry) drop(key string) {
	r.mu.Lock()
	delete(r.m, key)
	r.mu.Unlock()
}

// sweepLocked drops expired buffers and, over keep entries, the oldest.
func (r *streamRegistry) sweepLocked(now time.Time, keep int) {
	for k, b := range r.m {
		if b.expired(now) || !b.resumable() {
			delete(r.m, k)
		}
	}
	if len(r.m) <= keep {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(r.m))
	for k, b := range r.m {
		all = append(all, kv{k, b.created})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for _, e := range all[:len(all)-keep] {
		delete(r.m, e.k)
	}
}

func (r *streamRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// streamFollow writes events with index > after to w until the stream closes
// or the client goes away; with ping it keeps the socket alive meanwhile.
func streamFollow(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, b *streamBuf, after int, ping bool) {
	var ticker *time.Ticker
	var tick <-chan time.Time
	if ping {
		ticker = time.NewTicker(streamPingEvery)
		defer ticker.Stop()
		tick = ticker.C
	}
	for {
		events, done, wake := b.snapshot(after)
		for _, raw := range events {
			if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
				return
			}
			after++
		}
		if len(events) > 0 {
			flusher.Flush()
		}
		if done {
			return
		}
		select {
		case <-wake:
		case <-tick:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func streamSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// nginx honours this per-response: without it the proxy buffers the whole
	// stream and the client sees one late blob.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
}

func streamJSONError(w http.ResponseWriter, status int, msg, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if code == "" {
		fmt.Fprintf(w, `{"success":false,"error":%q}`, msg)
		return
	}
	fmt.Fprintf(w, `{"success":false,"error":%q,"code":%q}`, msg, code)
}

// GET /api/chatgpt-stream/resume?stream_id=…&after=N
func chatGPTStreamResume(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		streamJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	streamID := r.URL.Query().Get("stream_id")
	if !streamIDRe.MatchString(streamID) {
		streamJSONError(w, http.StatusBadRequest, "stream_id required", "")
		return
	}
	after := -1
	if s := r.URL.Query().Get("after"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < -1 {
			streamJSONError(w, http.StatusBadRequest, "after must be an event index", "")
			return
		}
		after = n
	}
	if !ipLimiter.GetLimiter(getClientIP(r)).Allow() || !deviceLimiter.GetLimiter(claims.DeviceID).Allow() {
		streamJSONError(w, http.StatusTooManyRequests, "Rate limit exceeded. Please try again.", "")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		streamJSONError(w, http.StatusInternalServerError, "Streaming unsupported", "")
		return
	}
	b := streams.lookup(streamKey(claims.DeviceID, streamID), time.Now())
	if b == nil {
		streamJSONError(w, http.StatusGone, "stream expired", "stream_expired")
		return
	}
	log.Printf("↩️ ChatGPT stream resume: device=%s after=%d", claims.DeviceID, after)
	streamSSEHeaders(w)
	streamFollow(r.Context(), w, flusher, b, after, true)
}
