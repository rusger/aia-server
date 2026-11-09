package main

// Chat uploads that survive a bad network (A45, owner 09.11.2026).
//
// Some RU networks stall a 20–200 KB chat POST mid-upload; nginx answers 408
// after client_body_timeout and the user sees an error. Three server pieces:
//
//   - decodeAIRequest: the body may arrive gzip-compressed (Content-Encoding:
//     gzip) — fewer bytes on the wire, fewer chances to stall. Raw and
//     decompressed sizes are capped (measured max 212 KB over 8 days of
//     access.log rl=, so aiRequestMaxBytes leaves ~10× headroom).
//   - the buffered /api/chatgpt honours stream_id like /api/chatgpt-stream
//     does: a repeat of the same request (client retry after a lost
//     response, or the buffered fallback after a failed stream) gets the
//     answer that is already being generated / was generated, with no second
//     model call and no second quota booking. See chatGPTBufferedSingleFlight.
//   - nginx: client_body_timeout 20s only for /api/chatgpt* (the location in
//     etc-nginx-sites_enabled-astrologer), so a stalled upload fails fast and
//     the client's retry starts sooner.

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// aiRequestMaxBytes caps an AI proxy request body, raw and decompressed.
const aiRequestMaxBytes = 2 << 20

var errAIRequestTooLarge = errors.New("request body too large")

// wireReader remembers the error of the raw (wire) body: over the cap a gzip
// reader may report its own error (unexpected EOF) instead of the
// MaxBytesError underneath, and the client must still get 413.
type wireReader struct {
	r   io.Reader
	err error
}

func (w *wireReader) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if err != nil && err != io.EOF {
		w.err = err
	}
	return n, err
}

// decodeAIRequest reads a (possibly gzip-compressed) JSON body into v.
func decodeAIRequest(w http.ResponseWriter, r *http.Request, v interface{}) error {
	wire := &wireReader{r: http.MaxBytesReader(w, r.Body, aiRequestMaxBytes)}
	var body io.Reader = wire
	tooLarge := func(err error) bool {
		var mbe *http.MaxBytesError
		return errors.As(err, &mbe) || errors.As(wire.err, &mbe)
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			if tooLarge(err) {
				return errAIRequestTooLarge
			}
			return err
		}
		defer zr.Close()
		body = zr
	}
	data, err := io.ReadAll(io.LimitReader(body, aiRequestMaxBytes+1))
	if err != nil {
		if tooLarge(err) {
			return errAIRequestTooLarge
		}
		return err
	}
	if len(data) > aiRequestMaxBytes {
		return errAIRequestTooLarge
	}
	return json.Unmarshal(data, v)
}

// bufferedReplayWait bounds how long a repeat waits for the first request's
// answer; nginx gives the upstream 180 s (proxy_read_timeout).
var bufferedReplayWait = 170 * time.Second

// bufferedAnswer waits for b to close and returns its text (the "c" events in
// order). ok=false when it ended in an error, carried no text, or the wait
// ran out — the caller then generates as usual.
func bufferedAnswer(ctx context.Context, b *streamBuf) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, bufferedReplayWait)
	defer cancel()
	for {
		events, done, wake := b.snapshot(-1)
		if done {
			var sb strings.Builder
			for _, raw := range events {
				var ev map[string]interface{}
				if json.Unmarshal(raw, &ev) != nil {
					continue
				}
				if _, bad := ev["error"]; bad {
					return "", false
				}
				if c, ok := ev["c"].(string); ok {
					sb.WriteString(c)
				}
			}
			return sb.String(), sb.Len() > 0
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return "", false
		}
	}
}

// chatGPTBufferedSingleFlight is the stream_id gate of the buffered handler.
// replay != "" → the same request was already answered (or is being answered
// right now): send that, no model call, no quota. Otherwise finish(content)
// must be called with the final answer on success (it is stored for repeats)
// and is a no-op without a stream_id; any return without finish drops the
// claim so a retry generates afresh (nothing was booked).
func chatGPTBufferedSingleFlight(ctx context.Context, deviceID, streamID string) (replay string, finish func(content string), release func()) {
	noop := func(string) {}
	if streamID == "" || !streamIDRe.MatchString(streamID) {
		return "", noop, func() {}
	}
	key := streamKey(deviceID, streamID)
	now := time.Now()
	if b := streams.lookup(key, now); b != nil {
		if text, ok := bufferedAnswer(ctx, b); ok {
			return text, noop, func() {}
		}
		streams.drop(key) // failed or empty: this request generates instead
	}
	b, existed := streams.register(key, now)
	if existed { // raced with a twin request: take its answer
		if text, ok := bufferedAnswer(ctx, b); ok {
			return text, noop, func() {}
		}
		return "", noop, func() {}
	}
	finished := false
	finish = func(content string) {
		finished = true
		b.append(map[string]interface{}{"c": content}, time.Now())
		b.append(map[string]interface{}{"done": true}, time.Now())
	}
	release = func() {
		if !finished {
			b.append(map[string]interface{}{"error": "not generated"}, time.Now())
			streams.drop(key)
		}
	}
	return "", finish, release
}
