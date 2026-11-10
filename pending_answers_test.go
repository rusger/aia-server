package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func openPendingTestDB(t *testing.T) {
	t.Helper()
	prev := db
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1) // one :memory: database for every query
	t.Cleanup(func() { db.Close(); db = prev })
	migratePendingAnswers()
	withFreshStreams(t)
}

func pendingCount(t *testing.T, deviceID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pending_answers WHERE device_id = ?`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// waitPending waits for the async save after "done".
func waitPending(t *testing.T, deviceID string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for pendingCount(t, deviceID) != want {
		if time.Now().After(deadline) {
			t.Fatalf("pending rows for %s: got %d, want %d", deviceID, pendingCount(t, deviceID), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func withClaims(r *http.Request, deviceID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), "claims", &JWTClaims{DeviceID: deviceID}))
}

// A finished stream that was asked to persist lands in the table; after a
// "restart" (fresh registry) resume and the buffered repeat both get it back
// with the original event indices — no model call.
func TestPendingAnswerSurvivesRestart(t *testing.T) {
	openPendingTestDB(t)
	now := time.Now()
	b, _ := streams.register(streamKey("dev1", "stream-p001"), now)
	b.persistAs("dev1", "stream-p001", "chatgpt")
	b.append(map[string]interface{}{"c": "Первая часть. "}, now)
	b.append(map[string]interface{}{"c": "Вторая."}, now)
	b.append(map[string]interface{}{"done": true}, now)
	waitPending(t, "dev1", 1)

	streams = &streamRegistry{m: map[string]*streamBuf{}} // process restart

	r := withClaims(httptest.NewRequest("GET", "/api/chatgpt-stream/resume?stream_id=stream-p001&after=0", nil), "dev1")
	w := httptest.NewRecorder()
	chatGPTStreamResume(w, r)
	evs := sseEvents(w.Body.String())
	if w.Code != 200 || len(evs) != 2 || evs[0]["c"] != "Вторая." || evs[0]["i"] != float64(1) || evs[1]["done"] != true {
		t.Fatalf("resume after restart: %d %v", w.Code, evs)
	}

	streams = &streamRegistry{m: map[string]*streamBuf{}}
	replay, _, release := chatGPTBufferedSingleFlight(context.Background(), "dev1", "stream-p001", "chatgpt", true)
	release()
	if replay != "Первая часть. Вторая." {
		t.Fatalf("buffered repeat after restart: %q", replay)
	}
}

func TestPendingAnswerNotKept(t *testing.T) {
	openPendingTestDB(t)
	now := time.Now()
	// no persistAs (old client / overhead pass)
	b, _ := streams.register(streamKey("dev1", "stream-p002"), now)
	b.append(map[string]interface{}{"c": "x"}, now)
	b.append(map[string]interface{}{"done": true}, now)
	// an errored stream is not an answer
	e, _ := streams.register(streamKey("dev1", "stream-p003"), now)
	e.persistAs("dev1", "stream-p003", "chatgpt")
	e.append(map[string]interface{}{"c": "half"}, now)
	e.append(map[string]interface{}{"error": "stream interrupted"}, now)
	// a done stream with no text is not an answer either
	savePendingAnswer("dev1", "stream-p004", "chatgpt", [][]byte{[]byte(`{"i":0,"done":true}`)}, now)
	time.Sleep(50 * time.Millisecond)
	if n := pendingCount(t, "dev1"); n != 0 {
		t.Fatalf("got %d rows, want 0", n)
	}
}

func TestPendingAnswersListAckAndChecksum(t *testing.T) {
	openPendingTestDB(t)
	now := time.Now()
	events := [][]byte{[]byte(`{"i":0,"c":"Ответ"}`), []byte(`{"i":1,"done":true}`)}
	savePendingAnswer("dev1", "stream-p010", "chatgpt", events, now)
	savePendingAnswer("dev2", "stream-p011", "chatgpt", events, now)

	w := httptest.NewRecorder()
	chatGPTPendingAnswers(w, withClaims(httptest.NewRequest("GET", "/api/chatgpt-stream/pending", nil), "dev1"))
	var list struct {
		Answers []pendingAnswerItem `json:"answers"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Answers) != 1 || list.Answers[0].StreamID != "stream-p010" || list.Answers[0].SHA256 != answerSHA256("Ответ") {
		t.Fatalf("pending list (only this device): %s", w.Body.String())
	}

	ack := func(device, id, sum string) int {
		body, _ := json.Marshal(map[string]string{"stream_id": id, "sha256": sum})
		w := httptest.NewRecorder()
		chatGPTAckAnswer(w, withClaims(httptest.NewRequest("POST", "/api/chatgpt-stream/ack", bytes.NewReader(body)), device))
		return w.Code
	}
	if c := ack("dev1", "stream-p010", answerSHA256("другой текст")); c != http.StatusConflict || pendingCount(t, "dev1") != 1 {
		t.Fatalf("wrong checksum must keep the answer: %d", c)
	}
	if c := ack("dev2", "stream-p010", answerSHA256("Ответ")); c != 200 || pendingCount(t, "dev1") != 1 {
		t.Fatalf("another device must not delete it: %d", c)
	}
	if c := ack("dev1", "stream-p010", answerSHA256("Ответ")); c != 200 || pendingCount(t, "dev1") != 0 {
		t.Fatalf("right checksum must delete: %d", c)
	}
	if c := ack("dev1", "stream-p010", answerSHA256("Ответ")); c != 200 {
		t.Fatalf("a repeated ack is fine: %d", c)
	}
	if c := ack("dev1", "bad id", "x"); c != http.StatusBadRequest {
		t.Fatalf("malformed ack: %d", c)
	}
}

func TestPendingAnswersCapAndRetention(t *testing.T) {
	openPendingTestDB(t)
	now := time.Now()
	events := [][]byte{[]byte(`{"i":0,"c":"a"}`), []byte(`{"i":1,"done":true}`)}
	for i := 0; i < pendingAnswersPerDevice+5; i++ {
		savePendingAnswer("dev1", fmt.Sprintf("stream-c%03d", i), "chatgpt", events, now.Add(time.Duration(i)*time.Second))
	}
	if n := pendingCount(t, "dev1"); n != pendingAnswersPerDevice {
		t.Fatalf("cap: %d rows", n)
	}
	if loadPendingAnswer("dev1", "stream-c000", now.Add(time.Minute)) != nil {
		t.Fatal("the oldest must be the ones dropped by the cap")
	}
	if loadPendingAnswer("dev1", "stream-c024", now.Add(time.Minute)) == nil {
		t.Fatal("the newest must stay")
	}
	// over 48 h: not served, and pruned
	if loadPendingAnswer("dev1", "stream-c024", now.Add(pendingAnswerRetention+time.Hour)) != nil {
		t.Fatal("an answer older than 48 h must not be served")
	}
	prunePendingAnswers(now.Add(pendingAnswerRetention + time.Hour))
	if n := pendingCount(t, "dev1"); n != 0 {
		t.Fatalf("prune left %d rows", n)
	}
}

// The stream handler's repeat POST also reaches the table (restart case).
func TestStreamRepeatRestoresFromTable(t *testing.T) {
	openPendingTestDB(t)
	savePendingAnswer("dev1", "stream-p020", "chatgpt",
		[][]byte{[]byte(`{"i":0,"c":"Готово"}`), []byte(`{"i":1,"done":true}`)}, time.Now())
	old := OPENAI_API_KEY
	OPENAI_API_KEY = "test" // never reached: the repeat is served from the table
	defer func() { OPENAI_API_KEY = old }()
	body := `{"model":"gpt-4o-mini","stream_id":"stream-p020","messages":[{"role":"user","content":"hi"}]}`
	r := withClaims(httptest.NewRequest("POST", "/api/chatgpt-stream", strings.NewReader(body)), "dev1")
	w := httptest.NewRecorder()
	chatGPTStreamProxy(w, r)
	evs := sseEvents(w.Body.String())
	if len(evs) != 2 || evs[0]["c"] != "Готово" {
		t.Fatalf("repeat: %d %s", w.Code, w.Body.String())
	}
}
