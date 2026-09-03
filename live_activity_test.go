package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func openLiveActivityTestDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	migrateLiveActivities()
}

func TestLiveActivityEndBodyAndTopic(t *testing.T) {
	if got := liveActivityTopic("com.astrolytix.app"); got != "com.astrolytix.app.push-type.liveactivity" {
		t.Fatalf("topic = %q", got)
	}
	now := time.Unix(1_700_000_000, 0)
	end := time.Unix(1_700_003_600, 0)
	body, err := liveActivityEndBody(now, end)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	aps := m["aps"]
	if aps["event"] != "end" {
		t.Errorf("event = %v", aps["event"])
	}
	if int64(aps["timestamp"].(float64)) != now.Unix() {
		t.Errorf("timestamp = %v", aps["timestamp"])
	}
	if int64(aps["dismissal-date"].(float64)) != end.Unix() {
		t.Errorf("dismissal-date = %v", aps["dismissal-date"])
	}
	if _, has := aps["content-state"]; has {
		t.Errorf("content-state must not be sent on end")
	}
}

// The end push must go out with the ActivityKit headers (topic suffix +
// push-type "liveactivity"), otherwise APNs rejects it with TopicDisallowed
// and the banner stays frozen.
func TestLiveActivityEndPushHeaders(t *testing.T) {
	var gotTopic, gotPushType, gotPriority, gotExpiration, gotPath string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTopic = r.Header.Get("apns-topic")
		gotPushType = r.Header.Get("apns-push-type")
		gotPriority = r.Header.Get("apns-priority")
		gotExpiration = r.Header.Get("apns-expiration")
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	saved := apnsHTTPClient
	apnsHTTPClient = srv.Client()
	defer func() { apnsHTTPClient = saved }()

	c := &apnsConfig{bundleID: "com.astrolytix.app", production: true}
	body, _ := liveActivityEndBody(time.Unix(1, 0), time.Unix(2, 0))
	status, _, err := sendAPNsRaw(c, "jwt", srv.Listener.Addr().String(),
		liveActivityTopic(c.bundleID), liveActivityPushType, "deadbeef", body, 0)
	if err != nil || status != http.StatusOK {
		t.Fatalf("send: status %d err %v", status, err)
	}
	if gotTopic != "com.astrolytix.app.push-type.liveactivity" {
		t.Errorf("apns-topic = %q", gotTopic)
	}
	if gotPushType != "liveactivity" {
		t.Errorf("apns-push-type = %q", gotPushType)
	}
	if gotPriority != "10" || gotExpiration != "" {
		t.Errorf("priority %q expiration %q", gotPriority, gotExpiration)
	}
	if gotPath != "/3/device/deadbeef" {
		t.Errorf("path = %q", gotPath)
	}
	if string(gotBody) != string(body) {
		t.Errorf("body = %s", gotBody)
	}
}

func TestLiveActivityDueAndReplacement(t *testing.T) {
	openLiveActivityTestDB(t)
	now := time.Unix(1_700_000_000, 0)
	end := now.Add(2 * time.Hour)

	// Same device registers twice (new day's activity replaces yesterday's).
	if err := upsertLiveActivityEnd("a@x", "dev1", "tokOLD", end, now); err != nil {
		t.Fatal(err)
	}
	if err := upsertLiveActivityEnd("a@x", "dev1", "tokNEW", end, now); err != nil {
		t.Fatal(err)
	}
	// Another device keeps its own row.
	if err := upsertLiveActivityEnd("b@x", "dev2", "tokB", end.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}

	if due, _ := dueLiveActivityEnds(end.Add(-time.Second)); len(due) != 0 {
		t.Fatalf("nothing due before end_at, got %d", len(due))
	}
	due, err := dueLiveActivityEnds(end)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].token != "tokNEW" || !due[0].endAt.Equal(end) {
		t.Fatalf("due = %+v (old token must be evicted, dev2 not yet due)", due)
	}

	var sent []string
	n := processDueLiveActivityEnds(end, func(token string, dismissAt time.Time) error {
		sent = append(sent, token)
		return nil
	})
	if n != 1 || strings.Join(sent, ",") != "tokNEW" {
		t.Fatalf("processed %d, sent %v", n, sent)
	}
	// Marked sent: not due again.
	if due, _ := dueLiveActivityEnds(end); len(due) != 0 {
		t.Fatalf("row must be marked sent, still due: %+v", due)
	}

	// dev2 becomes due later; a failing send still marks it (one-shot).
	n = processDueLiveActivityEnds(end.Add(time.Hour), func(string, time.Time) error {
		return errAPNsTest
	})
	if n != 1 {
		t.Fatalf("dev2 processed = %d", n)
	}
	if due, _ := dueLiveActivityEnds(end.Add(2 * time.Hour)); len(due) != 0 {
		t.Fatalf("failed send must not be retried: %+v", due)
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errAPNsTest = testErr("APNs 410: Unregistered")

func TestLiveActivityCancelScopedToDevice(t *testing.T) {
	openLiveActivityTestDB(t)
	now := time.Unix(1_700_000_000, 0)
	end := now.Add(time.Hour)
	if err := upsertLiveActivityEnd("a@x", "dev1", "tok1", end, now); err != nil {
		t.Fatal(err)
	}
	// Another device cannot cancel dev1's token.
	if err := deleteLiveActivityEnd("dev2", "tok1"); err != nil {
		t.Fatal(err)
	}
	if due, _ := dueLiveActivityEnds(end); len(due) != 1 {
		t.Fatalf("foreign delete must be a no-op, due = %+v", due)
	}
	if err := deleteLiveActivityEnd("dev1", "tok1"); err != nil {
		t.Fatal(err)
	}
	if due, _ := dueLiveActivityEnds(end); len(due) != 0 {
		t.Fatalf("own delete must remove the row, due = %+v", due)
	}
}

func TestLiveActivityPrune(t *testing.T) {
	openLiveActivityTestDB(t)
	now := time.Unix(1_700_000_000, 0)
	if err := upsertLiveActivityEnd("a@x", "dev1", "tokOld", now.Add(time.Hour), now.Add(-4*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := upsertLiveActivityEnd("a@x", "dev2", "tokFresh", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	pruneLiveActivityEnds(now)
	due, _ := dueLiveActivityEnds(now.Add(2 * time.Hour))
	if len(due) != 1 || due[0].token != "tokFresh" {
		t.Fatalf("prune kept wrong rows: %+v", due)
	}
}

func liveActivityRequest(method, body string, claims *JWTClaims) *http.Request {
	r := httptest.NewRequest(method, "/api/user/live-activity", strings.NewReader(body))
	if claims != nil {
		r = r.WithContext(context.WithValue(r.Context(), "claims", claims))
	}
	return r
}

func TestLiveActivityHandlers(t *testing.T) {
	openLiveActivityTestDB(t)
	claims := &JWTClaims{Email: "A@x", DeviceID: "dev1"}
	endMillis := time.Now().Add(3 * time.Hour).UnixMilli()

	// No claims → 401.
	w := httptest.NewRecorder()
	registerLiveActivity(w, liveActivityRequest("POST", `{"push_token":"t","end_millis":1}`, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: %d", w.Code)
	}
	// Missing token → 400.
	w = httptest.NewRecorder()
	registerLiveActivity(w, liveActivityRequest("POST", `{"end_millis":1}`, claims))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing token: %d", w.Code)
	}
	// Deadline in the past → 400.
	w = httptest.NewRecorder()
	registerLiveActivity(w, liveActivityRequest("POST", `{"push_token":"t","end_millis":1}`, claims))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("past deadline: %d", w.Code)
	}
	// Valid → row stored, email lower-cased.
	w = httptest.NewRecorder()
	registerLiveActivity(w, liveActivityRequest("POST",
		`{"push_token":"abc123","end_millis":`+strconv.FormatInt(endMillis, 10)+`}`, claims))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var email string
	if err := db.QueryRow(`SELECT email FROM live_activity_ends WHERE push_token='abc123'`).Scan(&email); err != nil || email != "a@x" {
		t.Fatalf("stored email = %q, err %v", email, err)
	}
	// DELETE without token → 400; with token → row gone.
	w = httptest.NewRecorder()
	cancelLiveActivity(w, liveActivityRequest("DELETE", `{}`, claims))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("delete missing token: %d", w.Code)
	}
	w = httptest.NewRecorder()
	cancelLiveActivity(w, liveActivityRequest("DELETE", `{"push_token":"abc123"}`, claims))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if due, _ := dueLiveActivityEnds(time.UnixMilli(endMillis)); len(due) != 0 {
		t.Fatalf("row must be gone after DELETE: %+v", due)
	}
}
