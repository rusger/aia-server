package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func openLiveActivityStartTestDB(t *testing.T) {
	t.Helper()
	openLiveActivityTestDB(t)
	migrateLiveActivityStarts()
}

func startRow(token string, start, end time.Time) liveActivityStartRow {
	return liveActivityStartRow{
		token: token, startAt: start, endAt: end,
		attributes: liveActivityAttributes{Title: "Психомарафон", Subtitle: "Отметить шкалы",
			DayLabel: "День 2 из 7", LeftLabel: "осталось", Closing: true, ClosingLabel: "Под угрозой"},
		alertTitle: "Марафон", alertBody: "Отметьте шкалы до полуночи",
	}
}

func TestLiveActivityStartBody(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	start := now.Add(-time.Minute)
	end := now.Add(2 * time.Hour)
	body, err := liveActivityStartBody(now, startRow("tok", start, end))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	aps := m["aps"]
	if aps["event"] != "start" || aps["attributes-type"] != liveActivityAttributesType {
		t.Errorf("event/type = %v / %v", aps["event"], aps["attributes-type"])
	}
	if int64(aps["timestamp"].(float64)) != now.Unix() || aps["input-push-token"].(float64) != 1 {
		t.Errorf("timestamp/input-push-token = %v / %v", aps["timestamp"], aps["input-push-token"])
	}
	cs := aps["content-state"].(map[string]interface{})
	if int64(cs["startUnix"].(float64)) != start.Unix() || int64(cs["endUnix"].(float64)) != end.Unix() {
		t.Errorf("content-state = %v", cs)
	}
	attrs := aps["attributes"].(map[string]interface{})
	for _, k := range []string{"title", "subtitle", "dayLabel", "leftLabel", "closing", "closingLabel"} {
		if _, ok := attrs[k]; !ok {
			t.Errorf("attributes missing %q (Swift struct key): %v", k, attrs)
		}
	}
	if attrs["closing"] != true || attrs["dayLabel"] != "День 2 из 7" {
		t.Errorf("attributes = %v", attrs)
	}
	alert := aps["alert"].(map[string]interface{})
	if alert["title"] != "Марафон" || alert["body"] != "Отметьте шкалы до полуночи" {
		t.Errorf("alert = %v", alert)
	}
}

// The start push carries the ActivityKit headers and expires at the
// deadline — a banner delivered after midnight is worse than none.
func TestLiveActivityStartPushHeaders(t *testing.T) {
	var gotTopic, gotPushType, gotPriority, gotExpiration string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTopic = r.Header.Get("apns-topic")
		gotPushType = r.Header.Get("apns-push-type")
		gotPriority = r.Header.Get("apns-priority")
		gotExpiration = r.Header.Get("apns-expiration")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	saved := apnsHTTPClient
	apnsHTTPClient = srv.Client()
	defer func() { apnsHTTPClient = saved }()

	c := &apnsConfig{bundleID: "com.astrolytix.app", production: true}
	end := time.Unix(1_700_003_600, 0)
	body, _ := liveActivityStartBody(time.Unix(1_700_000_000, 0), startRow("tok", time.Unix(1_699_999_000, 0), end))
	status, _, err := sendAPNsRaw(c, "jwt", srv.Listener.Addr().String(),
		liveActivityTopic(c.bundleID), liveActivityPushType, "deadbeef", body, end.Unix())
	if err != nil || status != http.StatusOK {
		t.Fatalf("send: status %d err %v", status, err)
	}
	if gotTopic != "com.astrolytix.app.push-type.liveactivity" || gotPushType != "liveactivity" || gotPriority != "10" {
		t.Errorf("headers: topic %q type %q priority %q", gotTopic, gotPushType, gotPriority)
	}
	if gotExpiration != strconv.FormatInt(end.Unix(), 10) {
		t.Errorf("apns-expiration = %q, want %d", gotExpiration, end.Unix())
	}
}

func TestLiveActivityStartWorthSending(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if liveActivityStartWorthSending(now, now.Add(4*time.Minute)) {
		t.Error("4 minutes left must be skipped")
	}
	if !liveActivityStartWorthSending(now, now.Add(5*time.Minute)) {
		t.Error("5 minutes left must be sent")
	}
}

func scheduleEntry(start, end time.Time, day string) liveActivityScheduleEntry {
	return liveActivityScheduleEntry{
		StartMillis: start.UnixMilli(), EndMillis: end.UnixMilli(),
		Attributes: liveActivityAttributes{Title: "T", Subtitle: "S", DayLabel: day},
		AlertTitle: "A", AlertBody: "B",
	}
}

func TestValidateLiveActivitySchedule(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	good := scheduleEntry(now.Add(time.Hour), now.Add(3*time.Hour), "Day 1")
	past := scheduleEntry(now.Add(-5*time.Hour), now.Add(-3*time.Hour), "Day 0")
	if kept, err := validateLiveActivitySchedule(liveActivityScheduleRequest{
		PushToStartToken: "tok", Entries: []liveActivityScheduleEntry{past, good}}, now); err != nil || len(kept) != 1 || kept[0].Attributes.DayLabel != "Day 1" {
		t.Fatalf("closed window must be dropped silently: kept %+v err %v", kept, err)
	}
	if kept, err := validateLiveActivitySchedule(liveActivityScheduleRequest{PushToStartToken: "tok"}, now); err != nil || len(kept) != 0 {
		t.Fatalf("empty entries = cancel: %+v %v", kept, err)
	}
	bad := []liveActivityScheduleRequest{
		{PushToStartToken: "", Entries: []liveActivityScheduleEntry{good}},
		{PushToStartToken: "tok", Entries: []liveActivityScheduleEntry{scheduleEntry(now.Add(3*time.Hour), now.Add(time.Hour), "x")}},
		{PushToStartToken: "tok", Entries: []liveActivityScheduleEntry{scheduleEntry(now.Add(time.Hour), now.Add(30*time.Hour), "x")}},
		{PushToStartToken: "tok", Entries: []liveActivityScheduleEntry{scheduleEntry(now.Add(32*24*time.Hour), now.Add(32*24*time.Hour+time.Hour), "x")}},
		{PushToStartToken: "tok", Entries: []liveActivityScheduleEntry{{StartMillis: good.StartMillis, EndMillis: good.EndMillis}}},
	}
	for i, req := range bad {
		if _, err := validateLiveActivitySchedule(req, now); err == nil {
			t.Errorf("case %d must be rejected", i)
		}
	}
	many := make([]liveActivityScheduleEntry, liveActivityScheduleMaxEntries+1)
	for i := range many {
		many[i] = good
	}
	if _, err := validateLiveActivitySchedule(liveActivityScheduleRequest{PushToStartToken: "tok", Entries: many}, now); err == nil {
		t.Error("too many entries must be rejected")
	}
}

func TestLiveActivityScheduleReplaceDueAndSkip(t *testing.T) {
	openLiveActivityStartTestDB(t)
	now := time.Unix(1_700_000_000, 0)
	day1 := scheduleEntry(now.Add(time.Hour), now.Add(3*time.Hour), "Day 1")
	day2 := scheduleEntry(now.Add(25*time.Hour), now.Add(27*time.Hour), "Day 2")
	if err := replaceLiveActivitySchedule("a@x", "dev1", "tokA", []liveActivityScheduleEntry{day1, day2}, now); err != nil {
		t.Fatal(err)
	}
	// Another device keeps its own rows.
	if err := replaceLiveActivitySchedule("b@x", "dev2", "tokB", []liveActivityScheduleEntry{day1}, now); err != nil {
		t.Fatal(err)
	}
	// Re-post replaces dev1's plan (day 1 got logged → only day 2 remains, new token).
	if err := replaceLiveActivitySchedule("a@x", "dev1", "tokA2", []liveActivityScheduleEntry{day2}, now); err != nil {
		t.Fatal(err)
	}

	if due, _ := dueLiveActivityStarts(now); len(due) != 0 {
		t.Fatalf("nothing due before start_at, got %d", len(due))
	}
	due, err := dueLiveActivityStarts(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].token != "tokB" || due[0].attributes.DayLabel != "Day 1" || due[0].alertBody != "B" {
		t.Fatalf("due = %+v (dev1's day 1 must be gone after the re-post)", due)
	}

	var sent []string
	n := processDueLiveActivityStarts(now.Add(time.Hour), func(r liveActivityStartRow) error {
		sent = append(sent, r.token)
		return nil
	})
	if n != 1 || strings.Join(sent, ",") != "tokB" {
		t.Fatalf("processed %d sent %v", n, sent)
	}
	if due, _ := dueLiveActivityStarts(now.Add(time.Hour)); len(due) != 0 {
		t.Fatalf("row must be marked sent: %+v", due)
	}

	// dev1's day 2 comes due only when the window is nearly closed
	// (server was down): skipped, marked, never sent.
	sent = nil
	late := now.Add(27*time.Hour - 2*time.Minute)
	n = processDueLiveActivityStarts(late, func(r liveActivityStartRow) error {
		sent = append(sent, r.token)
		return nil
	})
	if n != 1 || len(sent) != 0 {
		t.Fatalf("late row: processed %d sent %v (must be skipped)", n, sent)
	}
	if due, _ := dueLiveActivityStarts(late); len(due) != 0 {
		t.Fatalf("skipped row must be marked: %+v", due)
	}

	// Cancel: empty schedule removes dev1's unsent rows only.
	if err := replaceLiveActivitySchedule("a@x", "dev1", "tokA2", []liveActivityScheduleEntry{day1}, now); err != nil {
		t.Fatal(err)
	}
	if err := replaceLiveActivitySchedule("a@x", "dev1", "tokA2", nil, now); err != nil {
		t.Fatal(err)
	}
	if due, _ := dueLiveActivityStarts(now.Add(48 * time.Hour)); len(due) != 0 {
		t.Fatalf("cancel must leave nothing due: %+v", due)
	}
}

func TestLiveActivityStartPrune(t *testing.T) {
	openLiveActivityStartTestDB(t)
	now := time.Unix(1_700_000_000, 0)
	e := scheduleEntry(now.Add(time.Hour), now.Add(2*time.Hour), "D")
	if err := replaceLiveActivitySchedule("a@x", "old", "t1", []liveActivityScheduleEntry{e}, now.Add(-41*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := replaceLiveActivitySchedule("a@x", "fresh", "t2", []liveActivityScheduleEntry{e}, now); err != nil {
		t.Fatal(err)
	}
	pruneLiveActivityStarts(now)
	due, _ := dueLiveActivityStarts(now.Add(time.Hour))
	if len(due) != 1 || due[0].token != "t2" {
		t.Fatalf("prune kept wrong rows: %+v", due)
	}
}

func TestScheduleLiveActivityHandler(t *testing.T) {
	openLiveActivityStartTestDB(t)
	claims := &JWTClaims{Email: "A@x", DeviceID: "dev1"}
	call := func(body string, c *JWTClaims) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/user/live-activity/schedule", strings.NewReader(body))
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), "claims", c))
		}
		w := httptest.NewRecorder()
		scheduleLiveActivity(w, r)
		return w
	}
	if w := call(`{"push_to_start_token":"tok","entries":[]}`, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: %d", w.Code)
	}
	if w := call(`{"push_to_start_token":"","entries":[]}`, claims); w.Code != http.StatusBadRequest {
		t.Fatalf("empty token: %d %s", w.Code, w.Body.String())
	}
	start := time.Now().Add(time.Hour)
	end := start.Add(2 * time.Hour)
	body, _ := json.Marshal(liveActivityScheduleRequest{PushToStartToken: "tok",
		Entries: []liveActivityScheduleEntry{scheduleEntry(start, end, "Day 3")}})
	w := call(string(body), claims)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scheduled":1`) {
		t.Fatalf("schedule: %d %s", w.Code, w.Body.String())
	}
	due, _ := dueLiveActivityStarts(start)
	if len(due) != 1 || due[0].attributes.DayLabel != "Day 3" {
		t.Fatalf("stored row = %+v", due)
	}
	var email string
	if err := db.QueryRow(`SELECT email FROM live_activity_starts`).Scan(&email); err != nil || email != "a@x" {
		t.Fatalf("email = %q err %v (must be lower-cased)", email, err)
	}
}
