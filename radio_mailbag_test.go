package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// radioMailbagEpisode writes a valid episode (manifest + files) under <root>/mailbag/<dir>.
func radioMailbagEpisode(t *testing.T, root, dir, id, created string, mutate func(m map[string]interface{})) {
	t.Helper()
	base := filepath.Join(root, "mailbag", dir)
	durs := map[string]float64{}
	for _, ch := range radioCallStations {
		os.MkdirAll(filepath.Join(base, ch), 0o755)
		os.WriteFile(filepath.Join(base, ch, "intro.m4a"), []byte("i"), 0o644)
		os.WriteFile(filepath.Join(base, ch, "answer_en.m4a"), []byte("a"), 0o644)
		durs[ch] = 4.5
	}
	os.WriteFile(filepath.Join(base, "question.m4a"), []byte("q"), 0o644)
	os.WriteFile(filepath.Join(base, "answer_local.mp3"), []byte("l"), 0o644)
	m := map[string]interface{}{
		"id": id, "name": "Olga Petrova", "lang": "ru", "bank_n": 2, "created": created,
		"question_text": "Что значит Сатурн?", "question_en": "What does Saturn mean?",
		"answer_text": "Ответ", "answer_en": "Answer",
		"segments": []map[string]interface{}{
			{"src": "mailbag/" + id + "/{ch}/intro.m4a", "durs": durs, "kind": "intro_line"},
			{"src": "mailbag/" + id + "/question.m4a", "dur": 20.0, "kind": "caller"},
			{"src": "mailbag/" + id + "/answer_local.mp3", "dur": 30.0, "kind": "answer_local"},
			{"src": "mailbag/" + id + "/{ch}/answer_en.m4a", "durs": durs, "kind": "answer_en"},
		},
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(base, "manifest.json"), b, 0o644)
}

func setupMailbag(t *testing.T) (*mux.Router, string) {
	t.Helper()
	r, root := setupRadioCall(t, &radioFake{})
	t.Setenv("RADIO_MAILBAG", "1")
	t.Setenv("RADIO_MAILBAG_MIN_LISTENERS", "")
	t.Setenv("RADIO_MAILBAG_GAP_MIN", "")
	radioListenersFn = func(now time.Time) (int, error) { return 3, nil }
	t.Cleanup(func() { radioListenersFn = radioListenersFromLog })
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	radioMailbagNow = func() time.Time { return now }
	t.Cleanup(func() { radioMailbagNow = time.Now })
	for _, v := range []*atomic.Int64{&radioMailbagLiveFor, &radioMailbagSlack} {
		old := v.Load()
		t.Cleanup(func() { v.Store(old) })
	}
	radioMailbagLiveFor.Store(int64(30 * time.Millisecond))
	// the test episode plans 67 s (5 parts × 1 s pause + 4.5 + 20 + 30 + 4.5 + 3 cta): free the line ~at once
	radioMailbagSlack.Store(int64(-67*time.Second + 300*time.Millisecond))
	radioMailbagBad.Range(func(k, _ interface{}) bool { radioMailbagBad.Delete(k); return true })
	t.Setenv("ADMIN_SECRET_KEY", "")
	oldSecret, oldEmails := ADMIN_SECRET_KEY, ADMIN_EMAILS
	ADMIN_SECRET_KEY, ADMIN_EMAILS = "s3cret", []string{"boss@example.com"}
	t.Cleanup(func() { ADMIN_SECRET_KEY, ADMIN_EMAILS = oldSecret, oldEmails })
	r.HandleFunc("/api/admin/radio/calls", adminRadioCalls).Methods("GET")
	r.HandleFunc("/api/admin/radio/mailbag", adminRadioMailbag).Methods("GET")
	r.HandleFunc("/api/admin/radio/mailbag/{id}/delete", adminRadioMailbagDelete).Methods("POST")
	r.HandleFunc("/api/admin/radio/switches", adminRadioSwitches).Methods("GET", "POST")
	return r, root
}

func radioLineFree() bool {
	radioLine.Lock()
	defer radioLine.Unlock()
	return radioLine.call == nil
}

const radioAdminQS = "?admin_email=boss@example.com&admin_secret=s3cret"

func TestRadioMailbagAirsOnceThroughTheLine(t *testing.T) {
	r, root := setupMailbag(t)
	radioMailbagEpisode(t, root, "ep2", "ep2", "2026-10-14T10:00:00Z", nil)
	radioMailbagEpisode(t, root, "ep1", "ep1", "2026-10-13T10:00:00Z", nil)
	radioMailbagEpisode(t, root, ".incoming-ep0", "ep0", "2026-10-01T10:00:00Z", nil) // upload in progress
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)

	if got := radioMailbagTick(); got != "ep1" {
		t.Fatalf("oldest unaired first, got %q", got)
	}
	doc := radioNow(t, root)
	if doc["id"] != "mb-ep1" || doc["state"] != "live" || doc["hold"] != false {
		t.Fatalf("now.json %v", doc)
	}
	if got := strings.Join(radioKinds(doc), ","); got != "intro_line,caller,answer_local,answer_en,cta" {
		t.Fatalf("segments %s", got)
	}
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{}`); code != 409 || out["error"] != "line_busy" {
		t.Fatalf("a caller during a mailbag item: %d %v", code, out)
	}
	waitFor(t, func() bool { return radioNow(t, root)["state"] == "done" })
	waitFor(t, radioLineFree)
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM radio_calls`).Scan(&n)
	if n != 0 {
		t.Fatalf("a mailbag item must not create radio_calls rows: %d", n)
	}
	var charged int64
	db.QueryRow(`SELECT COALESCE(SUM(spent_usd_micro), 0) FROM voice_balance`).Scan(&charged)
	if charged != 0 {
		t.Fatal("nobody is charged for a mailbag item")
	}
	if got := radioMailbagTick(); got != "" {
		t.Fatalf("the gap (30 min) must hold the next one, got %q", got)
	}
	now := time.Date(2026, 10, 15, 12, 31, 0, 0, time.UTC)
	radioMailbagNow = func() time.Time { return now }
	if got := radioMailbagTick(); got != "ep2" {
		t.Fatalf("after the gap the next episode, got %q", got)
	}
	waitFor(t, radioLineFree)
	now = now.Add(time.Hour)
	if got := radioMailbagTick(); got != "" {
		t.Fatalf("each episode airs once; .incoming dirs never: %q", got)
	}
}

func TestRadioMailbagConditions(t *testing.T) {
	r, root := setupMailbag(t)
	radioMailbagEpisode(t, root, "ep1", "ep1", "2026-10-13T10:00:00Z", nil)

	t.Setenv("RADIO_MAILBAG", "")
	if radioMailbagTick() != "" {
		t.Fatal("off by default")
	}
	t.Setenv("RADIO_MAILBAG", "1")
	radioListenersFn = func(now time.Time) (int, error) { return 0, nil }
	if radioMailbagTick() != "" {
		t.Fatal("nobody listening — the reserve is not burned")
	}
	t.Setenv("RADIO_MAILBAG_MIN_LISTENERS", "5")
	radioListenersFn = func(now time.Time) (int, error) { return 4, nil }
	if radioMailbagTick() != "" {
		t.Fatal("below the threshold")
	}
	radioListenersFn = func(now time.Time) (int, error) { return 0, os.ErrPermission }
	if radioMailbagTick() != "" {
		t.Fatal("unreadable log — not airing")
	}
	radioListenersFn = func(now time.Time) (int, error) { return 5, nil }
	if code, _ := radioDo(t, r, "POST", "/api/admin/radio/switches"+radioAdminQS, "", `{"mailbag_off": true}`); code != 200 {
		t.Fatal("switch")
	}
	if radioMailbagTick() != "" {
		t.Fatal("mailbag_off")
	}
	radioDo(t, r, "POST", "/api/admin/radio/switches"+radioAdminQS, "", `{"mailbag_off": false}`)
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{}`)
	if radioMailbagTick() != "" {
		t.Fatal("a live caller holds the line")
	}
	radioLine.Lock()
	radioEnd(radioLine.call, "hangup", "test")
	radioLine.Unlock()
	if radioMailbagTick() != "ep1" {
		t.Fatal("all conditions met")
	}
}

func TestRadioMailbagInvalidManifestsSkipped(t *testing.T) {
	_, root := setupMailbag(t)
	radioMailbagEpisode(t, root, "nodur", "nodur", "2026-10-01T10:00:00Z", func(m map[string]interface{}) {
		segs := m["segments"].([]map[string]interface{})
		delete(segs[0]["durs"].(map[string]float64), "ketu")
	})
	radioMailbagEpisode(t, root, "nofile", "nofile", "2026-10-02T10:00:00Z", nil)
	os.Remove(filepath.Join(root, "mailbag", "nofile", "answer_local.mp3"))
	radioMailbagEpisode(t, root, "escape", "escape", "2026-10-03T10:00:00Z", func(m map[string]interface{}) {
		m["segments"].([]map[string]interface{})[1]["src"] = "call/other/caller.m4a"
	})
	radioMailbagEpisode(t, root, "wrongid", "other", "2026-10-04T10:00:00Z", nil)
	radioMailbagEpisode(t, root, "good", "good", "2026-10-05T10:00:00Z", nil)
	if got := radioMailbagTick(); got != "good" {
		t.Fatalf("only the valid episode airs, got %q", got)
	}
}

func TestRadioListenersFromNginxLog(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 58, 0, 0, time.UTC)
	log := strings.Join([]string{
		`84.145.25.134 - - [15/Oct/2026:12:57:39 +0000] "GET /radio/moon/live/aac_58460.ts HTTP/2.0" 200 80088 "-" "AppleCoreMedia/1.0"`,
		`84.145.25.134 - - [15/Oct/2026:12:57:43 +0000] "GET /radio/moon/live/aac_58461.ts HTTP/2.0" 200 80088 "-" "AppleCoreMedia/1.0"`,
		`10.0.0.2 - - [15/Oct/2026:14:57:50 +0200] "GET /radio/mars/live/aac_1.ts?x=1 HTTP/1.1" 206 100 "-" "Chrome"`,
		`10.0.0.3 - - [15/Oct/2026:12:56:10 +0000] "GET /radio/sun/live/aac_1.ts HTTP/1.1" 200 100 "-" "old"`,
		`10.0.0.4 - - [15/Oct/2026:12:57:50 +0000] "GET /radio/sun/live/aac.m3u8 HTTP/1.1" 200 100 "-" "playlist only"`,
		`10.0.0.5 - - [15/Oct/2026:12:57:50 +0000] "GET /radio/sun/live/aac_2.ts HTTP/1.1" 404 100 "-" "miss"`,
		`10.0.0.6 - - [15/Oct/2026:12:57:50 +0000] "GET /api/radio/call/jobs?wait=25 HTTP/1.1" 200 114 "-" "python" rl=238 rt=25.003`,
		`garbage`,
	}, "\n")
	if n := radioCountListeners([]byte(log), now); n != 2 {
		t.Fatalf("listeners = %d, want 2 (distinct IPs with a fresh HLS segment)", n)
	}
	p := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(p, []byte(strings.Repeat("x", 100)+"\n"+log+"\n"), 0o644)
	t.Setenv("RADIO_ACCESS_LOG", p)
	if n, err := radioListenersFromLog(now); err != nil || n != 2 {
		t.Fatalf("from file: %d %v", n, err)
	}
}

func TestRadioAdminEndpoints(t *testing.T) {
	r, root := setupMailbag(t)
	for _, path := range []string{"/api/admin/radio/calls", "/api/admin/radio/mailbag", "/api/admin/radio/switches"} {
		if code, _ := radioDo(t, r, "GET", path+"?admin_email=boss@example.com&admin_secret=nope", "", ""); code != 403 {
			t.Fatalf("%s with a wrong secret: %d", path, code)
		}
		if code, _ := radioDo(t, r, "GET", path+"?admin_email=x@example.com&admin_secret=s3cret", "", ""); code != 403 {
			t.Fatalf("%s for a non-admin: %d", path, code)
		}
	}
	ADMIN_SECRET_KEY = ""
	if code, _ := radioDo(t, r, "GET", "/api/admin/radio/switches?admin_email=boss@example.com&admin_secret=", "", ""); code != 403 {
		t.Fatal("no secret configured → closed")
	}
	ADMIN_SECRET_KEY = "s3cret"

	// calls_off: the app gets available=false and a refused start
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	if code, out := radioDo(t, r, "POST", "/api/admin/radio/switches"+radioAdminQS, "", `{"calls_off": true}`); code != 200 ||
		out["calls_off"] != true || out["mailbag_off"] != false {
		t.Fatalf("switches %d %v", code, out)
	}
	if _, st := radioDo(t, r, "GET", "/api/radio/call/status", radioOwner, ""); st["available"] != false || st["reason"] != "calls_off" {
		t.Fatalf("status with calls_off %v", st)
	}
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{}`); code != 403 || out["error"] != "calls_off" {
		t.Fatalf("start with calls_off %d %v", code, out)
	}
	if _, out := radioDo(t, r, "GET", "/api/admin/radio/switches"+radioAdminQS, "", ""); out["calls_off"] != true {
		t.Fatalf("persisted %v", out)
	}
	radioDo(t, r, "POST", "/api/admin/radio/switches"+radioAdminQS, "", `{"calls_off": false}`)
	if code, _ := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{}`); code != 200 {
		t.Fatal("calls back on")
	}

	db.Exec(`INSERT INTO radio_calls (id, email, lang, name, state, aired, charged_usd_micro, reason) VALUES ('c1', 'a@b', 'ru', 'Оля', 'aired', 1, 300000, '')`)
	_, out := radioDo(t, r, "GET", "/api/admin/radio/calls"+radioAdminQS+"&days=14", "", "")
	calls := out["calls"].([]interface{})
	if len(calls) != 2 {
		t.Fatalf("calls %v", out)
	}
	found := false
	for _, c := range calls {
		m := c.(map[string]interface{})
		if m["id"] == "c1" {
			found = m["name"] == "Оля" && m["aired"] == true && m["charged_usd"] == 0.3 && m["created"] != nil
		}
		if _, has := m["email"]; has {
			t.Fatal("no emails in the panel list")
		}
	}
	if !found {
		t.Fatalf("call row %v", calls)
	}

	radioMailbagEpisode(t, root, "ep1", "ep1", "2026-10-13T10:00:00Z", nil)
	_, out = radioDo(t, r, "GET", "/api/admin/radio/mailbag"+radioAdminQS, "", "")
	eps := out["episodes"].([]interface{})
	if len(eps) != 1 {
		t.Fatalf("episodes %v", out)
	}
	e := eps[0].(map[string]interface{})
	if e["id"] != "ep1" || e["name"] != "Olga" || e["bank_n"] != 2.0 || e["question_text"] != "Что значит Сатурн?" ||
		!strings.Contains(e["answer_text"].(string), "Answer") || e["aired_at"] != nil || e["deleted_at"] != nil {
		t.Fatalf("episode %v", e)
	}
	if code, _ := radioDo(t, r, "POST", "/api/admin/radio/mailbag/nope/delete"+radioAdminQS, "", ""); code != 404 {
		t.Fatalf("unknown episode %d", code)
	}
	if code, _ := radioDo(t, r, "POST", "/api/admin/radio/mailbag/..%2Fcall/delete"+radioAdminQS, "", ""); code == 200 {
		t.Fatal("path escape must be refused")
	}
	if code, out := radioDo(t, r, "POST", "/api/admin/radio/mailbag/ep1/delete"+radioAdminQS, "", ""); code != 200 {
		t.Fatalf("delete %d %v", code, out)
	}
	if _, err := os.Stat(filepath.Join(root, "mailbag", "ep1")); !os.IsNotExist(err) {
		t.Fatal("files removed")
	}
	radioMailbagEpisode(t, root, "ep1", "ep1", "2026-10-13T10:00:00Z", nil) // re-uploaded under the same id
	if got := radioMailbagTick(); got != "" {
		t.Fatalf("a deleted episode never airs, got %q", got)
	}
	_, out = radioDo(t, r, "GET", "/api/admin/radio/mailbag"+radioAdminQS, "", "")
	if e := out["episodes"].([]interface{})[0].(map[string]interface{}); e["deleted_at"] == nil {
		t.Fatalf("deleted mark %v", e)
	}
}

func TestRadioAdminDeleteOnAirRefused(t *testing.T) {
	r, root := setupMailbag(t)
	radioMailbagLiveFor.Store(int64(time.Hour))
	radioMailbagEpisode(t, root, "ep1", "ep1", "2026-10-13T10:00:00Z", nil)
	if radioMailbagTick() != "ep1" {
		t.Fatal("airing")
	}
	if code, _ := radioDo(t, r, "POST", "/api/admin/radio/mailbag/ep1/delete"+radioAdminQS, "", ""); code != http.StatusConflict {
		t.Fatalf("delete during air %d", code)
	}
	radioLine.Lock()
	radioLine.call = nil
	radioLine.Unlock()
}
