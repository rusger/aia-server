package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func setupPresenterJobsTest(t *testing.T) (voiceCalls *int) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// one connection: a second one to ":memory:" would be another, empty database
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	migratePresenterJobs()
	analyticsDB = nil
	vdir, adir := t.TempDir(), t.TempDir()
	os.Setenv("PRESENTER_VIDEO_DIR", vdir)
	os.Setenv("TTS_CACHE_DIR", adir)
	os.Setenv("PRESENTER_NODE_TOKEN", "node-secret")
	t.Cleanup(func() {
		os.Unsetenv("PRESENTER_VIDEO_DIR")
		os.Unsetenv("TTS_CACHE_DIR")
		os.Unsetenv("PRESENTER_NODE_TOKEN")
	})
	calls := 0
	oldFetch, oldInjected, oldNow := ttsFetch, ttsFetchInjected, presenterNow
	ttsFetch = func(model, voice, instructions, text string) ([]byte, error) {
		calls++
		return []byte(strings.Repeat("v", 3000)), nil
	}
	ttsFetchInjected = true
	presenterNodeSeenAt.Store(0)
	t.Cleanup(func() {
		ttsFetch, ttsFetchInjected, presenterNow = oldFetch, oldInjected, oldNow
		presenterNodeSeenAt.Store(0)
	})
	return &calls
}

// presenterRouter wires the real routes so {id} paths and the node auth are exercised.
func presenterRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/api/presenter/jobs", presenterJobCreateHandler).Methods("POST")
	r.HandleFunc("/api/presenter/jobs/{id}", presenterJobStatusHandler).Methods("GET")
	r.HandleFunc("/api/presenter/jobs/{id}/cancel", presenterJobCancelHandler).Methods("POST")
	r.HandleFunc("/api/presenter/node/claim", presenterNodeAuth(presenterNodeClaimHandler)).Methods("POST")
	r.HandleFunc("/api/presenter/node/audio", presenterNodeAuth(presenterNodeAudioHandler)).Methods("GET")
	r.HandleFunc("/api/presenter/node/result", presenterNodeAuth(presenterNodeResultHandler)).Methods("PUT")
	r.HandleFunc("/api/presenter/node/fail", presenterNodeAuth(presenterNodeFailHandler)).Methods("POST")
	r.HandleFunc("/api/presenter/node/video", presenterNodeAuth(presenterNodeVideoHandler)).Methods("PUT")
	return r
}

func presenterCall(t *testing.T, rt *mux.Router, method, url, body string, claims *JWTClaims, node bool) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if claims != nil {
		r = r.WithContext(context.WithValue(r.Context(), "claims", claims))
	}
	if node {
		r.Header.Set("X-Presenter-Node-Token", "node-secret")
	}
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func fakeMP4(n int) string {
	b := make([]byte, n)
	copy(b, "\x00\x00\x00\x18ftypmp42")
	for i := 8; i < n; i++ {
		b[i] = 'x'
	}
	return string(b)
}

// waitVoiced polls until the background voicing moved the job on.
func waitVoiced(t *testing.T, rt *mux.Router, id string, claims *JWTClaims) map[string]interface{} {
	t.Helper()
	for i := 0; i < 200; i++ {
		_, st := presenterCall(t, rt, "GET", "/api/presenter/jobs/"+id, "", claims, false)
		if st["status"] != "voicing" {
			return st
		}
		timeSleepMs(5)
	}
	t.Fatal("job stayed in voicing")
	return nil
}

func TestPresenterJobsHappyPath(t *testing.T) {
	voiceCalls := setupPresenterJobsTest(t)
	rt := presenterRouter()
	claims := &JWTClaims{Email: "a@x", DeviceID: "dev1"}
	body := `{"text":"Вы соединяете чуткость и стойкость.","gender":"f","lang":"ru","version":"v17","presenter":"j-b"}`

	// node offline → unavailable, nothing created, no voice ordered
	w, out := presenterCall(t, rt, "POST", "/api/presenter/jobs", body, claims, false)
	if w.Code != 200 || out["status"] != "unavailable" || out["node_online"] != false {
		t.Fatalf("offline: %d %v", w.Code, out)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM presenter_jobs`).Scan(&n)
	if n != 0 || *voiceCalls != 0 {
		t.Fatalf("offline must not create a job or a voice: rows=%d voice=%d", n, *voiceCalls)
	}

	// the node polls: nothing queued
	w, out = presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true)
	if w.Code != 200 || out["job"] != nil {
		t.Fatalf("empty claim: %d %v", w.Code, out)
	}
	if !presenterNodeOnline() {
		t.Fatal("a claim marks the node online")
	}

	// now a job is created and voiced in the background
	w, out = presenterCall(t, rt, "POST", "/api/presenter/jobs", body, claims, false)
	if w.Code != 200 || out["status"] != "voicing" || out["id"] == nil {
		t.Fatalf("create: %d %v", w.Code, out)
	}
	id := jsonID(out["id"])
	key := out["key"].(string)
	if key != ttsCacheKey(ttsModel, "nova", "ru", "Вы соединяете чуткость и стойкость.") {
		t.Fatalf("key: %s", key)
	}
	st := waitVoiced(t, rt, id, claims)
	if st["status"] != "queued" || *voiceCalls != 1 {
		t.Fatalf("after voicing: %v calls=%d", st, *voiceCalls)
	}
	// the same text again → the same job, no second voice
	_, again := presenterCall(t, rt, "POST", "/api/presenter/jobs", body, claims, false)
	if again["status"] != "queued" || jsonID(again["id"]) != id {
		t.Fatalf("dedup: %v", again)
	}

	// the node takes it
	_, claim := presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true)
	job := claim["job"].(map[string]interface{})
	if jsonID(job["id"]) != id || job["key"] != key || job["presenter"] != "j-b" || job["text"] != "Вы соединяете чуткость и стойкость." {
		t.Fatalf("claim: %v", job)
	}
	if _, st = presenterCall(t, rt, "GET", "/api/presenter/jobs/"+id, "", claims, false); st["status"] != "rendering" {
		t.Fatalf("after claim: %v", st)
	}
	// the creator can no longer cancel
	if _, c := presenterCall(t, rt, "POST", "/api/presenter/jobs/"+id+"/cancel", "", claims, false); c["cancelled"] != false {
		t.Fatalf("cancel while rendering: %v", c)
	}
	// the node fetches the voice
	a, _ := presenterCall(t, rt, "GET", "/api/presenter/node/audio?key="+key, "", nil, true)
	if a.Code != 200 || a.Body.Len() != 3000 {
		t.Fatalf("audio: %d %d", a.Code, a.Body.Len())
	}
	// and uploads the result
	if r, o := presenterCall(t, rt, "PUT", "/api/presenter/node/result?id="+id, "not a video at all "+strings.Repeat("x", 2000), nil, true); r.Code != 400 {
		t.Fatalf("junk result: %d %v", r.Code, o)
	}
	if r, _ := presenterCall(t, rt, "PUT", "/api/presenter/node/result?id="+id, fakeMP4(5000), nil, true); r.Code != 200 {
		t.Fatalf("result: %d", r.Code)
	}
	_, st = presenterCall(t, rt, "GET", "/api/presenter/jobs/"+id, "", claims, false)
	if st["status"] != "ready" {
		t.Fatalf("after result: %v", st)
	}
	var text string
	db.QueryRow(`SELECT text FROM presenter_jobs WHERE id = ?`, id).Scan(&text)
	if text != "" {
		t.Fatal("the text must be wiped once the job ended")
	}
	path, _ := presenterVideoPath("v17", key)
	if presenterVideoSize(path) != 5000 {
		t.Fatalf("stored video: %d", presenterVideoSize(path))
	}
	// a second result for a finished job is refused
	if r, _ := presenterCall(t, rt, "PUT", "/api/presenter/node/result?id="+id, fakeMP4(5000), nil, true); r.Code != 409 {
		t.Fatalf("result twice: %d", r.Code)
	}
	// and the app now gets «ready» straight away
	if _, o := presenterCall(t, rt, "POST", "/api/presenter/jobs", body, claims, false); o["status"] != "ready" {
		t.Fatalf("after ready: %v", o)
	}
}

func TestPresenterJobsValidationAndAuth(t *testing.T) {
	setupPresenterJobsTest(t)
	rt := presenterRouter()
	claims := &JWTClaims{Email: "a@x", DeviceID: "dev1"}
	presenterNodeSeenAt.Store(presenterNow())
	if w, _ := presenterCall(t, rt, "POST", "/api/presenter/jobs", `{"text":"x"}`, nil, false); w.Code != 401 {
		t.Fatalf("no claims: %d", w.Code)
	}
	for _, bad := range []string{
		`{"text":"  ","gender":"f","lang":"ru","version":"v17","presenter":"j-b"}`,
		`{"text":"x","gender":"f","lang":"ru","version":"17","presenter":"j-b"}`,
		`{"text":"x","gender":"f","lang":"ru","version":"v17","presenter":"../x"}`,
		`{"text":"x","gender":"f","lang":"ru","version":"v17"}`,
		`{"text":"` + strings.Repeat("а", ttsMaxChars+1) + `","gender":"f","lang":"ru","version":"v17","presenter":"j-b"}`,
	} {
		if w, _ := presenterCall(t, rt, "POST", "/api/presenter/jobs", bad, claims, false); w.Code != 400 {
			t.Fatalf("bad %q: %d", bad[:20], w.Code)
		}
	}
	if w, _ := presenterCall(t, rt, "GET", "/api/presenter/jobs/999", "", claims, false); w.Code != 404 {
		t.Fatalf("unknown job: %d", w.Code)
	}
	// node auth
	r := httptest.NewRequest("POST", "/api/presenter/node/claim", nil)
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("node without token: %d", w.Code)
	}
	r.Header.Set("X-Presenter-Node-Token", "wrong")
	w = httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("node with a wrong token: %d", w.Code)
	}
	os.Unsetenv("PRESENTER_NODE_TOKEN")
	if w, _ := presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true); w.Code != 503 {
		t.Fatalf("node not configured: %d", w.Code)
	}
	os.Setenv("PRESENTER_NODE_TOKEN", "node-secret")
	if w, _ := presenterCall(t, rt, "GET", "/api/presenter/node/audio?key=zz", "", nil, true); w.Code != 400 {
		t.Fatalf("bad audio key: %d", w.Code)
	}
	if w, _ := presenterCall(t, rt, "GET", "/api/presenter/node/audio?key="+strings.Repeat("a", 40), "", nil, true); w.Code != 404 {
		t.Fatalf("missing audio: %d", w.Code)
	}
}

func TestPresenterJobsLimitsCancelAndSweep(t *testing.T) {
	voiceCalls := setupPresenterJobsTest(t)
	rt := presenterRouter()
	claims := &JWTClaims{Email: "a@x", DeviceID: "dev1"}
	now := int64(1_000_000)
	presenterNow = func() int64 { return now }
	presenterNodeSeenAt.Store(now)
	mk := func(i int) string {
		return `{"text":"Текст номер ` + strings.Repeat("я", i) + `","gender":"m","lang":"ru","version":"v17","presenter":"m-l"}`
	}
	_, j1 := presenterCall(t, rt, "POST", "/api/presenter/jobs", mk(1), claims, false)
	_, j2 := presenterCall(t, rt, "POST", "/api/presenter/jobs", mk(2), claims, false)
	if w, _ := presenterCall(t, rt, "POST", "/api/presenter/jobs", mk(3), claims, false); w.Code != 429 {
		t.Fatalf("third active job per device: %d", w.Code)
	}
	id1, id2 := jsonID(j1["id"]), jsonID(j2["id"])
	waitVoiced(t, rt, id1, claims)
	waitVoiced(t, rt, id2, claims)
	if *voiceCalls != 2 {
		t.Fatalf("voices: %d", *voiceCalls)
	}
	// cancel the second while queued — another device cannot
	if _, c := presenterCall(t, rt, "POST", "/api/presenter/jobs/"+id2+"/cancel", "", &JWTClaims{DeviceID: "other"}, false); c["cancelled"] != false {
		t.Fatalf("foreign cancel: %v", c)
	}
	if _, c := presenterCall(t, rt, "POST", "/api/presenter/jobs/"+id2+"/cancel", "", claims, false); c["cancelled"] != true {
		t.Fatalf("own cancel: %v", c)
	}
	// the node claims job 1, loses it: once back to the queue, the second time failed
	_, c := presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true)
	if jsonID(c["job"].(map[string]interface{})["id"]) != id1 {
		t.Fatalf("claim: %v", c)
	}
	if _, c = presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true); c["job"] != nil {
		t.Fatalf("cancelled job must not be claimed: %v", c)
	}
	presenterCall(t, rt, "POST", "/api/presenter/node/fail", `{"id":`+id1+`,"error":"boom"}`, nil, true)
	if _, st := presenterCall(t, rt, "GET", "/api/presenter/jobs/"+id1, "", claims, false); st["status"] != "queued" {
		t.Fatalf("after first failure: %v", st)
	}
	_, c = presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true)
	if c["job"] == nil {
		t.Fatal("requeued job must be claimable")
	}
	// the node goes silent for longer than the stale limit: the sweep fails it (attempts exhausted)
	now += presenterRenderStaleSec + 1
	presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true)
	if _, st := presenterCall(t, rt, "GET", "/api/presenter/jobs/"+id1, "", claims, false); st["status"] != "failed" || st["error"] != "render_timeout" {
		t.Fatalf("after stale: %v", st)
	}
	// a queued job nobody takes expires
	_, j3 := presenterCall(t, rt, "POST", "/api/presenter/jobs", mk(3), claims, false)
	id3 := jsonID(j3["id"])
	waitVoiced(t, rt, id3, claims)
	now += presenterQueuedExpireSec + 1
	presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true)
	if _, st := presenterCall(t, rt, "GET", "/api/presenter/jobs/"+id3, "", claims, false); st["status"] != "failed" || st["error"] != "expired" {
		t.Fatalf("expired: %v", st)
	}
	// old finished rows are deleted
	now += presenterJobKeepSec + 1
	presenterCall(t, rt, "POST", "/api/presenter/node/claim", "", nil, true)
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM presenter_jobs`).Scan(&n)
	if n != 0 {
		t.Fatalf("rows after keep period: %d", n)
	}
	// a node that stopped polling is offline for the app
	now += presenterNodeOnlineSec + 1
	if _, o := presenterCall(t, rt, "POST", "/api/presenter/jobs", mk(4), claims, false); o["status"] != "unavailable" {
		t.Fatalf("node silent: %v", o)
	}
}

func TestPresenterJobsOneActivePerVideo(t *testing.T) {
	setupPresenterJobsTest(t)
	presenterNodeSeenAt.Store(presenterNow())
	// the unique index refuses a second active job for the same video, whoever asks
	for i, dev := range []string{"dev1", "dev2"} {
		_, err := db.Exec(`INSERT INTO presenter_jobs (key, version, text, gender, lang, presenter, device_id, status, created_at)
			VALUES (?, 'v17', 't', 'f', 'ru', 'j-b', ?, 'voicing', ?)`, strings.Repeat("c", 40), dev, presenterNow())
		if (err == nil) != (i == 0) {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	// a finished job frees the slot for a new one
	presenterFinish(1, "failed", "x")
	if _, err := db.Exec(`INSERT INTO presenter_jobs (key, version, text, gender, lang, presenter, device_id, status, created_at)
		VALUES (?, 'v17', 't', 'f', 'ru', 'j-b', 'dev3', 'queued', ?)`, strings.Repeat("c", 40), presenterNow()); err != nil {
		t.Fatalf("after finish: %v", err)
	}
}

func TestPresenterJobsVoiceFailure(t *testing.T) {
	setupPresenterJobsTest(t)
	ttsFetch = func(model, voice, instructions, text string) ([]byte, error) { return nil, os.ErrDeadlineExceeded }
	rt := presenterRouter()
	claims := &JWTClaims{Email: "a@x", DeviceID: "dev1"}
	presenterNodeSeenAt.Store(presenterNow())
	_, j := presenterCall(t, rt, "POST", "/api/presenter/jobs", `{"text":"Текст.","gender":"m","lang":"ru","version":"v17","presenter":"m-l"}`, claims, false)
	st := waitVoiced(t, rt, jsonID(j["id"]), claims)
	if st["status"] != "failed" || st["error"] != "voice_failed" {
		t.Fatalf("voice failure: %v", st)
	}
}

func TestPresenterNodeCatalogUpload(t *testing.T) {
	setupPresenterJobsTest(t)
	rt := presenterRouter()
	key := strings.Repeat("b", 40)
	if w, _ := presenterCall(t, rt, "PUT", "/api/presenter/node/video?key="+key+"&v=17", fakeMP4(3000), nil, true); w.Code != 400 {
		t.Fatalf("bad version: %d", w.Code)
	}
	if w, _ := presenterCall(t, rt, "PUT", "/api/presenter/node/video?key="+key+"&v=v17", strings.Repeat("x", 3000), nil, true); w.Code != 400 {
		t.Fatalf("not an mp4: %d", w.Code)
	}
	w, o := presenterCall(t, rt, "PUT", "/api/presenter/node/video?key="+key+"&v=v17", fakeMP4(4000), nil, true)
	if w.Code != 200 || o["bytes"].(float64) != 4000 {
		t.Fatalf("upload: %d %v", w.Code, o)
	}
	if presenterVideoSize(filepath.Join(os.Getenv("PRESENTER_VIDEO_DIR"), "v17", key+".mp4")) != 4000 {
		t.Fatal("catalog video not stored")
	}
	if entries, _ := os.ReadDir(filepath.Join(os.Getenv("PRESENTER_VIDEO_DIR"), "v17")); len(entries) != 1 {
		t.Fatalf("leftover files: %d", len(entries))
	}
}

func jsonID(v interface{}) string {
	f, _ := v.(float64)
	return strconv.FormatInt(int64(f), 10)
}

func timeSleepMs(ms int) { time.Sleep(time.Duration(ms) * time.Millisecond) }
