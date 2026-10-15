package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

const radioOwner = "owner@example.com"

type radioFake struct {
	transcripts []string // per transcription call, in order
	checks      []radioCheck
	flagged     bool
}

func setupRadioCall(t *testing.T, f *radioFake) (*mux.Router, string) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	voiceSchemaReady.Store(false)
	ensureVoiceSchema()
	radioCallSchemaReady.Store(false)
	ensureRadioCallSchema()
	root := t.TempDir()
	t.Setenv("RADIO_ROOT", root)
	t.Setenv("VOICE_ALLOWED_EMAILS", radioOwner)
	t.Setenv("RADIO_CALL_WORKER_TOKEN", "tok")
	t.Setenv("RADIO_CALL_PUBLIC", "")
	for _, ch := range radioCallStations {
		d := filepath.Join(root, ch, "call")
		os.MkdirAll(d, 0o755)
		cues := map[string][]map[string]interface{}{}
		for _, k := range []string{"announce", "onair", "dropped", "cta"} {
			cues[k] = []map[string]interface{}{{"src": ch + "/call/" + k + "_abc.m4a", "dur": 3.0}}
		}
		b, _ := json.Marshal(cues)
		os.WriteFile(filepath.Join(d, "cues.json"), b, 0o644)
	}
	radioLine.Lock()
	radioLine.call, radioLine.jobs, radioLine.wake = nil, nil, nil
	radioLine.Unlock()

	n := 0
	radioCallTranscribeFn = func(ctx context.Context, audio []byte, fn, lang string) (string, error) {
		i := n
		n++
		if i < len(f.transcripts) {
			return f.transcripts[i], nil
		}
		return "", nil
	}
	radioCallModerateFn = func(ctx context.Context, text string) (bool, error) { return f.flagged, nil }
	k := 0
	radioCallChatFn = func(ctx context.Context, system, user string) (string, int, int, error) {
		if strings.HasPrefix(system, "You screen") {
			c := f.checks[k]
			k++
			b, _ := json.Marshal(c)
			return string(b), 10, 5, nil
		}
		return `{"answer":"Ответ ведущего. Спасибо, что позвонили!","answer_en":"The host's answer. Thank you for calling!"}`, 20, 30, nil
	}
	radioCallPhoneFn = func(in, out string) (float64, error) { return 7.5, os.WriteFile(out, []byte("m4a"), 0o644) }
	radioCallDurFn = func(path string) (float64, error) { return 4.0, nil }
	radioCallLocalTTSFn = func(text, lang, gender string) ([]byte, error) { return []byte("mp3"), nil }
	radioCallKokoroFn = func(text, out string) error { return os.WriteFile(out, []byte("wav"), 0o644) }
	radioWorkerSeen.Store(time.Now().UnixNano()) // Мак на связи, если тест не скажет иначе

	r := mux.NewRouter()
	withUser := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			email := req.Header.Get("X-Test-User")
			if email != "" {
				req = req.WithContext(context.WithValue(req.Context(), "claims", &JWTClaims{Email: email, DeviceID: "dev"}))
			}
			h(w, req)
		}
	}
	r.HandleFunc("/api/radio/call/status", withUser(radioCallStatusHandler)).Methods("GET")
	r.HandleFunc("/api/radio/call/consent", withUser(radioCallConsentHandler)).Methods("POST")
	r.HandleFunc("/api/radio/call/start", withUser(radioCallStartHandler)).Methods("POST")
	r.HandleFunc("/api/radio/call/jobs", radioCallJobsHandler).Methods("GET")
	r.HandleFunc("/api/radio/call/jobs/{job}", radioCallJobDoneHandler).Methods("POST")
	r.HandleFunc("/api/radio/call/{id}/intro", withUser(radioCallIntroHandler)).Methods("POST")
	r.HandleFunc("/api/radio/call/{id}/question", withUser(radioCallQuestionHandler)).Methods("POST")
	r.HandleFunc("/api/radio/call/{id}/hangup", withUser(radioCallHangupHandler)).Methods("POST")
	r.HandleFunc("/api/radio/call/{id}", withUser(radioCallGetHandler)).Methods("GET")
	return r, root
}

func radioDo(t *testing.T, r *mux.Router, method, path, user, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func radioAudio(t *testing.T, r *mux.Router, path, user string) (int, map[string]interface{}) {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	fw, _ := mw.CreateFormFile("audio", "clip.m4a")
	fw.Write(bytes.Repeat([]byte{1}, 4000))
	mw.WriteField("chart_context", "Moon in Taurus")
	mw.Close()
	req := httptest.NewRequest("POST", path, &b)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Test-User", user)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// radioWorker serves one job like the Mac does: 9 station files + durs.
func radioWorker(t *testing.T, r *mux.Router, wantKind string) {
	t.Helper()
	var job map[string]interface{}
	for i := 0; i < 50 && job == nil; i++ {
		req := httptest.NewRequest("GET", "/api/radio/call/jobs?wait=0", nil)
		req.Header.Set("X-Radio-Worker", "tok")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var out struct {
			Jobs []map[string]interface{} `json:"jobs"`
		}
		json.Unmarshal(w.Body.Bytes(), &out)
		if len(out.Jobs) > 0 {
			job = out.Jobs[0]
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if job == nil || job["kind"] != wantKind {
		t.Fatalf("worker job = %v, want kind %s", job, wantKind)
	}
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	durs := map[string]float64{}
	for _, ch := range radioCallStations {
		fw, _ := mw.CreateFormFile(ch, ch+".m4a")
		fw.Write([]byte("audio"))
		durs[ch] = 5.5
	}
	db, _ := json.Marshal(durs)
	mw.WriteField("durs", string(db))
	mw.Close()
	req := httptest.NewRequest("POST", "/api/radio/call/jobs/"+job["id"].(string), &b)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Radio-Worker", "tok")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("job upload %d %s", w.Code, w.Body.String())
	}
}

func radioNow(t *testing.T, root string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "call", "now.json"))
	if err != nil {
		return nil
	}
	var doc map[string]interface{}
	json.Unmarshal(b, &doc)
	return doc
}

func radioKinds(doc map[string]interface{}) []string {
	var k []string
	for _, s := range doc["segments"].([]interface{}) {
		k = append(k, s.(map[string]interface{})["kind"].(string))
	}
	return k
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestRadioCallAiredInRussianWithTranslation(t *testing.T) {
	r, root := setupRadioCall(t, &radioFake{
		transcripts: []string{"Меня зовут Руслан, хочу спросить про Сатурн", "Что значит Сатурн над моей Луной?"},
		checks: []radioCheck{{OK: true, Name: "Руслан Иванов", TopicEN: "Saturn over his Moon", Language: "ru"},
			{OK: true, Language: "ru"}},
	})
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"ru"}`); code != 403 || out["error"] != "consent_required" {
		t.Fatalf("start without consent: %d %v", code, out)
	}
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	code, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"ru"}`)
	if code != 200 {
		t.Fatalf("start %d %v", code, out)
	}
	id := out["call_id"].(string)
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", "other@example.com", `{}`); code != 403 {
		t.Fatalf("second caller without consent/access must be refused: %d %v", code, out)
	}
	if radioNow(t, root) != nil {
		t.Fatal("nothing goes on air before the intro is checked")
	}
	code, out = radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	if code != 200 || out["ok"] != true || out["name"] != "Руслан" {
		t.Fatalf("intro %d %v (first name only)", code, out)
	}
	doc := radioNow(t, root)
	if doc["state"] != "live" || doc["hold_set"] != "day" || strings.Join(radioKinds(doc), ",") != "announce" {
		t.Fatalf("after intro now.json = %v", doc)
	}
	seg := doc["segments"].([]interface{})[0].(map[string]interface{})
	if !strings.HasPrefix(seg["src"].(string), "{ch}/call/announce_") || len(seg["durs"].(map[string]interface{})) != 9 {
		t.Fatalf("announce segment %v", seg)
	}
	radioWorker(t, r, "intro_line")
	waitFor(t, func() bool { return strings.Join(radioKinds(radioNow(t, root)), ",") == "announce,intro_line" })

	code, out = radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner)
	if code != 200 || out["ok"] != true {
		t.Fatalf("question %d %v", code, out)
	}
	doc = radioNow(t, root)
	if doc["hold_set"] != "think" || strings.Join(radioKinds(doc), ",") != "announce,intro_line,onair,caller" {
		t.Fatalf("after question %v", doc)
	}
	radioWorker(t, r, "answer_en")
	waitFor(t, func() bool { d := radioNow(t, root); return d["state"] == "done" })
	doc = radioNow(t, root)
	if got := strings.Join(radioKinds(doc), ","); got != "announce,intro_line,onair,caller,answer_local,answer_en,cta" {
		t.Fatalf("final segments %s", got)
	}
	if _, err := os.Stat(filepath.Join(root, "call", id, "mars", "answer_en.m4a")); err != nil {
		t.Fatal("station file of the reply not stored")
	}
	var state string
	var aired, charged int
	db.QueryRow(`SELECT state, aired, charged_usd_micro FROM radio_calls WHERE id = ?`, id).Scan(&state, &aired, &charged)
	if state != "aired" || aired != 1 || charged != 0 {
		t.Fatalf("row state=%s aired=%d charged=%d (owner is not charged)", state, aired, charged)
	}
	radioLine.Lock()
	free := radioLine.call == nil
	radioLine.Unlock()
	if !free {
		t.Fatal("line must be free after the call")
	}
}

func TestRadioCallIntroRejectedNothingOnAir(t *testing.T) {
	r, root := setupRadioCall(t, &radioFake{transcripts: []string{"buy crypto at my site"},
		checks: []radioCheck{{OK: false, Reason: "ad"}}})
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	code, out := radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	if code != 200 || out["ok"] != false {
		t.Fatalf("intro %d %v", code, out)
	}
	if radioNow(t, root) != nil {
		t.Fatal("a rejected intro must not reach the air")
	}
	if code, _ := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{}`); code != 200 {
		t.Fatal("line must be free again")
	}
}

func TestRadioCallFlaggedQuestionDropsLine(t *testing.T) {
	f := &radioFake{transcripts: []string{"I'm Anna, about Venus", "you are all idiots"},
		checks: []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus", Language: "en"}}}
	r, root := setupRadioCall(t, f)
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	f.flagged = true
	code, out := radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner)
	if code != 200 || out["ok"] != false || out["reason"] != "moderation" {
		t.Fatalf("question %d %v", code, out)
	}
	doc := radioNow(t, root)
	if doc["state"] != "done" || strings.Join(radioKinds(doc), ",") != "announce,dropped" {
		t.Fatalf("now.json %v", doc)
	}
}

func TestRadioCallAccessAndWorkerToken(t *testing.T) {
	r, _ := setupRadioCall(t, &radioFake{})
	if code, out := radioDo(t, r, "POST", "/api/radio/call/consent", "x@example.com", `{"version":"old"}`); code != 400 {
		t.Fatalf("wrong consent version %d %v", code, out)
	}
	radioDo(t, r, "POST", "/api/radio/call/consent", "x@example.com", `{"version":"`+radioCallConsentVersion+`"}`)
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", "x@example.com", `{}`); code != 403 || out["error"] != "not_available" {
		t.Fatalf("stage 1 is owner-only: %d %v", code, out)
	}
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{}`)
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{}`); code != 409 || out["error"] != "line_busy" {
		t.Fatalf("one line for all stations: %d %v", code, out)
	}
	req := httptest.NewRequest("GET", "/api/radio/call/jobs?wait=0", nil)
	req.Header.Set("X-Radio-Worker", "wrong")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("worker with a wrong token: %d", w.Code)
	}
	_, st := radioDo(t, r, "GET", "/api/radio/call/status", radioOwner, "")
	if st["line_busy"] != true || st["consented"] != true || st["available"] != true {
		t.Fatalf("status %v", st)
	}
}

func TestRadioCallTranscribeCost(t *testing.T) {
	if c := financeTokenCostUSD(radioCallTranscribe, 60000, 0, 0, false); c < 0.00299 || c > 0.00301 {
		t.Fatalf("a minute of audio = %.5f, want 0.003", c)
	}
}

func TestRadioCallDailyLimitForPublicCallers(t *testing.T) {
	r, _ := setupRadioCall(t, &radioFake{})
	t.Setenv("RADIO_CALL_PUBLIC", "1")
	const u = "listener@example.com"
	if err := voiceGrant(u, 1.0); err != nil {
		t.Fatal(err)
	}
	radioDo(t, r, "POST", "/api/radio/call/consent", u, `{"version":"`+radioCallConsentVersion+`"}`)
	for i := 0; i < radioCallDailyLimit; i++ {
		db.Exec(`INSERT INTO radio_calls (id, email, state) VALUES (?, ?, 'aired')`, "old"+strconv.Itoa(i), u)
	}
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", u, `{}`); code != 403 || out["error"] != "daily_limit" {
		t.Fatalf("third call today: %d %v", code, out)
	}
	db.Exec(`DELETE FROM radio_calls WHERE email = ?`, u)
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", u, `{}`); code != 200 {
		t.Fatalf("public caller with minutes: %d %v", code, out)
	}
}

func TestRadioCallNoMinutesForPublicCallers(t *testing.T) {
	r, _ := setupRadioCall(t, &radioFake{})
	t.Setenv("RADIO_CALL_PUBLIC", "1")
	const u = "broke@example.com"
	radioDo(t, r, "POST", "/api/radio/call/consent", u, `{"version":"`+radioCallConsentVersion+`"}`)
	if code, out := radioDo(t, r, "POST", "/api/radio/call/start", u, `{}`); code != 403 || out["error"] != "no_minutes" {
		t.Fatalf("no balance: %d %v", code, out)
	}
}

func TestRadioCallIntroLineBeforeOnAir(t *testing.T) {
	r, root := setupRadioCall(t, &radioFake{
		transcripts: []string{"I'm Anna, about Venus", "What does Venus in Pisces mean?"},
		checks:      []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus in Pisces", Language: "en"}, {OK: true, Language: "en"}},
	})
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	done := make(chan map[string]interface{}, 1)
	go func() { _, o := radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner); done <- o }()
	time.Sleep(100 * time.Millisecond)
	if got := strings.Join(radioKinds(radioNow(t, root)), ","); got != "announce" {
		t.Fatalf("the caller must wait for the intro line, on air: %s", got)
	}
	radioWorker(t, r, "intro_line") // Мак озвучил интро позже, чем пришёл вопрос
	if o := <-done; o["ok"] != true {
		t.Fatalf("question %v", o)
	}
	if got := strings.Join(radioKinds(radioNow(t, root)), ","); got != "announce,intro_line,onair,caller" {
		t.Fatalf("order on air: %s", got)
	}
}

func TestRadioCallIntroLineFallbackWhenMacLate(t *testing.T) {
	old := radioIntroWait.Load()
	radioIntroWait.Store(int64(50 * time.Millisecond))
	t.Cleanup(func() { radioIntroWait.Store(old) })
	r, root := setupRadioCall(t, &radioFake{
		transcripts: []string{"I'm Anna", "About Venus?"},
		checks:      []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus", Language: "en"}, {OK: true, Language: "en"}},
	})
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	if _, o := radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner); o["ok"] != true {
		t.Fatalf("question %v", o)
	}
	doc := radioNow(t, root)
	if got := strings.Join(radioKinds(doc), ","); got != "announce,intro_line,onair,caller" {
		t.Fatalf("Mac silent → the server voices the intro itself: %s", got)
	}
	if src := doc["segments"].([]interface{})[1].(map[string]interface{})["src"]; src != "call/"+id+"/intro_line_fb.mp3" {
		t.Fatalf("intro from the server TTS, got %v", src)
	}
}

func TestRadioCallReplyFallbackWhenMacLate(t *testing.T) {
	old := radioAnswerWait.Load()
	radioAnswerWait.Store(int64(50 * time.Millisecond))
	t.Cleanup(func() { radioAnswerWait.Store(old) })
	r, root := setupRadioCall(t, &radioFake{
		transcripts: []string{"I'm Anna, about Venus", "What does Venus in Pisces mean?"},
		checks:      []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus", Language: "en"}, {OK: true, Language: "en"}},
	})
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	radioWorker(t, r, "intro_line")
	radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner)
	waitFor(t, func() bool { d := radioNow(t, root); return d["state"] == "done" }) // Мак молчит на ответе
	doc := radioNow(t, root)
	if got := strings.Join(radioKinds(doc), ","); got != "announce,intro_line,onair,caller,answer_en,cta" {
		t.Fatalf("the reply must not be lost: %s", got)
	}
	segs := doc["segments"].([]interface{})
	if src := segs[len(segs)-2].(map[string]interface{})["src"]; src != "call/"+id+"/answer_en_fb.mp3" {
		t.Fatalf("reply from the server TTS, got %v", src)
	}
}

func TestRadioCallMacOfflineFallsBackFast(t *testing.T) {
	for _, v := range []*atomic.Int64{&radioMacGrace, &radioMacAlive} {
		old := v.Load()
		t.Cleanup(func() { v.Store(old) })
	}
	radioMacGrace.Store(int64(50 * time.Millisecond))
	radioMacAlive.Store(int64(20 * time.Millisecond))
	radioWorkerSeen.Store(time.Now().Add(-time.Hour).UnixNano()) // Мак давно не выходил на связь
	r, root := setupRadioCall(t, &radioFake{
		transcripts: []string{"I'm Anna", "About Venus?"},
		checks:      []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus", Language: "en"}, {OK: true, Language: "en"}},
	})
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	t0 := time.Now()
	radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner) // ждёт интро: Мак офлайн → резерв за ~grace, не 45 с
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("offline Mac must not hold the call for the full wait: %s", el)
	}
	waitFor(t, func() bool { d := radioNow(t, root); return d["state"] == "done" })
	if got := strings.Join(radioKinds(radioNow(t, root)), ","); got != "announce,intro_line,onair,caller,answer_en,cta" {
		t.Fatalf("server voices intro and reply: %s", got)
	}
}

func TestRadioCallOpenAIDownKokoroOnServer(t *testing.T) {
	old := radioAnswerWait.Load()
	radioAnswerWait.Store(int64(50 * time.Millisecond))
	t.Cleanup(func() { radioAnswerWait.Store(old) })
	r, root := setupRadioCall(t, &radioFake{
		transcripts: []string{"I'm Anna", "About Venus?"},
		checks:      []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus", Language: "en"}, {OK: true, Language: "en"}},
	})
	radioCallLocalTTSFn = func(text, lang, gender string) ([]byte, error) { return nil, errors.New("insufficient_quota") }
	var said string
	radioCallKokoroFn = func(text, out string) error { said = text; return os.WriteFile(out, []byte("wav"), 0o644) }
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	radioWorker(t, r, "intro_line")
	radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner)
	waitFor(t, func() bool { d := radioNow(t, root); return d["state"] == "done" })
	doc := radioNow(t, root)
	segs := doc["segments"].([]interface{})
	if src := segs[len(segs)-2].(map[string]interface{})["src"]; src != "call/"+id+"/answer_en_kokoro.wav" {
		t.Fatalf("OpenAI down → Kokoro on the server, got %v", src)
	}
	if !strings.Contains(said, "Thank you for calling") {
		t.Fatalf("Kokoro got the reply text: %q", said)
	}
}

func TestRadioCallRetention(t *testing.T) {
	r, root := setupRadioCall(t, &radioFake{
		transcripts: []string{"I'm Anna", "About Venus?"},
		checks:      []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus", Language: "en"}, {OK: true, Language: "en"}},
	})
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	radioWorker(t, r, "intro_line")
	radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner)
	if m, _ := filepath.Glob(filepath.Join(root, "call", id, "caller_raw*")); len(m) != 0 {
		t.Fatalf("the raw question recording must not be kept: %v", m)
	}
	radioWorker(t, r, "answer_en")
	waitFor(t, func() bool { d := radioNow(t, root); return d["state"] == "done" })

	old := filepath.Join(root, "call", "oldcall")
	os.MkdirAll(old, 0o755)
	os.WriteFile(filepath.Join(old, "caller.m4a"), []byte("x"), 0o644)
	past := time.Now().Add(-31 * 24 * time.Hour)
	os.Chtimes(old, past, past)
	db.Exec(`INSERT INTO radio_calls (id, email, state, name, question_text, created_at) VALUES ('ancient', ?, 'aired', 'Bob', 'q', ?)`,
		radioOwner, time.Now().Add(-400*24*time.Hour).UTC().Format("2006-01-02 15:04:05"))
	radioCallCleanup(time.Now())
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("call audio older than 30 days must be deleted")
	}
	if _, err := os.Stat(filepath.Join(root, "call", id)); err != nil {
		t.Fatal("a fresh call's audio must stay")
	}
	var name, q sql.NullString
	var state string
	db.QueryRow(`SELECT state, name, question_text FROM radio_calls WHERE id = 'ancient'`).Scan(&state, &name, &q)
	if state != "aired" || name.Valid || q.Valid {
		t.Fatalf("texts older than 12 months cleared, row kept: state=%q name=%v q=%v", state, name, q)
	}
	var fresh sql.NullString
	db.QueryRow(`SELECT question_text FROM radio_calls WHERE id = ?`, id).Scan(&fresh)
	if !fresh.Valid {
		t.Fatal("fresh transcripts must stay")
	}
}

func TestRadioCallRejectedHasNoCTA(t *testing.T) {
	f := &radioFake{transcripts: []string{"I'm Anna, about Venus", "you are all idiots"},
		checks: []radioCheck{{OK: true, Name: "Anna", TopicEN: "Venus", Language: "en"}}}
	r, root := setupRadioCall(t, f)
	radioDo(t, r, "POST", "/api/radio/call/consent", radioOwner, `{"version":"`+radioCallConsentVersion+`"}`)
	_, out := radioDo(t, r, "POST", "/api/radio/call/start", radioOwner, `{"lang":"en"}`)
	id := out["call_id"].(string)
	radioAudio(t, r, "/api/radio/call/"+id+"/intro", radioOwner)
	f.flagged = true
	radioAudio(t, r, "/api/radio/call/"+id+"/question", radioOwner)
	if got := strings.Join(radioKinds(radioNow(t, root)), ","); strings.Contains(got, "cta") {
		t.Fatalf("a call that did not air must not invite others: %s", got)
	}
}
