package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

const pultQS = "?admin_email=boss@example.com&admin_secret=s3cret"

func setupPult(t *testing.T) (*mux.Router, *sql.DB) {
	t.Helper()
	d, err := openPultDB(filepath.Join(t.TempDir(), "pult.db"))
	if err != nil {
		t.Fatalf("open pult db: %v", err)
	}
	oldDB, oldSecret, oldEmails, oldGuard := pultDB, ADMIN_SECRET_KEY, ADMIN_EMAILS, adminGuard
	pultDB = d
	ADMIN_SECRET_KEY, ADMIN_EMAILS = "s3cret", []string{"boss@example.com"}
	// httptest requests come from 192.0.2.1: allowlist it so the guard's
	// lockout/rate limit does not leak between test cases.
	adminGuard = NewAdminGuard()
	adminGuard.allowedIPs = map[string]bool{"192.0.2.1": true}
	t.Cleanup(func() {
		pultDB, ADMIN_SECRET_KEY, ADMIN_EMAILS, adminGuard = oldDB, oldSecret, oldEmails, oldGuard
		if err := d.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	r := mux.NewRouter()
	registerPultRoutes(r)
	return r, d
}

func pultDo(t *testing.T, r http.Handler, method, path, body string) (int, map[string]interface{}, string) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	raw := rec.Body.String()
	out := map[string]interface{}{}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatalf("%s %s: bad json %q: %v", method, path, raw, err)
		}
	}
	return rec.Code, out, raw
}

func pultSeed(t *testing.T, d *sql.DB) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO items VALUES('b1','{"title":"Секретный блок","task":"A1","rev":2,"order":1}',3,'2026-11-17T10:00:00Z')`,
		`INSERT INTO items VALUES('b2','{"title":"Второй","rev":1}',1,'2026-11-17T10:00:00Z')`,
		`INSERT INTO pages VALUES('rep-1','Отчёт','sess-x','<h1>Привет</h1>','2026-11-17T11:00:00Z')`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func TestPultAuthRequired(t *testing.T) {
	r, d := setupPult(t)
	pultSeed(t, d)
	cases := []struct{ method, path, body string }{
		{"GET", "/api/admin/pult/state", ""},
		{"POST", "/api/admin/pult/reply", `{"id":"b1","ok":true}`},
		{"POST", "/api/admin/pult/general", `{"text":"x"}`},
		{"GET", "/api/admin/pult/page/rep-1", ""},
	}
	for _, qs := range []string{"", "?admin_email=boss@example.com&admin_secret=wrong",
		"?admin_email=stranger@example.com&admin_secret=s3cret"} {
		for _, c := range cases {
			code, _, raw := pultDo(t, r, c.method, c.path+qs, c.body)
			if code != http.StatusForbidden || strings.Contains(raw, "Секретный") || strings.Contains(raw, "Привет") {
				t.Fatalf("%s %s%s: %d %s", c.method, c.path, qs, code, raw)
			}
		}
	}
	// empty ADMIN_SECRET_KEY refuses even an empty secret
	ADMIN_SECRET_KEY = ""
	for _, c := range cases {
		if code, _, _ := pultDo(t, r, c.method, c.path+"?admin_email=boss@example.com&admin_secret=", c.body); code != http.StatusForbidden {
			t.Fatalf("empty server secret: %s %s → %d", c.method, c.path, code)
		}
	}
	var n int
	if err := d.QueryRow(`SELECT (SELECT COUNT(*) FROM replies)+(SELECT COUNT(*) FROM general)+(SELECT COUNT(*) FROM reply_log)`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused requests wrote rows: %d %v", n, err)
	}
}

func TestPultShellPublicNoData(t *testing.T) {
	r, d := setupPult(t)
	pultSeed(t, d)
	for _, p := range []string{"/api/admin/pult", "/api/admin/pult/"} {
		req := httptest.NewRequest("GET", p, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
			rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %v", p, rec.Code, rec.Header())
		}
		if !strings.Contains(body, "Пульт владельца") || strings.Contains(body, "Секретный") || strings.Contains(body, "Привет") ||
			strings.Contains(body, "s3cret") {
			t.Fatalf("%s: shell must not carry data", p)
		}
	}
}

func TestPultReplyOverwritesAndLogs(t *testing.T) {
	r, d := setupPult(t)
	pultSeed(t, d)
	code, out, raw := pultDo(t, r, "POST", "/api/admin/pult/reply"+pultQS, `{"id":"b1","ok":true,"text":" первый ","rev":2,"title":"T","task":"A1"}`)
	if code != 200 || out["success"] != true {
		t.Fatalf("reply 1: %d %s", code, raw)
	}
	code, _, raw = pultDo(t, r, "POST", "/api/admin/pult/reply"+pultQS, `{"id":"b1","ok":false,"text":"второй","rev":2}`)
	if code != 200 {
		t.Fatalf("reply 2: %d %s", code, raw)
	}
	var data string
	var version int
	if err := d.QueryRow(`SELECT data, version FROM replies WHERE id='b1'`).Scan(&data, &version); err != nil {
		t.Fatal(err)
	}
	m := map[string]interface{}{}
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		t.Fatal(err)
	}
	if m["text"] != "второй" || m["ok"] != false || version != 2 || m["at"] == "" {
		t.Fatalf("replies[b1] = %v v%d", m, version)
	}
	var logged int
	if err := d.QueryRow(`SELECT COUNT(*) FROM reply_log WHERE id='b1'`).Scan(&logged); err != nil || logged != 2 {
		t.Fatalf("reply_log: %d %v", logged, err)
	}
	if code, _, _ := pultDo(t, r, "POST", "/api/admin/pult/reply"+pultQS, `{"id":"","ok":true}`); code != 400 {
		t.Fatalf("empty id: %d", code)
	}
}

func TestPultGeneralCreatesUnhandled(t *testing.T) {
	r, d := setupPult(t)
	code, out, raw := pultDo(t, r, "POST", "/api/admin/pult/general"+pultQS, `{"text":"идея","page":"rep-1","title":"Отчёт"}`)
	if code != 200 || out["id"] == nil {
		t.Fatalf("general: %d %s", code, raw)
	}
	var data string
	if err := d.QueryRow(`SELECT data FROM general WHERE id = ?`, out["id"]).Scan(&data); err != nil {
		t.Fatal(err)
	}
	m := map[string]interface{}{}
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		t.Fatal(err)
	}
	if m["text"] != "идея" || m["handled"] != false || m["page"] != "rep-1" || m["title"] != "Отчёт" || m["at"] == "" {
		t.Fatalf("general = %v", m)
	}
	if code, _, _ := pultDo(t, r, "POST", "/api/admin/pult/general"+pultQS, `{"text":"  "}`); code != 400 {
		t.Fatalf("empty text: %d", code)
	}
}

func TestPultPage(t *testing.T) {
	r, d := setupPult(t)
	pultSeed(t, d)
	code, out, raw := pultDo(t, r, "GET", "/api/admin/pult/page/rep-1"+pultQS, "")
	if code != 200 || out["html"] != "<h1>Привет</h1>" || out["title"] != "Отчёт" || out["session"] != "sess-x" || out["slug"] != "rep-1" {
		t.Fatalf("page: %d %s", code, raw)
	}
	if code, _, _ := pultDo(t, r, "GET", "/api/admin/pult/page/nope"+pultQS, ""); code != 404 {
		t.Fatalf("unknown slug: %d", code)
	}
}

func TestPultStateCollectsAll(t *testing.T) {
	r, d := setupPult(t)
	pultSeed(t, d)
	if code, _, raw := pultDo(t, r, "POST", "/api/admin/pult/reply"+pultQS, `{"id":"b2","ok":true,"rev":1}`); code != 200 {
		t.Fatalf("reply: %d %s", code, raw)
	}
	code, out, raw := pultDo(t, r, "GET", "/api/admin/pult/state"+pultQS, "")
	if code != 200 {
		t.Fatalf("state: %d %s", code, raw)
	}
	items, _ := out["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("items: %s", raw)
	}
	b1, _ := items[0].(map[string]interface{})
	if b1["id"] != "b1" || b1["title"] != "Секретный блок" || b1["version"] != float64(3) || b1["rev"] != float64(2) {
		t.Fatalf("item b1: %v", b1)
	}
	replies, _ := out["replies"].(map[string]interface{})
	if rb2, _ := replies["b2"].(map[string]interface{}); rb2 == nil || rb2["ok"] != true {
		t.Fatalf("replies: %v", replies)
	}
	pages, _ := out["pages"].([]interface{})
	p0, _ := pages[0].(map[string]interface{})
	if len(pages) != 1 || p0["slug"] != "rep-1" || p0["session"] != "sess-x" || p0["html"] != nil {
		t.Fatalf("pages: %v", pages)
	}
}

func TestPultStoreDownIs503(t *testing.T) {
	r, _ := setupPult(t)
	pultDB = nil
	if code, _, _ := pultDo(t, r, "GET", "/api/admin/pult/state"+pultQS, ""); code != http.StatusServiceUnavailable {
		t.Fatalf("store down: %d", code)
	}
	if code, _, _ := pultDo(t, r, "GET", "/api/admin/pult/state", ""); code != http.StatusForbidden {
		t.Fatalf("store down, no secret: %d", code)
	}
	// shell still served
	if code, _, _ := pultDo(t, r, "GET", "/api/admin/pult/", ""); code != 200 {
		t.Fatalf("shell: %d", code)
	}
	// an unopenable path → error, not panic
	if _, err := openPultDB(filepath.Join(t.TempDir(), "no-such-dir", "pult.db")); err == nil {
		t.Fatalf("open in a missing dir must fail")
	}
}
