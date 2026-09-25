package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// One push is logged once per device of the account, each in that device's
// language; the app keeps the first row per payload. The caller's own device
// must therefore come first (owner 25.09.2026: an old English device's row
// was newest → English card on a Russian phone).
func TestNotificationHistoryOwnDeviceFirst(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	notifHistoryReady.Store(false)
	ensureNotificationHistorySchema()
	ins := `INSERT INTO notification_history (email, device_id, title, body, payload, sent_at) VALUES (?, ?, ?, ?, ?, ?)`
	for _, r := range [][]string{
		{"owner@example.com", "OLD-RU", "Ваши события", "ru", "astro:slow_ingress:slow_ingress:Mercury:2026-09-26", "2026-09-25 08:02:10"},
		{"owner@example.com", "ME", "Ваши события", "ru", "astro:slow_ingress:slow_ingress:Mercury:2026-09-26", "2026-09-25 08:02:11"},
		{"owner@example.com", "EN-DEV", "Your events", "en", "astro:slow_ingress:slow_ingress:Mercury:2026-09-26", "2026-09-25 08:02:16"},
		{"owner@example.com", "ME", "Новолуние", "ru", "astro:lunar_phase:lunar_phase:new:2026-09-11", "2026-09-10 08:00:00"},
		{"other@example.com", "ME", "Someone else", "en", "astro:lunar_phase:lunar_phase:new:2026-09-11", "2026-09-26 08:00:00"},
	} {
		if _, err := db.Exec(ins, r[0], r[1], r[2], r[3], r[4], r[5]); err != nil {
			t.Fatal(err)
		}
	}
	call := func(query string) []map[string]string {
		req := httptest.NewRequest("GET", "/api/user/notification-history"+query, nil)
		req = req.WithContext(context.WithValue(req.Context(), "claims", &JWTClaims{Email: "Owner@example.com"}))
		w := httptest.NewRecorder()
		getUserNotificationHistory(w, req)
		var out struct {
			Success       bool                `json:"success"`
			Notifications []map[string]string `json:"notifications"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.Success {
			t.Fatalf("bad response: %v %s", err, w.Body.String())
		}
		return out.Notifications
	}

	got := call("?device_id=ME")
	if len(got) != 4 {
		t.Fatalf("rows = %d (other account leaked?)", len(got))
	}
	if got[0]["device_id"] != "ME" || got[1]["device_id"] != "ME" {
		t.Fatalf("own device must lead: %v", got)
	}
	if got[0]["body"] != "ru" || got[0]["title"] != "Ваши события" {
		t.Fatalf("own device's newest row first: %v", got[0])
	}
	if got[2]["device_id"] != "EN-DEV" || got[3]["device_id"] != "OLD-RU" {
		t.Fatalf("others newest-first after: %v", got[2:])
	}

	// no device_id → plain newest-first, device_id still exposed for the app
	legacy := call("")
	if legacy[0]["device_id"] != "EN-DEV" || legacy[0]["body"] != "en" {
		t.Fatalf("legacy order = %v", legacy[0])
	}
}
