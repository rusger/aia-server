package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// Owner 09.10.2026: a history card mixed the server's English title/body with
// the app's Russian article. The server composes each push in the device's
// language but never said which — now the language travels in the push data
// and is stored with the history row ("" = unknown, e.g. admin free text).
func TestPushPayloadsCarryLang(t *testing.T) {
	apns := apnsPayloadMap("New Moon 🌑", "A New Moon rises today", "astro:lunar_phase:lunar_phase:new:2026-10-09", "en")
	if apns["lang"] != "en" {
		t.Fatalf("APNs lang = %v", apns["lang"])
	}
	if apns["payload"] != "astro:lunar_phase:lunar_phase:new:2026-10-09" || apns["NotificationId"] == nil {
		t.Fatalf("APNs deep-link keys lost: %v", apns)
	}
	if _, has := apnsPayloadMap("Astrolytix", "hello", "", "")["lang"]; has {
		t.Fatal("unknown language must not be sent as an empty key")
	}

	fcm := fcmMessageMap("tok", "Новолуние 🌑", "Сегодня новолуние", "astro:lunar_phase:lunar_phase:new:2026-10-09", "ru", 0)
	data, _ := fcm["data"].(map[string]string)
	if data["lang"] != "ru" || data["payload"] != "astro:lunar_phase:lunar_phase:new:2026-10-09" {
		t.Fatalf("FCM data = %v", fcm["data"])
	}
	if _, has := fcmMessageMap("tok", "t", "b", "", "", 0)["data"]; has {
		t.Fatal("no payload and no lang → no data block, as before")
	}
	only, _ := fcmMessageMap("tok", "t", "b", "", "ru", 0)["data"].(map[string]string)
	if len(only) != 1 || only["lang"] != "ru" {
		t.Fatalf("lang alone still travels: %v", only)
	}
}

func TestNotificationHistoryStoresLang(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	notifHistoryReady.Store(false)
	// A pre-09.10 table without the column: the schema call must add it
	// (the deploy is git pull + build + restart, no manual migration).
	if _, err := db.Exec(`CREATE TABLE notification_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, device_id TEXT,
		title TEXT, body TEXT, payload TEXT, sent_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO notification_history (email, device_id, title, body, payload) VALUES ('owner@example.com', 'ME', 'Full Moon 🌕', 'old row', 'astro:lunar_phase:lunar_phase:full:2026-09-26')`); err != nil {
		t.Fatal(err)
	}
	ensureNotificationHistorySchema()
	ensureNotificationHistorySchema() // idempotent: "duplicate column" is not an error
	if !notifHistoryReady.Load() {
		t.Fatal("schema not ready after migration")
	}
	recordNotificationHistory("Owner@example.com", "ME", "New Moon 🌑", "A New Moon rises today", "astro:lunar_phase:lunar_phase:new:2026-10-09", "en")
	recordNotificationHistory("owner@example.com", "ME", "Astrolytix", "admin text", "astro:lunar_phase:lunar_phase:new:2026-10-10", "")

	req := httptest.NewRequest("GET", "/api/user/notification-history?device_id=ME", nil)
	req = req.WithContext(context.WithValue(req.Context(), "claims", &JWTClaims{Email: "owner@example.com"}))
	w := httptest.NewRecorder()
	getUserNotificationHistory(w, req)
	var out struct {
		Success       bool                `json:"success"`
		Notifications []map[string]string `json:"notifications"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.Success {
		t.Fatalf("bad response: %v %s", err, w.Body.String())
	}
	got := map[string]string{}
	for _, n := range out.Notifications {
		lang, has := n["lang"]
		if !has {
			t.Fatalf("row without lang field: %v", n)
		}
		got[n["payload"]] = lang
	}
	if got["astro:lunar_phase:lunar_phase:new:2026-10-09"] != "en" {
		t.Fatalf("event push row lang = %q", got["astro:lunar_phase:lunar_phase:new:2026-10-09"])
	}
	if got["astro:lunar_phase:lunar_phase:new:2026-10-10"] != "" {
		t.Fatalf("admin free text must stay unknown, got %q", got["astro:lunar_phase:lunar_phase:new:2026-10-10"])
	}
	if got["astro:lunar_phase:lunar_phase:full:2026-09-26"] != "" {
		t.Fatalf("legacy row (NULL) must read as empty, got %q", got["astro:lunar_phase:lunar_phase:full:2026-09-26"])
	}
}
