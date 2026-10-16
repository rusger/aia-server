package main

import (
	"database/sql"
	"testing"
)

// A Sandbox chain (TestFlight yearly renewing daily, 12 cycles then EXPIRED)
// landed in apple_notifications on 27.09–09.10.2026 and showed up in
// renewal-stats as "yearly: 11 renewals of 17 cycles" and in finance as
// 11 × yearly revenue. Stats must read production rows only.
func TestAppleRenewalQuerySkipsSandbox(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE apple_notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT, notification_uuid TEXT, notification_type TEXT,
		subtype TEXT, environment TEXT, transaction_id TEXT, original_transaction_id TEXT,
		product_id TEXT, created_at DATETIME)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	rows := []struct{ env, otxn, created string }{
		{"Production", "prod-1", "2026-10-01 10:00:00"},
		{"", "legacy-1", "2026-10-02 10:00:00"}, // pre-migration row: production
		{"Sandbox", "sb-1", "2026-10-03 10:00:00"},
		{"Sandbox", "sb-1", "2026-10-04 10:00:00"},
	}
	for i, r := range rows {
		if _, err := db.Exec(`INSERT INTO apple_notifications
			(notification_uuid, notification_type, subtype, environment, transaction_id, original_transaction_id, product_id, created_at)
			VALUES (?, 'DID_RENEW', '', ?, ?, ?, 'astrolytix_pro_yearly_v2', ?)`,
			i, r.env, r.otxn+"-tx", r.otxn, r.created); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	agg := computeRenewalAgg(appleRenewalQuery, classifyApple, appleChurnReason)
	if agg.total != 2 {
		t.Fatalf("total events = %d, want 2 (production + legacy; sandbox excluded)", agg.total)
	}
	if got := agg.byPlan["yearly"]["renewed"]; got != 2 {
		t.Fatalf("yearly renewed = %d, want 2", got)
	}
}
