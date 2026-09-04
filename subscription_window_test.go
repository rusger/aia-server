package main

// Pins the forward-only rule for users.subscription_expiry (2026-09-04):
// iOS re-delivers the expired previous period of a subscription on every
// launch and the client syncs it through recordPurchase; the stored window
// must never jump backwards because of that.

import (
	"database/sql"
	"testing"
	"time"
)

func TestSubscriptionWindowUpdate(t *testing.T) {
	past := time.Date(2026, 8, 20, 4, 7, 32, 0, time.UTC)
	future := time.Date(2026, 9, 20, 4, 7, 32, 0, time.UTC)
	later := future.Add(30 * 24 * time.Hour)
	stored := func(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
	none := sql.NullString{}

	cases := []struct {
		name        string
		curLength   string
		curExpiry   sql.NullString
		inLength    string
		in          *time.Time
		wantLength  string
		wantExpiry  *time.Time
		wantAdvance bool
	}{
		{"expired period after current keeps current", "monthly", stored(future.Format("2006-01-02 15:04:05.999999999 -0700 MST")), "monthly", &past, "monthly", &future, false},
		{"renewal moves forward", "monthly", stored(future.Format("2006-01-02 15:04:05")), "monthly", &later, "monthly", &later, true},
		{"empty window is backfilled", "monthly", none, "monthly", &past, "monthly", &past, true},
		{"empty string window is backfilled", "monthly", stored(""), "yearly", &future, "yearly", &future, true},
		{"lifetime purchase always wins", "monthly", stored(future.Format(time.RFC3339)), "lifetime", nil, "lifetime", nil, true},
		{"lifetime row is never demoted", "lifetime", none, "monthly", &past, "lifetime", nil, false},
		{"dated window not replaced by unknown", "monthly", stored(future.Format(time.RFC3339)), "monthly", nil, "monthly", nil, false},
		{"unreadable stored value replaced by verified", "monthly", stored("garbage"), "monthly", &future, "monthly", &future, true},
		{"equal dates keep current", "monthly", stored(future.Format(time.RFC3339)), "yearly", &future, "monthly", &future, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotLength, gotExpiry, gotAdvance := subscriptionWindowUpdate(c.curLength, c.curExpiry, c.inLength, c.in)
			if gotAdvance != c.wantAdvance {
				t.Fatalf("advance = %v, want %v", gotAdvance, c.wantAdvance)
			}
			if gotLength != c.wantLength {
				t.Fatalf("length = %q, want %q", gotLength, c.wantLength)
			}
			switch {
			case c.wantExpiry == nil && gotExpiry != nil:
				t.Fatalf("expiry = %v, want nil", gotExpiry)
			case c.wantExpiry != nil && gotExpiry == nil:
				t.Fatalf("expiry = nil, want %v", c.wantExpiry)
			case c.wantExpiry != nil && !gotExpiry.Equal(*c.wantExpiry):
				t.Fatalf("expiry = %v, want %v", gotExpiry, c.wantExpiry)
			}
		})
	}
}
