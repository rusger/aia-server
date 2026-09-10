package main

import (
	"database/sql"
	"testing"
	"time"
)

func TestAppleTxnIsFreeTrial(t *testing.T) {
	cases := []struct {
		name string
		txn  *appleTransactionInfo
		want bool
	}{
		{"nil", nil, false},
		{"no offer", &appleTransactionInfo{}, false},
		{"intro free trial", &appleTransactionInfo{OfferType: 1, OfferDiscountType: "FREE_TRIAL"}, true},
		{"offer code free trial", &appleTransactionInfo{OfferType: 3, OfferDiscountType: "FREE_TRIAL"}, true},
		{"intro pay as you go", &appleTransactionInfo{OfferType: 1, OfferDiscountType: "PAY_AS_YOU_GO"}, false},
		{"intro pay up front", &appleTransactionInfo{OfferType: 1, OfferDiscountType: "PAY_UP_FRONT"}, false},
	}
	for _, c := range cases {
		if got := appleTxnIsFreeTrial(c.txn); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestSubscriptionWindowActive(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	ns := func(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
	cases := []struct {
		name   string
		length string
		expiry sql.NullString
		want   bool
	}{
		{"lifetime, no expiry", "lifetime", sql.NullString{}, true},
		{"lifetime, stale expiry", "lifetime", ns("2020-01-01 00:00:00 +0000 UTC"), true},
		{"monthly, future (driver format)", "monthly", ns("2026-09-13 09:53:29 +0000 UTC"), true},
		{"monthly, past (driver format) — the 7099 restore case", "monthly", ns("2026-08-24 12:56:43 +0000 UTC"), false},
		{"monthly, future RFC3339", "monthly", ns("2026-10-01T00:00:00Z"), true},
		{"monthly, NULL", "monthly", sql.NullString{}, false},
		{"monthly, empty", "monthly", ns(""), false},
		{"monthly, garbage", "monthly", ns("soon"), false},
		{"never paid", "", sql.NullString{}, false},
	}
	for _, c := range cases {
		if got := subscriptionWindowActive(c.length, c.expiry, now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
