package main

import (
	"testing"
	"time"
)

// A203 д: an empty subscription_expiry is "forever" only for lifetime plans.
func TestEntitlementStrictEmptyExpiry(t *testing.T) {
	setupAppleExpiryDB(t)
	if _, err := db.Exec(`ALTER TABLE users ADD COLUMN is_super INTEGER DEFAULT 0;
		ALTER TABLE users ADD COLUMN referral_premium_until DATETIME`); err != nil {
		t.Fatal(err)
	}
	future := time.Now().AddDate(0, 1, 0).UTC().Format("2006-01-02 15:04:05")
	past := time.Now().AddDate(0, -1, 0).UTC().Format("2006-01-02 15:04:05")
	cases := []struct {
		email, length string
		expiry        interface{}
		want          bool
	}{
		{"monthly-none@test", "monthly", nil, false},
		{"yearly-empty@test", "yearly", "", false},
		{"lifetime-none@test", "lifetime", nil, true},
		{"monthly-future@test", "monthly", future, true},
		{"monthly-past@test", "monthly", past, false},
	}
	for _, c := range cases {
		if _, err := db.Exec(`INSERT INTO users (email, subscription_type, subscription_length, subscription_expiry)
			VALUES (?, 'paid', ?, ?)`, c.email, c.length, c.expiry); err != nil {
			t.Fatal(err)
		}
		if paid, _ := userEntitlement(c.email, ""); paid != c.want {
			t.Errorf("userEntitlement(%s) = %v, want %v", c.email, paid, c.want)
		}
		if got := accountHasAccess(c.email); got != c.want {
			t.Errorf("accountHasAccess(%s) = %v, want %v", c.email, got, c.want)
		}
	}
}
