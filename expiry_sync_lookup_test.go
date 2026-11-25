package main

import (
	"database/sql"
	"testing"
)

// A203: accounts with a transaction_id but no original_transaction_id must still be looked up at Apple.
func TestAccountsMissingExpiryTxnFallback(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE users (email TEXT, subscription_type TEXT, subscription_length TEXT, subscription_expiry DATETIME)`,
		`CREATE TABLE purchase_history (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, store TEXT,
			transaction_id TEXT, original_transaction_id TEXT)`,
		`INSERT INTO users VALUES ('orig@t','paid','monthly',NULL), ('txn@t','paid','monthly',''),
			('none@t','paid','yearly',NULL), ('life@t','paid','lifetime',NULL),
			('dated@t','paid','monthly','2027-01-01 00:00:00'), ('free@t','free','monthly',NULL)`,
		`INSERT INTO purchase_history (email, store, transaction_id, original_transaction_id) VALUES
			('orig@t','apple','111','100'), ('txn@t','apple','221',''), ('txn@t','apple','222',NULL),
			('txn@t','google','999',NULL), ('none@t','apple','',NULL), ('life@t','apple','5','5'),
			('dated@t','apple','6','6')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	got, err := accountsMissingExpiry()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]expiryRepair{}
	for _, r := range got {
		by[r.Email] = r
	}
	if len(by) != 3 {
		t.Fatalf("candidates = %v, want orig@t, txn@t, none@t", got)
	}
	if r := by["orig@t"]; r.OrigTxn != "100" || r.LookupBy != "original_transaction_id" {
		t.Fatalf("orig@t: %+v", r)
	}
	if r := by["txn@t"]; r.OrigTxn != "222" || r.LookupBy != "transaction_id" {
		t.Fatalf("txn@t (latest apple transaction_id expected): %+v", r)
	}
	if r := by["none@t"]; r.OrigTxn != "" || r.LookupBy != "" {
		t.Fatalf("none@t: %+v", r)
	}
}
