package main

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// A203 test DB: users + purchase_history (same shape as the purchase handler tests) + apple_notifications.
func setupAppleExpiryDB(t *testing.T) {
	t.Helper()
	setupPurchaseHandlerDB(t)
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE apple_notifications (id INTEGER PRIMARY KEY AUTOINCREMENT,
		notification_type TEXT, subtype TEXT, environment TEXT, transaction_id TEXT, original_transaction_id TEXT,
		product_id TEXT, created_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
}

func userWindow(t *testing.T, email string) (typ string, expiry sql.NullString) {
	t.Helper()
	if err := db.QueryRow(`SELECT subscription_type, subscription_expiry FROM users WHERE email=?`, email).
		Scan(&typ, &expiry); err != nil {
		t.Fatal(err)
	}
	return
}

func TestAppleExpiryWindow(t *testing.T) {
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	past, future := now.AddDate(0, -2, 0), now.AddDate(0, 1, 0)
	none := sql.NullString{}
	cur := func(tm time.Time) sql.NullString {
		return sql.NullString{String: tm.Format("2006-01-02 15:04:05"), Valid: true}
	}
	cases := []struct {
		name               string
		curLen             string
		curExp             sql.NullString
		in                 time.Time
		pay, wPaid, wWrite bool
	}{
		{"lifetime without expiry is never touched", "lifetime", none, future, true, false, false},
		{"empty window takes a past signed date, no paid", "monthly", none, past, false, false, true},
		{"empty window + payment in the future → paid", "monthly", none, future, true, true, true},
		{"empty window + non-payment future date → date only", "monthly", none, future, false, false, true},
		{"later renewal advances and re-opens", "monthly", cur(past), future, true, true, true},
		{"older date never moves the window back", "monthly", cur(future), past, true, false, false},
	}
	for _, c := range cases {
		_, _, paid, write := appleExpiryWindow(c.curLen, c.curExp, "monthly", c.in, c.pay, now)
		if paid != c.wPaid || write != c.wWrite {
			t.Errorf("%s: paid=%v write=%v, want %v %v", c.name, paid, write, c.wPaid, c.wWrite)
		}
	}
}

// The 25.11 case: the client synced renewal txn R2 with no original id; Apple's chain is O1.
// EXPIRED (txn R2) must now reach the account and give it a real (past) expiry; a later DID_RENEW
// (txn R3, original O1) must attribute through the backfilled original id and re-open the account.
func TestApplyAppleExpiryAttributesThroughTransactionID(t *testing.T) {
	setupAppleExpiryDB(t)
	if _, err := db.Exec(`UPDATE users SET subscription_type='paid', subscription_length='monthly' WHERE email='buyer@test';
		INSERT INTO purchase_history (email, store, transaction_id, original_transaction_id) VALUES ('buyer@test','apple','R2','')`); err != nil {
		t.Fatal(err)
	}
	past := time.Now().AddDate(0, -1, 0)
	applyAppleExpiryFromNotification("EXPIRED", &appleTransactionInfo{
		TransactionID: "R2", OriginalTransactionID: "O1", ProductID: "astrolytix_pro_monthly_v2", ExpiresDate: past.UnixMilli()})

	var orig string
	db.QueryRow(`SELECT original_transaction_id FROM purchase_history WHERE transaction_id='R2'`).Scan(&orig)
	if orig != "O1" {
		t.Fatalf("original id not backfilled: %q", orig)
	}
	typ, exp := userWindow(t, "buyer@test")
	if !exp.Valid || exp.String == "" {
		t.Fatalf("EXPIRED did not write the signed expiry (type=%s)", typ)
	}
	if entitlementNotExpired(exp) {
		t.Fatalf("account still entitled after EXPIRED: %q", exp.String)
	}

	future := time.Now().AddDate(0, 1, 0)
	if _, err := db.Exec(`UPDATE users SET subscription_type='free' WHERE email='buyer@test'`); err != nil {
		t.Fatal(err)
	}
	applyAppleExpiryFromNotification("DID_RENEW", &appleTransactionInfo{
		TransactionID: "R3", OriginalTransactionID: "O1", ProductID: "astrolytix_pro_monthly_v2", ExpiresDate: future.UnixMilli()})
	typ, exp = userWindow(t, "buyer@test")
	if typ != "paid" || !entitlementNotExpired(exp) {
		t.Fatalf("renewal did not re-open the payer: type=%s expiry=%q", typ, exp.String)
	}
}

func TestApplyAppleExpirySkipsRefundAndUnknownAccounts(t *testing.T) {
	setupAppleExpiryDB(t)
	if _, err := db.Exec(`INSERT INTO purchase_history (email, store, transaction_id, original_transaction_id)
		VALUES ('buyer@test','apple','T1','T1')`); err != nil {
		t.Fatal(err)
	}
	future := time.Now().AddDate(0, 1, 0).UnixMilli()
	applyAppleExpiryFromNotification("REFUND", &appleTransactionInfo{TransactionID: "T1", OriginalTransactionID: "T1", ExpiresDate: future})
	if typ, exp := userWindow(t, "buyer@test"); typ != "free" || exp.Valid {
		t.Fatalf("REFUND wrote a window: %s %q", typ, exp.String)
	}
	applyAppleExpiryFromNotification("DID_RENEW", &appleTransactionInfo{TransactionID: "X9", OriginalTransactionID: "X0", ExpiresDate: future})
	if typ, _ := userWindow(t, "buyer@test"); typ != "free" {
		t.Fatalf("unattributed renewal changed an unrelated account: %s", typ)
	}
}

func TestExpiryRepairWrite(t *testing.T) {
	now := time.Now()
	if w, p := expiryRepairWrite("missing_expiry", 2, now.AddDate(0, -1, 0), now); !w || p {
		t.Fatalf("missing expiry must take the signed past date without paid: %v %v", w, p)
	}
	if w, p := expiryRepairWrite("lapsed_renewed", 1, now.AddDate(0, 1, 0), now); !w || !p {
		t.Fatalf("active payer must be re-opened: %v %v", w, p)
	}
	for _, st := range []int{2, 3, 4, 5} {
		if w, _ := expiryRepairWrite("lapsed_renewed", st, now.AddDate(0, 1, 0), now); w {
			t.Fatalf("status %d re-opened a lapsed account", st)
		}
	}
	if w, _ := expiryRepairWrite("lapsed_renewed", 1, now.AddDate(0, -1, 0), now); w {
		t.Fatal("active status with a past date re-opened a lapsed account")
	}
}

func TestAccountsLapsedButRenewed(t *testing.T) {
	setupAppleExpiryDB(t)
	if _, err := db.Exec(`
		INSERT INTO users (email, subscription_type, subscription_length, subscription_expiry) VALUES
			('payer@t','free','monthly','2026-09-15 06:27:11 +0000 UTC'),
			('ended@t','paid','monthly','2026-09-15 06:27:11 +0000 UTC'),
			('sandbox@t','free','monthly','2026-09-15 06:27:11 +0000 UTC'),
			('legacy@t','free','monthly','2026-09-15 06:27:11 +0000 UTC'),
			('emptyid@t','free','monthly','2026-09-15 06:27:11 +0000 UTC');
		INSERT INTO purchase_history (email, store, transaction_id, original_transaction_id) VALUES
			('payer@t','apple','P1',''), ('ended@t','apple','E1','E1'), ('sandbox@t','apple','S1','S1'),
			('legacy@t','apple','L1','L1'), ('emptyid@t','apple','','');
		INSERT INTO apple_notifications (notification_type, environment, transaction_id, original_transaction_id, created_at) VALUES
			('DID_RENEW','Production','P5','P1','2026-11-16 20:25:22'),
			('DID_RENEW','Production','E2','E1','2026-10-01 00:00:00'),
			('EXPIRED','Production','E2','E1','2026-11-01 00:00:00'),
			('DID_RENEW','Sandbox','S2','S1','2026-11-16 00:00:00'),
			('DID_RENEW',NULL,'L2','L1','2026-11-16 00:00:00'),
			('DID_RENEW','Production','','','2026-11-16 00:00:00');`); err != nil {
		t.Fatal(err)
	}
	got, err := accountsLapsedButRenewed()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]expiryRepair{}
	for _, r := range got {
		by[r.Email] = r
	}
	if len(by) != 2 || by["payer@t"].OrigTxn != "P1" || by["payer@t"].Kind != "lapsed_renewed" || by["legacy@t"].OrigTxn != "L1" {
		t.Fatalf("candidates = %+v, want payer@t via P1 and legacy@t (NULL environment = production) via L1", got)
	}
}

// Fail closed: a Google claim without a purchase token used to grant paid with the client's own expiry.
func TestRecordPurchaseRefusesGoogleWithoutToken(t *testing.T) {
	setupPurchaseHandlerDB(t)
	rec := callRecordPurchase(t, map[string]interface{}{
		"product_id":        "astrolytix_pro_monthly_v2",
		"store":             "google",
		"subscription_type": "paid",
		"transaction_id":    "GPA.0000",
		"expiry_date":       time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
	})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "verification failed") {
		t.Fatalf("status %d body %s, want 400 verification failed", rec.Code, rec.Body.String())
	}
	if got := userSubscriptionType(t, "buyer@test"); got != "free" {
		t.Fatalf("tokenless Google claim granted %s", got)
	}
}
