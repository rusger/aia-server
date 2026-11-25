package main

// Apple S2S keeps the subscription window current (A203, 25.11.2026).
//
// Found on 25.11: 25 monthly/yearly accounts were 'paid' with no expiry at all, and two people who pay every
// month were shown as free. Causes, all in the S2S path:
//   - SUBSCRIBED for a transaction the client had already synced (old clients sent no expiry and no original id)
//     returned early in upsertAppleTransaction, so its signed expiresDate was dropped;
//   - DID_RENEW/EXPIRED were attributed only through original_transaction_id, which those rows lacked;
//   - DID_CHANGE_RENEWAL_PREF (UPGRADE) and other types were logged and otherwise ignored.
//
// Now every signed transaction that carries an expiresDate goes through applyAppleExpiryFromNotification:
// it backfills the original id on the matching purchase rows and moves users.subscription_expiry forward
// (an empty window takes the signed date even if it is in the past — that is what makes a lapsed account read
// as expired instead of "paid forever"). Only payment notifications with a future date may set 'paid'.

import (
	"database/sql"
	"log"
	"time"
)

// appleExpiryPayTypes may (re)grant 'paid' when they carry a future expiresDate.
var appleExpiryPayTypes = map[string]bool{
	"SUBSCRIBED": true, "DID_RENEW": true, "OFFER_REDEEMED": true, "DID_CHANGE_RENEWAL_PREF": true,
}

// appleExpirySkipTypes never write a window: a refund/revoke carries the period that was taken back.
var appleExpirySkipTypes = map[string]bool{"REFUND": true, "REVOKE": true, "TEST": true}

// backfillAppleOriginalTxn writes the original id onto this account's Apple rows for this transaction chain
// that were stored without one.
func backfillAppleOriginalTxn(email string, txn *appleTransactionInfo) {
	if email == "" || txn == nil || txn.OriginalTransactionID == "" {
		return
	}
	res, err := db.Exec(`UPDATE purchase_history SET original_transaction_id = ?
		WHERE store = 'apple' AND email = ? AND COALESCE(original_transaction_id, '') = ''
		  AND transaction_id IN (?, ?)`,
		txn.OriginalTransactionID, email, txn.TransactionID, txn.OriginalTransactionID)
	if err != nil {
		log.Printf("⚠️ [apple S2S] original id backfill failed for %s: %v", email, err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("🍎 [apple S2S] original id backfilled on %d row(s): email=%s otxn=%s", n, email, txn.OriginalTransactionID)
	}
}

// appleExpiryWindow decides the new window from a signed expiry. write=false means leave the row alone.
func appleExpiryWindow(curLength string, curExpiry sql.NullString, inLength string, in time.Time, payType bool, now time.Time) (length string, expiry time.Time, setPaid, write bool) {
	curEmpty := !curExpiry.Valid || curExpiry.String == ""
	if curLength == "lifetime" && curEmpty {
		return curLength, time.Time{}, false, false
	}
	future := in.After(now)
	if curEmpty {
		return inLength, in, payType && future, true
	}
	curT, err := parseDBTime(curExpiry.String)
	if err != nil || in.After(curT) {
		return inLength, in, payType && future, true
	}
	return curLength, curT, false, false
}

// applyAppleExpiryFromNotification is the A203 hook run for every verified S2S notification.
func applyAppleExpiryFromNotification(notificationType string, txn *appleTransactionInfo) {
	if txn == nil || appleExpirySkipTypes[notificationType] {
		return
	}
	email := appleAttributeEmail(txn)
	if email == "" {
		return
	}
	backfillAppleOriginalTxn(email, txn)
	if txn.ExpiresDate == 0 {
		return
	}
	var curLength string
	var curExpiry sql.NullString
	if err := db.QueryRow(`SELECT COALESCE(subscription_length, ''), subscription_expiry FROM users WHERE email = ?`, email).
		Scan(&curLength, &curExpiry); err != nil {
		if err != sql.ErrNoRows {
			log.Printf("⚠️ [apple S2S] window lookup failed for %s: %v", email, err)
		}
		return
	}
	in := time.UnixMilli(txn.ExpiresDate).UTC()
	length, expiry, setPaid, write := appleExpiryWindow(curLength, curExpiry, productToLength(txn.ProductID), in,
		appleExpiryPayTypes[notificationType], time.Now())
	if !write {
		return
	}
	var err error
	if setPaid {
		_, err = db.Exec(`UPDATE users SET subscription_type = 'paid', subscription_length = ?, subscription_expiry = ?,
			last_payment_method = 'apple', updated_at = CURRENT_TIMESTAMP WHERE email = ?`, length, expiry, email)
	} else {
		_, err = db.Exec(`UPDATE users SET subscription_length = ?, subscription_expiry = ?,
			updated_at = CURRENT_TIMESTAMP WHERE email = ?`, length, expiry, email)
	}
	if err != nil {
		log.Printf("⚠️ [apple S2S] window update (%s) failed for %s: %v", notificationType, email, err)
		return
	}
	log.Printf("🍎 [apple S2S] window from %s: email=%s until=%v paid=%v", notificationType, email, expiry, setPaid)
}
