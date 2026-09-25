package main

// Pins recordPurchase's side-effect rule (2026-09-25): the first-purchase
// effects follow the TRANSACTION, not the purchase_history row. The unique
// index is per (email, txn, store), so a restore onto a new account inserts a
// row — that used to fire purchase_completed, the welcome email and the
// referral reward for a receipt bought weeks earlier.

import "testing"

func TestRecordPurchaseEffects(t *testing.T) {
	cases := []struct {
		name     string
		inserted bool
		prior    priorPurchaseKinds
		want     purchaseEffects
	}{
		{"same account re-confirms: nothing", false, priorPurchaseKinds{}, purchaseEffects{}},
		{"nothing inserted even if unknown elsewhere: nothing", false, priorPurchaseKinds{placeholder: true}, purchaseEffects{}},
		{"brand new transaction: event + welcome", true, priorPurchaseKinds{}, purchaseEffects{funnelEvent: true, firstPurchase: true}},
		{"known under another real email: restore, nothing", true, priorPurchaseKinds{realEmail: true}, purchaseEffects{}},
		{"real email wins over placeholder", true, priorPurchaseKinds{realEmail: true, placeholder: true}, purchaseEffects{}},
		{"S2S placeholder got there first: welcome only", true, priorPurchaseKinds{placeholder: true}, purchaseEffects{firstPurchase: true}},
		{"bought under the device account, now logged in: welcome only", true, priorPurchaseKinds{deviceEmail: true}, purchaseEffects{firstPurchase: true}},
		{"placeholder and device account: welcome only", true, priorPurchaseKinds{placeholder: true, deviceEmail: true}, purchaseEffects{firstPurchase: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := recordPurchaseEffects(c.inserted, c.prior); got != c.want {
				t.Fatalf("effects = %+v, want %+v", got, c.want)
			}
		})
	}
}
