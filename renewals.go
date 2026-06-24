package main

// ---------------------------------------------------------------------------
// Subscription renewal / retention stats (the "Renewals" Stellar Vault tab)
//
// Source of truth is the apple_notifications audit log in users.db, which the
// Apple App Store Server Notifications V2 webhook (POST /api/apple/notifications)
// fills in. Each row carries notification_type / subtype / original_transaction_id
// / product_id / created_at, which is everything we need to answer
// "what % of subscribers renew?" honestly.
//
// IMPORTANT — Apple only. Google Play RTDN is NOT wired up, so Android renewals
// produce no events and are invisible here. Every rate below is Apple-only; the
// response says so explicitly so the dashboard / MCP agent never overstate it.
//
// We expose three honest views instead of one hand-wavy number:
//   1. cycle_outcomes  — per time window, of the billing cycles that actually
//      came due (DID_RENEW + DID_FAIL_TO_RENEW + EXPIRED), what share renewed.
//      This is the cleanest "monthly renewal rate".
//   2. subscription_states — every distinct original_transaction_id classified
//      by its latest state: active / auto_renew_off (will churn) / churned.
//   3. by_plan — cycle outcomes split monthly vs yearly (from product_id).
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// planFromProductID maps an App Store product_id to a coarse billing length.
func planFromProductID(pid string) string {
	p := strings.ToLower(pid)
	switch {
	case strings.Contains(p, "year") || strings.Contains(p, "annual") || strings.Contains(p, "12m") || strings.Contains(p, "yr"):
		return "yearly"
	case strings.Contains(p, "month") || strings.Contains(p, "1m") || strings.Contains(p, "mo"):
		return "monthly"
	default:
		return "unknown"
	}
}

func adminRenewalStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	adminEmail := r.URL.Query().Get("admin_email")
	adminSecret := r.URL.Query().Get("admin_secret")
	if !isAdminEmail(adminEmail) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}
	if ADMIN_SECRET_KEY != "" && adminSecret != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid admin secret"})
		return
	}

	// --- 1. Per-window billing-cycle outcomes -------------------------------
	windows := []struct {
		Label string
		Days  int
	}{{"last_7d", 7}, {"last_30d", 30}, {"last_90d", 90}, {"all_time", 0}}

	cycleOutcomes := map[string]interface{}{}
	for _, win := range windows {
		clause := ""
		var winArgs []interface{}
		if win.Days > 0 {
			clause = " AND created_at >= ?"
			winArgs = append(winArgs, time.Now().AddDate(0, 0, -win.Days).Format("2006-01-02 15:04:05"))
		}
		count := func(typeClause string) int {
			var n int
			db.QueryRow("SELECT COUNT(*) FROM apple_notifications WHERE 1=1 "+typeClause+clause, winArgs...).Scan(&n)
			return n
		}
		renewed := count("AND notification_type='DID_RENEW'")
		failed := count("AND notification_type='DID_FAIL_TO_RENEW'")
		expired := count("AND notification_type='EXPIRED'")
		newSubs := count("AND notification_type IN ('SUBSCRIBED','OFFER_REDEEMED')")
		autoOff := count("AND notification_type='DID_CHANGE_RENEWAL_STATUS' AND subtype='AUTO_RENEW_DISABLED'")
		autoOn := count("AND notification_type='DID_CHANGE_RENEWAL_STATUS' AND subtype='AUTO_RENEW_ENABLED'")

		denom := renewed + failed + expired
		var rate interface{}
		if denom > 0 {
			rate = float64(renewed) / float64(denom)
		}
		cycleOutcomes[win.Label] = map[string]interface{}{
			"new_subscriptions":   newSubs,
			"renewed":             renewed,
			"failed_to_renew":     failed,
			"expired":             expired,
			"auto_renew_disabled": autoOff,
			"auto_renew_enabled":  autoOn,
			"billing_cycles_due":  denom,
			"renewal_rate":        rate, // null when no cycles came due in the window
		}
	}

	// --- 2. Subscription-level state machine (all-time) ---------------------
	// Replay every event per original_transaction_id in time order.
	type subState struct {
		alive      bool // currently entitled (last lifecycle event kept it active)
		autoOff    bool // auto-renew currently disabled -> will churn at period end
		renewCount int
		plan       string
	}
	subs := map[string]*subState{}

	rows, err := db.Query(`SELECT original_transaction_id, notification_type, COALESCE(subtype,''), COALESCE(product_id,'')
		FROM apple_notifications
		WHERE original_transaction_id IS NOT NULL AND original_transaction_id != ''
		ORDER BY original_transaction_id, created_at ASC, id ASC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var otxn, ntype, subtype, pid string
			if rows.Scan(&otxn, &ntype, &subtype, &pid) != nil {
				continue
			}
			s := subs[otxn]
			if s == nil {
				s = &subState{plan: "unknown"}
				subs[otxn] = s
			}
			if pid != "" {
				s.plan = planFromProductID(pid)
			}
			switch ntype {
			case "SUBSCRIBED", "OFFER_REDEEMED":
				s.alive = true
				s.autoOff = false
			case "DID_RENEW":
				s.alive = true
				s.autoOff = false
				s.renewCount++
			case "DID_CHANGE_RENEWAL_STATUS":
				if subtype == "AUTO_RENEW_DISABLED" {
					s.autoOff = true
				} else if subtype == "AUTO_RENEW_ENABLED" {
					s.autoOff = false
				}
			case "EXPIRED", "REVOKE", "REFUND", "GRACE_PERIOD_EXPIRED":
				s.alive = false
			}
		}
	}

	var active, atRisk, churned, renewedSubs int
	for _, s := range subs {
		if s.renewCount > 0 {
			renewedSubs++
		}
		switch {
		case !s.alive:
			churned++
		case s.autoOff:
			atRisk++
		default:
			active++
		}
	}
	// Lifetime retention proxy: of subs that reached a renewal decision
	// (renewed at least once, or churned), what share renewed.
	var lifetimeRate interface{}
	if renewedSubs+churned > 0 {
		lifetimeRate = float64(renewedSubs) / float64(renewedSubs+churned)
	}

	// --- 3. By-plan cycle outcomes (all-time) -------------------------------
	byPlan := map[string]map[string]interface{}{}
	planRows, perr := db.Query(`SELECT COALESCE(product_id,''), notification_type, COUNT(*)
		FROM apple_notifications
		WHERE notification_type IN ('DID_RENEW','DID_FAIL_TO_RENEW','EXPIRED')
		GROUP BY product_id, notification_type`)
	if perr == nil {
		defer planRows.Close()
		for planRows.Next() {
			var pid, ntype string
			var n int
			if planRows.Scan(&pid, &ntype, &n) != nil {
				continue
			}
			plan := planFromProductID(pid)
			if byPlan[plan] == nil {
				byPlan[plan] = map[string]interface{}{"renewed": 0, "failed_to_renew": 0, "expired": 0}
			}
			key := map[string]string{"DID_RENEW": "renewed", "DID_FAIL_TO_RENEW": "failed_to_renew", "EXPIRED": "expired"}[ntype]
			byPlan[plan][key] = byPlan[plan][key].(int) + n
		}
		for _, m := range byPlan {
			denom := m["renewed"].(int) + m["failed_to_renew"].(int) + m["expired"].(int)
			if denom > 0 {
				m["renewal_rate"] = float64(m["renewed"].(int)) / float64(denom)
			} else {
				m["renewal_rate"] = nil
			}
			m["billing_cycles_due"] = denom
		}
	}

	// Low-confidence flag: tiny samples make any rate noisy.
	var totalEvents int
	db.QueryRow("SELECT COUNT(*) FROM apple_notifications").Scan(&totalEvents)
	allTime := cycleOutcomes["all_time"].(map[string]interface{})
	lowConfidence := allTime["billing_cycles_due"].(int) < 20

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"source":         "apple_notifications (Apple App Store Server Notifications V2)",
		"coverage":       "apple_only",
		"total_events":   totalEvents,
		"low_confidence": lowConfidence,
		"cycle_outcomes": cycleOutcomes,
		"subscription_states": map[string]interface{}{
			"active":                active,
			"auto_renew_off":        atRisk,
			"churned":               churned,
			"total_tracked":         len(subs),
			"renewed_at_least_once": renewedSubs,
			"lifetime_renewal_rate": lifetimeRate,
		},
		"by_plan": byPlan,
		"notes": []string{
			"Apple only — Google Play RTDN is not connected, so Android renewals are not counted here.",
			"renewal_rate (cycle_outcomes) = renewed / (renewed + failed_to_renew + expired) for billing cycles that came due in the window. This is the cleanest monthly renewal rate.",
			"auto_renew_off = subscriptions still active but with auto-renew turned off; they are expected to churn at period end (leading churn indicator).",
			"lifetime_renewal_rate = renewed_at_least_once / (renewed_at_least_once + churned); a coarse cohort proxy, not a monthly rate.",
			"low_confidence=true means the sample is small (<20 billing cycles) and any rate is statistically noisy.",
		},
	})
}
