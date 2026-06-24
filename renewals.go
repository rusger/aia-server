package main

// ---------------------------------------------------------------------------
// Subscription renewal / retention stats (the "Renewals" Stellar Vault tab)
//
// Two sources, one metric:
//   • apple_notifications  — Apple App Store Server Notifications V2
//   • google_notifications — Google Play RTDN (Cloud Pub/Sub push)
//
// Both are normalised to the same event categories so the renewal rate is
// comparable and can be summed. The response carries the COMBINED numbers at
// the top level (cycle_outcomes / subscription_states / by_plan) plus a
// by_platform split so the dashboard can show Apple vs Google vs Total.
//
// renewal_rate = renewed / (renewed + failed_to_renew + expired) for the
// billing cycles that came due in the window — the cleanest monthly rate.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// planFromProductID maps an App Store product_id / Play subscription_id to a
// coarse billing length.
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

var renewalWindows = []struct {
	Label string
	Days  int
}{{"last_7d", 7}, {"last_30d", 30}, {"last_90d", 90}, {"all_time", 0}}

// parseRenewalTS parses created_at robustly. The modernc/sqlite driver returns
// DATETIME columns as RFC3339 ("2026-06-09T05:02:15Z") even though SQLite stores
// "2026-06-09 05:02:15", so a single strict layout is not enough.
func parseRenewalTS(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	if len(s) >= 19 {
		if t, err := time.Parse("2006-01-02 15:04:05", strings.Replace(s[:19], "T", " ", 1)); err == nil {
			return t
		}
	}
	return time.Time{}
}

var cycleCats = []string{"new", "renewed", "failed", "expired", "autooff", "autoon"}

// classifyApple maps an Apple notification (type, subtype) to a normalised
// event category shared with Google.
func classifyApple(ntype, subtype string) string {
	switch ntype {
	case "SUBSCRIBED", "OFFER_REDEEMED":
		return "new"
	case "DID_RENEW":
		return "renewed"
	case "DID_FAIL_TO_RENEW":
		return "failed"
	case "EXPIRED", "GRACE_PERIOD_EXPIRED":
		return "expired"
	case "REVOKE", "REFUND":
		return "revoke"
	case "DID_CHANGE_RENEWAL_STATUS":
		if subtype == "AUTO_RENEW_DISABLED" {
			return "autooff"
		}
		if subtype == "AUTO_RENEW_ENABLED" {
			return "autoon"
		}
	}
	return "other"
}

// classifyGoogle maps a Google RTDN notification_name to the same categories.
func classifyGoogle(name, _ string) string {
	switch name {
	case "SUBSCRIPTION_PURCHASED":
		return "new"
	case "SUBSCRIPTION_RENEWED", "SUBSCRIPTION_RECOVERED", "SUBSCRIPTION_RESTARTED":
		return "renewed"
	case "SUBSCRIPTION_ON_HOLD", "SUBSCRIPTION_IN_GRACE_PERIOD":
		return "failed"
	case "SUBSCRIPTION_EXPIRED":
		return "expired"
	case "SUBSCRIPTION_REVOKED":
		return "revoke"
	case "SUBSCRIPTION_CANCELED":
		return "autooff"
	}
	return "other"
}

type subAgg struct {
	alive      bool
	autoOff    bool
	renewCount int
	plan       string
}

type renewalAgg struct {
	cycle  map[string]map[string]int // window -> category -> count
	states map[string]int
	byPlan map[string]map[string]int // plan -> {renewed,failed,expired}
	total  int
}

// computeRenewalAgg reads one source table (ordered by subscription key + time)
// and aggregates cycle outcomes, subscription states and a by-plan split.
// `query` must select: typeCol, subtypeCol, planSrcCol, subKeyCol, created_at.
func computeRenewalAgg(query string, classify func(string, string) string) renewalAgg {
	agg := renewalAgg{
		cycle:  map[string]map[string]int{},
		byPlan: map[string]map[string]int{},
	}
	for _, win := range renewalWindows {
		m := map[string]int{}
		for _, c := range cycleCats {
			m[c] = 0
		}
		agg.cycle[win.Label] = m
	}
	subs := map[string]*subAgg{}
	now := time.Now()

	rows, err := db.Query(query)
	if err != nil {
		// Table may not exist yet (e.g. no Google events ever) — return zeros.
		agg.states = map[string]int{"active": 0, "auto_renew_off": 0, "churned": 0, "total_tracked": 0, "renewed_at_least_once": 0}
		return agg
	}
	defer rows.Close()

	for rows.Next() {
		var t1, t2, planSrc, subKey, createdAt string
		if rows.Scan(&t1, &t2, &planSrc, &subKey, &createdAt) != nil {
			continue
		}
		agg.total++
		cat := classify(t1, t2)
		plan := planFromProductID(planSrc)

		ct := parseRenewalTS(createdAt)
		for _, win := range renewalWindows {
			inWindow := win.Days == 0 || (!ct.IsZero() && ct.After(now.AddDate(0, 0, -win.Days)))
			if inWindow {
				if _, ok := agg.cycle[win.Label][cat]; ok {
					agg.cycle[win.Label][cat]++
				}
			}
		}

		if cat == "renewed" || cat == "failed" || cat == "expired" {
			if agg.byPlan[plan] == nil {
				agg.byPlan[plan] = map[string]int{"renewed": 0, "failed": 0, "expired": 0}
			}
			agg.byPlan[plan][cat]++
		}

		if subKey != "" {
			s := subs[subKey]
			if s == nil {
				s = &subAgg{plan: "unknown"}
				subs[subKey] = s
			}
			if plan != "unknown" {
				s.plan = plan
			}
			switch cat {
			case "new":
				s.alive, s.autoOff = true, false
			case "renewed":
				s.alive, s.autoOff = true, false
				s.renewCount++
			case "autooff":
				s.autoOff = true
			case "autoon":
				s.autoOff = false
			case "expired", "revoke":
				s.alive = false
			}
		}
	}

	active, atRisk, churned, renewedSubs := 0, 0, 0, 0
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
	agg.states = map[string]int{
		"active": active, "auto_renew_off": atRisk, "churned": churned,
		"total_tracked": len(subs), "renewed_at_least_once": renewedSubs,
	}
	return agg
}

func combineAggs(a, b renewalAgg) renewalAgg {
	out := renewalAgg{
		cycle:  map[string]map[string]int{},
		byPlan: map[string]map[string]int{},
		states: map[string]int{},
		total:  a.total + b.total,
	}
	for _, win := range renewalWindows {
		m := map[string]int{}
		for _, c := range cycleCats {
			m[c] = a.cycle[win.Label][c] + b.cycle[win.Label][c]
		}
		out.cycle[win.Label] = m
	}
	for _, src := range []map[string]map[string]int{a.byPlan, b.byPlan} {
		for plan, m := range src {
			if out.byPlan[plan] == nil {
				out.byPlan[plan] = map[string]int{"renewed": 0, "failed": 0, "expired": 0}
			}
			for k, v := range m {
				out.byPlan[plan][k] += v
			}
		}
	}
	for _, k := range []string{"active", "auto_renew_off", "churned", "total_tracked", "renewed_at_least_once"} {
		out.states[k] = a.states[k] + b.states[k]
	}
	return out
}

func formatCycle(cycle map[string]map[string]int) map[string]interface{} {
	out := map[string]interface{}{}
	for label, c := range cycle {
		denom := c["renewed"] + c["failed"] + c["expired"]
		var rate interface{}
		if denom > 0 {
			rate = float64(c["renewed"]) / float64(denom)
		}
		out[label] = map[string]interface{}{
			"new_subscriptions":   c["new"],
			"renewed":             c["renewed"],
			"failed_to_renew":     c["failed"],
			"expired":             c["expired"],
			"auto_renew_disabled": c["autooff"],
			"auto_renew_enabled":  c["autoon"],
			"billing_cycles_due":  denom,
			"renewal_rate":        rate,
		}
	}
	return out
}

func formatPlan(byPlan map[string]map[string]int) map[string]interface{} {
	out := map[string]interface{}{}
	for plan, m := range byPlan {
		denom := m["renewed"] + m["failed"] + m["expired"]
		var rate interface{}
		if denom > 0 {
			rate = float64(m["renewed"]) / float64(denom)
		}
		out[plan] = map[string]interface{}{
			"renewed":            m["renewed"],
			"failed_to_renew":    m["failed"],
			"expired":            m["expired"],
			"billing_cycles_due": denom,
			"renewal_rate":       rate,
		}
	}
	return out
}

func formatStates(states map[string]int) map[string]interface{} {
	denom := states["renewed_at_least_once"] + states["churned"]
	var rate interface{}
	if denom > 0 {
		rate = float64(states["renewed_at_least_once"]) / float64(denom)
	}
	return map[string]interface{}{
		"active":                states["active"],
		"auto_renew_off":        states["auto_renew_off"],
		"churned":               states["churned"],
		"total_tracked":         states["total_tracked"],
		"renewed_at_least_once": states["renewed_at_least_once"],
		"lifetime_renewal_rate": rate,
	}
}

func formatPlatform(agg renewalAgg) map[string]interface{} {
	return map[string]interface{}{
		"total_events":        agg.total,
		"cycle_outcomes":      formatCycle(agg.cycle),
		"subscription_states": formatStates(agg.states),
		"by_plan":             formatPlan(agg.byPlan),
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

	// Make sure the Google table exists so its query returns zeros, not an error.
	ensureGoogleNotificationsTable()

	apple := computeRenewalAgg(
		`SELECT notification_type, COALESCE(subtype,''), COALESCE(product_id,''), COALESCE(original_transaction_id,''), created_at
		 FROM apple_notifications
		 ORDER BY original_transaction_id, created_at ASC, id ASC`,
		classifyApple,
	)
	google := computeRenewalAgg(
		`SELECT notification_name, '', COALESCE(subscription_id,''), COALESCE(purchase_token,''), created_at
		 FROM google_notifications
		 ORDER BY purchase_token, created_at ASC, id ASC`,
		classifyGoogle,
	)
	combined := combineAggs(apple, google)

	allTimeDue := combined.cycle["all_time"]["renewed"] + combined.cycle["all_time"]["failed"] + combined.cycle["all_time"]["expired"]

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":             true,
		"coverage":            "apple+google",
		"total_events":        combined.total,
		"low_confidence":      allTimeDue < 20,
		"cycle_outcomes":      formatCycle(combined.cycle),   // COMBINED (Apple+Google)
		"subscription_states": formatStates(combined.states), // COMBINED
		"by_plan":             formatPlan(combined.byPlan),   // COMBINED
		"by_platform": map[string]interface{}{
			"apple":  formatPlatform(apple),
			"google": formatPlatform(google),
		},
		"notes": []string{
			"Top-level cycle_outcomes / subscription_states / by_plan are COMBINED Apple+Google. See by_platform for the split.",
			"renewal_rate = renewed / (renewed + failed_to_renew + expired) for billing cycles that came due in the window — the cleanest monthly renewal rate.",
			"auto_renew_off = active subs with auto-renew turned off (Apple AUTO_RENEW_DISABLED, Google SUBSCRIPTION_CANCELED); expected to churn at period end.",
			"Google events arrive via Play RTDN; if google.total_events is 0, no Android events have been received yet.",
			"low_confidence=true means <20 billing cycles overall — any rate is statistically noisy.",
		},
	})
}
