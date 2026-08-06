package main

// ---------------------------------------------------------------------------
// Finance stats (the "Finance" Stellar Vault tab) — GET /api/admin/finance-stats
//
// Calendar-month P&L: subscription revenue (net of Apple/Google commission)
// vs OpenAI token spend, plus unit economics (what a paying user brings vs
// what paying and free users cost in tokens).
//
// Revenue sources, deduplicated by store transaction id:
//   • apple_notifications  — SUBSCRIBED / DID_RENEW / ONE_TIME_CHARGE add
//     revenue, REFUND / REVOKE subtract it.
//   • purchase_history     — Apple rows only, as backfill for purchases made
//     before App Store Server Notifications were connected (skipped when the
//     transaction already appears in apple_notifications).
//   • google_notifications — SUBSCRIPTION_PURCHASED / _RENEWED / _RECOVERED /
//     _RESTARTED add revenue, _REVOKED subtracts. purchase_history Google rows
//     are NOT trusted (fail-open verification let pirated purchases through);
//     rows without a matching RTDN event are only counted in data_quality.
//
// Store prices are not present in any notification we store, so revenue is
// list price (USD) × events. Override with FINANCE_PRICES='{"product_id":9.99}'.
// Commission defaults to 15% for both stores (App Store Small Business
// Program / Play Media Experience tier); override with APPLE_COMMISSION_PCT /
// GOOGLE_COMMISSION_PCT.
//
// Token spend is priced with the same per-model table as /api/admin/usage-report
// and multiplied by FINANCE_COST_CALIBRATION (default 1.0) — set it after
// reconciling a full month against the real OpenAI invoice.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Config

var (
	FINANCE_PRICES_JSON   = getEnv("FINANCE_PRICES", "")
	APPLE_COMMISSION_PCT  = getEnv("APPLE_COMMISSION_PCT", "15")
	GOOGLE_COMMISSION_PCT = getEnv("GOOGLE_COMMISSION_PCT", "15")
	// 1.014 = OpenAI July-2026 dashboard ($25.42) / internal estimate ($25.07)
	FINANCE_COST_CALIBRATION = getEnv("FINANCE_COST_CALIBRATION", "1.014")
)

// Default USD list prices per plan; product-id overrides via FINANCE_PRICES.
var financeDefaultPlanPrices = map[string]float64{
	"monthly":  4.99,
	"yearly":   49.99,
	"lifetime": 99.99,
}

func financePriceOverrides() map[string]float64 {
	out := map[string]float64{}
	if FINANCE_PRICES_JSON != "" {
		_ = json.Unmarshal([]byte(FINANCE_PRICES_JSON), &out)
	}
	return out
}

func financePctEnv(s string, def float64) float64 {
	if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && v >= 0 && v <= 100 {
		return v
	}
	return def
}

// financePlan is planFromProductID plus the lifetime bucket.
func financePlan(pid string) string {
	if strings.Contains(strings.ToLower(pid), "life") {
		return "lifetime"
	}
	return planFromProductID(pid)
}

func financePriceUSD(pid string, overrides map[string]float64) float64 {
	if p, ok := overrides[pid]; ok {
		return p
	}
	if p, ok := financeDefaultPlanPrices[financePlan(pid)]; ok {
		return p
	}
	return financeDefaultPlanPrices["monthly"]
}

// ---------------------------------------------------------------------------
// Token pricing — same table as adminUsageReport ("updated 2026-06").
// Recorded cached_tokens are trusted as-is: with them the July-2026 estimate
// landed within 1.4% of the real OpenAI invoice. The 50%-cached imputation is
// applied only where cache data never existed (api_calls_monthly rollups).

func financeTokenCostUSD(model string, promptToks, completionToks, cachedToks int64, imputeCached bool) float64 {
	if imputeCached && cachedToks == 0 && promptToks > 0 {
		cachedToks = promptToks / 2 // observed ratio from OpenAI billing data
	}
	if cachedToks > promptToks {
		cachedToks = promptToks
	}
	regF := float64(promptToks-cachedToks) / 1e6
	cacF := float64(cachedToks) / 1e6
	outF := float64(completionToks) / 1e6
	switch {
	case strings.Contains(model, "gpt-4.1-nano"):
		return regF*0.10 + cacF*0.025 + outF*0.40
	case strings.Contains(model, "gpt-4.1-mini"):
		return regF*0.40 + cacF*0.10 + outF*1.60
	case strings.Contains(model, "gpt-4.1"):
		return regF*2.00 + cacF*0.50 + outF*8.00
	case strings.Contains(model, "gpt-4o-mini"):
		return regF*0.15 + cacF*0.075 + outF*0.60
	case strings.Contains(model, "gpt-4o"):
		return regF*2.50 + cacF*1.25 + outF*10.00
	case strings.Contains(model, "o1-mini"):
		return regF*1.10 + cacF*0.55 + outF*4.40
	case strings.Contains(model, "o1"):
		return regF*15.00 + cacF*7.50 + outF*60.00
	default:
		return regF*0.40 + cacF*0.10 + outF*1.60 // gpt-4.1-mini rate
	}
}

// Overhead call types (server-side validation calls, not user-visible answers).
var financeOverheadTypes = map[string]bool{
	"grounding_fix": true, "claim_audit": true, "barnum_judge": true,
	"barnum_fix": true, "barnum_point_fix": true, "external_check": true,
	"yoga_fix": true,
}

// ---------------------------------------------------------------------------
// Per-month accumulators

type financeStoreMonth struct {
	NewPurchases int     `json:"new_purchases"`
	Renewals     int     `json:"renewals"`
	Refunds      int     `json:"refunds"`
	Gross        float64 `json:"gross_usd"`
	Fees         float64 `json:"platform_fee_usd"`
	Net          float64 `json:"net_usd"`
}

type financeMonth struct {
	apple, google financeStoreMonth
	newByPlan     map[string]int

	costRaw      float64 // uncalibrated USD
	costOverhead float64
	costPaid     float64 // spend by devices attributed to paying users
	costFree     float64
	costByModel  map[string]float64
	calls        int64
	tokens       int64

	payingDevices map[string]bool
	freeDevices   map[string]bool
}

func newFinanceMonth() *financeMonth {
	return &financeMonth{
		newByPlan:     map[string]int{},
		costByModel:   map[string]float64{},
		payingDevices: map[string]bool{},
		freeDevices:   map[string]bool{},
	}
}

func monthKey(t time.Time) string { return t.UTC().Format("2006-01") }

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// ---------------------------------------------------------------------------
// Paying-user attribution: email → paid interval, email → devices.
// An email counts as paying in month M when its first non-trial purchase is
// before the end of M and its entitlement (row expiry, current expiry in
// users, or lifetime) reaches into M.

type financePaidSpan struct {
	start, end time.Time
	lifetime   bool
}

func financeLoadPaidSpans() map[string]*financePaidSpan {
	spans := map[string]*financePaidSpan{}
	rows, err := db.Query(`SELECT email, COALESCE(created_at,''), COALESCE(expiry_date,''), subscription_length
	                       FROM purchase_history WHERE is_trial = 0`)
	if err != nil {
		return spans
	}
	defer rows.Close()
	for rows.Next() {
		var email, created, expiry, length string
		if rows.Scan(&email, &created, &expiry, &length) != nil {
			continue
		}
		start := parseRenewalTS(created)
		if start.IsZero() {
			continue
		}
		end := parseRenewalTS(expiry)
		if end.IsZero() { // no expiry recorded — assume one plan period
			switch length {
			case "yearly":
				end = start.AddDate(1, 0, 0)
			default:
				end = start.AddDate(0, 1, 0)
			}
		}
		sp, ok := spans[email]
		if !ok {
			sp = &financePaidSpan{start: start, end: end}
			spans[email] = sp
		}
		if start.Before(sp.start) {
			sp.start = start
		}
		if end.After(sp.end) {
			sp.end = end
		}
		if length == "lifetime" {
			sp.lifetime = true
		}
	}
	// Renewals only bump users.subscription_expiry, not purchase_history —
	// extend each span with the live expiry.
	urows, err := db.Query(`SELECT email, COALESCE(subscription_expiry,''), subscription_length
	                        FROM users WHERE subscription_type = 'paid'`)
	if err == nil {
		defer urows.Close()
		for urows.Next() {
			var email, expiry, length string
			if urows.Scan(&email, &expiry, &length) != nil {
				continue
			}
			sp, ok := spans[email]
			if !ok {
				continue
			}
			if length == "lifetime" {
				sp.lifetime = true
			} else if e := parseRenewalTS(expiry); !e.IsZero() && e.After(sp.end) {
				sp.end = e
			}
		}
	}
	return spans
}

func (sp *financePaidSpan) coversMonth(mStart, mEnd time.Time) bool {
	if sp == nil || sp.start.After(mEnd) {
		return false
	}
	return sp.lifetime || sp.end.After(mStart)
}

// financeDeviceEmails maps device_id → set of emails that logged in on it.
func financeDeviceEmails() map[string][]string {
	out := map[string][]string{}
	add := func(dev, email string) {
		if dev == "" || email == "" {
			return
		}
		for _, e := range out[dev] {
			if e == email {
				return
			}
		}
		out[dev] = append(out[dev], email)
	}
	rows, err := db.Query(`SELECT DISTINCT COALESCE(device_id,''), email FROM login_history`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dev, email string
			if rows.Scan(&dev, &email) == nil {
				add(dev, email)
			}
		}
	}
	crows, err := db.Query(`SELECT COALESCE(current_device_id,''), email FROM users`)
	if err == nil {
		defer crows.Close()
		for crows.Next() {
			var dev, email string
			if crows.Scan(&dev, &email) == nil {
				add(dev, email)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Handler

func adminFinanceStats(w http.ResponseWriter, r *http.Request) {
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

	monthsBack := 12
	if v, err := strconv.Atoi(r.URL.Query().Get("months")); err == nil && v > 0 && v <= 36 {
		monthsBack = v
	}

	ensureGoogleNotificationsTable()

	prices := financePriceOverrides()
	appleFee := financePctEnv(APPLE_COMMISSION_PCT, 15) / 100
	googleFee := financePctEnv(GOOGLE_COMMISSION_PCT, 15) / 100
	calibration := 1.0
	if v, err := strconv.ParseFloat(FINANCE_COST_CALIBRATION, 64); err == nil && v > 0 && v < 10 {
		calibration = v
	}

	now := time.Now().UTC()
	firstMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -(monthsBack - 1), 0)
	months := map[string]*financeMonth{}
	getMonth := func(t time.Time) *financeMonth {
		if t.Before(firstMonth) {
			return nil
		}
		k := monthKey(t)
		m, ok := months[k]
		if !ok {
			m = newFinanceMonth()
			months[k] = m
		}
		return m
	}

	// ---------------- Revenue: Apple notifications --------------------------
	appleSeenTxn := map[string]bool{} // every transaction id Apple has notified about
	arows, err := db.Query(`SELECT notification_type, COALESCE(subtype,''), COALESCE(product_id,''),
	                               COALESCE(transaction_id,''), created_at
	                        FROM apple_notifications ORDER BY created_at ASC, id ASC`)
	if err == nil {
		defer arows.Close()
		for arows.Next() {
			var ntype, subtype, pid, txn, created string
			if arows.Scan(&ntype, &subtype, &pid, &txn, &created) != nil {
				continue
			}
			if txn != "" {
				appleSeenTxn[txn] = true
			}
			ts := parseRenewalTS(created)
			m := getMonth(ts)
			if m == nil {
				continue
			}
			price := financePriceUSD(pid, prices)
			_ = subtype
			switch ntype {
			case "SUBSCRIBED", "OFFER_REDEEMED", "ONE_TIME_CHARGE":
				m.apple.NewPurchases++
				m.apple.Gross += price
				m.newByPlan[financePlan(pid)]++
			case "DID_RENEW":
				m.apple.Renewals++
				m.apple.Gross += price
			case "REFUND", "REVOKE":
				m.apple.Refunds++
				m.apple.Gross -= price
			}
		}
	}

	// Apple purchase_history backfill (pre-notification era), dedup by txn id
	// against every Apple notification AND within purchase_history itself.
	phSeenTxn := map[string]bool{}
	phrows, err := db.Query(`SELECT COALESCE(product_id,''), COALESCE(transaction_id,''), created_at
	                         FROM purchase_history
	                         WHERE store = 'apple' AND is_trial = 0
	                         ORDER BY created_at ASC, id ASC`)
	appleBackfilled := 0
	if err == nil {
		defer phrows.Close()
		for phrows.Next() {
			var pid, txn, created string
			if phrows.Scan(&pid, &txn, &created) != nil {
				continue
			}
			if txn != "" && (appleSeenTxn[txn] || phSeenTxn[txn]) {
				continue
			}
			if txn != "" {
				phSeenTxn[txn] = true
			}
			ts := parseRenewalTS(created)
			m := getMonth(ts)
			if m == nil {
				continue
			}
			appleBackfilled++
			m.apple.NewPurchases++
			m.apple.Gross += financePriceUSD(pid, prices)
			m.newByPlan[financePlan(pid)]++
		}
	}

	// ---------------- Revenue: Google RTDN ----------------------------------
	googleVerifiedTokens := map[string]bool{}
	grows, err := db.Query(`SELECT COALESCE(notification_name,''), COALESCE(subscription_id,''),
	                               COALESCE(purchase_token,''), created_at
	                        FROM google_notifications ORDER BY created_at ASC, id ASC`)
	if err == nil {
		defer grows.Close()
		for grows.Next() {
			var name, pid, token, created string
			if grows.Scan(&name, &pid, &token, &created) != nil {
				continue
			}
			if token != "" {
				googleVerifiedTokens[token] = true
			}
			ts := parseRenewalTS(created)
			m := getMonth(ts)
			if m == nil {
				continue
			}
			price := financePriceUSD(pid, prices)
			switch name {
			case "SUBSCRIPTION_PURCHASED":
				m.google.NewPurchases++
				m.google.Gross += price
				m.newByPlan[financePlan(pid)]++
			case "SUBSCRIPTION_RENEWED", "SUBSCRIPTION_RECOVERED", "SUBSCRIPTION_RESTARTED":
				m.google.Renewals++
				m.google.Gross += price
			case "SUBSCRIPTION_REVOKED":
				m.google.Refunds++
				m.google.Gross -= price
			}
		}
	}

	// Google purchase_history rows without an RTDN event: likely the fail-open
	// pirated purchases — excluded from revenue, surfaced in data_quality.
	unverifiedGoogle := 0
	_ = db.QueryRow(`SELECT COUNT(*) FROM purchase_history
	                 WHERE store = 'google' AND is_trial = 0
	                   AND COALESCE(purchase_token,'') NOT IN
	                       (SELECT COALESCE(purchase_token,'') FROM google_notifications)`).Scan(&unverifiedGoogle)

	// ---------------- Costs: token usage ------------------------------------
	paidSpans := financeLoadPaidSpans()
	deviceEmails := financeDeviceEmails()

	devicePaidInMonth := func(dev, mk string) bool {
		mStart, err := time.Parse("2006-01", mk)
		if err != nil {
			return false
		}
		mEnd := mStart.AddDate(0, 1, 0)
		for _, email := range deviceEmails[dev] {
			if paidSpans[email].coversMonth(mStart, mEnd) {
				return true
			}
		}
		return false
	}

	addCost := func(mk, dev, callType, model string, prompt, completion, cached, calls int64, imputeCached bool) {
		m, ok := months[mk]
		if !ok {
			if t, err := time.Parse("2006-01", mk); err != nil || t.Before(firstMonth) {
				return
			}
			m = newFinanceMonth()
			months[mk] = m
		}
		cost := financeTokenCostUSD(model, prompt, completion, cached, imputeCached)
		m.costRaw += cost
		m.costByModel[model] += cost
		m.calls += calls
		m.tokens += prompt + completion
		if financeOverheadTypes[callType] {
			m.costOverhead += cost
		}
		if devicePaidInMonth(dev, mk) {
			m.costPaid += cost
			m.payingDevices[dev] = true
		} else {
			m.costFree += cost
			m.freeDevices[dev] = true
		}
	}

	if analyticsDB != nil {
		// Raw per-call rows (recent months). total_tokens > 0 keeps only real
		// LLM calls — astrolog/transit rows carry junk in the model column.
		crows, err := analyticsDB.Query(`SELECT strftime('%Y-%m', created_at), COALESCE(device_id,''),
		                                        COALESCE(call_type,''), COALESCE(model,''),
		                                        SUM(prompt_tokens), SUM(completion_tokens), SUM(cached_tokens), COUNT(*)
		                                 FROM api_calls WHERE total_tokens > 0
		                                 GROUP BY 1, 2, 3, 4`)
		if err == nil {
			defer crows.Close()
			for crows.Next() {
				var mk, dev, ct, model string
				var p, c, cach, n int64
				if crows.Scan(&mk, &dev, &ct, &model, &p, &c, &cach, &n) == nil {
					addCost(mk, dev, ct, model, p, c, cach, n, false)
				}
			}
		}
		// Rollup rows for months whose raw rows were already aggregated away.
		// No cached_tokens column there — financeTokenCostUSD imputes 50%.
		mrows, err := analyticsDB.Query(`SELECT year_month, COALESCE(device_id,''), COALESCE(call_type,''),
		                                        COALESCE(model,''), SUM(total_prompt_tokens),
		                                        SUM(total_completion_tokens), SUM(total_calls)
		                                 FROM api_calls_monthly WHERE total_tokens > 0
		                                 GROUP BY 1, 2, 3, 4`)
		if err == nil {
			defer mrows.Close()
			for mrows.Next() {
				var mk, dev, ct, model string
				var p, c, n int64
				if mrows.Scan(&mk, &dev, &ct, &model, &p, &c, &n) == nil {
					addCost(mk, dev, ct, model, p, c, 0, n, true)
				}
			}
		}
	}

	// ---------------- Current snapshot (MRR, active paid) -------------------
	var activeMonthly, activeYearly, activeLifetime int
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE subscription_type='paid'
	                 AND subscription_length='monthly' AND subscription_expiry > datetime('now')`).Scan(&activeMonthly)
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE subscription_type='paid'
	                 AND subscription_length='yearly' AND subscription_expiry > datetime('now')`).Scan(&activeYearly)
	_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE subscription_type='paid'
	                 AND subscription_length='lifetime'`).Scan(&activeLifetime)
	blendedFee := (appleFee + googleFee) / 2
	mrrGross := float64(activeMonthly)*financeDefaultPlanPrices["monthly"] +
		float64(activeYearly)*financeDefaultPlanPrices["yearly"]/12
	mrrNet := mrrGross * (1 - blendedFee)

	// ---------------- Assemble response -------------------------------------
	keys := make([]string, 0, len(months))
	for k := range months {
		keys = append(keys, k)
	}
	// simple ascending sort (YYYY-MM sorts lexicographically)
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	type monthOut map[string]interface{}
	out := make([]monthOut, 0, len(keys))
	cumulative := 0.0
	var totGross, totFees, totNet, totCost float64
	var totNew, totRenew, totRefund int

	for _, k := range keys {
		m := months[k]
		m.apple.Fees = round2(m.apple.Gross * appleFee)
		m.apple.Net = round2(m.apple.Gross - m.apple.Fees)
		m.apple.Gross = round2(m.apple.Gross)
		m.google.Fees = round2(m.google.Gross * googleFee)
		m.google.Net = round2(m.google.Gross - m.google.Fees)
		m.google.Gross = round2(m.google.Gross)

		gross := m.apple.Gross + m.google.Gross
		fees := m.apple.Fees + m.google.Fees
		net := m.apple.Net + m.google.Net
		cost := m.costRaw * calibration
		balance := net - cost
		cumulative += balance

		payingN := len(m.payingDevices)
		freeN := len(m.freeDevices)
		costPaid := m.costPaid * calibration
		costFree := m.costFree * calibration

		ue := map[string]interface{}{
			"paying_devices": payingN,
			"free_devices":   freeN,
		}
		if payingN > 0 {
			arppu := net / float64(payingN)
			cpp := costPaid / float64(payingN)
			ue["arppu_net_usd"] = round2(arppu)
			ue["token_cost_per_paying_user_usd"] = round2(cpp)
			ue["paying_user_margin_usd"] = round2(arppu - cpp)
			if freeN > 0 && costFree > 0 {
				cpf := costFree / float64(freeN)
				ue["token_cost_per_free_user_usd"] = round2(cpf)
				if arppu > cpp {
					ue["free_users_carried_per_paying_user"] = round2((arppu - cpp) / cpf)
				} else {
					ue["free_users_carried_per_paying_user"] = 0.0
				}
			}
		}

		byModel := map[string]float64{}
		for model, c := range m.costByModel {
			byModel[model] = round2(c * calibration)
		}

		out = append(out, monthOut{
			"month": k,
			"revenue": map[string]interface{}{
				"apple":            m.apple,
				"google":           m.google,
				"gross_usd":        round2(gross),
				"platform_fee_usd": round2(fees),
				"net_usd":          round2(net),
				"new_by_plan":      m.newByPlan,
			},
			"costs": map[string]interface{}{
				"token_cost_usd":   round2(cost),
				"uncalibrated_usd": round2(m.costRaw),
				"overhead_usd":     round2(m.costOverhead * calibration),
				"paid_users_usd":   round2(costPaid),
				"free_users_usd":   round2(costFree),
				"by_model":         byModel,
				"llm_calls":        m.calls,
				"tokens":           m.tokens,
			},
			"balance": map[string]interface{}{
				"net_usd":        round2(balance),
				"cumulative_usd": round2(cumulative),
			},
			"unit_economics": ue,
		})

		totGross += gross
		totFees += fees
		totNet += net
		totCost += cost
		totNew += m.apple.NewPurchases + m.google.NewPurchases
		totRenew += m.apple.Renewals + m.google.Renewals
		totRefund += m.apple.Refunds + m.google.Refunds
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"months":  out,
		"totals": map[string]interface{}{
			"gross_usd":        round2(totGross),
			"platform_fee_usd": round2(totFees),
			"net_usd":          round2(totNet),
			"token_cost_usd":   round2(totCost),
			"balance_usd":      round2(totNet - totCost),
			"new_purchases":    totNew,
			"renewals":         totRenew,
			"refunds":          totRefund,
		},
		"current": map[string]interface{}{
			"active_paid_monthly": activeMonthly,
			"active_paid_yearly":  activeYearly,
			"lifetime_owners":     activeLifetime,
			"mrr_gross_usd":       round2(mrrGross),
			"mrr_net_usd":         round2(mrrNet),
		},
		"config": map[string]interface{}{
			"plan_prices_usd":       financeDefaultPlanPrices,
			"price_overrides":       prices,
			"apple_commission_pct":  appleFee * 100,
			"google_commission_pct": googleFee * 100,
			"cost_calibration":      calibration,
		},
		"data_quality": map[string]interface{}{
			"apple_backfilled_purchases":  appleBackfilled,
			"unverified_google_purchases": unverifiedGoogle,
		},
		"notes": []string{
			"Revenue = USD list price × store events (stores don't send us the charged price); local-currency storefronts and store taxes make real proceeds differ slightly.",
			"Net revenue = gross − platform commission (default 15% both stores; APPLE_COMMISSION_PCT / GOOGLE_COMMISSION_PCT to override).",
			"Google revenue counts only RTDN-confirmed events; unverified_google_purchases = purchase_history rows Google never confirmed (fail-open era, likely pirated) — excluded.",
			"Apple months before server notifications were connected are backfilled from purchase_history (new purchases only — renewals from that era are invisible).",
			"Token cost = recorded tokens × per-model price table × cost_calibration (FINANCE_COST_CALIBRATION). Calibrated 2026-07-30: internal estimate $25.07 vs OpenAI dashboard $25.42 for July 2026 to date (−1.4%).",
			"paying_devices = devices whose user had an active non-trial purchase that month; free_devices = everything else with LLM calls that month.",
			"free_users_carried_per_paying_user = (ARPPU_net − token cost of a paying user) ÷ token cost of an average free user.",
		},
	})
}
