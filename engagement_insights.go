package main

// Engagement insights dashboard (owner request 2026-08-28, overnight task):
// one admin-gated HTML page answering four product questions from the data
// the app already collects —
//   1. насколько нравится  → pulse: DAU/WAU/MAU, new devices, retention D7/D30
//   2. что обожают         → screens by depth×reach, AI features, psy lenses
//   3. что скучно          → shallow screens, one-and-done features
//   4. где теряется интерес / точки роста → churn exits, friction, purchase
//      funnel, share signals, hidden gems
//
// GET /api/admin/engagement-insights?admin_email=…&admin_secret=…&days=30
// Sources: analytics.db (analytics_events, api_calls) + users.db (screen_time).
// Plain HTML tables, no JS — meant to be opened in a browser and read top to
// bottom like a report.

import (
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
)

type insightRow struct {
	cells []string
}

func insightsQuery(dbKind string, query string, args ...interface{}) ([]insightRow, error) {
	conn := db
	if dbKind == "analytics" {
		conn = analyticsDB
	}
	rows, err := conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []insightRow
	for rows.Next() {
		raw := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := insightRow{}
		for _, v := range raw {
			switch t := v.(type) {
			case nil:
				r.cells = append(r.cells, "—")
			case []byte:
				r.cells = append(r.cells, string(t))
			case float64:
				r.cells = append(r.cells, strconv.FormatFloat(t, 'f', 1, 64))
			default:
				r.cells = append(r.cells, fmt.Sprintf("%v", t))
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func insightsTable(sb *strings.Builder, title, note string, headers []string, rows []insightRow, err error) {
	sb.WriteString("<h3>" + html.EscapeString(title) + "</h3>")
	if note != "" {
		sb.WriteString("<p class=note>" + html.EscapeString(note) + "</p>")
	}
	if err != nil {
		sb.WriteString("<p class=err>query error: " + html.EscapeString(err.Error()) + "</p>")
		return
	}
	if len(rows) == 0 {
		sb.WriteString("<p class=note>нет данных</p>")
		return
	}
	sb.WriteString("<table><tr>")
	for _, h := range headers {
		sb.WriteString("<th>" + html.EscapeString(h) + "</th>")
	}
	sb.WriteString("</tr>")
	for _, r := range rows {
		sb.WriteString("<tr>")
		for _, c := range r.cells {
			sb.WriteString("<td>" + html.EscapeString(c) + "</td>")
		}
		sb.WriteString("</tr>")
	}
	sb.WriteString("</table>")
}

func adminEngagementInsights(w http.ResponseWriter, r *http.Request) {
	adminEmail := r.URL.Query().Get("admin_email")
	adminSecret := r.URL.Query().Get("admin_secret")
	if !isAdminEmail(adminEmail) || ADMIN_SECRET_KEY == "" || adminSecret != ADMIN_SECRET_KEY {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":false,"error":"Unauthorized"}`)
		return
	}

	days := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v > 0 && v <= 365 {
		days = v
	}
	win := fmt.Sprintf("-%d days", days)

	sb := &strings.Builder{}
	sb.WriteString(`<!doctype html><meta charset="utf-8"><title>Engagement Insights</title><style>
body{font-family:-apple-system,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#222}
h2{border-bottom:2px solid #444;padding-bottom:4px;margin-top:36px}
h3{margin:20px 0 4px}
table{border-collapse:collapse;margin:8px 0;width:100%}
th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:13px}
th{background:#f2f2f2}
tr:nth-child(even){background:#fafafa}
.note{color:#666;font-size:12px;margin:2px 0}
.err{color:#b00}
</style>`)
	fmt.Fprintf(sb, "<h1>Engagement Insights</h1><p class=note>окно «последние %d дней» там, где указано; остальное — за всю историю</p>", days)

	// ── 1. Пульс ────────────────────────────────────────────────────────
	sb.WriteString("<h2>1. Пульс — насколько приложением живут</h2>")
	rows, err := insightsQuery("analytics", `
		SELECT
		  (SELECT COUNT(DISTINCT device_id) FROM analytics_events)                                               AS devices_ever,
		  (SELECT COUNT(DISTINCT device_id) FROM analytics_events WHERE created_at >= datetime('now','-1 day'))  AS dau,
		  (SELECT COUNT(DISTINCT device_id) FROM analytics_events WHERE created_at >= datetime('now','-7 days')) AS wau,
		  (SELECT COUNT(DISTINCT device_id) FROM analytics_events WHERE created_at >= datetime('now','-30 days'))AS mau,
		  (SELECT COUNT(*) FROM (SELECT device_id, MIN(created_at) fs FROM analytics_events GROUP BY 1
		                         HAVING fs >= datetime('now', ?)))                                               AS new_devices_window`, win)
	insightsTable(sb, "Аудитория", "sticky-метрика: WAU/MAU выше ~0.5 — живое ядро", []string{"устройств всего", "DAU", "WAU", "MAU", "новых за окно"}, rows, err)

	rows, err = insightsQuery("analytics", `
		WITH firsts AS (SELECT device_id, MIN(created_at) fs FROM analytics_events GROUP BY 1),
		cohort AS (SELECT * FROM firsts WHERE fs <= datetime('now','-30 days'))
		SELECT COUNT(*)                                            AS cohort_size,
		  SUM(EXISTS(SELECT 1 FROM analytics_events e WHERE e.device_id=cohort.device_id
		       AND e.created_at BETWEEN datetime(fs,'+1 day') AND datetime(fs,'+7 days')))  AS returned_d7,
		  SUM(EXISTS(SELECT 1 FROM analytics_events e WHERE e.device_id=cohort.device_id
		       AND e.created_at BETWEEN datetime(fs,'+7 day') AND datetime(fs,'+30 days'))) AS returned_d30
		FROM cohort`)
	insightsTable(sb, "Возвращаемость (устройства старше 30 дней)", "returned_d7 = вернулись в дни 1–7 после первого запуска; d30 = в дни 7–30", []string{"когорта", "вернулись до D7", "вернулись до D30"}, rows, err)

	// ── 2. Что обожают ─────────────────────────────────────────────────
	sb.WriteString("<h2>2. Что обожают</h2>")
	rows, err = insightsQuery("users", `
		SELECT screen_key, COUNT(DISTINCT device_id) devs,
		       CAST(SUM(total_seconds)/3600.0 AS REAL) hours,
		       CAST(SUM(total_seconds)*1.0/COUNT(DISTINCT device_id)/60.0 AS REAL) min_per_dev
		FROM screen_time GROUP BY 1 ORDER BY SUM(total_seconds) DESC LIMIT 15`)
	insightsTable(sb, "Экраны по суммарному времени", "любовь = и охват (devs), и глубина (мин/устройство) высокие", []string{"экран", "устройств", "часов всего", "мин/устройство"}, rows, err)

	rows, err = insightsQuery("analytics", `
		SELECT call_type, COUNT(DISTINCT device_id) devs, COUNT(*) calls,
		       CAST(COUNT(*)*1.0/COUNT(DISTINCT device_id) AS REAL) calls_per_dev
		FROM api_calls WHERE created_at >= datetime('now', ?)
		  AND call_type NOT IN ('astrolog','transit-year','transit-multi-year')
		GROUP BY 1 ORDER BY devs DESC LIMIT 12`, win)
	insightsTable(sb, "ИИ-фичи за окно", "служебные расчётные вызовы (astrolog/transit-year) исключены; barnum_*/grounding_* — наши перепроверки, не действия юзера", []string{"call_type", "устройств", "вызовов", "вызовов/устройство"}, rows, err)

	rows, err = insightsQuery("analytics", `
		SELECT COALESCE(json_extract(properties,'$.approach_id'),'?') lens,
		       COUNT(*) req, COUNT(DISTINCT device_id) devs
		FROM analytics_events WHERE event_name='psychology_requested'
		GROUP BY 1 ORDER BY req DESC LIMIT 20`)
	insightsTable(sb, "Психо-линзы по популярности", "", []string{"линза", "запросов", "устройств"}, rows, err)

	rows, err = insightsQuery("analytics", `
		SELECT COALESCE(json_extract(properties,'$.type'),'?') t, COUNT(*) req, COUNT(DISTINCT device_id) devs
		FROM analytics_events WHERE event_name='horoscope_requested'
		GROUP BY 1 ORDER BY req DESC LIMIT 10`)
	insightsTable(sb, "Гороскопы по типам", "", []string{"тип", "запросов", "устройств"}, rows, err)

	// ── 3. Что скучно ──────────────────────────────────────────────────
	sb.WriteString("<h2>3. Что скучно</h2>")
	rows, err = insightsQuery("users", `
		SELECT screen_key, COUNT(DISTINCT device_id) devs,
		       CAST(SUM(total_seconds)*1.0/COUNT(DISTINCT device_id) AS REAL) sec_per_dev
		FROM screen_time GROUP BY 1 HAVING devs >= 20
		ORDER BY sec_per_dev ASC LIMIT 12`)
	insightsTable(sb, "Мелкие экраны: открывают, но не задерживаются", "охват ≥20 устройств, отсортировано по секундам на устройство (меньше = скучнее)", []string{"экран", "устройств", "сек/устройство"}, rows, err)

	rows, err = insightsQuery("analytics", `
		WITH per_dev AS (SELECT call_type, device_id, COUNT(*) n FROM api_calls
		    WHERE call_type IN ('chatgpt','external_check') OR call_type LIKE '%_requested' GROUP BY 1,2)
		SELECT call_type, COUNT(*) users,
		       SUM(CASE WHEN n=1 THEN 1 ELSE 0 END) one_and_done,
		       CAST(100.0*SUM(CASE WHEN n=1 THEN 1 ELSE 0 END)/COUNT(*) AS REAL) pct
		FROM per_dev GROUP BY 1 ORDER BY users DESC LIMIT 10`)
	insightsTable(sb, "Попробовали один раз и бросили", "высокий % = фича не зацепила после первой пробы", []string{"фича", "пользователей", "один раз", "%"}, rows, err)

	// ── 4. Где теряется интерес ────────────────────────────────────────
	sb.WriteString("<h2>4. Где теряется интерес</h2>")
	rows, err = insightsQuery("analytics", `
		SELECT
		  (SELECT COUNT(DISTINCT device_id) FROM analytics_events) total,
		  (SELECT COUNT(*) FROM (SELECT device_id, MAX(created_at) mx FROM analytics_events GROUP BY 1
		     HAVING mx < datetime('now','-14 days'))) churned`)
	insightsTable(sb, "Отвал", "churned = ни одного события 14+ дней", []string{"устройств всего", "молчат 14+ дней"}, rows, err)

	rows, err = insightsQuery("analytics", `
		WITH last_meaningful AS (
		  SELECT device_id, MAX(created_at) mx FROM analytics_events
		  WHERE event_type != 'session' GROUP BY device_id),
		churned AS (
		  SELECT lm.device_id, lm.mx FROM last_meaningful lm
		  JOIN (SELECT device_id, MAX(created_at) allmx FROM analytics_events GROUP BY 1) t
		    ON t.device_id = lm.device_id
		  WHERE t.allmx < datetime('now','-14 days'))
		SELECT e.event_name, COUNT(DISTINCT e.device_id) n FROM analytics_events e
		JOIN churned c ON c.device_id = e.device_id AND c.mx = e.created_at
		WHERE e.event_type != 'session'
		GROUP BY 1 ORDER BY n DESC LIMIT 12`)
	insightsTable(sb, "Последнее осмысленное действие ушедших", "на чём именно людей потеряли (session-события исключены)", []string{"последнее событие", "устройств"}, rows, err)

	rows, err = insightsQuery("analytics", `
		SELECT event_name, COUNT(*) n, COUNT(DISTINCT device_id) devs
		FROM analytics_events
		WHERE event_name IN ('rate_limit_hit','feature_locked','upgrade_dismissed','error_shown')
		  AND created_at >= datetime('now', ?)
		GROUP BY 1 ORDER BY n DESC`, win)
	insightsTable(sb, "Трение за окно", "лимиты/замки — это и раздражение, и сигнал готовности платить", []string{"событие", "раз", "устройств"}, rows, err)

	// ── 5. Точки роста ─────────────────────────────────────────────────
	sb.WriteString("<h2>5. Точки роста</h2>")
	rows, err = insightsQuery("analytics", `
		SELECT event_name, COUNT(*) n, COUNT(DISTINCT device_id) devs FROM analytics_events
		WHERE event_name IN ('upgrade_screen_shown','upgrade_clicked','purchase_screen_shown',
		  'purchase_button_tapped','purchase_plan_selected','purchase_completed','purchase_cancelled','purchase_failed')
		GROUP BY 1
		ORDER BY CASE event_name
		  WHEN 'upgrade_screen_shown' THEN 1 WHEN 'upgrade_clicked' THEN 2
		  WHEN 'purchase_screen_shown' THEN 3 WHEN 'purchase_button_tapped' THEN 4
		  WHEN 'purchase_plan_selected' THEN 5 WHEN 'purchase_completed' THEN 6
		  WHEN 'purchase_cancelled' THEN 7 ELSE 8 END`)
	insightsTable(sb, "Воронка покупки (вся история)", "каждый разрыв между шагами = конкретное место для роста конверсии", []string{"шаг", "раз", "устройств"}, rows, err)

	rows, err = insightsQuery("analytics", `
		SELECT COALESCE(json_extract(properties,'$.screen'),'?') s, COUNT(*) n
		FROM analytics_events WHERE event_name='share_clicked'
		GROUP BY 1 ORDER BY n DESC LIMIT 10`)
	insightsTable(sb, "Чем делятся", "органический рост: то, чем гордятся — усиливать и упрощать шаринг", []string{"экран", "шарингов"}, rows, err)

	rows, err = insightsQuery("users", `
		SELECT screen_key, COUNT(DISTINCT device_id) devs,
		       CAST(SUM(total_seconds)*1.0/COUNT(DISTINCT device_id)/60.0 AS REAL) min_per_dev
		FROM screen_time GROUP BY 1
		HAVING devs BETWEEN 5 AND 100 AND min_per_dev >= 10
		ORDER BY min_per_dev DESC LIMIT 10`)
	insightsTable(sb, "Скрытые жемчужины", "малый охват (5–100 устройств), но нашедшие сидят по 10+ минут — кандидаты на продвижение внутри приложения", []string{"экран", "устройств", "мин/устройство"}, rows, err)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sb.String()))
}
