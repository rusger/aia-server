package main

import (
	"strings"
	"testing"
	"time"
)

func TestAppBuildOf(t *testing.T) {
	for in, want := range map[string]int{"2.1.30+174": 174, "2.1.31+175": 175, "2.1.30": 0, "": 0, "server": 0, "1+x": 0} {
		if got := appBuildOf(in); got != want {
			t.Errorf("appBuildOf(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestFixedAnswerPushText(t *testing.T) {
	d := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	cases := []struct{ lang, feature, want string }{
		{"ru", "astrologer_chat", "Ответ в чате с астрологом от 23 ноября оборвался. Исправили — теперь он полный."},
		{"ru", "natal_interpretation", "Ответ в разделе «Ваше описание» от 23 ноября оборвался. Исправили — теперь он полный."},
		{"en", "ashtakavarga", "Your answer in Ashtakavarga from Nov 23 was cut off. Fixed — it's complete now."},
		{"zh", "astrologer_chat", "11月23日「与占星师聊天」中的回答被截断了。已修复，现在是完整的。"},
		{"zh_Hant", "natal_interpretation", "11月23日「您的描述」中的回答被截断了。已修复，现在是完整的。"},
		{"ar", "natal_interpretation", "انقطع الرد في قسم «وصفك» بتاريخ 23 نوفمبر. تم الإصلاح، وهو الآن كامل."},
		{"de", "astrologer_chat", "Your answer in Chat with Astrologer from Nov 23 was cut off. Fixed — it's complete now."},
	}
	for _, c := range cases {
		got, _, ok := fixedAnswerPushText(c.lang, c.feature, d)
		if !ok || got != c.want {
			t.Errorf("%s/%s = %q (ok=%v), want %q", c.lang, c.feature, got, ok, c.want)
		}
	}
	if _, _, ok := fixedAnswerPushText("ru", "guru_chat", d); ok {
		t.Error("a feature without a section name must not get a text")
	}
}

func setupFixedAnswerPush(t *testing.T) *[]string {
	t.Helper()
	openFixedAnswerTestDBs(t)
	for _, q := range []string{
		`DROP TABLE devices`,
		`CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, device_id TEXT, platform TEXT,
			revoked INTEGER DEFAULT 0, push_token TEXT, language TEXT, app_language TEXT, tz_offset_minutes INTEGER)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := analyticsDB.Exec(`CREATE TABLE analytics_events (id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id TEXT, app_version TEXT, created_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	var sent []string
	prev := fixedAnswerSend
	fixedAnswerSend = func(platform, token, title, body, payload, lang string, ttl time.Duration) error {
		sent = append(sent, token+"|"+body+"|"+payload+"|"+lang)
		return nil
	}
	t.Cleanup(func() { fixedAnswerSend = prev })
	return &sent
}

func addPushRow(t *testing.T, id, dev, feature, at string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO fixed_answers (answer_id, device_id, feature, language, answered_at, mode, created_at)
		VALUES (?, ?, ?, 'zh', ?, 'replace', 0)`, id, dev, feature, at); err != nil {
		t.Fatal(err)
	}
}

func TestPushDueFixedAnswers(t *testing.T) {
	sent := setupFixedAnswerPush(t)
	now := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	// dev-new: on 175 (ru, UTC+3: 23.11 22:30 UTC is 24.11 locally); dev-old: still 174;
	// dev-fetched: already opened its fix; dev-none: no events at all.
	db.Exec(`INSERT INTO devices (email, device_id, platform, push_token, language, app_language, tz_offset_minutes)
		VALUES ('', 'dev-new', 'iOS', 'tok-new', 'ru', 'ru', 180), ('', 'dev-old', 'iOS', 'tok-old', 'zh', 'zh', 480),
		       ('', 'dev-fetched', 'iOS', 'tok-f', 'en', 'en', 0), ('', 'dev-none', 'iOS', 'tok-n', 'en', 'en', 0)`)
	analyticsDB.Exec(`INSERT INTO analytics_events (device_id, app_version, created_at) VALUES
		('dev-new', '2.1.30+174', '2026-11-30 10:00:00'), ('dev-new', '2.1.31+175', '2026-12-01 09:00:00'),
		('dev-new', 'server', '2026-12-01 09:30:00'),
		('dev-old', '2.1.30+174', '2026-12-01 09:00:00'), ('dev-fetched', '2.1.31+175', '2026-12-01 09:00:00')`)
	addPushRow(t, "ans-new-0001", "dev-new", "astrologer_chat", "2026-11-23 22:30:00")
	addPushRow(t, "ans-old-0001", "dev-old", "natal_interpretation", "2026-11-21 07:13:05")
	addPushRow(t, "ans-fet-0001", "dev-fetched", "ashtakavarga", "2026-11-24 07:00:00")
	addPushRow(t, "ans-non-0001", "dev-none", "ashtakavarga", "2026-11-24 07:00:00")
	db.Exec(`UPDATE fixed_answers SET fetched_at = 1 WHERE answer_id = 'ans-fet-0001'`)

	// Dry run: one would go, nothing sent, nothing marked.
	n, err := pushDueFixedAnswers(fixedAnswerMinBuild, true, now)
	if err != nil || n != 1 || len(*sent) != 0 {
		t.Fatalf("dry run: n=%d err=%v sent=%v", n, err, *sent)
	}
	var marked int
	db.QueryRow(`SELECT COUNT(*) FROM fixed_answers WHERE pushed_at IS NOT NULL`).Scan(&marked)
	if marked != 0 {
		t.Fatalf("dry run marked %d rows", marked)
	}

	// Real run: only dev-new, local date 24 ноября, payload fix:<id>, result logged.
	n, err = pushDueFixedAnswers(fixedAnswerMinBuild, false, now)
	if err != nil || n != 1 || len(*sent) != 1 {
		t.Fatalf("run: n=%d err=%v sent=%v", n, err, *sent)
	}
	want := "tok-new|Ответ в чате с астрологом от 24 ноября оборвался. Исправили — теперь он полный.|fix:ans-new-0001|ru"
	if (*sent)[0] != want {
		t.Fatalf("sent %q, want %q", (*sent)[0], want)
	}
	var pushedAt int64
	var text, result string
	if err := db.QueryRow(`SELECT pushed_at, push_text, push_result FROM fixed_answers WHERE answer_id = 'ans-new-0001'`).
		Scan(&pushedAt, &text, &result); err != nil {
		t.Fatal(err)
	}
	if pushedAt != now.Unix() || !strings.HasPrefix(text, "Ответ в чате") || result != "iOS: ok" {
		t.Fatalf("row after send: pushed_at=%d text=%q result=%q", pushedAt, text, result)
	}

	// One attempt per row: a second run sends nothing.
	if n, err := pushDueFixedAnswers(fixedAnswerMinBuild, false, now); err != nil || n != 0 || len(*sent) != 1 {
		t.Fatalf("second run: n=%d err=%v sent=%v", n, err, *sent)
	}
}

func TestPushDueFixedAnswersSendFailureIsFinal(t *testing.T) {
	sent := setupFixedAnswerPush(t)
	fixedAnswerSend = func(platform, token, title, body, payload, lang string, ttl time.Duration) error {
		*sent = append(*sent, token)
		return errTestAPNs
	}
	now := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	db.Exec(`INSERT INTO devices (email, device_id, platform, push_token, language) VALUES ('', 'dev-a', 'iOS', 'tok-a', 'en')`)
	analyticsDB.Exec(`INSERT INTO analytics_events (device_id, app_version, created_at) VALUES ('dev-a', '2.1.31+175', '2026-12-01 09:00:00')`)
	addPushRow(t, "ans-a-000001", "dev-a", "ashtakavarga", "2026-11-24 07:00:00")
	if _, err := pushDueFixedAnswers(fixedAnswerMinBuild, false, now); err != nil {
		t.Fatal(err)
	}
	var result string
	db.QueryRow(`SELECT push_result FROM fixed_answers WHERE answer_id = 'ans-a-000001'`).Scan(&result)
	if !strings.Contains(result, "BadDeviceToken") {
		t.Fatalf("result %q should keep the APNs answer", result)
	}
	if _, err := pushDueFixedAnswers(fixedAnswerMinBuild, false, now); err != nil || len(*sent) != 1 {
		t.Fatalf("failed row must not be retried: sent=%v err=%v", *sent, err)
	}
}

type testAPNsErr struct{}

func (testAPNsErr) Error() string { return "apns 400: BadDeviceToken" }

var errTestAPNs error = testAPNsErr{}
