package main

// Queued `fix:` pushes for the A194 corrected answers (fixed_answers.go).
//
// The app learned to handle `fix:<answer_id>` in the release after 2.1.30
// (174): a device on an older build would get a push it cannot open. So a
// row is pushed only once its device reports a build >= fixedAnswerMinBuild
// in analytics_events, and only once (pushed_at is set before sending).
// Coordinator 25.11.2026: «Одна попытка на строку. В журнал: кому, когда,
// ответ APNs/FCM», «Cron включай только после looks-good и мержа, с dry-run».
//
// Text: the template the owner approved 24.11 23:12 («<Ответ в разделе> от
// <даты> оборвался. Исправили — теперь он полный.») and saw on his phone
// 25.11 09:18, in the device's language; section names are the app's own
// strings (lib/l10n/app_localizations.dart: your_description,
// chat_with_astrologer, ashtakavarga). Other languages get the English text.
//
//   ./astrolog_api fixed-answer-push-due [--dry-run] [--min-build N]

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// fixedAnswerMinBuild is the first build number with the `fix:` route.
const fixedAnswerMinBuild = 175

// fixedAnswerSend is sendPushToToken; a variable so tests do not reach APNs.
var fixedAnswerSend = sendPushToToken

func migrateFixedAnswerPush() {
	for _, stmt := range []string{
		`ALTER TABLE fixed_answers ADD COLUMN push_text TEXT`,
		`ALTER TABLE fixed_answers ADD COLUMN pushed_at INTEGER`,
		`ALTER TABLE fixed_answers ADD COLUMN push_result TEXT`,
	} {
		if _, err := db.Exec(stmt); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			fmt.Printf("fixed_answers push migration: %v\n", err)
		}
	}
}

// appBuildOf("2.1.30+174") → 174; 0 when there is no build number.
func appBuildOf(version string) int {
	i := strings.LastIndex(version, "+")
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(version[i+1:]))
	if err != nil {
		return 0
	}
	return n
}

var (
	ruMonthsGen = []string{"января", "февраля", "марта", "апреля", "мая", "июня",
		"июля", "августа", "сентября", "октября", "ноября", "декабря"}
	enMonthsShort = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	arMonths = []string{"يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو",
		"يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"}
)

// fixedAnswerSection is the app's own name of the place the answer lives in.
var fixedAnswerSection = map[string]map[string]string{
	"ru": {"natal_interpretation": "разделе «Ваше описание»", "astrologer_chat": "чате с астрологом", "ashtakavarga": "разделе «Аштакаварга»"},
	"en": {"natal_interpretation": "Your Description", "astrologer_chat": "Chat with Astrologer", "ashtakavarga": "Ashtakavarga"},
	"zh": {"natal_interpretation": "您的描述", "astrologer_chat": "与占星师聊天", "ashtakavarga": "八分星盘"},
	"ar": {"natal_interpretation": "وصفك", "astrologer_chat": "الدردشة مع المنجم", "ashtakavarga": "أشتاكافارغا"},
}

// fixedAnswerPushText builds the approved push text for one row: language,
// feature of the cut-off answer and its LOCAL date. ok=false for a feature
// the template has no section name for (the row is then left alone).
func fixedAnswerPushText(lang, feature string, localDate time.Time) (string, string, bool) {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if i := strings.IndexAny(lang, "-_"); i > 0 {
		lang = lang[:i]
	}
	if _, ok := fixedAnswerSection[lang]; !ok {
		lang = "en"
	}
	section, ok := fixedAnswerSection[lang][feature]
	if !ok {
		return "", lang, false
	}
	d, m := localDate.Day(), int(localDate.Month())-1
	switch lang {
	case "ru":
		return fmt.Sprintf("Ответ в %s от %d %s оборвался. Исправили — теперь он полный.", section, d, ruMonthsGen[m]), lang, true
	case "zh":
		return fmt.Sprintf("%d月%d日「%s」中的回答被截断了。已修复，现在是完整的。", m+1, d, section), lang, true
	case "ar":
		return fmt.Sprintf("انقطع الرد في قسم «%s» بتاريخ %d %s. تم الإصلاح، وهو الآن كامل.", section, d, arMonths[m]), lang, true
	default:
		return fmt.Sprintf("Your answer in %s from %s %d was cut off. Fixed — it's complete now.", section, enMonthsShort[m], d), lang, true
	}
}

type fixedAnswerDue struct {
	answerID, deviceID, feature, rowLang, answeredAt string
}

// fixedAnswerDeviceInfo: language (devices.language → app_language → the
// row's own) and timezone offset of the device's first live row.
func fixedAnswerDeviceInfo(deviceID, rowLang string) (string, int) {
	var lang, appLang string
	var tz int
	err := db.QueryRow(`SELECT COALESCE(language,''), COALESCE(app_language,''), COALESCE(tz_offset_minutes,0)
		FROM devices WHERE device_id = ? AND revoked = 0 ORDER BY (language IS NULL OR language = ''), id LIMIT 1`,
		deviceID).Scan(&lang, &appLang, &tz)
	if err != nil && err != sql.ErrNoRows {
		fmt.Printf("devices %s: %v\n", shortDeviceHash(deviceID), err)
	}
	for _, l := range []string{lang, appLang, rowLang} {
		if strings.TrimSpace(l) != "" {
			return l, tz
		}
	}
	return "en", tz
}

// fixedAnswerLatestBuild: the build the device reported last (analytics_events).
func fixedAnswerLatestBuild(deviceID string) (int, error) {
	var v string
	err := analyticsDB.QueryRow(`SELECT COALESCE(app_version,'') FROM analytics_events
		WHERE device_id = ? AND app_version != '' AND app_version != 'server'
		ORDER BY created_at DESC LIMIT 1`, deviceID).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return appBuildOf(v), nil
}

// pushDueFixedAnswers sends (or, dryRun, only lists) the pushes due now and
// returns how many rows would go / went. Every row gets ONE attempt:
// pushed_at is written before the send.
func pushDueFixedAnswers(minBuild int, dryRun bool, now time.Time) (int, error) {
	rows, err := db.Query(`SELECT answer_id, device_id, feature, language, answered_at FROM fixed_answers
		WHERE fetched_at IS NULL AND pushed_at IS NULL ORDER BY answered_at`)
	if err != nil {
		return 0, err
	}
	var due []fixedAnswerDue
	for rows.Next() {
		var d fixedAnswerDue
		if err := rows.Scan(&d.answerID, &d.deviceID, &d.feature, &d.rowLang, &d.answeredAt); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, d)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	stamp := now.UTC().Format("2006-01-02 15:04:05")
	sent, waiting := 0, 0
	for _, d := range due {
		tag := fmt.Sprintf("%s dev#%s", headRunes(d.answerID, 8), shortDeviceHash(d.deviceID))
		build, err := fixedAnswerLatestBuild(d.deviceID)
		if err != nil {
			return sent, fmt.Errorf("%s: app version: %w", tag, err)
		}
		if build < minBuild {
			waiting++
			fmt.Printf("%s\twait\t%s\tbuild=%d\n", stamp, tag, build)
			continue
		}
		lang, tz := fixedAnswerDeviceInfo(d.deviceID, d.rowLang)
		at, err := time.Parse("2006-01-02 15:04:05", d.answeredAt)
		if err != nil {
			fmt.Printf("%s\tskip\t%s\tbad answered_at %q\n", stamp, tag, d.answeredAt)
			continue
		}
		text, lang, ok := fixedAnswerPushText(lang, d.feature, at.Add(time.Duration(tz)*time.Minute))
		if !ok {
			fmt.Printf("%s\tskip\t%s\tno template for feature %q\n", stamp, tag, d.feature)
			continue
		}
		if dryRun {
			sent++
			fmt.Printf("%s\twould-send\t%s\tbuild=%d\t%s\t%s\n", stamp, tag, build, lang, text)
			continue
		}
		res, err := db.Exec(`UPDATE fixed_answers SET pushed_at = ?, push_text = ?
			WHERE answer_id = ? AND pushed_at IS NULL`, now.Unix(), text, d.answerID)
		if err != nil {
			return sent, fmt.Errorf("%s: mark pushed: %w", tag, err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			fmt.Printf("%s\tskip\t%s\talready pushed (rows=%d, err=%v)\n", stamp, tag, n, err)
			continue
		}
		targets, err := resolvePushTargets(d.deviceID, "")
		var results []string
		if err != nil {
			results = append(results, "targets: "+err.Error())
		} else if len(targets) == 0 {
			results = append(results, "no_token")
		}
		payload := fixedAnswerPayloadPrefix + d.answerID
		for _, t := range targets {
			if err := fixedAnswerSend(t.platform, t.token, "Astrolytix", text, payload, lang, 0); err != nil {
				results = append(results, t.platform+": "+headRunes(err.Error(), 200))
				continue
			}
			results = append(results, t.platform+": ok")
			recordNotificationHistory(t.email, t.deviceID, "Astrolytix", text, payload, lang)
		}
		result := strings.Join(results, "; ")
		if _, err := db.Exec(`UPDATE fixed_answers SET push_result = ? WHERE answer_id = ?`, result, d.answerID); err != nil {
			fmt.Printf("%s\twarn\t%s\tsave result: %v\n", stamp, tag, err)
		}
		sent++
		fmt.Printf("%s\tsent\t%s\tbuild=%d\t%s\t%s\n", stamp, tag, build, lang, result)
	}
	verb := "sent"
	if dryRun {
		verb = "would send"
	}
	fmt.Printf("%s\tsummary\t%s %d, waiting for build>=%d: %d, rows open: %d\n", stamp, verb, sent, minBuild, waiting, len(due))
	return sent, nil
}

const fixedAnswerPayloadPrefix = "fix:"

func runFixedAnswerPushDueCLI(args []string) {
	dryRun := false
	minBuild := fixedAnswerMinBuild
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			dryRun = true
		case "--min-build":
			if i+1 >= len(args) {
				fmt.Println("--min-build needs a number")
				os.Exit(2)
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				fmt.Printf("bad --min-build %q\n", args[i+1])
				os.Exit(2)
			}
			minBuild = n
			i++
		default:
			fmt.Println("usage: astrolog_api fixed-answer-push-due [--dry-run] [--min-build N]")
			os.Exit(2)
		}
	}
	if !dryRun {
		if _, err := loadAPNsConfig(); err != nil {
			fmt.Printf("APNs: %v\n", err)
			os.Exit(1)
		}
	}
	openFixedAnswerCLIDBs(true) // runs migrateFixedAnswers → push columns
	defer db.Close()
	defer analyticsDB.Close()
	if _, err := pushDueFixedAnswers(minBuild, dryRun, time.Now()); err != nil {
		fmt.Printf("push-due: %v\n", err)
		os.Exit(1)
	}
}
