package main

// ---------------------------------------------------------------------------
// D1: Referral program — "invite a friend, get premium".
//
// Mechanics (user-approved design, see my_first_app/docs/REFERRAL_DESIGN.md):
//   * Every account owns a permanent 8-char referral code (users.referral_code),
//     shared as https://astrolytix.com/r/{code}. If the recipient already has
//     the app, the universal link opens it (deep link); otherwise the URL
//     serves an HTML landing page (referralLandingPage) with the code + store
//     buttons, and the recipient types the code manually in the app.
//   * POST /api/referral/claim binds invitee → inviter exactly once per
//     account AND per physical device, with self-referral and new-user checks.
//     A successful claim grants the INSTALL reward (1 week) to both sides.
//   * The PAID reward (1 month, both sides) fires the first time the invitee's
//     REAL charge is confirmed — never on a free-trial start. Hooks mirror the
//     C2 first-purchase email: recordPurchase (!IsTrial), applyAppleRenewal
//     (Apple trial → paid via S2S DID_RENEW), and the Google trial
//     re-verification cron below (RTDN can't be mapped to a user, so we poll
//     the Play API until paymentState=1).
//   * Rewards are QUEUED DAYS (users.referral_days_pending), not fixed dates:
//     they activate lazily — the first time entitlement is computed while NO
//     store subscription is active — so a reward never burns underneath a
//     paying subscription and waits for the card to stop charging.
// ---------------------------------------------------------------------------

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

const (
	referralInstallRewardDays = 7  // both sides, on claim (install + code entry)
	referralPaidRewardDays    = 30 // both sides, on invitee's first real charge
	referralClaimWindowDays   = 14 // invitee account must be younger than this
	referralInstallRewardCap  = 10 // max install rewards per inviter (anti device-farm)
	referralShareURLBase      = "https://astrolytix.com/r/"
	referralAppStoreURL       = "https://apps.apple.com/app/id6759404465"
	referralPlayStoreURL      = "https://play.google.com/store/apps/details?id=com.astrolytix.app"
	devicePlaceholderSuffix   = "@device.astrolytix.app"
)

var referralSchemaReady atomic.Bool

// referralClaimLimiter throttles POST /api/referral/claim per device to slow
// down referral-code brute force (codes have ~40 bits of entropy on top).
var referralClaimLimiter = NewDeviceLimiter()

// ensureReferralSchema applies the D1 migrations. Same self-healing pattern as
// ensureNotificationHistorySchema: called at startup and defensively from the
// handlers; retries next call until it succeeds.
func ensureReferralSchema() {
	if referralSchemaReady.Load() {
		return
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS referrals (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		inviter_email TEXT NOT NULL,
		invitee_email TEXT NOT NULL UNIQUE,
		invitee_device_id TEXT NOT NULL UNIQUE,
		code TEXT NOT NULL,
		claimed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		install_reward_granted_at DATETIME,
		paid_reward_granted_at DATETIME
	)`); err != nil {
		log.Printf("⚠️ referrals schema failed: %v — will retry", err)
		return
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_referrals_inviter ON referrals(inviter_email)`); err != nil {
		log.Printf("⚠️ referrals inviter index failed: %v — will retry", err)
		return
	}
	// users: permanent share code + the two reward slots (active window +
	// queued days). ALTERs error with "duplicate column" once applied — ignored.
	for _, ddl := range []string{
		`ALTER TABLE users ADD COLUMN referral_code TEXT`,
		`ALTER TABLE users ADD COLUMN referral_premium_until DATETIME`,
		`ALTER TABLE users ADD COLUMN referral_days_pending INTEGER NOT NULL DEFAULT 0`,
		// purchase_history: what the Google trial re-verifier needs. purchase_token
		// lets the cron poll the Play API; is_trial marks rows pending conversion;
		// trial_converted_at is the exactly-once guard when the charge lands.
		`ALTER TABLE purchase_history ADD COLUMN purchase_token TEXT`,
		`ALTER TABLE purchase_history ADD COLUMN is_trial INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE purchase_history ADD COLUMN trial_converted_at DATETIME`,
	} {
		if _, err := db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("⚠️ referral migration %q failed: %v — will retry", ddl, err)
			return
		}
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code
		ON users(referral_code) WHERE referral_code IS NOT NULL`); err != nil {
		log.Printf("⚠️ referral_code index failed: %v — will retry", err)
		return
	}
	referralSchemaReady.Store(true)
}

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func devicePlaceholderEmail(deviceID string) string {
	return strings.ToLower(deviceID) + devicePlaceholderSuffix
}

// generateReferralCode returns an 8-char code from an alphabet without
// look-alike characters (same alphabet as the T2.B invite hashes).
func generateReferralCode() (string, error) {
	const alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	const length = 8
	code := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		code[i] = alphabet[n.Int64()]
	}
	return string(code), nil
}

// getOrCreateReferralCode returns the account's permanent code, generating it
// on first use. The guarded UPDATE + unique index make concurrent first calls
// converge on a single code.
func getOrCreateReferralCode(email string) (string, error) {
	ensureReferralSchema()
	email = normEmail(email)
	var code sql.NullString
	if err := db.QueryRow(`SELECT referral_code FROM users WHERE email = ?`, email).Scan(&code); err != nil {
		return "", err
	}
	if code.Valid && code.String != "" {
		return code.String, nil
	}
	for attempt := 0; attempt < 5; attempt++ {
		c, err := generateReferralCode()
		if err != nil {
			return "", err
		}
		res, err := db.Exec(`UPDATE users SET referral_code = ?
			WHERE email = ? AND (referral_code IS NULL OR referral_code = '')`, c, email)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue // collided with another account's code — retry
			}
			return "", err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return c, nil
		}
		// Raced with a parallel request that already set the code — re-read.
		if err := db.QueryRow(`SELECT referral_code FROM users WHERE email = ?`, email).Scan(&code); err == nil &&
			code.Valid && code.String != "" {
			return code.String, nil
		}
	}
	return "", fmt.Errorf("could not allocate referral code for %s", email)
}

// grantReferralDays adds reward days to the account's pending queue. The queue
// is drained lazily by referralPremiumUntil the first time entitlement is
// computed while no premium (store or reward) is active — so rewards never
// burn in parallel with a paid subscription.
func grantReferralDays(email string, days int, reason string) {
	ensureReferralSchema()
	email = normEmail(email)
	if email == "" || days <= 0 {
		return
	}
	res, err := db.Exec(`UPDATE users SET referral_days_pending = COALESCE(referral_days_pending, 0) + ?
		WHERE email = ?`, days, email)
	if err != nil {
		log.Printf("⚠️ [referral] grant %dd to %s (%s) failed: %v", days, email, reason, err)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		log.Printf("⚠️ [referral] grant %dd to %s (%s): no users row", days, email, reason)
		return
	}
	log.Printf("🎁 [referral] +%d premium day(s) queued for %s (%s)", days, email, reason)
}

// referralPremiumUntil returns the active reward window for ONE account,
// lazily activating queued days. Call it only when no store subscription is
// active — the caller's check is what makes rewards wait behind paid periods.
func referralPremiumUntil(email string) (time.Time, bool) {
	ensureReferralSchema()
	email = normEmail(email)
	var untilStr sql.NullString
	var pending int
	if err := db.QueryRow(`SELECT referral_premium_until, COALESCE(referral_days_pending, 0)
		FROM users WHERE email = ?`, email).Scan(&untilStr, &pending); err != nil {
		return time.Time{}, false
	}
	if untilStr.Valid && untilStr.String != "" {
		if t, err := parseDBTime(untilStr.String); err == nil && time.Now().Before(t) {
			return t, true // active window; queued days wait for it to lapse
		}
	}
	if pending <= 0 {
		return time.Time{}, false
	}
	// No store premium (caller checked), no active window, days queued →
	// start the clock now. Guarded on the exact pending value so concurrent
	// requests activate exactly once.
	until := time.Now().Add(time.Duration(pending) * 24 * time.Hour)
	res, err := db.Exec(`UPDATE users SET referral_premium_until = ?, referral_days_pending = 0
		WHERE email = ? AND referral_days_pending = ?`, until, email, pending)
	if err != nil {
		log.Printf("⚠️ [referral] activation failed for %s: %v", email, err)
		return time.Time{}, false
	}
	if n, _ := res.RowsAffected(); n != 1 {
		// Raced — the other request won; re-read the window it created.
		if err := db.QueryRow(`SELECT referral_premium_until FROM users WHERE email = ?`, email).
			Scan(&untilStr); err == nil && untilStr.Valid && untilStr.String != "" {
			if t, perr := parseDBTime(untilStr.String); perr == nil && time.Now().Before(t) {
				return t, true
			}
		}
		return time.Time{}, false
	}
	log.Printf("✨ [referral] %d queued day(s) activated for %s → premium until %v", pending, email, until)
	return until, true
}

// referralEntitlement resolves reward premium across the caller's two possible
// identities (real email + the anonymous device account), mirroring the
// OR-with-device logic used for store subscriptions.
func referralEntitlement(email, deviceID string) (time.Time, bool) {
	email = normEmail(email)
	if t, ok := referralPremiumUntil(email); ok {
		return t, true
	}
	if deviceID != "" {
		if ph := devicePlaceholderEmail(deviceID); ph != email {
			if t, ok := referralPremiumUntil(ph); ok {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// Reward pushes (iOS, same pipeline as admin/event pushes)
// ---------------------------------------------------------------------------

// referralPushText returns the localized (title, body) for a reward push.
// kind ∈ install_invitee | install_inviter | paid_invitee | paid_inviter.
func referralPushText(lang, kind string) (string, string) {
	type msgs struct{ instInvitee, instInviter, paidInvitee, paidInviter [2]string }
	m := map[string]msgs{
		"en": {
			[2]string{"🎉 +7 days of Premium", "Friend's code accepted — a week of Astrolytix Premium is yours!"},
			[2]string{"🎉 +7 days of Premium", "Your friend joined Astrolytix on your invitation — a week of Premium is yours!"},
			[2]string{"🌟 +1 month of Premium", "A month of Astrolytix Premium is yours — thanks for joining through a friend!"},
			[2]string{"🌟 +1 month of Premium", "Your friend subscribed — a month of Astrolytix Premium is yours!"},
		},
		"ru": {
			[2]string{"🎉 +7 дней Премиум", "Код друга принят — вам начислена неделя Astrolytix Premium!"},
			[2]string{"🎉 +7 дней Премиум", "Ваш друг присоединился к Astrolytix по вашему приглашению — вам начислена неделя Премиум!"},
			[2]string{"🌟 +1 месяц Премиум", "Вам начислен месяц Astrolytix Premium — спасибо, что пришли по приглашению друга!"},
			[2]string{"🌟 +1 месяц Премиум", "Ваш друг оформил подписку — вам начислен месяц Astrolytix Premium!"},
		},
		"es": {
			[2]string{"🎉 +7 días de Premium", "Código de tu amigo aceptado: ¡una semana de Astrolytix Premium para ti!"},
			[2]string{"🎉 +7 días de Premium", "Tu amigo se unió a Astrolytix con tu invitación: ¡una semana de Premium para ti!"},
			[2]string{"🌟 +1 mes de Premium", "Un mes de Astrolytix Premium para ti. ¡Gracias por venir invitado por un amigo!"},
			[2]string{"🌟 +1 mes de Premium", "Tu amigo se suscribió: ¡un mes de Astrolytix Premium para ti!"},
		},
		"fr": {
			[2]string{"🎉 +7 jours de Premium", "Code de votre ami accepté — une semaine d'Astrolytix Premium offerte !"},
			[2]string{"🎉 +7 jours de Premium", "Votre ami a rejoint Astrolytix sur votre invitation — une semaine de Premium offerte !"},
			[2]string{"🌟 +1 mois de Premium", "Un mois d'Astrolytix Premium offert — merci d'être venu sur invitation d'un ami !"},
			[2]string{"🌟 +1 mois de Premium", "Votre ami s'est abonné — un mois d'Astrolytix Premium offert !"},
		},
		"de": {
			[2]string{"🎉 +7 Tage Premium", "Code deines Freundes angenommen — eine Woche Astrolytix Premium für dich!"},
			[2]string{"🎉 +7 Tage Premium", "Dein Freund ist auf deine Einladung Astrolytix beigetreten — eine Woche Premium für dich!"},
			[2]string{"🌟 +1 Monat Premium", "Ein Monat Astrolytix Premium für dich — danke, dass du über einen Freund gekommen bist!"},
			[2]string{"🌟 +1 Monat Premium", "Dein Freund hat abonniert — ein Monat Astrolytix Premium für dich!"},
		},
		"it": {
			[2]string{"🎉 +7 giorni di Premium", "Codice del tuo amico accettato: una settimana di Astrolytix Premium per te!"},
			[2]string{"🎉 +7 giorni di Premium", "Il tuo amico si è unito ad Astrolytix con il tuo invito: una settimana di Premium per te!"},
			[2]string{"🌟 +1 mese di Premium", "Un mese di Astrolytix Premium per te: grazie per essere arrivato tramite un amico!"},
			[2]string{"🌟 +1 mese di Premium", "Il tuo amico si è abbonato: un mese di Astrolytix Premium per te!"},
		},
		"pt": {
			[2]string{"🎉 +7 dias de Premium", "Código do seu amigo aceito — uma semana de Astrolytix Premium para você!"},
			[2]string{"🎉 +7 dias de Premium", "Seu amigo entrou no Astrolytix pelo seu convite — uma semana de Premium para você!"},
			[2]string{"🌟 +1 mês de Premium", "Um mês de Astrolytix Premium para você — obrigado por vir pelo convite de um amigo!"},
			[2]string{"🌟 +1 mês de Premium", "Seu amigo assinou — um mês de Astrolytix Premium para você!"},
		},
		"zh": {
			[2]string{"🎉 高级版 +7 天", "好友邀请码已接受——您获得一周 Astrolytix 高级版！"},
			[2]string{"🎉 高级版 +7 天", "您的好友通过您的邀请加入了 Astrolytix——您获得一周高级版！"},
			[2]string{"🌟 高级版 +1 个月", "您获得一个月 Astrolytix 高级版——感谢通过好友邀请加入！"},
			[2]string{"🌟 高级版 +1 个月", "您的好友已订阅——您获得一个月 Astrolytix 高级版！"},
		},
		"ja": {
			[2]string{"🎉 プレミアム +7日", "友達のコードが承認されました — Astrolytix プレミアム1週間をプレゼント！"},
			[2]string{"🎉 プレミアム +7日", "あなたの招待で友達が Astrolytix に参加しました — プレミアム1週間をプレゼント！"},
			[2]string{"🌟 プレミアム +1か月", "Astrolytix プレミアム1か月をプレゼント — 友達の招待からのご参加ありがとうございます！"},
			[2]string{"🌟 プレミアム +1か月", "友達が購読を開始しました — Astrolytix プレミアム1か月をプレゼント！"},
		},
		"ko": {
			[2]string{"🎉 프리미엄 +7일", "친구의 코드가 확인되었습니다 — Astrolytix 프리미엄 1주일이 지급되었습니다!"},
			[2]string{"🎉 프리미엄 +7일", "친구가 회원님의 초대로 Astrolytix에 가입했습니다 — 프리미엄 1주일이 지급되었습니다!"},
			[2]string{"🌟 프리미엄 +1개월", "Astrolytix 프리미엄 1개월이 지급되었습니다 — 친구 초대로 와주셔서 감사합니다!"},
			[2]string{"🌟 프리미엄 +1개월", "친구가 구독을 시작했습니다 — Astrolytix 프리미엄 1개월이 지급되었습니다!"},
		},
		"hi": {
			[2]string{"🎉 +7 दिन प्रीमियम", "दोस्त का कोड स्वीकार हुआ — आपको एक सप्ताह का Astrolytix Premium मिला!"},
			[2]string{"🎉 +7 दिन प्रीमियम", "आपके निमंत्रण पर आपका दोस्त Astrolytix से जुड़ा — आपको एक सप्ताह का Premium मिला!"},
			[2]string{"🌟 +1 महीना प्रीमियम", "आपको एक महीने का Astrolytix Premium मिला — दोस्त के निमंत्रण से आने के लिए धन्यवाद!"},
			[2]string{"🌟 +1 महीना प्रीमियम", "आपके दोस्त ने सदस्यता ली — आपको एक महीने का Astrolytix Premium मिला!"},
		},
		"ar": {
			[2]string{"🎉 ‏+7 أيام بريميوم", "تم قبول رمز صديقك — حصلت على أسبوع من Astrolytix Premium!"},
			[2]string{"🎉 ‏+7 أيام بريميوم", "انضم صديقك إلى Astrolytix بدعوتك — حصلت على أسبوع من بريميوم!"},
			[2]string{"🌟 ‏+شهر بريميوم", "حصلت على شهر من Astrolytix Premium — شكرًا لانضمامك بدعوة من صديق!"},
			[2]string{"🌟 ‏+شهر بريميوم", "اشترك صديقك — حصلت على شهر من Astrolytix Premium!"},
		},
		"mr": {
			[2]string{"🎉 +7 दिवस प्रीमियम", "मित्राचा कोड स्वीकारला गेला — आपल्याला एक आठवड्याचे Astrolytix Premium मिळाले!"},
			[2]string{"🎉 +7 दिवस प्रीमियम", "आपल्या निमंत्रणावरून आपला मित्र Astrolytix मध्ये सामील झाला — आपल्याला एक आठवड्याचे Premium मिळाले!"},
			[2]string{"🌟 +1 महिना प्रीमियम", "आपल्याला एक महिन्याचे Astrolytix Premium मिळाले — मित्राच्या निमंत्रणाने आल्याबद्दल धन्यवाद!"},
			[2]string{"🌟 +1 महिना प्रीमियम", "आपल्या मित्राने सदस्यता घेतली — आपल्याला एक महिन्याचे Astrolytix Premium मिळाले!"},
		},
		"te": {
			[2]string{"🎉 +7 రోజుల ప్రీమియం", "మీ స్నేహితుడి కోడ్ ఆమోదించబడింది — మీకు ఒక వారం Astrolytix Premium లభించింది!"},
			[2]string{"🎉 +7 రోజుల ప్రీమియం", "మీ ఆహ్వానంతో మీ స్నేహితుడు Astrolytixలో చేరారు — మీకు ఒక వారం Premium లభించింది!"},
			[2]string{"🌟 +1 నెల ప్రీమియం", "మీకు ఒక నెల Astrolytix Premium లభించింది — స్నేహితుడి ఆహ్వానంతో వచ్చినందుకు ధన్యవాదాలు!"},
			[2]string{"🌟 +1 నెల ప్రీమియం", "మీ స్నేహితుడు సభ్యత్వం తీసుకున్నారు — మీకు ఒక నెల Astrolytix Premium లభించింది!"},
		},
		"ta": {
			[2]string{"🎉 +7 நாட்கள் பிரீமியம்", "நண்பரின் குறியீடு ஏற்கப்பட்டது — உங்களுக்கு ஒரு வாரம் Astrolytix Premium கிடைத்தது!"},
			[2]string{"🎉 +7 நாட்கள் பிரீமியம்", "உங்கள் அழைப்பில் உங்கள் நண்பர் Astrolytix-இல் இணைந்தார் — உங்களுக்கு ஒரு வாரம் Premium கிடைத்தது!"},
			[2]string{"🌟 +1 மாதம் பிரீமியம்", "உங்களுக்கு ஒரு மாதம் Astrolytix Premium கிடைத்தது — நண்பரின் அழைப்பில் வந்ததற்கு நன்றி!"},
			[2]string{"🌟 +1 மாதம் பிரீமியம்", "உங்கள் நண்பர் சந்தா எடுத்தார் — உங்களுக்கு ஒரு மாதம் Astrolytix Premium கிடைத்தது!"},
		},
		"kn": {
			[2]string{"🎉 +7 ದಿನಗಳ ಪ್ರೀಮಿಯಂ", "ಸ್ನೇಹಿತರ ಕೋಡ್ ಸ್ವೀಕರಿಸಲಾಗಿದೆ — ನಿಮಗೆ ಒಂದು ವಾರದ Astrolytix Premium ಸಿಕ್ಕಿದೆ!"},
			[2]string{"🎉 +7 ದಿನಗಳ ಪ್ರೀಮಿಯಂ", "ನಿಮ್ಮ ಆಹ್ವಾನದ ಮೇರೆಗೆ ನಿಮ್ಮ ಸ್ನೇಹಿತರು Astrolytix ಸೇರಿದ್ದಾರೆ — ನಿಮಗೆ ಒಂದು ವಾರದ Premium ಸಿಕ್ಕಿದೆ!"},
			[2]string{"🌟 +1 ತಿಂಗಳ ಪ್ರೀಮಿಯಂ", "ನಿಮಗೆ ಒಂದು ತಿಂಗಳ Astrolytix Premium ಸಿಕ್ಕಿದೆ — ಸ್ನೇಹಿತರ ಆಹ್ವಾನದ ಮೂಲಕ ಬಂದದ್ದಕ್ಕೆ ಧನ್ಯವಾದಗಳು!"},
			[2]string{"🌟 +1 ತಿಂಗಳ ಪ್ರೀಮಿಯಂ", "ನಿಮ್ಮ ಸ್ನೇಹಿತರು ಚಂದಾದಾರರಾಗಿದ್ದಾರೆ — ನಿಮಗೆ ಒಂದು ತಿಂಗಳ Astrolytix Premium ಸಿಕ್ಕಿದೆ!"},
		},
	}
	t, ok := m[lang]
	if !ok {
		t = m["en"]
	}
	var pair [2]string
	switch kind {
	case "install_invitee":
		pair = t.instInvitee
	case "install_inviter":
		pair = t.instInviter
	case "paid_invitee":
		pair = t.paidInvitee
	case "paid_inviter":
		pair = t.paidInviter
	default:
		pair = t.instInvitee
	}
	return pair[0], pair[1]
}

// sendReferralPush notifies an account about a granted reward. Fire-and-forget:
// failures only log. Resolves by email first; anonymous device accounts fall
// back to their device_id so tokenless placeholder rows still get found.
func sendReferralPush(email, kind string) {
	email = normEmail(email)
	if email == "" {
		return
	}
	targets, err := resolvePushTargets("", email)
	if (err != nil || len(targets) == 0) && strings.HasSuffix(email, devicePlaceholderSuffix) {
		deviceID := strings.TrimSuffix(email, devicePlaceholderSuffix)
		targets, err = resolvePushTargets(deviceID, "")
	}
	if err != nil || len(targets) == 0 {
		return
	}
	title, body := referralPushText(userAppLanguage(email), kind)
	payload := "astro:referral:" + kind
	for _, t := range targets {
		if sendErr := sendAPNs(t.token, title, body, payload, 0); sendErr != nil {
			log.Printf("⚠️ [referral] push to %s failed: %v", t.deviceID, sendErr)
			continue
		}
		histEmail := t.email
		if histEmail == "" {
			histEmail = email
		}
		recordNotificationHistory(histEmail, t.deviceID, title, body, payload)
	}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// referralInfo — GET /api/referral/info (JWT). Everything the referral screen
// needs in one call: the share code, stats, reward balance, and whether the
// caller may still enter someone else's code.
func referralInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}
	ensureReferralSchema()
	email := normEmail(claims.Email)
	deviceID := claims.DeviceID

	code, err := getOrCreateReferralCode(email)
	if err != nil {
		log.Printf("⚠️ [referral] code for %s failed: %v", email, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}

	var invited, installRewards, paidRewards int
	db.QueryRow(`SELECT COUNT(*),
		COUNT(install_reward_granted_at),
		COUNT(paid_reward_granted_at)
		FROM referrals WHERE inviter_email = ?`, email).Scan(&invited, &installRewards, &paidRewards)

	var pending int
	var untilStr sql.NullString
	db.QueryRow(`SELECT COALESCE(referral_days_pending, 0), referral_premium_until
		FROM users WHERE email = ?`, email).Scan(&pending, &untilStr)
	premiumUntil := ""
	if untilStr.Valid && untilStr.String != "" {
		if t, perr := parseDBTime(untilStr.String); perr == nil && time.Now().Before(t) {
			premiumUntil = t.UTC().Format(time.RFC3339)
		}
	}

	claimed := referralAlreadyClaimed(email, deviceID)
	canClaim := !claimed && referralInviteeIsEligible(email, deviceID) == ""

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"code":            code,
		"share_url":       referralShareURLBase + code,
		"invited_count":   invited,
		"install_rewards": installRewards,
		"paid_rewards":    paidRewards,
		"days_pending":    pending,
		"premium_until":   premiumUntil,
		"claimed":         claimed,
		"can_claim":       canClaim,
	})
}

// referralAlreadyClaimed reports whether this account or this physical device
// has already entered someone's code.
func referralAlreadyClaimed(email, deviceID string) bool {
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM referrals
		WHERE invitee_email = ? OR invitee_email = ? OR (? != '' AND invitee_device_id = ?)`,
		email, devicePlaceholderEmail(deviceID), deviceID, deviceID).Scan(&n)
	return n > 0
}

// referralInviteeIsEligible returns "" when the caller may claim a code, or a
// machine-readable reason. New-user rules: the account must be younger than
// referralClaimWindowDays and must not have any purchase yet (on either its
// real email or its device placeholder).
func referralInviteeIsEligible(email, deviceID string) string {
	var createdAt string
	if err := db.QueryRow(`SELECT created_at FROM users WHERE email = ?`, email).Scan(&createdAt); err != nil {
		return "no_account"
	}
	if t, err := parseDBTime(createdAt); err == nil {
		if time.Since(t) > time.Duration(referralClaimWindowDays)*24*time.Hour {
			return "not_new_user"
		}
	}
	var purchases int
	db.QueryRow(`SELECT COUNT(*) FROM purchase_history WHERE email = ? OR email = ?`,
		email, devicePlaceholderEmail(deviceID)).Scan(&purchases)
	if purchases > 0 {
		return "not_new_user"
	}
	return ""
}

// referralClaim — POST /api/referral/claim {"code": "..."} (JWT). Binds the
// caller to the code owner and grants the install reward (1 week both sides).
func referralClaim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Unauthorized"})
		return
	}
	ensureReferralSchema()
	inviteeEmail := normEmail(claims.Email)
	inviteeDevice := claims.DeviceID
	if inviteeDevice == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "no_device"})
		return
	}
	if !referralClaimLimiter.GetLimiter(inviteeDevice).Allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "rate_limited"})
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid_body"})
		return
	}
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	if len(code) < 4 || len(code) > 16 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid_code"})
		return
	}

	var inviterEmail string
	if err := db.QueryRow(`SELECT email FROM users WHERE referral_code = ?`, code).Scan(&inviterEmail); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid_code"})
		return
	}
	inviterEmail = normEmail(inviterEmail)

	// --- Self-referral checks: the two accounts must not share a person's
	// device in any combination of real email / device placeholder. ---
	selfReferral := inviterEmail == inviteeEmail ||
		inviterEmail == devicePlaceholderEmail(inviteeDevice)
	if !selfReferral {
		// Has the inviter's account ever been used on the invitee's device?
		var n int
		db.QueryRow(`SELECT COUNT(*) FROM devices WHERE email = ? AND device_id = ?`,
			inviterEmail, inviteeDevice).Scan(&n)
		selfReferral = n > 0
	}
	if !selfReferral && strings.HasSuffix(inviterEmail, devicePlaceholderSuffix) {
		// Inviter is an anonymous device account — has the invitee's email
		// ever been used on THAT device?
		inviterDevice := strings.TrimSuffix(inviterEmail, devicePlaceholderSuffix)
		selfReferral = strings.EqualFold(inviterDevice, inviteeDevice)
		if !selfReferral {
			var n int
			db.QueryRow(`SELECT COUNT(*) FROM devices WHERE email = ? AND device_id = ?`,
				inviteeEmail, inviterDevice).Scan(&n)
			selfReferral = n > 0
		}
	}
	if selfReferral {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "self_referral"})
		return
	}

	if reason := referralInviteeIsEligible(inviteeEmail, inviteeDevice); reason != "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": reason})
		return
	}

	// One claim per account AND per physical device (UNIQUE columns); OR IGNORE
	// turns a repeat into 0 rows affected.
	res, err := db.Exec(`INSERT OR IGNORE INTO referrals (inviter_email, invitee_email, invitee_device_id, code)
		VALUES (?, ?, ?, ?)`, inviterEmail, inviteeEmail, inviteeDevice, code)
	if err != nil {
		log.Printf("⚠️ [referral] claim insert failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "already_claimed"})
		return
	}
	log.Printf("🤝 [referral] %s claimed code %s of %s", inviteeEmail, code, inviterEmail)

	// Install reward — exactly once per claim row (guarded UPDATE, C2 pattern).
	gres, gerr := db.Exec(`UPDATE referrals SET install_reward_granted_at = CURRENT_TIMESTAMP
		WHERE invitee_email = ? AND install_reward_granted_at IS NULL`, inviteeEmail)
	if gerr == nil {
		if n, _ := gres.RowsAffected(); n == 1 {
			grantReferralDays(inviteeEmail, referralInstallRewardDays, "install reward (invitee)")
			sendReferralPush(inviteeEmail, "install_invitee")
			// The inviter's install rewards are capped to keep device farms
			// pointless; the count includes the row granted just above.
			var granted int
			db.QueryRow(`SELECT COUNT(*) FROM referrals
				WHERE inviter_email = ? AND install_reward_granted_at IS NOT NULL`, inviterEmail).Scan(&granted)
			if granted <= referralInstallRewardCap {
				grantReferralDays(inviterEmail, referralInstallRewardDays, "install reward (inviter)")
				sendReferralPush(inviterEmail, "install_inviter")
			} else {
				log.Printf("ℹ️ [referral] inviter %s hit install-reward cap (%d) — invitee still rewarded",
					inviterEmail, referralInstallRewardCap)
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"granted_days": referralInstallRewardDays,
	})
}

// maybeGrantReferralPaidReward grants the 1-month reward to BOTH sides the
// first time the invitee's real paid charge is confirmed. Exactly-once via a
// guarded UPDATE on paid_reward_granted_at (same pattern as the C2 email).
// deviceID may be empty (Apple S2S path only knows the email). Fire-and-forget.
func maybeGrantReferralPaidReward(email, deviceID string) {
	ensureReferralSchema()
	email = normEmail(email)
	if email == "" || strings.HasPrefix(email, "apple:") {
		return
	}
	// The claim may have been made under either of the buyer's identities.
	placeholder := email
	if deviceID != "" {
		placeholder = devicePlaceholderEmail(deviceID)
	}
	var id int
	var inviter, invitee string
	err := db.QueryRow(`SELECT id, inviter_email, invitee_email FROM referrals
		WHERE paid_reward_granted_at IS NULL
		  AND (invitee_email = ? OR invitee_email = ? OR (? != '' AND invitee_device_id = ?))
		LIMIT 1`, email, placeholder, deviceID, deviceID).Scan(&id, &inviter, &invitee)
	if err != nil {
		return // no pending referral for this buyer
	}
	res, err := db.Exec(`UPDATE referrals SET paid_reward_granted_at = CURRENT_TIMESTAMP
		WHERE id = ? AND paid_reward_granted_at IS NULL`, id)
	if err != nil {
		log.Printf("⚠️ [referral] paid-reward guard failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return // another path won the race
	}
	log.Printf("💎 [referral] paid conversion by %s → 1 month to %s and %s", email, invitee, inviter)
	grantReferralDays(invitee, referralPaidRewardDays, "paid reward (invitee)")
	grantReferralDays(inviter, referralPaidRewardDays, "paid reward (inviter)")
	sendReferralPush(invitee, "paid_invitee")
	sendReferralPush(inviter, "paid_inviter")
}

// ---------------------------------------------------------------------------
// Public landing page — GET /r/{code}
//
// Served for recipients who do NOT have the app installed (universal links
// open the app directly when it is). Shows the offer, the code itself and the
// store buttons; the recipient types the code in Settings → Invite a friend
// after installing. Requires an nginx location for /r/ → :8081 (deploy step).
// ---------------------------------------------------------------------------

type referralLandingText struct {
	title, offer, codeLabel, install, terms string
}

var referralLandingTexts = map[string]referralLandingText{
	"en": {"Astrolytix — invitation", "Your friend invites you to Astrolytix — you both get Premium!", "Invitation code",
		"Install Astrolytix and enter this code in Settings → Invite a friend.",
		"You both get 1 week of Premium when you join, and 1 month each when you purchase any subscription."},
	"ru": {"Astrolytix — приглашение", "Друг приглашает вас в Astrolytix — вы оба получите Премиум!", "Код приглашения",
		"Установите Astrolytix и введите этот код в Настройки → Пригласи друга.",
		"Вы оба получите 1 неделю Премиума за установку и по 1 месяцу, когда вы оформите любую подписку."},
	"es": {"Astrolytix — invitación", "Tu amigo te invita a Astrolytix: ¡ambos recibiréis Premium!", "Código de invitación",
		"Instala Astrolytix e introduce este código en Ajustes → Invita a un amigo.",
		"Ambos recibiréis 1 semana de Premium al uniros y 1 mes cada uno cuando compres cualquier suscripción."},
	"fr": {"Astrolytix — invitation", "Votre ami vous invite sur Astrolytix — vous recevez tous les deux Premium !", "Code d'invitation",
		"Installez Astrolytix et saisissez ce code dans Réglages → Inviter un ami.",
		"Vous recevez tous les deux 1 semaine de Premium à l'inscription et 1 mois chacun lors de l'achat d'un abonnement."},
	"de": {"Astrolytix — Einladung", "Dein Freund lädt dich zu Astrolytix ein — ihr bekommt beide Premium!", "Einladungscode",
		"Installiere Astrolytix und gib diesen Code unter Einstellungen → Freund einladen ein.",
		"Ihr bekommt beide 1 Woche Premium beim Beitritt und je 1 Monat, wenn ein Abo gekauft wird."},
	"it": {"Astrolytix — invito", "Il tuo amico ti invita su Astrolytix: entrambi ricevete Premium!", "Codice di invito",
		"Installa Astrolytix e inserisci questo codice in Impostazioni → Invita un amico.",
		"Entrambi ricevete 1 settimana di Premium all'iscrizione e 1 mese ciascuno all'acquisto di un abbonamento."},
	"pt": {"Astrolytix — convite", "Seu amigo convida você para o Astrolytix — vocês dois ganham Premium!", "Código de convite",
		"Instale o Astrolytix e insira este código em Configurações → Convide um amigo.",
		"Vocês dois ganham 1 semana de Premium ao entrar e 1 mês cada quando qualquer assinatura for comprada."},
	"zh": {"Astrolytix — 邀请", "您的朋友邀请您加入 Astrolytix——你们都将获得高级版！", "邀请码",
		"安装 Astrolytix，然后在 设置 → 邀请好友 中输入此邀请码。",
		"加入后你们各获得 1 周高级版；购买任意订阅后各获得 1 个月。"},
	"ja": {"Astrolytix — 招待", "友達があなたを Astrolytix に招待しています — 2人ともプレミアムがもらえます！", "招待コード",
		"Astrolytix をインストールし、設定 → 友達を招待 でこのコードを入力してください。",
		"参加すると2人とも1週間のプレミアム、サブスクリプション購入で各1か月がもらえます。"},
	"ko": {"Astrolytix — 초대", "친구가 Astrolytix에 초대했습니다 — 두 분 모두 프리미엄을 받으세요!", "초대 코드",
		"Astrolytix를 설치하고 설정 → 친구 초대에서 이 코드를 입력하세요.",
		"가입 시 두 분 모두 프리미엄 1주일, 구독 구매 시 각각 1개월을 받습니다."},
	"hi": {"Astrolytix — निमंत्रण", "आपका दोस्त आपको Astrolytix पर आमंत्रित करता है — आप दोनों को प्रीमियम मिलेगा!", "निमंत्रण कोड",
		"Astrolytix इंस्टॉल करें और यह कोड सेटिंग्स → दोस्त को आमंत्रित करें में दर्ज करें।",
		"जुड़ने पर आप दोनों को 1 सप्ताह का प्रीमियम और कोई भी सदस्यता खरीदने पर 1-1 महीना मिलेगा।"},
	"ar": {"Astrolytix — دعوة", "صديقك يدعوك إلى Astrolytix — ستحصلان كلاكما على بريميوم!", "رمز الدعوة",
		"ثبّت Astrolytix وأدخل هذا الرمز في الإعدادات ← ادعُ صديقًا.",
		"تحصلان كلاكما على أسبوع من بريميوم عند الانضمام، وشهر لكل منكما عند شراء أي اشتراك."},
	"mr": {"Astrolytix — निमंत्रण", "आपला मित्र आपल्याला Astrolytix वर आमंत्रित करत आहे — आपणा दोघांना प्रीमियम मिळेल!", "निमंत्रण कोड",
		"Astrolytix इंस्टॉल करा आणि हा कोड सेटिंग्ज → मित्राला आमंत्रित करा मध्ये टाका.",
		"सामील झाल्यावर आपणा दोघांना 1 आठवड्याचे प्रीमियम आणि कोणतीही सदस्यता खरेदी केल्यावर प्रत्येकी 1 महिना मिळेल."},
	"te": {"Astrolytix — ఆహ్వానం", "మీ స్నేహితుడు మిమ్మల్ని Astrolytixకు ఆహ్వానిస్తున్నారు — మీ ఇద్దరికీ ప్రీమియం లభిస్తుంది!", "ఆహ్వాన కోడ్",
		"Astrolytix ఇన్‌స్టాల్ చేసి, ఈ కోడ్‌ను సెట్టింగ్‌లు → స్నేహితుడిని ఆహ్వానించండి లో నమోదు చేయండి.",
		"చేరినప్పుడు మీ ఇద్దరికీ 1 వారం ప్రీమియం, ఏదైనా సభ్యత్వం కొన్నప్పుడు ఒక్కొక్కరికి 1 నెల లభిస్తుంది."},
	"ta": {"Astrolytix — அழைப்பு", "உங்கள் நண்பர் உங்களை Astrolytix-க்கு அழைக்கிறார் — இருவருக்கும் பிரீமியம் கிடைக்கும்!", "அழைப்புக் குறியீடு",
		"Astrolytix-ஐ நிறுவி, இந்தக் குறியீட்டை அமைப்புகள் → நண்பரை அழையுங்கள் இல் உள்ளிடுங்கள்.",
		"இணைந்ததும் இருவருக்கும் 1 வாரம் பிரீமியம், ஏதேனும் சந்தா வாங்கியதும் தலா 1 மாதம் கிடைக்கும்."},
	"kn": {"Astrolytix — ಆಹ್ವಾನ", "ನಿಮ್ಮ ಸ್ನೇಹಿತರು ನಿಮ್ಮನ್ನು Astrolytixಗೆ ಆಹ್ವಾನಿಸುತ್ತಿದ್ದಾರೆ — ನಿಮ್ಮಿಬ್ಬರಿಗೂ ಪ್ರೀಮಿಯಂ ಸಿಗುತ್ತದೆ!", "ಆಹ್ವಾನ ಕೋಡ್",
		"Astrolytix ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ, ಈ ಕೋಡ್ ಅನ್ನು ಸೆಟ್ಟಿಂಗ್‌ಗಳು → ಸ್ನೇಹಿತರನ್ನು ಆಹ್ವಾನಿಸಿ ನಲ್ಲಿ ನಮೂದಿಸಿ.",
		"ಸೇರಿದಾಗ ನಿಮ್ಮಿಬ್ಬರಿಗೂ 1 ವಾರದ ಪ್ರೀಮಿಯಂ, ಯಾವುದೇ ಚಂದಾದಾರಿಕೆ ಖರೀದಿಸಿದಾಗ ತಲಾ 1 ತಿಂಗಳು ಸಿಗುತ್ತದೆ."},
}

// referralLandingLang picks the best supported language from Accept-Language.
func referralLandingLang(header string) string {
	for _, part := range strings.Split(header, ",") {
		lang := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if len(lang) >= 2 {
			if _, ok := referralLandingTexts[lang[:2]]; ok {
				return lang[:2]
			}
		}
	}
	return "en"
}

// referralLandingPage — GET /r/{code} (public). Self-contained HTML, no
// external assets. The code is sanitized to the code alphabet so it can be
// embedded directly.
func referralLandingPage(w http.ResponseWriter, r *http.Request) {
	code := strings.ToUpper(strings.TrimSpace(mux.Vars(r)["code"]))
	clean := make([]byte, 0, len(code))
	for i := 0; i < len(code) && i < 16; i++ {
		c := code[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			clean = append(clean, c)
		}
	}
	code = string(clean)
	if len(code) < 4 {
		http.NotFound(w, r)
		return
	}
	t := referralLandingTexts[referralLandingLang(r.Header.Get("Accept-Language"))]

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body{margin:0;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#12101f;color:#f0ecff;
display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center}
.card{max-width:420px;padding:40px 28px}
h1{font-size:1.5rem;line-height:1.35;margin:0 0 28px}
.label{font-size:.8rem;letter-spacing:.12em;text-transform:uppercase;color:#a89fd0;margin-bottom:10px}
.code{font-size:2.1rem;letter-spacing:.18em;font-weight:700;background:#241f3d;border:1px solid #4b3f7a;
border-radius:14px;padding:16px 10px;margin-bottom:26px;user-select:all}
p{color:#c9c2e8;font-size:.95rem;line-height:1.5}
.btn{display:block;margin:12px auto;padding:14px 20px;max-width:280px;border-radius:12px;background:#6c5ce7;
color:#fff;text-decoration:none;font-weight:600}
.terms{font-size:.75rem;color:#8d84b8;margin-top:30px}
</style></head><body><div class="card">
<h1>%s</h1>
<div class="label">%s</div>
<div class="code">%s</div>
<p>%s</p>
<a class="btn" href="%s">App Store</a>
<a class="btn" href="%s">Google Play</a>
<div class="terms">%s</div>
</div></body></html>`,
		t.title, t.offer, t.codeLabel, code, t.install,
		referralAppStoreURL, referralPlayStoreURL, t.terms)
}

// ---------------------------------------------------------------------------
// Google trial re-verification cron
//
// Google Play RTDN events carry no purchase_token → user mapping, so a trial
// conversion is invisible to the webhook (documented gap in google.go). We
// instead persist the purchase_token at recordPurchase time and poll the Play
// API until paymentState flips to 1 (payment received). That moment is the
// invitee's first real charge → paid referral reward AND the C2 first-purchase
// email (closing the old gap for Google trial users too).
// ---------------------------------------------------------------------------

// startGoogleTrialReverifier launches the polling loop. No-op when Google Play
// credentials are not configured.
func startGoogleTrialReverifier() {
	if GOOGLE_PLAY_CREDENTIALS_FILE == "" {
		log.Println("ℹ️ [referral] Google trial re-verifier disabled (no Play credentials)")
		return
	}
	go func() {
		time.Sleep(2 * time.Minute) // let startup settle
		for {
			reverifyGoogleTrials()
			time.Sleep(12 * time.Hour)
		}
	}()
}

// reverifyGoogleTrials checks every un-converted Google trial purchase from
// the last 90 days. Expired/cancelled trials never reach paymentState 1 and
// age out of the window naturally.
func reverifyGoogleTrials() {
	ensureReferralSchema()
	rows, err := db.Query(`SELECT id, email, COALESCE(device_id, ''), product_id, purchase_token
		FROM purchase_history
		WHERE store = 'google' AND COALESCE(is_trial, 0) = 1 AND trial_converted_at IS NULL
		  AND purchase_token IS NOT NULL AND purchase_token != ''
		  AND purchase_date > datetime('now', '-90 days')`)
	if err != nil {
		log.Printf("⚠️ [referral] trial re-verify query failed: %v", err)
		return
	}
	type trialRow struct {
		id                          int
		email, deviceID, productID, token string
	}
	var trials []trialRow
	for rows.Next() {
		var t trialRow
		if err := rows.Scan(&t.id, &t.email, &t.deviceID, &t.productID, &t.token); err == nil {
			trials = append(trials, t)
		}
	}
	rows.Close()
	if len(trials) == 0 {
		return
	}
	log.Printf("🔄 [referral] re-verifying %d Google trial purchase(s)", len(trials))
	for _, t := range trials {
		state, expiry, err := queryGooglePlaySubscriptionState(t.productID, t.token)
		if err != nil {
			log.Printf("⚠️ [referral] Play re-verify failed for %s: %v", t.email, err)
			continue
		}
		if state != 1 { // 1 = payment received; 2 = still in free trial
			continue
		}
		res, err := db.Exec(`UPDATE purchase_history SET trial_converted_at = CURRENT_TIMESTAMP
			WHERE id = ? AND trial_converted_at IS NULL`, t.id)
		if err != nil {
			continue
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue
		}
		log.Printf("💰 [referral] Google trial converted to paid: %s (%s)", t.email, t.productID)
		// Keep the subscription window current — RTDN can't do it for us.
		if expiry != nil && time.Now().Before(*expiry) {
			db.Exec(`UPDATE users SET subscription_type = 'paid', subscription_expiry = ?,
				updated_at = CURRENT_TIMESTAMP WHERE email = ?`, *expiry, t.email)
		}
		maybeSendFirstPurchaseEmail(t.email)
		maybeGrantReferralPaidReward(t.email, t.deviceID)
	}
}

// queryGooglePlaySubscriptionState fetches the raw paymentState + expiry for a
// subscription token. Unlike verifyGooglePlayPurchase it does not gate on
// GOOGLE_PLAY_VERIFY_PURCHASES and reports the trial state distinctly.
func queryGooglePlaySubscriptionState(productID, purchaseToken string) (int, *time.Time, error) {
	accessToken, err := getGooglePlayAccessToken()
	if err != nil {
		return 0, nil, fmt.Errorf("access token: %v", err)
	}
	apiURL := fmt.Sprintf(
		"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/subscriptions/%s/tokens/%s",
		GOOGLE_PLAY_PACKAGE_NAME, productID, purchaseToken)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, nil, fmt.Errorf("Play API %d: %s", resp.StatusCode, string(body))
	}
	var pr GooglePlayPurchaseResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		return 0, nil, err
	}
	var expiry *time.Time
	if pr.ExpiryTimeMillis != "" {
		if ms, perr := strconv.ParseInt(pr.ExpiryTimeMillis, 10, 64); perr == nil {
			t := time.UnixMilli(ms)
			expiry = &t
		}
	}
	return pr.PaymentState, expiry, nil
}

// ---------------------------------------------------------------------------
// Stellar Vault admin stats — GET /api/admin/referral-stats
//
// Feeds the dashboard's Referrals tab: who invited whom, what came of it
// (install / purchase), and which rewards were granted. Auth mirrors
// adminRenewalStats (admin_email + admin_secret query params on top of
// adminGuardMiddleware's IP limiter).
// ---------------------------------------------------------------------------

func adminReferralStats(w http.ResponseWriter, r *http.Request) {
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

	ensureReferralSchema()

	// Summary counters.
	var totalClaims, installGrants, paidGrants, uniqueInviters, codesIssued int
	db.QueryRow(`SELECT COUNT(*),
		COUNT(install_reward_granted_at),
		COUNT(paid_reward_granted_at),
		COUNT(DISTINCT inviter_email)
		FROM referrals`).Scan(&totalClaims, &installGrants, &paidGrants, &uniqueInviters)
	db.QueryRow(`SELECT COUNT(*) FROM users WHERE referral_code IS NOT NULL AND referral_code != ''`).
		Scan(&codesIssued)

	// Full claims list, newest first. LEFT JOIN pulls the inviter's share code.
	claims := []map[string]interface{}{}
	rows, err := db.Query(`SELECT r.inviter_email, COALESCE(u.referral_code, r.code),
			r.invitee_email, r.invitee_device_id, r.claimed_at,
			COALESCE(r.install_reward_granted_at, ''), COALESCE(r.paid_reward_granted_at, '')
		FROM referrals r LEFT JOIN users u ON u.email = r.inviter_email
		ORDER BY r.claimed_at DESC LIMIT 1000`)
	if err != nil {
		log.Printf("⚠️ [referral] admin stats query failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Database error"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var inviter, code, invitee, device, claimedAt, installAt, paidAt string
		if err := rows.Scan(&inviter, &code, &invitee, &device, &claimedAt, &installAt, &paidAt); err != nil {
			continue
		}
		result := "claimed"
		daysEach := 0
		if installAt != "" {
			result = "install"
			daysEach += referralInstallRewardDays
		}
		if paidAt != "" {
			result = "purchase"
			daysEach += referralPaidRewardDays
		}
		claims = append(claims, map[string]interface{}{
			"inviter_email":     inviter,
			"inviter_code":      code,
			"invitee_email":     invitee,
			"invitee_device_id": device,
			"claimed_at":        claimedAt,
			"install_reward_at": installAt,
			"paid_reward_at":    paidAt,
			"result":            result, // claimed | install | purchase (purchase implies install)
			"days_each_side":    daysEach,
		})
	}

	// Per-inviter leaderboard. Inviter install-reward days honor the cap the
	// claim handler enforces (invitee days are never capped).
	top := []map[string]interface{}{}
	trows, err := db.Query(`SELECT r.inviter_email, COALESCE(u.referral_code, ''),
			COUNT(*),
			COUNT(r.install_reward_granted_at),
			COUNT(r.paid_reward_granted_at),
			MAX(r.claimed_at)
		FROM referrals r LEFT JOIN users u ON u.email = r.inviter_email
		GROUP BY r.inviter_email
		ORDER BY COUNT(r.paid_reward_granted_at) DESC, COUNT(*) DESC
		LIMIT 100`)
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var inviter, code, lastClaim string
			var cnt, installs, paids int
			if err := trows.Scan(&inviter, &code, &cnt, &installs, &paids, &lastClaim); err != nil {
				continue
			}
			cappedInstalls := installs
			if cappedInstalls > referralInstallRewardCap {
				cappedInstalls = referralInstallRewardCap
			}
			top = append(top, map[string]interface{}{
				"inviter_email": inviter,
				"inviter_code":  code,
				"claims":        cnt,
				"installs":      installs,
				"purchases":     paids,
				"days_earned":   cappedInstalls*referralInstallRewardDays + paids*referralPaidRewardDays,
				"last_claim_at": lastClaim,
			})
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"summary": map[string]interface{}{
			"codes_issued":    codesIssued,
			"total_claims":    totalClaims,
			"install_rewards": installGrants,
			"paid_rewards":    paidGrants,
			"unique_inviters": uniqueInviters,
			// Days handed out across BOTH sides (invitee uncapped; the small
			// over-count past an inviter's install cap is ignored here — the
			// leaderboard shows the capped per-inviter number).
			"days_granted_both_sides": 2 * (installGrants*referralInstallRewardDays + paidGrants*referralPaidRewardDays),
		},
		"top_inviters": top,
		"claims":       claims,
	})
}
