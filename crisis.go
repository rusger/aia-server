package main

// Crisis-marker detection for the AI chat proxy.
//
// Design contract (owner decision, 2026-08-28):
//   - NON-BLOCKING: a hit never suppresses or alters the LLM call. The
//     localized hotline block is prepended to the normal reply text, so the
//     client renders it as an ordinary chat message — zero app changes.
//   - Matching is plain lowercase substring per language. False positives are
//     cheap by design (the user still gets their normal answer below the
//     block), so the lists lean toward over-triggering, never under.
//   - Only the LAST user-role message is scanned: earlier user messages are
//     history already scanned on their own turns, and generated analysis
//     prompts carry chart data, not user speech.
//
// Hotline numbers verified against official sources 2026-08-28 (Korea 109
// unified line since 2024-01-01, China 12356 nationwide since 2025-05,
// India Tele-MANAS 14416, UAE 800-HOPE, KSA NCMH 920033360).

import (
	"strings"
)

// crisisLangOrder fixes the scan order so detection is deterministic when a
// marker exists in several languages ("suicide" is both en and fr). The first
// language to match supplies the primary hotline shown on top.
var crisisLangOrder = []string{
	"ru", "en", "es", "fr", "de", "it", "pt",
	"zh", "ja", "ko", "ar", "hi", "mr", "te", "ta", "kn",
}

// Markers are stored lowercase; input is lowercased once before matching.
var crisisMarkers = map[string][]string{
	"ru": {
		"не хочу жить", "не хочу больше жить", "покончить с собой", "суицид",
		"нет смысла жить", "причинить себе вред", "лучше бы меня не было",
		"не вижу смысла продолжать", "хочу умереть", "наложить на себя руки",
		"свести счёты с жизнью", "свести счеты с жизнью",
	},
	"en": {
		"kill myself", "suicide", "end my life", "don't want to live",
		"do not want to live", "want to die", "hurt myself", "self-harm",
		"better off dead", "no reason to live",
	},
	"es": {
		"suicidarme", "suicidio", "quitarme la vida", "no quiero vivir",
		"hacerme daño", "quiero morir", "mejor estar muerto",
	},
	"fr": {
		"me suicider", "suicide", "mettre fin à ma vie", "ne veux plus vivre",
		"me faire du mal", "envie de mourir", "veux mourir",
	},
	"de": {
		"selbstmord", "suizid", "mich umbringen", "nicht mehr leben",
		"das leben nehmen", "mich verletzen", "will sterben",
	},
	"it": {
		"suicidarmi", "suicidio", "farla finita", "non voglio più vivere",
		"togliermi la vita", "farmi del male", "voglio morire",
	},
	"pt": {
		"suicídio", "suicidio", "me matar", "acabar com a minha vida",
		"não quero mais viver", "me machucar", "quero morrer",
	},
	"zh": {
		"自杀", "不想活", "想死", "结束生命", "轻生", "伤害自己",
	},
	"ja": {
		"自殺", "死にたい", "消えたい", "生きたくない", "自傷",
	},
	"ko": {
		"자살", "죽고 싶", "살고 싶지 않", "자해", "죽어버리",
	},
	"ar": {
		"انتحار", "أريد أن أموت", "اريد ان اموت", "لا أريد أن أعيش",
		"لا اريد ان اعيش", "أؤذي نفسي", "اؤذي نفسي",
	},
	"hi": {
		"आत्महत्या", "मरना चाहता", "मरना चाहती", "जीना नहीं चाहता",
		"जीना नहीं चाहती", "खुद को नुकसान",
	},
	"mr": {
		"आत्महत्या", "मरायचं आहे", "जगायचं नाही",
	},
	"te": {
		"ఆత్మహత్య", "చనిపోవాలని", "బతకాలని లేదు",
	},
	"ta": {
		"தற்கொலை", "சாக விரும்புகிறேன்", "வாழ விருப்பம் இல்லை",
	},
	"kn": {
		"ಆತ್ಮಹತ್ಯೆ", "ಸಾಯಬೇಕು", "ಬದುಕಲು ಇಷ್ಟವಿಲ್ಲ",
	},
}

// crisisHeaders: one short, warm sentence pair per language. Kept deliberately
// brief — the user's actual answer continues right below the block.
var crisisHeaders = map[string]string{
	"ru": "Похоже, вам сейчас очень тяжело. С этим не обязательно справляться в одиночку — живые специалисты готовы поддержать, бесплатно и анонимно:",
	"en": "It sounds like you are going through something really hard right now. You don't have to face this alone — trained people are ready to support you, free and confidential:",
	"es": "Parece que estás pasando por un momento muy difícil. No tienes que afrontarlo en soledad — hay especialistas dispuestos a apoyarte, gratis y de forma confidencial:",
	"fr": "Il semble que vous traversiez un moment très difficile. Vous n'avez pas à y faire face seul(e) — des professionnels sont prêts à vous soutenir, gratuitement et en toute confidentialité :",
	"de": "Es klingt, als wäre es gerade sehr schwer für Sie. Sie müssen das nicht allein durchstehen — geschulte Menschen sind für Sie da, kostenlos und vertraulich:",
	"it": "Sembra che tu stia attraversando un momento molto difficile. Non devi affrontarlo da solo/a — ci sono specialisti pronti a sostenerti, gratuitamente e in modo riservato:",
	"pt": "Parece que você está passando por um momento muito difícil. Você não precisa enfrentar isso sozinho(a) — há especialistas prontos para apoiar, de forma gratuita e confidencial:",
	"zh": "听起来您现在正经历非常艰难的时刻。您不必独自面对——专业人员随时准备为您提供免费、保密的支持：",
	"ja": "今、とてもつらい状況にいらっしゃるようです。ひとりで抱え込む必要はありません。無料・匿名で相談できる窓口があります：",
	"ko": "지금 매우 힘든 시간을 보내고 계신 것 같습니다. 혼자 감당하지 않으셔도 됩니다 — 전문 상담원이 무료로, 비밀리에 도와드립니다:",
	"ar": "يبدو أنك تمر بوقت عصيب جداً الآن. لست مضطراً لمواجهة هذا وحدك — هناك مختصون مستعدون لدعمك مجاناً وبسرية تامة:",
	"hi": "लगता है आप अभी बहुत कठिन समय से गुज़र रहे हैं। आपको इसका सामना अकेले नहीं करना है — प्रशिक्षित विशेषज्ञ निःशुल्क और गोपनीय सहायता के लिए तैयार हैं:",
	"mr": "असे दिसते की तुम्ही सध्या खूप कठीण काळातून जात आहात. हे एकट्याने सहन करण्याची गरज नाही — तज्ज्ञ मोफत आणि गोपनीय मदतीसाठी तयार आहेत:",
	"te": "మీరు ఇప్పుడు చాలా కష్టమైన సమయాన్ని ఎదుర్కొంటున్నట్లు అనిపిస్తోంది. దీన్ని ఒంటరిగా ఎదుర్కోవాల్సిన అవసరం లేదు — నిపుణులు ఉచితంగా, గోప్యంగా సహాయం చేయడానికి సిద్ధంగా ఉన్నారు:",
	"ta": "நீங்கள் இப்போது மிகவும் கடினமான நேரத்தை கடந்து செல்வது போல் தெரிகிறது. இதை தனியாக எதிர்கொள்ள வேண்டியதில்லை — நிபுணர்கள் இலவசமாகவும் ரகசியமாகவும் உதவ தயாராக உள்ளனர்:",
	"kn": "ನೀವು ಈಗ ತುಂಬಾ ಕಷ್ಟದ ಸಮಯದಲ್ಲಿದ್ದೀರಿ ಎಂದು ತೋರುತ್ತದೆ. ಇದನ್ನು ಒಬ್ಬಂಟಿಯಾಗಿ ಎದುರಿಸಬೇಕಾಗಿಲ್ಲ — ತಜ್ಞರು ಉಚಿತವಾಗಿ ಮತ್ತು ಗೌಪ್ಯವಾಗಿ ಸಹಾಯ ಮಾಡಲು ಸಿದ್ಧರಿದ್ದಾರೆ:",
}

// crisisPrimary maps a detected language to the hotline line(s) shown first —
// the caller's most likely country. Lines not in the standard list below are
// only shown here.
var crisisPrimary = map[string][]string{
	"ru": {"🇷🇺 8-800-2000-122 (24/7)"},
	"en": {"🇺🇸 🇨🇦 988 (24/7)"},
	"es": {"🇪🇸 024 (24/7)"},
	"fr": {"🇫🇷 3114 (24/7)"},
	"de": {"🇩🇪 0800 111 0 111 (24/7)"},
	"it": {"🇮🇹 02 2327 2327 (Telefono Amico)"},
	"pt": {"🇵🇹 213 544 545 (SOS Voz Amiga)", "🇧🇷 188 (CVV, 24/7)"},
	"zh": {"🇨🇳 12356"},
	"ja": {"🇯🇵 0120-279-338 (よりそいホットライン, 24/7)"},
	"ko": {"🇰🇷 109 (24/7)"},
	"ar": {"🇸🇦 920033360", "🇦🇪 800-4673 (HOPE)"},
	"hi": {"🇮🇳 14416 (Tele-MANAS, 24/7)"},
	"mr": {"🇮🇳 14416 (Tele-MANAS, 24/7)"},
	"te": {"🇮🇳 14416 (Tele-MANAS, 24/7)"},
	"ta": {"🇮🇳 14416 (Tele-MANAS, 24/7)"},
	"kn": {"🇮🇳 14416 (Tele-MANAS, 24/7)"},
}

// crisisStandardList — the owner-specified always-shown roster: USA, Russia,
// Canada, Europe, Japan, China, South Korea, Australia, New Zealand, Brazil,
// UAE, Saudi Arabia (+ India, since four app languages are Indian).
var crisisStandardList = []string{
	"🇺🇸 🇨🇦 988",
	"🇷🇺 8-800-2000-122",
	"🇪🇺 116 123",
	"🇯🇵 0120-279-338",
	"🇨🇳 12356",
	"🇰🇷 109",
	"🇦🇺 13 11 14",
	"🇳🇿 1737",
	"🇧🇷 188",
	"🇦🇪 800-4673",
	"🇸🇦 920033360",
	"🇮🇳 14416",
}

// detectCrisis reports whether text contains a crisis marker and the language
// of the first matching marker list.
func detectCrisis(text string) (bool, string) {
	if text == "" {
		return false, ""
	}
	lowered := strings.ToLower(text)
	for _, lang := range crisisLangOrder {
		for _, marker := range crisisMarkers[lang] {
			if strings.Contains(lowered, marker) {
				return true, lang
			}
		}
	}
	return false, ""
}

// lastUserMessage returns the content of the final role=="user" entry — the
// text the person actually typed this turn.
func lastUserMessage(messages []map[string]string) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i]["role"] == "user" {
			return messages[i]["content"]
		}
	}
	return ""
}

// crisisNotice renders the localized info block: header, the caller's likely
// country first, then the standard roster (minus lines already shown).
func crisisNotice(lang string) string {
	header, ok := crisisHeaders[lang]
	if !ok {
		header = crisisHeaders["en"]
	}
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	shown := map[string]bool{}
	for _, line := range crisisPrimary[lang] {
		b.WriteString("\n" + line)
		shown[line] = true
	}
	for _, line := range crisisStandardList {
		// A standard entry duplicates a primary one when the primary line is
		// the same number plus an annotation — compare by the number prefix.
		dup := false
		for p := range shown {
			if strings.HasPrefix(p, line) {
				dup = true
				break
			}
		}
		if !dup {
			b.WriteString("\n" + line)
		}
	}
	return b.String()
}
