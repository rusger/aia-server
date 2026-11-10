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
	"fmt"
	"strings"
)

// crisisLangOrder fixes the scan order so detection is deterministic when a
// marker exists in several languages ("suicide" is both en and fr). The first
// language to match supplies the primary hotline shown on top.
var crisisLangOrder = []string{
	"ru", "en", "es", "fr", "de", "it", "pt",
	"zh", "ja", "ko", "ar", "hi", "mr", "te", "ta", "kn",
}

// Markers are stored lowercase, «ё» as «е» and with a straight apostrophe:
// the input is normalized the same way once before matching. A marker's
// number in its list (ru#3) goes into the log line, never the text.
//
// 2026-11-10: word forms added in every language after «не хочется жить»
// in a diary note slipped past «не хочу жить» (owner: the screen must catch
// how people actually say it).
var crisisMarkers = map[string][]string{
	"ru": {
		"не хочу жить", "не хочу больше жить", "покончить с собой", "суицид",
		"нет смысла жить", "причинить себе вред", "лучше бы меня не было",
		"не вижу смысла продолжать", "хочу умереть", "наложить на себя руки",
		"свести счеты с жизнью",
		"не хочется жить", "жить не хочется", "жить не хочу", "незачем жить",
		"жить незачем", "надоело жить", "жить надоело", "нет сил жить",
		"устал жить", "устала жить", "хочется умереть", "лучше умереть",
		"лучше бы я умер", "убить себя", "покончу с собой", "хочу сдохнуть",
		"не вижу смысла жить", "смысла жить нет", "зачем мне жить",
	},
	"en": {
		"kill myself", "suicide", "end my life", "don't want to live",
		"do not want to live", "want to die", "hurt myself", "self-harm",
		"better off dead", "no reason to live",
		"dont want to live", "don't wanna live", "don't feel like living",
		"tired of living", "wish i was dead", "wish i were dead",
		"no point living", "no point in living", "killing myself",
		"take my own life", "not worth living", "end it all",
	},
	"es": {
		"suicidarme", "suicidio", "quitarme la vida", "no quiero vivir",
		"hacerme daño", "quiero morir", "mejor estar muerto",
		"no quiero seguir viviendo", "no tengo ganas de vivir",
		"acabar con mi vida", "me quiero morir", "quisiera morir",
		"no vale la pena vivir", "matarme",
	},
	"fr": {
		"me suicider", "suicide", "mettre fin à ma vie", "ne veux plus vivre",
		"me faire du mal", "envie de mourir", "veux mourir",
		"plus envie de vivre", "pas envie de vivre", "marre de vivre",
		"envie de me tuer", "voudrais mourir",
	},
	"de": {
		"selbstmord", "suizid", "mich umbringen", "nicht mehr leben",
		"das leben nehmen", "mich verletzen", "will sterben",
		"keine lust mehr zu leben", "nicht leben will", "lebensmüde",
		"mich töten", "sterben möchte", "möchte sterben",
	},
	"it": {
		"suicidarmi", "suicidio", "farla finita", "non voglio più vivere",
		"togliermi la vita", "farmi del male", "voglio morire",
		"non ho voglia di vivere", "non voglio vivere", "uccidermi",
		"vorrei morire",
	},
	"pt": {
		"suicídio", "suicidio", "me matar", "acabar com a minha vida",
		"não quero mais viver", "me machucar", "quero morrer",
		"não quero viver", "nao quero viver", "nao quero mais viver",
		"sem vontade de viver", "me suicidar", "queria morrer",
		"tirar minha vida", "tirar a minha vida",
	},
	"zh": {
		"自杀", "不想活", "想死", "结束生命", "轻生", "伤害自己",
		"活着没意思", "活不下去", "活着没有意义",
	},
	"ja": {
		"自殺", "死にたい", "消えたい", "生きたくない", "自傷",
		"生きていたくない", "生きる意味がない", "消えてしまいたい",
	},
	"ko": {
		"자살", "죽고 싶", "살고 싶지 않", "자해", "죽어버리",
		"죽고싶", "살고싶지 않", "살기 싫",
	},
	"ar": {
		"انتحار", "أريد أن أموت", "اريد ان اموت", "لا أريد أن أعيش",
		"لا اريد ان اعيش", "أؤذي نفسي", "اؤذي نفسي",
		"لا أريد العيش", "لا اريد العيش", "أتمنى الموت", "اتمنى الموت",
		"أقتل نفسي", "اقتل نفسي",
	},
	"hi": {
		"आत्महत्या", "मरना चाहता", "मरना चाहती", "जीना नहीं चाहता",
		"जीना नहीं चाहती", "खुद को नुकसान",
		"जीने का मन नहीं", "जीने की इच्छा नहीं", "मर जाना चाहता",
		"मर जाना चाहती", "खुद को मार",
	},
	"mr": {
		"आत्महत्या", "मरायचं आहे", "जगायचं नाही",
		"जगावंसं वाटत नाही", "जगण्यात अर्थ नाही", "मरावंसं वाटतं",
	},
	"te": {
		"ఆత్మహత్య", "చనిపోవాలని", "బతకాలని లేదు", "బ్రతకాలని లేదు",
	},
	"ta": {
		"தற்கொலை", "சாக விரும்புகிறேன்", "வாழ விருப்பம் இல்லை",
		"சாக வேண்டும்", "வாழ பிடிக்கவில்லை",
	},
	"kn": {
		"ಆತ್ಮಹತ್ಯೆ", "ಸಾಯಬೇಕು", "ಬದುಕಲು ಇಷ್ಟವಿಲ್ಲ", "ಬದುಕಲು ಇಷ್ಟ ಇಲ್ಲ",
	},
}

// crisisIdioms are everyday turns of speech that contain a marker but mean
// nothing of the kind («想死你了» = «miss you terribly»). They are cut out of
// the text BEFORE the markers are matched, so a real marker elsewhere in the
// same message still hits.
var crisisIdioms = []string{
	"想死你了", "想死我了", "死にたいくらい", "dying to",
	"умереть со смеху", "умереть от смеха", "kill myself laughing",
	"die of embarrassment", "want to die of embarrassment",
	"matarme de risa",
}

// crisisHeaders: one short, warm sentence pair per language. Kept deliberately
// brief — the user's actual answer continues right below the block.
var crisisHeaders = map[string]string{
	"ru": "Сработал предохранитель: в ваших словах есть фраза, которую мы всегда принимаем всерьёз. Если сейчас тяжело — с этим не нужно оставаться одному, специалисты помогут бесплатно и анонимно:",
	"en": "A safeguard was triggered: your words contain a phrase we always take seriously. If things are hard right now, you don't have to face this alone — trained people can help, free and confidential:",
	"es": "Se activó una protección: en tus palabras hay una frase que siempre tomamos en serio. Si ahora es difícil, no tienes que afrontarlo en soledad — hay especialistas que pueden ayudarte, gratis y de forma confidencial:",
	"fr": "Une protection s'est déclenchée : vos mots contiennent une phrase que nous prenons toujours au sérieux. Si c'est difficile en ce moment, vous n'avez pas à y faire face seul(e) — des professionnels peuvent vous aider, gratuitement et en toute confidentialité :",
	"de": "Eine Schutzfunktion hat angeschlagen: Ihre Worte enthalten einen Satz, den wir immer ernst nehmen. Wenn es gerade schwer ist, müssen Sie das nicht allein durchstehen — geschulte Menschen helfen Ihnen, kostenlos und vertraulich:",
	"it": "È scattata una protezione: nelle tue parole c'è una frase che prendiamo sempre sul serio. Se adesso è difficile, non devi affrontarlo da solo/a — ci sono specialisti che possono aiutarti, gratuitamente e in modo riservato:",
	"pt": "Uma proteção foi acionada: suas palavras contêm uma frase que sempre levamos a sério. Se agora está difícil, você não precisa enfrentar isso sozinho(a) — há especialistas que podem ajudar, de forma gratuita e confidencial:",
	"zh": "安全提示已触发：您的话中有一句我们始终认真对待的表达。如果您现在很难受，不必独自面对——专业人员可以为您提供免费、保密的帮助：",
	"ja": "セーフガードが作動しました：あなたの言葉に、私たちが常に真剣に受け止める表現が含まれていました。今つらいなら、ひとりで抱え込む必要はありません。無料・匿名で相談できる窓口があります：",
	"ko": "안전장치가 작동했습니다: 말씀하신 내용에 저희가 항상 진지하게 받아들이는 표현이 있습니다. 지금 힘드시다면 혼자 감당하지 않으셔도 됩니다 — 전문 상담원이 무료로, 비밀리에 도와드립니다:",
	"ar": "تم تفعيل إجراء الحماية: في كلماتك عبارة نأخذها دائماً على محمل الجد. إذا كان الأمر صعباً الآن، فلست مضطراً لمواجهته وحدك — هناك مختصون يمكنهم مساعدتك مجاناً وبسرية تامة:",
	"hi": "सुरक्षा व्यवस्था सक्रिय हुई: आपके शब्दों में एक ऐसा वाक्य है जिसे हम हमेशा गंभीरता से लेते हैं। अगर अभी कठिन लग रहा है, तो आपको इसका सामना अकेले नहीं करना है — प्रशिक्षित विशेषज्ञ निःशुल्क और गोपनीय सहायता दे सकते हैं:",
	"mr": "सुरक्षा यंत्रणा सक्रिय झाली: तुमच्या शब्दांत असे वाक्य आहे जे आम्ही नेहमी गांभीर्याने घेतो. आत्ता कठीण वाटत असेल तर हे एकट्याने सहन करण्याची गरज नाही — तज्ज्ञ मोफत आणि गोपनीय मदत करू शकतात:",
	"te": "భద్రతా వ్యవస్థ పనిచేసింది: మీ మాటల్లో మేము ఎప్పుడూ తీవ్రంగా తీసుకునే వాక్యం ఉంది. ఇప్పుడు కష్టంగా ఉంటే, దీన్ని ఒంటరిగా ఎదుర్కోవాల్సిన అవసరం లేదు — నిపుణులు ఉచితంగా, గోప్యంగా సహాయం చేయగలరు:",
	"ta": "பாதுகாப்பு அமைப்பு செயல்பட்டது: உங்கள் வார்த்தைகளில் நாங்கள் எப்போதும் தீவிரமாக எடுத்துக்கொள்ளும் ஒரு சொற்றொடர் உள்ளது. இப்போது கடினமாக இருந்தால், இதை தனியாக எதிர்கொள்ள வேண்டியதில்லை — நிபுணர்கள் இலவசமாகவும் ரகசியமாகவும் உதவ முடியும்:",
	"kn": "ಸುರಕ್ಷತಾ ವ್ಯವಸ್ಥೆ ಸಕ್ರಿಯವಾಯಿತು: ನಿಮ್ಮ ಮಾತುಗಳಲ್ಲಿ ನಾವು ಯಾವಾಗಲೂ ಗಂಭೀರವಾಗಿ ಪರಿಗಣಿಸುವ ಒಂದು ವಾಕ್ಯವಿದೆ. ಈಗ ಕಷ್ಟವಾಗಿದ್ದರೆ, ಇದನ್ನು ಒಬ್ಬಂಟಿಯಾಗಿ ಎದುರಿಸಬೇಕಾಗಿಲ್ಲ — ತಜ್ಞರು ಉಚಿತವಾಗಿ ಮತ್ತು ಗೌಪ್ಯವಾಗಿ ಸಹಾಯ ಮಾಡಬಹುದು:",
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
	hit, lang, _ := detectCrisisMarker(text)
	return hit, lang
}

// crisisNormalize lowercases, folds «ё» into «е» and curly apostrophes into
// straight ones, then cuts out the everyday idioms ([crisisIdioms]).
func crisisNormalize(text string) string {
	t := strings.ToLower(text)
	t = strings.NewReplacer("ё", "е", "’", "'", "‘", "'").Replace(t)
	for _, idiom := range crisisIdioms {
		t = strings.ReplaceAll(t, idiom, " ")
	}
	return t
}

// detectCrisisMarker also names the marker that hit as «lang#index» for the
// log: which word forms fire is how false positives get counted, and the
// user's text itself is never logged.
func detectCrisisMarker(text string) (bool, string, string) {
	if text == "" {
		return false, "", ""
	}
	lowered := crisisNormalize(text)
	for _, lang := range crisisLangOrder {
		for i, marker := range crisisMarkers[lang] {
			if strings.Contains(lowered, marker) {
				return true, lang, fmt.Sprintf("%s#%d", lang, i)
			}
		}
	}
	return false, "", ""
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
