package main

// Strings of the Moon-sign month pages (seo_sign.go); merged into seoStr at
// init like seo_day_i18n.go. Placeholders: {sign}, {month}, {year}, {n}.

var seoSignStr = map[string]map[string]string{
	"sign_title": {
		"en": "{sign}: horoscope for {month} {year} by Moon sign (Vedic transits)",
		"es": "{sign}: horóscopo de {month} de {year} por signo lunar (tránsitos védicos)",
		"fr": "{sign} : horoscope de {month} {year} par signe lunaire (transits védiques)",
		"de": "{sign}: Horoskop für {month} {year} nach Mondzeichen (vedische Transite)",
		"it": "{sign}: oroscopo di {month} {year} per segno lunare (transiti vedici)",
		"pt": "{sign}: horóscopo de {month} de {year} por signo lunar (trânsitos védicos)",
		"ru": "{sign}: гороскоп на {month} {year} по лунному знаку (транзиты Джйотиш)",
		"zh": "{sign}：{year}年{month}月亮星座运势（吠陀过境）",
		"ja": "{sign}：{year}年{month}の月星座ホロスコープ（ヴェーダのトランジット）",
		"ko": "{sign}: {year}년 {month} 달 별자리 운세 (베다 트랜짓)",
		"hi": "{sign}: {month} {year} का चंद्र राशिफल (वैदिक गोचर)",
		"ar": "{sign}: توقعات {month} {year} حسب البرج القمري (عبور فيدي)",
		"mr": "{sign}: {month} {year} चे चंद्र राशिभविष्य (वैदिक गोचर)",
		"te": "{sign}: {month} {year} చంద్ర రాశి ఫలాలు (వేద గోచారం)",
		"ta": "{sign}: {month} {year} சந்திர ராசி பலன் (வேத கோட்சாரம்)",
		"kn": "{sign}: {month} {year} ಚಂದ್ರ ರಾಶಿ ಭವಿಷ್ಯ (ವೈದಿಕ ಗೋಚಾರ)",
	},
	"sign_h1": {
		"en": "{sign} in {month} {year}: horoscope by Moon sign",
		"es": "{sign} en {month} de {year}: horóscopo por signo lunar",
		"fr": "{sign} en {month} {year} : horoscope par signe lunaire",
		"de": "{sign} im {month} {year}: Horoskop nach Mondzeichen",
		"it": "{sign} a {month} {year}: oroscopo per segno lunare",
		"pt": "{sign} em {month} de {year}: horóscopo por signo lunar",
		"ru": "{sign}: {month} {year} по лунному знаку",
		"zh": "{sign} {year}年{month}：月亮星座运势",
		"ja": "{sign} {year}年{month}：月星座ホロスコープ",
		"ko": "{sign} {year}년 {month}: 달 별자리 운세",
		"hi": "{sign}, {month} {year}: चंद्र राशिफल",
		"ar": "{sign} في {month} {year}: توقعات البرج القمري",
		"mr": "{sign}, {month} {year}: चंद्र राशिभविष्य",
		"te": "{sign}, {month} {year}: చంద్ర రాశి ఫలాలు",
		"ta": "{sign}, {month} {year}: சந்திர ராசி பலன்",
		"kn": "{sign}, {month} {year}: ಚಂದ್ರ ರಾಶಿ ಭವಿಷ್ಯ",
	},
	"sign_transits_h": {
		"en": "Transits from your Moon sign in {month} {year}",
		"es": "Tránsitos desde tu signo lunar en {month} de {year}",
		"fr": "Transits depuis votre signe lunaire en {month} {year}",
		"de": "Transite von Ihrem Mondzeichen aus im {month} {year}",
		"it": "Transiti dal tuo segno lunare a {month} {year}",
		"pt": "Trânsitos a partir do seu signo lunar em {month} de {year}",
		"ru": "Транзиты от вашей Луны: {month} {year}",
		"zh": "{year}年{month}从月亮星座起算的过境",
		"ja": "{year}年{month}の月星座から見たトランジット",
		"ko": "{year}년 {month} 달 별자리 기준 트랜짓",
		"hi": "{month} {year} में आपकी चंद्र राशि से गोचर",
		"ar": "العبور من برجك القمري في {month} {year}",
		"mr": "{month} {year} मधील तुमच्या चंद्र राशीपासून गोचर",
		"te": "{month} {year} లో మీ చంద్ర రాశి నుండి గోచారం",
		"ta": "{month} {year} இல் உங்கள் சந்திர ராசியிலிருந்து கோட்சாரம்",
		"kn": "{month} {year} ರಲ್ಲಿ ನಿಮ್ಮ ಚಂದ್ರ ರಾಶಿಯಿಂದ ಗೋಚಾರ",
	},
	"col_house": {
		"en": "House from Moon", "es": "Casa desde la Luna", "fr": "Maison depuis la Lune", "de": "Haus vom Mond", "it": "Casa dalla Luna",
		"pt": "Casa a partir da Lua", "ru": "Дом от Луны", "zh": "从月亮起的宫位", "ja": "月からのハウス", "ko": "달 기준 하우스",
		"hi": "चंद्र से भाव", "ar": "البيت من القمر", "mr": "चंद्रापासून भाव", "te": "చంద్రుని నుండి భావం", "ta": "சந்திரனிலிருந்து பாவம்", "kn": "ಚಂದ್ರನಿಂದ ಭಾವ",
	},
	"house_n": {
		"en": "house {n}", "es": "casa {n}", "fr": "maison {n}", "de": "Haus {n}", "it": "casa {n}", "pt": "casa {n}", "ru": "дом {n}",
		"zh": "第{n}宫", "ja": "第{n}ハウス", "ko": "{n}하우스", "hi": "भाव {n}", "ar": "البيت {n}", "mr": "भाव {n}", "te": "భావం {n}", "ta": "பாவம் {n}", "kn": "ಭಾವ {n}",
	},
	"key_dates": {
		"en": "Key dates", "es": "Fechas clave", "fr": "Dates clés", "de": "Wichtige Daten", "it": "Date chiave", "pt": "Datas-chave", "ru": "Ключевые даты",
		"zh": "关键日期", "ja": "重要な日付", "ko": "주요 날짜", "hi": "मुख्य तिथियाँ", "ar": "تواريخ مهمة", "mr": "महत्त्वाच्या तारखा", "te": "ముఖ్యమైన తేదీలు", "ta": "முக்கிய தேதிகள்", "kn": "ಪ್ರಮುಖ ದಿನಾಂಕಗಳು",
	},
	"section_signs": {
		"en": "By Moon sign", "es": "Por signo lunar", "fr": "Par signe lunaire", "de": "Nach Mondzeichen", "it": "Per segno lunare", "pt": "Por signo lunar",
		"ru": "По лунному знаку", "zh": "按月亮星座", "ja": "月星座別", "ko": "달 별자리별", "hi": "चंद्र राशि के अनुसार", "ar": "حسب البرج القمري",
		"mr": "चंद्र राशीनुसार", "te": "చంద్ర రాశి ప్రకారం", "ta": "சந்திர ராசி வாரியாக", "kn": "ಚಂದ್ರ ರಾಶಿಯ ಪ್ರಕಾರ",
	},
	"moon_sign_note": {
		"en": "These forecasts are by the Moon sign (rashi) of Vedic astrology, not the Western Sun sign. The Astrolytix app shows your Moon sign from your birth data for free.",
		"es": "Estas previsiones son por el signo lunar (rashi) de la astrología védica, no por el signo solar occidental. La app Astrolytix muestra tu signo lunar gratis a partir de tus datos de nacimiento.",
		"fr": "Ces prévisions suivent le signe lunaire (rashi) de l'astrologie védique, pas le signe solaire occidental. L'application Astrolytix donne gratuitement votre signe lunaire à partir de vos données de naissance.",
		"de": "Diese Prognosen gelten für das Mondzeichen (Rashi) der vedischen Astrologie, nicht für das westliche Sonnenzeichen. Die Astrolytix-App zeigt Ihr Mondzeichen aus Ihren Geburtsdaten kostenlos an.",
		"it": "Queste previsioni seguono il segno lunare (rashi) dell'astrologia vedica, non il segno solare occidentale. L'app Astrolytix mostra gratis il tuo segno lunare dai dati di nascita.",
		"pt": "Estas previsões são pelo signo lunar (rashi) da astrologia védica, não pelo signo solar ocidental. O app Astrolytix mostra o seu signo lunar grátis a partir dos dados de nascimento.",
		"ru": "Прогноз по лунному знаку (раши) ведической астрологии, а не по западному солнечному знаку. Приложение Astrolytix бесплатно покажет ваш лунный знак по данным рождения.",
		"zh": "本运势按吠陀占星的月亮星座（Rashi）计算，而非西方太阳星座。Astrolytix 应用可根据出生信息免费显示您的月亮星座。",
		"ja": "この予測はヴェーダ占星術の月星座（ラーシ）によるもので、西洋の太陽星座ではありません。Astrolytix アプリは出生データから月星座を無料で表示します。",
		"ko": "이 예측은 베다 점성술의 달 별자리(라시) 기준이며 서양 태양 별자리가 아닙니다. Astrolytix 앱은 출생 정보로 달 별자리를 무료로 알려 줍니다.",
		"hi": "ये भविष्यफल वैदिक ज्योतिष की चंद्र राशि के अनुसार हैं, पश्चिमी सूर्य राशि के नहीं। Astrolytix ऐप जन्म विवरण से आपकी चंद्र राशि निःशुल्क दिखाता है।",
		"ar": "هذه التوقعات حسب البرج القمري (راشي) في علم التنجيم الفيدي، لا البرج الشمسي الغربي. يعرض تطبيق Astrolytix برجك القمري مجانًا من بيانات ميلادك.",
		"mr": "हे भविष्य वैदिक ज्योतिषाच्या चंद्र राशीनुसार आहे, पाश्चात्य सूर्य राशीनुसार नाही. Astrolytix अ‍ॅप जन्मतपशिलावरून तुमची चंद्र राशी मोफत दाखवते.",
		"te": "ఈ ఫలాలు వేద జ్యోతిష్య చంద్ర రాశి (రాశి) ప్రకారం, పాశ్చాత్య సూర్య రాశి ప్రకారం కాదు. Astrolytix యాప్ మీ జనన వివరాలతో చంద్ర రాశిని ఉచితంగా చూపిస్తుంది.",
		"ta": "இந்தப் பலன்கள் வேத ஜோதிடத்தின் சந்திர ராசி அடிப்படையிலானவை, மேற்கத்திய சூரிய ராசி அல்ல. Astrolytix செயலி உங்கள் பிறப்புத் தரவிலிருந்து சந்திர ராசியை இலவசமாகக் காட்டும்.",
		"kn": "ಈ ಭವಿಷ್ಯ ವೈದಿಕ ಜ್ಯೋತಿಷ್ಯದ ಚಂದ್ರ ರಾಶಿ ಆಧಾರಿತ, ಪಾಶ್ಚಾತ್ಯ ಸೂರ್ಯ ರಾಶಿಯಲ್ಲ. Astrolytix ಆಪ್ ನಿಮ್ಮ ಜನ್ಮ ವಿವರಗಳಿಂದ ಚಂದ್ರ ರಾಶಿಯನ್ನು ಉಚಿತವಾಗಿ ತೋರಿಸುತ್ತದೆ.",
	},
}

func init() {
	for k, v := range seoSignStr {
		seoStr[k] = v
	}
}
