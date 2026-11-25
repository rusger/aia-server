package main

// A212 (owner 25.11.2026, canon of every /astro/ content page): first
// paragraph → «Читать далее ниже ↓» (in-page link, smooth scroll) → app
// frame (personal horoscope + store buttons) → the page's content.
// Owner 14:55: «рамку надо ставить под первым абзацам… в конце первого абзаца
// поставить читать далее ниже и… стрелочка вниз и одновременно гиперссылка…
// чуть-чуть перемотай страницу ниже этого блока»; 14:56: «утвердите это как
// канон… на все остальные тоже на будущее шаблон».
//
// Done once in renderSeoLayout: any page with a <p class="lead"> gets it,
// new page types included. Only hubs (seoPage.hub: language hub, month hub —
// lists of links) are left out. TestSeoAppFrameOnEveryContentPage keeps it so.

import "strings"

// seoMoreAnchor is where «read more» lands: right after the app frame.
const seoMoreAnchor = "after-app"

// The frame's words are the site's own (astrolytix/locales/*.json
// featureDetails.horoscopes.title / .desc), copied verbatim;
// TestSeoAppFrameStringsMatchSite compares them when the site checkout is
// next to this one.
var seoAppTitle = map[string]string{
	"en": "Your Horoscopes",
	"es": "Tus horóscopos",
	"fr": "Vos horoscopes",
	"de": "Ihre Horoskope",
	"it": "I tuoi oroscopi",
	"pt": "Seus horóscopos",
	"ru": "Гороскопы",
	"zh": "您的星座运势",
	"ja": "あなたの運勢",
	"ko": "당신의 운세",
	"hi": "आपकी राशिफल",
	"ar": "أبراجك",
	"mr": "आपले राशिभविष्य",
	"te": "మీ జాతకఫలాలు",
	"ta": "உங்கள் ராசிபலன்கள்",
	"kn": "ನಿಮ್ಮ ರಾಶಿಫಲ",
}

var seoAppDesc = map[string]string{
	"en": "Get personalized horoscope forecasts for tomorrow, the coming week, month, and year. Our AI analyzes your unique birth chart to deliver accurate predictions tailored specifically to you.",
	"es": "Obtén pronósticos personalizados para mañana, la próxima semana, mes y año. Nuestra IA analiza tu carta natal única para entregar predicciones precisas adaptadas específicamente para ti.",
	"fr": "Obtenez des prévisions personnalisées pour demain, la semaine, le mois et l'année à venir. Notre IA analyse votre thème natal unique pour délivrer des prédictions précises adaptées spécifiquement à vous.",
	"de": "Erhalten Sie personalisierte Prognosen für morgen, die kommende Woche, den Monat und das Jahr. Unsere KI analysiert Ihr einzigartiges Geburtshoroskop, um genaue Vorhersagen speziell für Sie zu liefern.",
	"it": "Ottieni previsioni personalizzate per domani, la prossima settimana, mese e anno. La nostra IA analizza la tua carta natale unica per fornire previsioni accurate su misura per te.",
	"pt": "Obtenha previsões personalizadas para amanhã, a próxima semana, mês e ano. Nossa IA analisa seu mapa natal único para entregar previsões precisas adaptadas especificamente para você.",
	"ru": "Получайте персонализированные прогнозы на завтра, предстоящую неделю, месяц и год. Наш ИИ анализирует вашу уникальную карту рождения для точных предсказаний, адаптированных специально для вас.",
	"zh": "获取明天、下周、下月和来年的个性化预测。我们的AI分析您独特的本命星盘，为您量身定制准确的预测。",
	"ja": "明日、来週、来月、来年のパーソナライズされた予報を取得します。AIがあなた独自の出生チャートを分析し、特別にカスタマイズされた正確な予測を提供します。",
	"ko": "내일, 다음 주, 다음 달 및 내년에 대한 개인화된 예측을 받으세요. AI가 고유한 출생 차트를 분석하여 특별히 맞춤화된 정확한 예측을 제공합니다.",
	"hi": "कल, आने वाले सप्ताह, महीने और वर्ष के लिए व्यक्तिगत भविष्यवाणी प्राप्त करें। हमारा AI आपकी अनूठी जन्म कुंडली का विश्लेषण करता है और विशेष रूप से आपके लिए तैयार सटीक भविष्यवाणियां देता है।",
	"ar": "احصل على توقعات مخصصة للغد والأسبوع والشهر والسنة القادمة. يحلل الذكاء الاصطناعي لدينا خريطة ميلادك الفريدة لتقديم تنبؤات دقيقة مصممة خصيصًا لك.",
	"mr": "उद्या, येणारा आठवडा, महिना आणि वर्षासाठी वैयक्तिकृत राशिभविष्य मिळवा. आमचा AI आपल्या अद्वितीय जन्मकुंडलीचे विश्लेषण करून खास आपल्यासाठी तयार केलेली अचूक भाकिते देतो.",
	"te": "రేపటికి, రాబోయే వారానికి, నెలకు మరియు సంవత్సరానికి వ్యక్తిగతీకరించిన జాతకఫల భవిష్యవాణులను పొందండి. మా AI మీ ప్రత్యేకమైన జన్మ కుండలిని విశ్లేషించి, ప్రత్యేకంగా మీ కోసం రూపొందించిన ఖచ్చితమైన భవిష్యవాణులను అందిస్తుంది.",
	"ta": "நாளை, வரும் வாரம், மாதம் மற்றும் ஆண்டுக்கான தனிப்பயனாக்கப்பட்ட ராசிபலன் கணிப்புகளைப் பெறுங்கள். எங்கள் AI உங்கள் தனித்துவமான பிறப்பு ஜாதகத்தை பகுப்பாய்வு செய்து, உங்களுக்காகவே வடிவமைக்கப்பட்ட துல்லியமான கணிப்புகளை வழங்குகிறது.",
	"kn": "ನಾಳೆ, ಮುಂಬರುವ ವಾರ, ತಿಂಗಳು ಮತ್ತು ವರ್ಷಕ್ಕೆ ವೈಯಕ್ತಿಕಗೊಳಿಸಿದ ರಾಶಿಫಲ ಭವಿಷ್ಯವಾಣಿಗಳನ್ನು ಪಡೆಯಿರಿ. ನಮ್ಮ AI ನಿಮ್ಮ ವಿಶಿಷ್ಟ ಜನ್ಮ ಕುಂಡಲಿಯನ್ನು ವಿಶ್ಲೇಷಿಸಿ, ವಿಶೇಷವಾಗಿ ನಿಮಗಾಗಿ ಸಿದ್ಧಪಡಿಸಿದ ನಿಖರವಾದ ಭವಿಷ್ಯವಾಣಿಗಳನ್ನು ನೀಡುತ್ತದೆ.",
}

// seoReadMore: ru is the owner's own words; the others translate them.
var seoReadMore = map[string]string{
	"en": "Read more below",
	"es": "Sigue leyendo abajo",
	"fr": "Lire la suite ci-dessous",
	"de": "Weiterlesen unten",
	"it": "Continua a leggere sotto",
	"pt": "Continue lendo abaixo",
	"ru": "Читать далее ниже",
	"zh": "继续阅读下文",
	"ja": "続きは下へ",
	"ko": "아래에서 계속 읽기",
	"hi": "आगे नीचे पढ़ें",
	"ar": "تابع القراءة في الأسفل",
	"mr": "पुढे खाली वाचा",
	"te": "క్రింద మరింత చదవండి",
	"ta": "மேலும் கீழே படிக்கவும்",
	"kn": "ಮುಂದೆ ಕೆಳಗೆ ಓದಿ",
}

// withAppFrame inserts the read-more link at the end of the first lead
// paragraph and the app frame right after it. ok=false: no lead paragraph.
func withAppFrame(lang, body string) (string, bool) {
	const open = "<p class=\"lead\">"
	i := strings.Index(body, open)
	if i < 0 {
		return body, false
	}
	j := strings.Index(body[i:], "</p>")
	if j < 0 {
		return body, false
	}
	j += i
	more := " <a class=\"more\" href=\"#" + seoMoreAnchor + "\">" + esc(tr(seoReadMore, lang)) + "&nbsp;↓</a>"
	frame := "\n<section class=\"cta cta-top\"><h2>" + esc(tr(seoAppTitle, lang)) + "</h2><p>" + esc(tr(seoAppDesc, lang)) + "</p>" +
		"<div class=\"btns\"><a class=\"btn ios\" rel=\"noopener\" href=\"" + seoGoIOS + "?from=top\">" + esc(seoT("cta_ios", lang, nil)) + "</a>" +
		"<a class=\"btn alt android\" rel=\"noopener\" href=\"" + seoGoAndroid + "?from=top\">" + esc(seoT("cta_android", lang, nil)) + "</a></div></section>\n" +
		"<div id=\"" + seoMoreAnchor + "\"></div>"
	end := j + len("</p>")
	return body[:j] + more + "</p>" + frame + body[end:], true
}
