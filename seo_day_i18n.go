package main

// Localized strings and name tables for the daily SEO pages (seo_day.go).
// Same inline-map structure as seo_i18n.go; ru is the reference locale and
// TestSeoStringsCoverAllLangs asserts 16-language coverage of every key in
// seoStr — these tables are merged into seoStr at init so the same test and
// seoT() serve them. Placeholders: {date}, {weekday}, {sign}, {nakshatra},
// {tithi}, {planet}, {month}, {year}, {n}.

var seoDayStr = map[string]map[string]string{
	"day_title": {
		"en": "Planetary positions on {date}: signs, nakshatras, tithi (Vedic)",
		"es": "Posiciones planetarias el {date}: signos, nakshatras, tithi (védico)",
		"fr": "Positions planétaires le {date} : signes, nakshatras, tithi (védique)",
		"de": "Planetenpositionen am {date}: Zeichen, Nakshatras, Tithi (vedisch)",
		"it": "Posizioni planetarie del {date}: segni, nakshatra, tithi (vedico)",
		"pt": "Posições planetárias em {date}: signos, nakshatras, tithi (védico)",
		"ru": "Положение планет {date}: знаки, накшатры, титхи (Джйотиш)",
		"zh": "{date} 行星位置：星座、纳克沙特拉、提提（吠陀）",
		"ja": "{date}の惑星位置：星座・ナクシャトラ・ティティ（ヴェーダ）",
		"ko": "{date} 행성 위치: 별자리, 나크샤트라, 티티 (베다)",
		"hi": "{date} की ग्रह स्थिति: राशि, नक्षत्र, तिथि (वैदिक)",
		"ar": "مواقع الكواكب في {date}: الأبراج، الناكشاترا، التيثي (فيدي)",
		"mr": "{date} ची ग्रहस्थिती: राशी, नक्षत्र, तिथी (वैदिक)",
		"te": "{date} గ్రహ స్థానాలు: రాశులు, నక్షత్రాలు, తిథి (వేద)",
		"ta": "{date} கிரக நிலைகள்: ராசி, நட்சத்திரம், திதி (வேத)",
		"kn": "{date} ಗ್ರಹ ಸ್ಥಾನಗಳು: ರಾಶಿ, ನಕ್ಷತ್ರ, ತಿಥಿ (ವೈದಿಕ)",
	},
	"day_h1": {
		"en": "Sky on {date}", "es": "El cielo del {date}", "fr": "Le ciel du {date}", "de": "Der Himmel am {date}",
		"it": "Il cielo del {date}", "pt": "O céu em {date}", "ru": "Небо {date}", "zh": "{date} 的星空",
		"ja": "{date}の空", "ko": "{date}의 하늘", "hi": "{date} का आकाश", "ar": "السماء في {date}",
		"mr": "{date} चे आकाश", "te": "{date} ఆకాశం", "ta": "{date} வானம்", "kn": "{date} ಆಕಾಶ",
	},
	"day_intro": {
		"en": "Sidereal positions of the nine grahas at 12:00 UTC on {date}: sign and degree, nakshatra with pada, direction of motion, the tithi of the day and the nearest planetary events.",
		"es": "Posiciones siderales de los nueve grahas a las 12:00 UTC del {date}: signo y grado, nakshatra con pada, sentido del movimiento, tithi del día y los eventos planetarios más cercanos.",
		"fr": "Positions sidérales des neuf grahas à 12:00 UTC le {date} : signe et degré, nakshatra avec pada, sens du mouvement, tithi du jour et événements planétaires les plus proches.",
		"de": "Siderische Positionen der neun Grahas um 12:00 UTC am {date}: Zeichen und Grad, Nakshatra mit Pada, Bewegungsrichtung, Tithi des Tages und die nächsten Planetenereignisse.",
		"it": "Posizioni siderali dei nove graha alle 12:00 UTC del {date}: segno e grado, nakshatra con pada, direzione del moto, tithi del giorno ed eventi planetari più vicini.",
		"pt": "Posições siderais dos nove grahas às 12:00 UTC em {date}: signo e grau, nakshatra com pada, sentido do movimento, tithi do dia e os eventos planetários mais próximos.",
		"ru": "Сидерические положения девяти грах на 12:00 UTC {date}: знак и градус, накшатра с падой, направление движения, титхи дня и ближайшие планетные события.",
		"zh": "{date} 12:00 UTC 九曜的恒星黄道位置：星座与度数、纳克沙特拉及其帕达、顺逆行、当日提提以及最近的行星事件。",
		"ja": "{date} 12:00 UTC における九曜のサイデリアル位置：星座と度数、ナクシャトラとパダ、順行・逆行、当日のティティ、直近の惑星イベント。",
		"ko": "{date} 12:00 UTC 기준 아홉 그라하의 항성 황도 위치: 별자리와 도수, 나크샤트라와 파다, 순행·역행, 그날의 티티, 가까운 행성 이벤트.",
		"hi": "{date} को 12:00 UTC पर नौ ग्रहों की निरयण स्थिति: राशि और अंश, नक्षत्र और पद, गति की दिशा, दिन की तिथि और निकटतम ग्रह घटनाएँ।",
		"ar": "المواقع النجمية للكواكب التسعة في {date} الساعة 12:00 بتوقيت UTC: البرج والدرجة، الناكشاترا مع البادا، اتجاه الحركة، تيثي اليوم وأقرب الأحداث الكوكبية.",
		"mr": "{date} रोजी 12:00 UTC ला नऊ ग्रहांची निरयन स्थिती: राशी आणि अंश, नक्षत्र व पद, गतीची दिशा, दिवसाची तिथी आणि जवळच्या ग्रह घटना.",
		"te": "{date} 12:00 UTC కు నవగ్రహాల నిరయన స్థానాలు: రాశి మరియు డిగ్రీ, నక్షత్రం పాదంతో, గమన దిశ, ఆ రోజు తిథి మరియు సమీప గ్రహ సంఘటనలు.",
		"ta": "{date} 12:00 UTC இல் நவகிரகங்களின் நிராயன நிலைகள்: ராசி மற்றும் பாகை, நட்சத்திரம் மற்றும் பாதம், இயக்கத் திசை, அன்றைய திதி மற்றும் அருகிலுள்ள கிரக நிகழ்வுகள்.",
		"kn": "{date} 12:00 UTC ಕ್ಕೆ ನವಗ್ರಹಗಳ ನಿರಯನ ಸ್ಥಾನಗಳು: ರಾಶಿ ಮತ್ತು ಡಿಗ್ರಿ, ನಕ್ಷತ್ರ ಮತ್ತು ಪಾದ, ಚಲನೆಯ ದಿಕ್ಕು, ಆ ದಿನದ ತಿಥಿ ಮತ್ತು ಹತ್ತಿರದ ಗ್ರಹ ಘಟನೆಗಳು.",
	},
	"today_title": {
		"en": "Planetary positions today, {date}: signs, nakshatras, tithi (Vedic)",
		"es": "Posiciones planetarias hoy, {date}: signos, nakshatras, tithi (védico)",
		"fr": "Positions planétaires aujourd'hui, {date} : signes, nakshatras, tithi (védique)",
		"de": "Planetenpositionen heute, {date}: Zeichen, Nakshatras, Tithi (vedisch)",
		"it": "Posizioni planetarie oggi, {date}: segni, nakshatra, tithi (vedico)",
		"pt": "Posições planetárias hoje, {date}: signos, nakshatras, tithi (védico)",
		"ru": "Положение планет сегодня, {date}: знаки, накшатры, титхи (Джйотиш)",
		"zh": "今日行星位置 {date}：星座、纳克沙特拉、提提（吠陀）",
		"ja": "今日の惑星位置 {date}：星座・ナクシャトラ・ティティ（ヴェーダ）",
		"ko": "오늘의 행성 위치 {date}: 별자리, 나크샤트라, 티티 (베다)",
		"hi": "आज की ग्रह स्थिति, {date}: राशि, नक्षत्र, तिथि (वैदिक)",
		"ar": "مواقع الكواكب اليوم، {date}: الأبراج، الناكشاترا، التيثي (فيدي)",
		"mr": "आजची ग्रहस्थिती, {date}: राशी, नक्षत्र, तिथी (वैदिक)",
		"te": "నేటి గ్రహ స్థానాలు, {date}: రాశులు, నక్షత్రాలు, తిథి (వేద)",
		"ta": "இன்றைய கிரக நிலைகள், {date}: ராசி, நட்சத்திரம், திதி (வேத)",
		"kn": "ಇಂದಿನ ಗ್ರಹ ಸ್ಥಾನಗಳು, {date}: ರಾಶಿ, ನಕ್ಷತ್ರ, ತಿಥಿ (ವೈದಿಕ)",
	},
	"today_h1": {
		"en": "Planets today: {date}", "es": "Planetas hoy: {date}", "fr": "Les planètes aujourd'hui : {date}", "de": "Planeten heute: {date}",
		"it": "I pianeti oggi: {date}", "pt": "Planetas hoje: {date}", "ru": "Планеты сегодня: {date}", "zh": "今日行星：{date}",
		"ja": "今日の惑星：{date}", "ko": "오늘의 행성: {date}", "hi": "आज के ग्रह: {date}", "ar": "الكواكب اليوم: {date}",
		"mr": "आजचे ग्रह: {date}", "te": "నేటి గ్రహాలు: {date}", "ta": "இன்றைய கிரகங்கள்: {date}", "kn": "ಇಂದಿನ ಗ್ರಹಗಳು: {date}",
	},
	"today_intro": {
		"en": "This page is recomputed every day from the same ephemeris the Astrolytix app uses. Positions are for 12:00 UTC; the sidereal (Lahiri) zodiac of Vedic astrology is used.",
		"es": "Esta página se recalcula cada día con la misma efeméride que usa la app Astrolytix. Posiciones a las 12:00 UTC; se usa el zodiaco sideral (Lahiri) de la astrología védica.",
		"fr": "Cette page est recalculée chaque jour avec la même éphéméride que l'application Astrolytix. Positions à 12:00 UTC ; zodiaque sidéral (Lahiri) de l'astrologie védique.",
		"de": "Diese Seite wird täglich mit derselben Ephemeride wie die Astrolytix-App neu berechnet. Positionen für 12:00 UTC; siderischer (Lahiri) Tierkreis der vedischen Astrologie.",
		"it": "Questa pagina viene ricalcolata ogni giorno con le stesse effemeridi usate dall'app Astrolytix. Posizioni alle 12:00 UTC; zodiaco siderale (Lahiri) dell'astrologia vedica.",
		"pt": "Esta página é recalculada todos os dias com a mesma efeméride usada pelo app Astrolytix. Posições às 12:00 UTC; zodíaco sideral (Lahiri) da astrologia védica.",
		"ru": "Страница пересчитывается каждый день по той же эфемериде, что использует приложение Astrolytix. Положения на 12:00 UTC; сидерический зодиак (Лахири) ведической астрологии.",
		"zh": "本页每天根据 Astrolytix 应用使用的同一星历重新计算。位置为 12:00 UTC；采用吠陀占星的恒星黄道（拉希里）。",
		"ja": "このページは Astrolytix アプリと同じ天体暦で毎日再計算されます。位置は 12:00 UTC、ヴェーダ占星術のサイデリアル（ラヒリ）獣帯を使用。",
		"ko": "이 페이지는 Astrolytix 앱이 사용하는 동일한 천체력으로 매일 다시 계산됩니다. 위치는 12:00 UTC 기준이며 베다 점성술의 항성(라히리) 황도대를 사용합니다.",
		"hi": "यह पृष्ठ हर दिन उसी पंचांग-गणना से पुनः बनता है जो Astrolytix ऐप उपयोग करता है। स्थितियाँ 12:00 UTC की हैं; वैदिक ज्योतिष का निरयण (लाहिरी) राशिचक्र।",
		"ar": "يُعاد حساب هذه الصفحة يوميًا من التقويم الفلكي نفسه الذي يستخدمه تطبيق Astrolytix. المواقع عند 12:00 UTC؛ البروج النجمية (لاهيري) في علم التنجيم الفيدي.",
		"mr": "हे पान दररोज Astrolytix अ‍ॅप वापरत असलेल्या त्याच पंचांग-गणनेने पुन्हा मोजले जाते. स्थिती 12:00 UTC च्या; वैदिक ज्योतिषाचे निरयन (लाहिरी) राशिचक्र.",
		"te": "ఈ పేజీ Astrolytix యాప్ ఉపయోగించే అదే పంచాంగ గణనతో ప్రతిరోజూ తిరిగి లెక్కించబడుతుంది. స్థానాలు 12:00 UTC కు; వేద జ్యోతిష్య నిరయన (లాహిరి) రాశిచక్రం.",
		"ta": "இந்தப் பக்கம் Astrolytix செயலி பயன்படுத்தும் அதே பஞ்சாங்கக் கணக்கீட்டால் தினமும் மீண்டும் கணக்கிடப்படுகிறது. நிலைகள் 12:00 UTC; வேத ஜோதிடத்தின் நிராயன (லாஹிரி) ராசிச்சக்கரம்.",
		"kn": "ಈ ಪುಟ Astrolytix ಆಪ್ ಬಳಸುವ ಅದೇ ಪಂಚಾಂಗ ಗಣನೆಯಿಂದ ಪ್ರತಿದಿನ ಮರು ಲೆಕ್ಕಹಾಕಲಾಗುತ್ತದೆ. ಸ್ಥಾನಗಳು 12:00 UTC; ವೈದಿಕ ಜ್ಯೋತಿಷ್ಯದ ನಿರಯನ (ಲಾಹಿರಿ) ರಾಶಿಚಕ್ರ.",
	},
	"month_title": {
		"en": "{month} {year}: daily planetary positions, nakshatras and tithis (Vedic)",
		"es": "{month} de {year}: posiciones planetarias diarias, nakshatras y tithis (védico)",
		"fr": "{month} {year} : positions planétaires quotidiennes, nakshatras et tithis (védique)",
		"de": "{month} {year}: tägliche Planetenpositionen, Nakshatras und Tithis (vedisch)",
		"it": "{month} {year}: posizioni planetarie giornaliere, nakshatra e tithi (vedico)",
		"pt": "{month} de {year}: posições planetárias diárias, nakshatras e tithis (védico)",
		"ru": "{month} {year}: положение планет по дням, накшатры и титхи (Джйотиш)",
		"zh": "{year}年{month}：每日行星位置、纳克沙特拉与提提（吠陀）",
		"ja": "{year}年{month}：毎日の惑星位置・ナクシャトラ・ティティ（ヴェーダ）",
		"ko": "{year}년 {month}: 일별 행성 위치, 나크샤트라, 티티 (베다)",
		"hi": "{month} {year}: दैनिक ग्रह स्थिति, नक्षत्र और तिथि (वैदिक)",
		"ar": "{month} {year}: مواقع الكواكب اليومية والناكشاترا والتيثي (فيدي)",
		"mr": "{month} {year}: दैनिक ग्रहस्थिती, नक्षत्रे आणि तिथी (वैदिक)",
		"te": "{month} {year}: రోజువారీ గ్రహ స్థానాలు, నక్షత్రాలు మరియు తిథులు (వేద)",
		"ta": "{month} {year}: தினசரி கிரக நிலைகள், நட்சத்திரங்கள் மற்றும் திதிகள் (வேத)",
		"kn": "{month} {year}: ದೈನಂದಿನ ಗ್ರಹ ಸ್ಥಾನಗಳು, ನಕ್ಷತ್ರಗಳು ಮತ್ತು ತಿಥಿಗಳು (ವೈದಿಕ)",
	},
	"month_intro": {
		"en": "One page per day: Moon sign and nakshatra, tithi and the positions of all nine grahas. Days are listed in UTC.",
		"es": "Una página por día: signo y nakshatra de la Luna, tithi y posiciones de los nueve grahas. Los días se listan en UTC.",
		"fr": "Une page par jour : signe et nakshatra de la Lune, tithi et positions des neuf grahas. Les jours sont indiqués en UTC.",
		"de": "Eine Seite pro Tag: Mondzeichen und Nakshatra, Tithi und die Positionen aller neun Grahas. Tage in UTC.",
		"it": "Una pagina per giorno: segno e nakshatra della Luna, tithi e posizioni dei nove graha. I giorni sono in UTC.",
		"pt": "Uma página por dia: signo e nakshatra da Lua, tithi e posições dos nove grahas. Dias listados em UTC.",
		"ru": "Одна страница на день: знак и накшатра Луны, титхи и положения всех девяти грах. Дни указаны по UTC.",
		"zh": "每日一页：月亮星座与纳克沙特拉、提提以及九曜的位置。日期按 UTC 列出。",
		"ja": "1日1ページ：月の星座とナクシャトラ、ティティ、九曜の位置。日付は UTC。",
		"ko": "하루 한 페이지: 달의 별자리와 나크샤트라, 티티, 아홉 그라하의 위치. 날짜는 UTC 기준.",
		"hi": "प्रति दिन एक पृष्ठ: चंद्र राशि और नक्षत्र, तिथि और नौ ग्रहों की स्थिति। दिन UTC में।",
		"ar": "صفحة لكل يوم: برج القمر وناكشاترا، التيثي ومواقع الكواكب التسعة. الأيام بتوقيت UTC.",
		"mr": "दररोज एक पान: चंद्र राशी आणि नक्षत्र, तिथी आणि नऊ ग्रहांची स्थिती. दिवस UTC नुसार.",
		"te": "రోజుకు ఒక పేజీ: చంద్ర రాశి మరియు నక్షత్రం, తిథి మరియు నవగ్రహాల స్థానాలు. రోజులు UTC లో.",
		"ta": "ஒரு நாளுக்கு ஒரு பக்கம்: சந்திர ராசி மற்றும் நட்சத்திரம், திதி மற்றும் நவகிரகங்களின் நிலைகள். நாட்கள் UTC படி.",
		"kn": "ದಿನಕ್ಕೊಂದು ಪುಟ: ಚಂದ್ರ ರಾಶಿ ಮತ್ತು ನಕ್ಷತ್ರ, ತಿಥಿ ಮತ್ತು ನವಗ್ರಹಗಳ ಸ್ಥಾನಗಳು. ದಿನಗಳು UTC ಪ್ರಕಾರ.",
	},
	"section_today": {
		"en": "Planets today", "es": "Planetas hoy", "fr": "Les planètes aujourd'hui", "de": "Planeten heute", "it": "I pianeti oggi",
		"pt": "Planetas hoje", "ru": "Планеты сегодня", "zh": "今日行星", "ja": "今日の惑星", "ko": "오늘의 행성", "hi": "आज के ग्रह",
		"ar": "الكواكب اليوم", "mr": "आजचे ग्रह", "te": "నేటి గ్రహాలు", "ta": "இன்றைய கிரகங்கள்", "kn": "ಇಂದಿನ ಗ್ರಹಗಳು",
	},
	"section_days": {
		"en": "Day by day", "es": "Día a día", "fr": "Jour par jour", "de": "Tag für Tag", "it": "Giorno per giorno", "pt": "Dia a dia",
		"ru": "По дням", "zh": "逐日", "ja": "日ごと", "ko": "일별", "hi": "दिन-प्रतिदिन", "ar": "يومًا بيوم", "mr": "दिवसागणिक",
		"te": "రోజువారీ", "ta": "நாள்தோறும்", "kn": "ದಿನದಿಂದ ದಿನಕ್ಕೆ",
	},
	"sun_line": {
		"en": "Sun in {sign}", "es": "Sol en {sign}", "fr": "Soleil en {sign}", "de": "Sonne in {sign}", "it": "Sole in {sign}", "pt": "Sol em {sign}",
		"ru": "Солнце в знаке {sign}", "zh": "太阳在{sign}", "ja": "太陽は{sign}", "ko": "태양은 {sign}", "hi": "सूर्य {sign} में", "ar": "الشمس في {sign}",
		"mr": "सूर्य {sign} मध्ये", "te": "సూర్యుడు {sign}లో", "ta": "சூரியன் {sign}ல்", "kn": "ಸೂರ್ಯ {sign}ದಲ್ಲಿ",
	},
	"moon_line": {
		"en": "Moon in {sign}, nakshatra {nakshatra}", "es": "Luna en {sign}, nakshatra {nakshatra}", "fr": "Lune en {sign}, nakshatra {nakshatra}",
		"de": "Mond in {sign}, Nakshatra {nakshatra}", "it": "Luna in {sign}, nakshatra {nakshatra}", "pt": "Lua em {sign}, nakshatra {nakshatra}",
		"ru": "Луна в знаке {sign}, накшатра {nakshatra}", "zh": "月亮在{sign}，纳克沙特拉 {nakshatra}", "ja": "月は{sign}、ナクシャトラ {nakshatra}",
		"ko": "달은 {sign}, 나크샤트라 {nakshatra}", "hi": "चंद्रमा {sign} में, नक्षत्र {nakshatra}", "ar": "القمر في {sign}، ناكشاترا {nakshatra}",
		"mr": "चंद्र {sign} मध्ये, नक्षत्र {nakshatra}", "te": "చంద్రుడు {sign}లో, నక్షత్రం {nakshatra}", "ta": "சந்திரன் {sign}ல், நட்சத்திரம் {nakshatra}",
		"kn": "ಚಂದ್ರ {sign}ದಲ್ಲಿ, ನಕ್ಷತ್ರ {nakshatra}",
	},
	"tithi_line": {
		"en": "Tithi: {tithi}", "es": "Tithi: {tithi}", "fr": "Tithi : {tithi}", "de": "Tithi: {tithi}", "it": "Tithi: {tithi}", "pt": "Tithi: {tithi}",
		"ru": "Титхи: {tithi}", "zh": "提提：{tithi}", "ja": "ティティ：{tithi}", "ko": "티티: {tithi}", "hi": "तिथि: {tithi}", "ar": "تيثي: {tithi}",
		"mr": "तिथी: {tithi}", "te": "తిథి: {tithi}", "ta": "திதி: {tithi}", "kn": "ತಿಥಿ: {tithi}",
	},
	"tithi_fmt": {
		"en": "{paksha} {tithi} ({n})", "es": "{paksha} {tithi} ({n})", "fr": "{paksha} {tithi} ({n})", "de": "{paksha} {tithi} ({n})",
		"it": "{paksha} {tithi} ({n})", "pt": "{paksha} {tithi} ({n})", "ru": "{paksha} {tithi} ({n})", "zh": "{paksha} {tithi}（{n}）",
		"ja": "{paksha} {tithi}（{n}）", "ko": "{paksha} {tithi} ({n})", "hi": "{paksha} {tithi} ({n})", "ar": "{paksha} {tithi} ({n})",
		"mr": "{paksha} {tithi} ({n})", "te": "{paksha} {tithi} ({n})", "ta": "{paksha} {tithi} ({n})", "kn": "{paksha} {tithi} ({n})",
	},
	"paksha_shukla": {
		"en": "Shukla", "es": "Shukla", "fr": "Shukla", "de": "Shukla", "it": "Shukla", "pt": "Shukla", "ru": "Шукла", "zh": "白分",
		"ja": "白分", "ko": "슈클라", "hi": "शुक्ल", "ar": "شوكلا", "mr": "शुक्ल", "te": "శుక్ల", "ta": "வளர்பிறை", "kn": "ಶುಕ್ಲ",
	},
	"paksha_krishna": {
		"en": "Krishna", "es": "Krishna", "fr": "Krishna", "de": "Krishna", "it": "Krishna", "pt": "Krishna", "ru": "Кришна", "zh": "黑分",
		"ja": "黒分", "ko": "크리슈나", "hi": "कृष्ण", "ar": "كريشنا", "mr": "कृष्ण", "te": "కృష్ణ", "ta": "தேய்பிறை", "kn": "ಕೃಷ್ಣ",
	},
	"pada_fmt": {
		"en": "{nakshatra}, pada {n}", "es": "{nakshatra}, pada {n}", "fr": "{nakshatra}, pada {n}", "de": "{nakshatra}, Pada {n}",
		"it": "{nakshatra}, pada {n}", "pt": "{nakshatra}, pada {n}", "ru": "{nakshatra}, пада {n}", "zh": "{nakshatra}，第 {n} 帕达",
		"ja": "{nakshatra}、パダ {n}", "ko": "{nakshatra}, 파다 {n}", "hi": "{nakshatra}, पद {n}", "ar": "{nakshatra}، بادا {n}",
		"mr": "{nakshatra}, पद {n}", "te": "{nakshatra}, పాదం {n}", "ta": "{nakshatra}, பாதம் {n}", "kn": "{nakshatra}, ಪಾದ {n}",
	},
	"col_degree": {
		"en": "Degree", "es": "Grado", "fr": "Degré", "de": "Grad", "it": "Grado", "pt": "Grau", "ru": "Градус", "zh": "度数", "ja": "度数",
		"ko": "도수", "hi": "अंश", "ar": "الدرجة", "mr": "अंश", "te": "డిగ్రీ", "ta": "பாகை", "kn": "ಡಿಗ್ರಿ",
	},
	"col_nakshatra": {
		"en": "Nakshatra", "es": "Nakshatra", "fr": "Nakshatra", "de": "Nakshatra", "it": "Nakshatra", "pt": "Nakshatra", "ru": "Накшатра",
		"zh": "纳克沙特拉", "ja": "ナクシャトラ", "ko": "나크샤트라", "hi": "नक्षत्र", "ar": "ناكشاترا", "mr": "नक्षत्र", "te": "నక్షత్రం", "ta": "நட்சத்திரம்", "kn": "ನಕ್ಷತ್ರ",
	},
	"col_tithi": {
		"en": "Tithi", "es": "Tithi", "fr": "Tithi", "de": "Tithi", "it": "Tithi", "pt": "Tithi", "ru": "Титхи", "zh": "提提", "ja": "ティティ",
		"ko": "티티", "hi": "तिथि", "ar": "تيثي", "mr": "तिथी", "te": "తిథి", "ta": "திதி", "kn": "ತಿಥಿ",
	},
	"col_motion": {
		"en": "Motion", "es": "Movimiento", "fr": "Mouvement", "de": "Bewegung", "it": "Moto", "pt": "Movimento", "ru": "Движение", "zh": "顺逆",
		"ja": "順逆", "ko": "순역", "hi": "गति", "ar": "الحركة", "mr": "गती", "te": "గమనం", "ta": "இயக்கம்", "kn": "ಚಲನೆ",
	},
	"motion_direct": {
		"en": "direct", "es": "directo", "fr": "direct", "de": "direktläufig", "it": "diretto", "pt": "direto", "ru": "директное", "zh": "顺行",
		"ja": "順行", "ko": "순행", "hi": "मार्गी", "ar": "مستقيم", "mr": "मार्गी", "te": "మార్గి", "ta": "நேர்", "kn": "ಮಾರ್ಗಿ",
	},
	"motion_retro": {
		"en": "retrograde", "es": "retrógrado", "fr": "rétrograde", "de": "rückläufig", "it": "retrogrado", "pt": "retrógrado", "ru": "ретроградное",
		"zh": "逆行", "ja": "逆行", "ko": "역행", "hi": "वक्री", "ar": "تراجعي", "mr": "वक्री", "te": "వక్ర", "ta": "வக்ர", "kn": "ವಕ್ರ",
	},
	"events_today": {
		"en": "Events on this day", "es": "Eventos de este día", "fr": "Événements de ce jour", "de": "Ereignisse an diesem Tag", "it": "Eventi di questo giorno",
		"pt": "Eventos deste dia", "ru": "События этого дня", "zh": "当日事件", "ja": "この日のイベント", "ko": "이날의 이벤트", "hi": "इस दिन की घटनाएँ",
		"ar": "أحداث هذا اليوم", "mr": "या दिवसाच्या घटना", "te": "ఈ రోజు సంఘటనలు", "ta": "இந்த நாளின் நிகழ்வுகள்", "kn": "ಈ ದಿನದ ಘಟನೆಗಳು",
	},
	"no_events": {
		"en": "No sign changes, stations, lunations or eclipses on this day.",
		"es": "Sin cambios de signo, estaciones, lunaciones ni eclipses este día.",
		"fr": "Aucun changement de signe, station, lunaison ni éclipse ce jour-là.",
		"de": "Keine Zeichenwechsel, Stationen, Lunationen oder Finsternisse an diesem Tag.",
		"it": "Nessun cambio di segno, stazione, lunazione o eclissi in questo giorno.",
		"pt": "Sem mudanças de signo, estações, lunações ou eclipses neste dia.",
		"ru": "В этот день нет смен знаков, станций, новолуний, полнолуний и затмений.",
		"zh": "当日无换座、留、朔望或日月食。",
		"ja": "この日は星座移動・留・朔望・食はありません。",
		"ko": "이날은 별자리 이동, 유(留), 삭망, 식이 없습니다.",
		"hi": "इस दिन कोई राशि परिवर्तन, स्थिरता, अमावस्या-पूर्णिमा या ग्रहण नहीं।",
		"ar": "لا تغيّر أبراج ولا توقّفات ولا أهلّة ولا كسوف في هذا اليوم.",
		"mr": "या दिवशी राशी बदल, स्थिरता, अमावास्या-पौर्णिमा किंवा ग्रहण नाही.",
		"te": "ఈ రోజు రాశి మార్పులు, స్థంభనలు, అమావాస్య-పౌర్ణమి లేదా గ్రహణాలు లేవు.",
		"ta": "இந்த நாளில் ராசி மாற்றம், நிலைமாற்றம், அமாவாசை-பௌர்ணமி அல்லது கிரகணம் இல்லை.",
		"kn": "ಈ ದಿನ ರಾಶಿ ಬದಲಾವಣೆ, ಸ್ಥಂಭನ, ಅಮಾವಾಸ್ಯೆ-ಹುಣ್ಣಿಮೆ ಅಥವಾ ಗ್ರಹಣ ಇಲ್ಲ.",
	},
	"upcoming": {
		"en": "Upcoming events", "es": "Próximos eventos", "fr": "Événements à venir", "de": "Bevorstehende Ereignisse", "it": "Prossimi eventi",
		"pt": "Próximos eventos", "ru": "Ближайшие события", "zh": "即将发生的事件", "ja": "今後のイベント", "ko": "다가오는 이벤트", "hi": "आगामी घटनाएँ",
		"ar": "الأحداث القادمة", "mr": "आगामी घटना", "te": "రాబోయే సంఘటనలు", "ta": "வரவிருக்கும் நிகழ்வுகள்", "kn": "ಮುಂಬರುವ ಘಟನೆಗಳು",
	},
	"station_retro": {
		"en": "{planet} turns retrograde", "es": "{planet} se vuelve retrógrado", "fr": "{planet} devient rétrograde", "de": "{planet} wird rückläufig",
		"it": "{planet} diventa retrogrado", "pt": "{planet} fica retrógrado", "ru": "{planet}: начало ретроградности", "zh": "{planet}开始逆行",
		"ja": "{planet}が逆行開始", "ko": "{planet} 역행 시작", "hi": "{planet} वक्री होता है", "ar": "{planet} يبدأ التراجع",
		"mr": "{planet} वक्री होतो", "te": "{planet} వక్రం అవుతుంది", "ta": "{planet} வக்ரமாகிறது", "kn": "{planet} ವಕ್ರವಾಗುತ್ತದೆ",
	},
	"station_direct": {
		"en": "{planet} turns direct", "es": "{planet} vuelve a ser directo", "fr": "{planet} redevient direct", "de": "{planet} wird wieder direktläufig",
		"it": "{planet} torna diretto", "pt": "{planet} volta a ser direto", "ru": "{planet}: конец ретроградности", "zh": "{planet}恢复顺行",
		"ja": "{planet}が順行に戻る", "ko": "{planet} 순행 전환", "hi": "{planet} मार्गी होता है", "ar": "{planet} يعود مستقيمًا",
		"mr": "{planet} मार्गी होतो", "te": "{planet} మార్గి అవుతుంది", "ta": "{planet} நேர்நிலைக்கு திரும்புகிறது", "kn": "{planet} ಮಾರ್ಗಿಯಾಗುತ್ತದೆ",
	},
	"prev_day": {
		"en": "Previous day", "es": "Día anterior", "fr": "Jour précédent", "de": "Vortag", "it": "Giorno precedente", "pt": "Dia anterior",
		"ru": "Предыдущий день", "zh": "前一天", "ja": "前日", "ko": "전날", "hi": "पिछला दिन", "ar": "اليوم السابق", "mr": "मागील दिवस",
		"te": "మునుపటి రోజు", "ta": "முந்தைய நாள்", "kn": "ಹಿಂದಿನ ದಿನ",
	},
	"next_day": {
		"en": "Next day", "es": "Día siguiente", "fr": "Jour suivant", "de": "Folgetag", "it": "Giorno successivo", "pt": "Dia seguinte",
		"ru": "Следующий день", "zh": "后一天", "ja": "翌日", "ko": "다음날", "hi": "अगला दिन", "ar": "اليوم التالي", "mr": "पुढील दिवस",
		"te": "తదుపరి రోజు", "ta": "அடுத்த நாள்", "kn": "ಮುಂದಿನ ದಿನ",
	},
	"this_month": {
		"en": "Whole month", "es": "Todo el mes", "fr": "Tout le mois", "de": "Ganzer Monat", "it": "Tutto il mese", "pt": "Mês inteiro",
		"ru": "Весь месяц", "zh": "整月", "ja": "月全体", "ko": "한 달 전체", "hi": "पूरा महीना", "ar": "الشهر كله", "mr": "संपूर्ण महिना",
		"te": "మొత్తం నెల", "ta": "முழு மாதம்", "kn": "ಇಡೀ ತಿಂಗಳು",
	},
	"dated_link": {
		"en": "Permanent page for this date", "es": "Página permanente de esta fecha", "fr": "Page permanente de cette date", "de": "Dauerhafte Seite dieses Datums",
		"it": "Pagina permanente di questa data", "pt": "Página permanente desta data", "ru": "Постоянная страница этой даты", "zh": "此日期的固定页面",
		"ja": "この日付の固定ページ", "ko": "이 날짜의 고정 페이지", "hi": "इस तिथि का स्थायी पृष्ठ", "ar": "الصفحة الدائمة لهذا التاريخ",
		"mr": "या तारखेचे कायमचे पान", "te": "ఈ తేదీ శాశ్వత పేజీ", "ta": "இந்தத் தேதியின் நிரந்தரப் பக்கம்", "kn": "ಈ ದಿನಾಂಕದ ಶಾಶ್ವತ ಪುಟ",
	},
	"noon_note": {
		"en": "Positions at 12:00 UTC; motion is the change between this noon and the previous one. Rahu and Ketu are the mean nodes and always move backwards.",
		"es": "Posiciones a las 12:00 UTC; el movimiento es el cambio entre este mediodía y el anterior. Rahu y Ketu son los nodos medios y siempre retroceden.",
		"fr": "Positions à 12:00 UTC ; le mouvement est la variation entre ce midi et le précédent. Rahu et Ketu sont les nœuds moyens et reculent toujours.",
		"de": "Positionen um 12:00 UTC; die Bewegung ist die Änderung zwischen diesem und dem vorigen Mittag. Rahu und Ketu sind die mittleren Knoten und laufen immer rückwärts.",
		"it": "Posizioni alle 12:00 UTC; il moto è la variazione tra questo mezzogiorno e il precedente. Rahu e Ketu sono i nodi medi e si muovono sempre all'indietro.",
		"pt": "Posições às 12:00 UTC; o movimento é a variação entre este meio-dia e o anterior. Rahu e Ketu são os nodos médios e sempre andam para trás.",
		"ru": "Положения на 12:00 UTC; движение — изменение между этим полднем и предыдущим. Раху и Кету — средние узлы, всегда идут назад.",
		"zh": "位置为 12:00 UTC；顺逆以本日正午与前一日正午之差判定。罗睺与计都为平均交点，始终逆行。",
		"ja": "位置は 12:00 UTC。順逆は当日正午と前日正午の差で判定。ラーフとケートゥは平均交点で常に逆行。",
		"ko": "위치는 12:00 UTC 기준이며 순역은 당일 정오와 전날 정오의 차이로 판정합니다. 라후와 케투는 평균 교점으로 항상 역행합니다.",
		"hi": "स्थितियाँ 12:00 UTC की; गति इस दोपहर और पिछली दोपहर के बीच का अंतर है। राहु-केतु मध्यम पात हैं और सदा वक्री रहते हैं।",
		"ar": "المواقع عند 12:00 UTC؛ الحركة هي الفرق بين هذا الظهر والظهر السابق. راهو وكيتو عقدتان متوسطتان وتتحركان دائمًا إلى الخلف.",
		"mr": "स्थिती 12:00 UTC च्या; गती म्हणजे या दुपार व मागील दुपारमधील फरक. राहू-केतू मध्यम पात असून नेहमी वक्री असतात.",
		"te": "స్థానాలు 12:00 UTC కు; గమనం ఈ మధ్యాహ్నం మరియు మునుపటి మధ్యాహ్నం మధ్య మార్పు. రాహు-కేతువులు సగటు పాతాలు, ఎల్లప్పుడూ వక్రంగా ఉంటాయి.",
		"ta": "நிலைகள் 12:00 UTC; இயக்கம் இன்றைய நண்பகலுக்கும் முந்தைய நண்பகலுக்கும் இடையிலான மாற்றம். ராகு-கேது சராசரி முனைகள், எப்போதும் பின்னோக்கிச் செல்லும்.",
		"kn": "ಸ್ಥಾನಗಳು 12:00 UTC; ಚಲನೆ ಈ ಮಧ್ಯಾಹ್ನ ಮತ್ತು ಹಿಂದಿನ ಮಧ್ಯಾಹ್ನದ ನಡುವಿನ ಬದಲಾವಣೆ. ರಾಹು-ಕೇತು ಸರಾಸರಿ ಪಾತಗಳು, ಯಾವಾಗಲೂ ವಕ್ರ.",
	},
}

// Month names, nominative (zh/ja/ko use numerals via seoDate).
var seoMonthNames = map[string][12]string{
	"en": {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"},
	"es": {"enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"},
	"fr": {"janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"},
	"de": {"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"},
	"it": {"gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"},
	"pt": {"janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"},
	"ru": {"январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"},
	"zh": {"1月", "2月", "3月", "4月", "5月", "6月", "7月", "8月", "9月", "10月", "11月", "12月"},
	"ja": {"1月", "2月", "3月", "4月", "5月", "6月", "7月", "8月", "9月", "10月", "11月", "12月"},
	"ko": {"1월", "2월", "3월", "4월", "5월", "6월", "7월", "8월", "9월", "10월", "11월", "12월"},
	"hi": {"जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"},
	"ar": {"يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو", "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"},
	"mr": {"जानेवारी", "फेब्रुवारी", "मार्च", "एप्रिल", "मे", "जून", "जुलै", "ऑगस्ट", "सप्टेंबर", "ऑक्टोबर", "नोव्हेंबर", "डिसेंबर"},
	"te": {"జనవరి", "ఫిబ్రవరి", "మార్చి", "ఏప్రిల్", "మే", "జూన్", "జూలై", "ఆగస్టు", "సెప్టెంబర్", "అక్టోబర్", "నవంబర్", "డిసెంబర్"},
	"ta": {"ஜனவரி", "பிப்ரவரி", "மார்ச்", "ஏப்ரல்", "மே", "ஜூன்", "ஜூலை", "ஆகஸ்ட்", "செப்டம்பர்", "அக்டோபர்", "நவம்பர்", "டிசம்பர்"},
	"kn": {"ಜನವರಿ", "ಫೆಬ್ರವರಿ", "ಮಾರ್ಚ್", "ಏಪ್ರಿಲ್", "ಮೇ", "ಜೂನ್", "ಜುಲೈ", "ಆಗಸ್ಟ್", "ಸೆಪ್ಟೆಂಬರ್", "ಅಕ್ಟೋಬರ್", "ನವೆಂಬರ್", "ಡಿಸೆಂಬರ್"},
}

// Russian month names in the genitive, for "12 октября 2026".
var seoMonthGenitiveRu = [12]string{"января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"}

// Weekday names, Sunday first (time.Weekday order).
var seoWeekdayNames = map[string][7]string{
	"en": {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"},
	"es": {"domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"},
	"fr": {"dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"},
	"de": {"Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"},
	"it": {"domenica", "lunedì", "martedì", "mercoledì", "giovedì", "venerdì", "sabato"},
	"pt": {"domingo", "segunda-feira", "terça-feira", "quarta-feira", "quinta-feira", "sexta-feira", "sábado"},
	"ru": {"воскресенье", "понедельник", "вторник", "среда", "четверг", "пятница", "суббота"},
	"zh": {"星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六"},
	"ja": {"日曜日", "月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日"},
	"ko": {"일요일", "월요일", "화요일", "수요일", "목요일", "금요일", "토요일"},
	"hi": {"रविवार", "सोमवार", "मंगलवार", "बुधवार", "गुरुवार", "शुक्रवार", "शनिवार"},
	"ar": {"الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت"},
	"mr": {"रविवार", "सोमवार", "मंगळवार", "बुधवार", "गुरुवार", "शुक्रवार", "शनिवार"},
	"te": {"ఆదివారం", "సోమవారం", "మంగళవారం", "బుధవారం", "గురువారం", "శుక్రవారం", "శనివారం"},
	"ta": {"ஞாயிறு", "திங்கள்", "செவ்வாய்", "புதன்", "வியாழன்", "வெள்ளி", "சனி"},
	"kn": {"ಭಾನುವಾರ", "ಸೋಮವಾರ", "ಮಂಗಳವಾರ", "ಬುಧವಾರ", "ಗುರುವಾರ", "ಶುಕ್ರವಾರ", "ಶನಿವಾರ"},
}

// The 27 nakshatras from Ashwini. Latin-script languages use the common
// IAST-less transliteration; Indic languages their own script; zh/ja the
// classical lunar-mansion names (宿曜 correspondence, Abhijit/牛宿 omitted)
// with the Sanskrit name alongside, since both spellings are searched for.
var seoNakshatraNames = map[string][27]string{
	"en": {"Ashwini", "Bharani", "Krittika", "Rohini", "Mrigashira", "Ardra", "Punarvasu", "Pushya", "Ashlesha", "Magha", "Purva Phalguni", "Uttara Phalguni", "Hasta", "Chitra", "Swati", "Vishakha", "Anuradha", "Jyeshtha", "Mula", "Purva Ashadha", "Uttara Ashadha", "Shravana", "Dhanishta", "Shatabhisha", "Purva Bhadrapada", "Uttara Bhadrapada", "Revati"},
	"ru": {"Ашвини", "Бхарани", "Криттика", "Рохини", "Мригашира", "Ардра", "Пунарвасу", "Пушья", "Ашлеша", "Магха", "Пурва Пхалгуни", "Уттара Пхалгуни", "Хаста", "Читра", "Свати", "Вишакха", "Анурадха", "Джьештха", "Мула", "Пурва Ашадха", "Уттара Ашадха", "Шравана", "Дхаништха", "Шатабхиша", "Пурва Бхадрапада", "Уттара Бхадрапада", "Ревати"},
	"zh": {"娄宿 (Ashwini)", "胃宿 (Bharani)", "昴宿 (Krittika)", "毕宿 (Rohini)", "觜宿 (Mrigashira)", "参宿 (Ardra)", "井宿 (Punarvasu)", "鬼宿 (Pushya)", "柳宿 (Ashlesha)", "星宿 (Magha)", "张宿 (Purva Phalguni)", "翼宿 (Uttara Phalguni)", "轸宿 (Hasta)", "角宿 (Chitra)", "亢宿 (Swati)", "氐宿 (Vishakha)", "房宿 (Anuradha)", "心宿 (Jyeshtha)", "尾宿 (Mula)", "箕宿 (Purva Ashadha)", "斗宿 (Uttara Ashadha)", "女宿 (Shravana)", "虚宿 (Dhanishta)", "危宿 (Shatabhisha)", "室宿 (Purva Bhadrapada)", "壁宿 (Uttara Bhadrapada)", "奎宿 (Revati)"},
	"ja": {"婁宿 (Ashwini)", "胃宿 (Bharani)", "昴宿 (Krittika)", "畢宿 (Rohini)", "觜宿 (Mrigashira)", "参宿 (Ardra)", "井宿 (Punarvasu)", "鬼宿 (Pushya)", "柳宿 (Ashlesha)", "星宿 (Magha)", "張宿 (Purva Phalguni)", "翼宿 (Uttara Phalguni)", "軫宿 (Hasta)", "角宿 (Chitra)", "亢宿 (Swati)", "氐宿 (Vishakha)", "房宿 (Anuradha)", "心宿 (Jyeshtha)", "尾宿 (Mula)", "箕宿 (Purva Ashadha)", "斗宿 (Uttara Ashadha)", "女宿 (Shravana)", "虚宿 (Dhanishta)", "危宿 (Shatabhisha)", "室宿 (Purva Bhadrapada)", "壁宿 (Uttara Bhadrapada)", "奎宿 (Revati)"},
	"ko": {"아슈위니", "바라니", "크리티카", "로히니", "므리가시라", "아르드라", "푸나르바수", "푸쉬야", "아슐레샤", "마가", "푸르바 팔구니", "우타라 팔구니", "하스타", "치트라", "스와티", "비샤카", "아누라다", "지예슈타", "물라", "푸르바 아샤다", "우타라 아샤다", "슈라바나", "다니슈타", "샤타비샤", "푸르바 바드라파다", "우타라 바드라파다", "레바티"},
	"hi": {"अश्विनी", "भरणी", "कृत्तिका", "रोहिणी", "मृगशिरा", "आर्द्रा", "पुनर्वसु", "पुष्य", "आश्लेषा", "मघा", "पूर्वा फाल्गुनी", "उत्तरा फाल्गुनी", "हस्त", "चित्रा", "स्वाति", "विशाखा", "अनुराधा", "ज्येष्ठा", "मूल", "पूर्वाषाढ़ा", "उत्तराषाढ़ा", "श्रवण", "धनिष्ठा", "शतभिषा", "पूर्वा भाद्रपद", "उत्तरा भाद्रपद", "रेवती"},
	"mr": {"अश्विनी", "भरणी", "कृत्तिका", "रोहिणी", "मृगशीर्ष", "आर्द्रा", "पुनर्वसु", "पुष्य", "आश्लेषा", "मघा", "पूर्वा फाल्गुनी", "उत्तरा फाल्गुनी", "हस्त", "चित्रा", "स्वाती", "विशाखा", "अनुराधा", "ज्येष्ठा", "मूळ", "पूर्वाषाढा", "उत्तराषाढा", "श्रवण", "धनिष्ठा", "शततारका", "पूर्वा भाद्रपदा", "उत्तरा भाद्रपदा", "रेवती"},
	"te": {"అశ్విని", "భరణి", "కృత్తిక", "రోహిణి", "మృగశిర", "ఆర్ద్ర", "పునర్వసు", "పుష్యమి", "ఆశ్లేష", "మఖ", "పుబ్బ", "ఉత్తర", "హస్త", "చిత్త", "స్వాతి", "విశాఖ", "అనూరాధ", "జ్యేష్ఠ", "మూల", "పూర్వాషాఢ", "ఉత్తరాషాఢ", "శ్రవణం", "ధనిష్ఠ", "శతభిషం", "పూర్వాభాద్ర", "ఉత్తరాభాద్ర", "రేవతి"},
	"ta": {"அசுவினி", "பரணி", "கார்த்திகை", "ரோகிணி", "மிருகசீரிடம்", "திருவாதிரை", "புனர்பூசம்", "பூசம்", "ஆயில்யம்", "மகம்", "பூரம்", "உத்திரம்", "அஸ்தம்", "சித்திரை", "சுவாதி", "விசாகம்", "அனுஷம்", "கேட்டை", "மூலம்", "பூராடம்", "உத்திராடம்", "திருவோணம்", "அவிட்டம்", "சதயம்", "பூரட்டாதி", "உத்திரட்டாதி", "ரேவதி"},
	"kn": {"ಅಶ್ವಿನಿ", "ಭರಣಿ", "ಕೃತ್ತಿಕಾ", "ರೋಹಿಣಿ", "ಮೃಗಶಿರಾ", "ಆರ್ದ್ರಾ", "ಪುನರ್ವಸು", "ಪುಷ್ಯ", "ಆಶ್ಲೇಷಾ", "ಮಘಾ", "ಪೂರ್ವ ಫಲ್ಗುಣಿ", "ಉತ್ತರ ಫಲ್ಗುಣಿ", "ಹಸ್ತ", "ಚಿತ್ರಾ", "ಸ್ವಾತಿ", "ವಿಶಾಖಾ", "ಅನುರಾಧಾ", "ಜ್ಯೇಷ್ಠಾ", "ಮೂಲಾ", "ಪೂರ್ವಾಷಾಢಾ", "ಉತ್ತರಾಷಾಢಾ", "ಶ್ರವಣ", "ಧನಿಷ್ಠಾ", "ಶತಭಿಷಾ", "ಪೂರ್ವ ಭಾದ್ರಪದ", "ಉತ್ತರ ಭಾದ್ರಪದ", "ರೇವತಿ"},
	"ar": {"أشويني", "بهاراني", "كريتيكا", "روهيني", "مريغاشيرا", "أردرا", "بونارفاسو", "بوشيا", "أشليشا", "ماغها", "بورفا فالغوني", "أوتارا فالغوني", "هاستا", "تشيترا", "سواتي", "فيشاكا", "أنورادها", "جييشتا", "مولا", "بورفا أشادها", "أوتارا أشادها", "شرافانا", "دهانيشتا", "شاتابيشا", "بورفا بهادرابادا", "أوتارا بهادرابادا", "ريفاتي"},
}

// Tithi names: index 0..13 = Pratipada..Chaturdashi, 14 = Purnima, 15 = Amavasya.
var seoTithiNames = map[string][16]string{
	"en": {"Pratipada", "Dwitiya", "Tritiya", "Chaturthi", "Panchami", "Shashthi", "Saptami", "Ashtami", "Navami", "Dashami", "Ekadashi", "Dwadashi", "Trayodashi", "Chaturdashi", "Purnima", "Amavasya"},
	"ru": {"Пратипада", "Двитья", "Тритья", "Чатуртхи", "Панчами", "Шаштхи", "Саптами", "Аштами", "Навами", "Дашами", "Экадаши", "Двадаши", "Трайодаши", "Чатурдаши", "Пурнима", "Амавасья"},
	"hi": {"प्रतिपदा", "द्वितीया", "तृतीया", "चतुर्थी", "पंचमी", "षष्ठी", "सप्तमी", "अष्टमी", "नवमी", "दशमी", "एकादशी", "द्वादशी", "त्रयोदशी", "चतुर्दशी", "पूर्णिमा", "अमावस्या"},
	"mr": {"प्रतिपदा", "द्वितीया", "तृतीया", "चतुर्थी", "पंचमी", "षष्ठी", "सप्तमी", "अष्टमी", "नवमी", "दशमी", "एकादशी", "द्वादशी", "त्रयोदशी", "चतुर्दशी", "पौर्णिमा", "अमावास्या"},
	"te": {"పాడ్యమి", "విదియ", "తదియ", "చవితి", "పంచమి", "షష్ఠి", "సప్తమి", "అష్టమి", "నవమి", "దశమి", "ఏకాదశి", "ద్వాదశి", "త్రయోదశి", "చతుర్దశి", "పౌర్ణమి", "అమావాస్య"},
	"ta": {"பிரதமை", "துவிதியை", "திருதியை", "சதுர்த்தி", "பஞ்சமி", "சஷ்டி", "சப்தமி", "அஷ்டமி", "நவமி", "தசமி", "ஏகாதசி", "துவாதசி", "திரயோதசி", "சதுர்த்தசி", "பௌர்ணமி", "அமாவாசை"},
	"kn": {"ಪಾಡ್ಯ", "ಬಿದಿಗೆ", "ತದಿಗೆ", "ಚೌತಿ", "ಪಂಚಮಿ", "ಷಷ್ಠಿ", "ಸಪ್ತಮಿ", "ಅಷ್ಟಮಿ", "ನವಮಿ", "ದಶಮಿ", "ಏಕಾದಶಿ", "ದ್ವಾದಶಿ", "ತ್ರಯೋದಶಿ", "ಚತುರ್ದಶಿ", "ಹುಣ್ಣಿಮೆ", "ಅಮಾವಾಸ್ಯೆ"},
	"ko": {"프라티파다", "드위티야", "트리티야", "차투르티", "판차미", "샤슈티", "삽타미", "아슈타미", "나바미", "다샤미", "에카다시", "드와다시", "트라요다시", "차투르다시", "푸르니마", "아마바스야"},
	"ar": {"براتيبادا", "دويتيا", "تريتيا", "تشاتورثي", "بانشامي", "شاشتي", "سابتامي", "أشتامي", "نافامي", "داشامي", "إيكاداشي", "دواداشي", "ترايوداشي", "تشاتورداشي", "بورنيما", "أمافاسيا"},
}

func init() {
	for k, v := range seoDayStr {
		seoStr[k] = v
	}
}

// seoNakshatraName falls back to the English transliteration for languages
// without a native table (es/fr/de/it/pt use the same Latin spelling).
func seoNakshatraName(idx int, lang string) string {
	if idx < 0 || idx >= 27 {
		return ""
	}
	if t, ok := seoNakshatraNames[lang]; ok {
		return t[idx]
	}
	return seoNakshatraNames["en"][idx]
}

func seoTithiName(idx int, lang string) string {
	if idx < 0 || idx >= 16 {
		return ""
	}
	if t, ok := seoTithiNames[lang]; ok {
		return t[idx]
	}
	return seoTithiNames["en"][idx]
}

func seoMonthName(m int, lang string) string {
	if m < 1 || m > 12 {
		return ""
	}
	if t, ok := seoMonthNames[lang]; ok {
		return t[m-1]
	}
	return seoMonthNames["en"][m-1]
}

func seoWeekdayName(wd int, lang string) string {
	if wd < 0 || wd > 6 {
		return ""
	}
	if t, ok := seoWeekdayNames[lang]; ok {
		return t[wd]
	}
	return seoWeekdayNames["en"][wd]
}
