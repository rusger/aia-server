package main

// A95 (owner 25.11.2026): every razbor — a long YouTube walk-through of one
// sky event for all twelve ascendants — gets its own page on the site,
// /astro/<lang>/<year>/<slug>.html, shown in the visitor's language when we
// have the text in it.
//
// The page text IS the video text (owner 16.11: «текст уже есть! Его и
// используем!»). insta-agent scripts/ytlong/razbor_site.py joins the
// approved yaml lines, the YouTube chapters and the subtitle translations
// (A209) into seo_razbor/<slug>.json in this repo; a language is listed in
// its "langs" only when every line and heading exists in it. No player on
// the site (owner 15.11): links to YouTube at the chapter's time code, the
// sign's short chapter video once it is public, and the channel subscribe
// link.
//
// Language: the URL carries it like every /astro/ page (hreflang, canonical,
// footer switcher). For people, a small script repeats the main site's
// choice (astrolytix i18n.js): the language saved by hand in localStorage
// "astrolytix_language", else the country from GeoIP — and moves to that
// language's page only when it exists. Footer clicks save the choice. Bots
// are never moved, and nothing redirects on the server.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// seoRazborDir is read relative to the working directory (the box cron runs
// seo-gen from ~/aia/server, the deployed checkout of this repo).
const seoRazborDir = "seo_razbor"

type seoRazborText map[string]string // lang -> text

type seoRazborLine struct {
	Host string        `json:"host"`
	Text seoRazborText `json:"text"`
	Sub  seoRazborText `json:"sub,omitempty"`
}

type seoRazborClip struct {
	ID        string `json:"id"`
	PublishAt string `json:"publish_at"`
}

type seoRazborSection struct {
	T     int             `json:"t"`
	Sign  int             `json:"sign"`
	H     seoRazborText   `json:"h"`
	Clip  *seoRazborClip  `json:"clip,omitempty"`
	Lines []seoRazborLine `json:"lines"`
}

type seoRazbor struct {
	Slug      string             `json:"slug"`
	Year      int                `json:"year"`
	Video     string             `json:"video"`
	Published string             `json:"published"`
	Duration  string             `json:"duration"`
	Related   []string           `json:"related"`
	Langs     []string           `json:"langs"`
	Title     seoRazborText      `json:"title"`
	Lead      seoRazborText      `json:"lead"`
	Sections  []seoRazborSection `json:"sections"`
}

func (r *seoRazbor) rel() string { return strconv.Itoa(r.Year) + "/" + r.Slug + ".html" }

// langs keeps only the site's languages, in seoLangs order.
func (r *seoRazbor) siteLangs() []string {
	var out []string
	for _, l := range seoLangs {
		if hasLang(r.Langs, l) {
			out = append(out, l)
		}
	}
	return out
}

// validate refuses a razbor the page cannot be built from completely.
func (r *seoRazbor) validate() error {
	if r.Slug == "" || r.Video == "" || r.Year == 0 || len(r.Sections) == 0 {
		return fmt.Errorf("slug/video/year/sections missing")
	}
	if strings.ContainsAny(r.Slug, "/\\. ") {
		return fmt.Errorf("bad slug %q", r.Slug)
	}
	if !hasLang(r.Langs, "en") {
		return fmt.Errorf("no en text")
	}
	for _, l := range r.Langs {
		if r.Title[l] == "" || r.Lead[l] == "" {
			return fmt.Errorf("%s: title/lead missing", l)
		}
		for i, s := range r.Sections {
			if s.H[l] == "" {
				return fmt.Errorf("%s: section %d heading missing", l, i)
			}
			for j, ln := range s.Lines {
				if ln.Text[l] == "" || (ln.Sub != nil && ln.Sub[l] == "") {
					return fmt.Errorf("%s: section %d line %d missing", l, i, j)
				}
			}
		}
	}
	return nil
}

func loadRazbors(dir string) ([]*seoRazbor, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []*seoRazbor
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r seoRazbor
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, &r)
	}
	return out, nil
}

// fmtClock is a YouTube-style time code: 4:37, 1:04:58.
func fmtClock(sec int) string {
	h, m, s := sec/3600, sec%3600/60, sec%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

func ytAt(video string, sec int) string {
	if sec <= 0 {
		return "https://youtu.be/" + video
	}
	return "https://youtu.be/" + video + "?t=" + strconv.Itoa(sec)
}

// clipLive: the sign's chapter video is linked only once YouTube shows it.
func clipLive(c *seoRazborClip, now time.Time) bool {
	if c == nil || c.ID == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, c.PublishAt)
	return err == nil && !t.After(now)
}

func razborAnchor(i int, s seoRazborSection) string {
	if s.Sign >= 0 && s.Sign < 12 {
		return signSlug(s.Sign)
	}
	return "part-" + strconv.Itoa(i+1)
}

func buildRazborPage(lang string, r *seoRazbor, now time.Time) seoPage {
	t := func(key string, repl map[string]string) string { return razborT(key, lang, repl) }
	var b strings.Builder
	b.WriteString("<h1>" + esc(r.Title[lang]) + "</h1>\n")
	b.WriteString("<p class=\"lead\">" + esc(r.Lead[lang]) + "</p>\n")
	b.WriteString("<div class=\"btns\"><a class=\"btn\" rel=\"noopener\" href=\"" + ytAt(r.Video, 0) + "\">▶ " + esc(t("watch", nil)) + "</a>")
	b.WriteString("<a class=\"btn alt\" rel=\"noopener\" href=\"" + seoYouTube + "?sub_confirmation=1\">" + esc(t("subscribe", nil)) + "</a></div>\n")
	b.WriteString("<nav class=\"toc\"><h2>" + esc(t("contents", nil)) + "</h2><ol>\n")
	for i, s := range r.Sections {
		b.WriteString("<li><a href=\"#" + razborAnchor(i, s) + "\">" + esc(s.H[lang]) + "</a> <span class=\"note\">" + fmtClock(s.T) + "</span></li>\n")
	}
	b.WriteString("</ol></nav>\n")
	for i, s := range r.Sections {
		b.WriteString("<section class=\"year razbor\" id=\"" + razborAnchor(i, s) + "\"><h2>" + esc(s.H[lang]) + "</h2>\n")
		b.WriteString("<p class=\"watch\"><a rel=\"noopener\" href=\"" + ytAt(r.Video, s.T) + "\">▶ " + esc(t("watch_from", map[string]string{"time": fmtClock(s.T)})) + "</a>")
		if clipLive(s.Clip, now) {
			b.WriteString(" · <a rel=\"noopener\" href=\"https://youtu.be/" + s.Clip.ID + "\">" + esc(t("clip", map[string]string{"title": s.H[lang]})) + "</a>")
		}
		b.WriteString("</p>\n")
		for _, ln := range s.Lines {
			if ln.Sub != nil {
				b.WriteString("<h3>" + esc(ln.Sub[lang]) + "</h3>\n")
			}
			cls := "a"
			if ln.Host == "A" {
				cls = "q"
			}
			b.WriteString("<p class=\"" + cls + "\">" + esc(ln.Text[lang]) + "</p>\n")
		}
		b.WriteString("</section>\n")
	}
	b.WriteString("<div class=\"btns\"><a class=\"btn alt\" rel=\"noopener\" href=\"" + seoYouTube + "?sub_confirmation=1\">" + esc(t("subscribe", nil)) + "</a></div>\n")
	langs := r.siteLangs()
	b.WriteString("<script>" + razborLangJS(lang, r.rel(), langs) + "</script>\n")
	return seoPage{langs: langs, rel: r.rel(), title: r.Title[lang], desc: r.Lead[lang], body: b.String(), ld: razborVideoLD(lang, r)}
}

// razborVideoLD is the VideoObject with one Clip per YouTube chapter.
func razborVideoLD(lang string, r *seoRazbor) string {
	var parts []string
	for i, s := range r.Sections {
		end := 0
		if i+1 < len(r.Sections) {
			end = r.Sections[i+1].T
		}
		c := `{"@type":"Clip","name":` + strconv.Quote(s.H[lang]) + `,"startOffset":` + strconv.Itoa(s.T)
		if end > 0 {
			c += `,"endOffset":` + strconv.Itoa(end)
		}
		parts = append(parts, c+`,"url":"`+ytAt(r.Video, s.T)+`"}`)
	}
	return `{"@type":"VideoObject","name":` + strconv.Quote(r.Title[lang]) + `,"description":` + strconv.Quote(r.Lead[lang]) +
		`,"thumbnailUrl":"https://i.ytimg.com/vi/` + r.Video + `/hqdefault.jpg","uploadDate":"` + r.Published + `","duration":"` + r.Duration +
		`","embedUrl":"https://www.youtube.com/embed/` + r.Video + `","url":"https://www.youtube.com/watch?v=` + r.Video + `","inLanguage":"en","hasPart":[` + strings.Join(parts, ",") + `]}`
}

// razborLinks: the block other /astro/ pages show for the razbors that
// exist in their language; rel "" is the language hub, else a year page
// "<year>/<topic>.html" listed in a razbor's "related".
func razborLinks(lang, rel string, rs []*seoRazbor) string {
	var items []string
	for _, r := range rs {
		if !hasLang(r.siteLangs(), lang) {
			continue
		}
		if rel != "" {
			y, topic, ok := strings.Cut(strings.TrimSuffix(rel, ".html"), "/")
			if !ok || y != strconv.Itoa(r.Year) || !hasLang(r.Related, topic) {
				continue
			}
		}
		items = append(items, "<li><a href=\""+seoURL(lang, r.rel())+"\">"+esc(r.Title[lang])+"</a></li>")
	}
	if len(items) == 0 {
		return ""
	}
	return "<section class=\"year\"><h2>" + esc(razborT("section", lang, nil)) + "</h2><ul class=\"links\">\n" + strings.Join(items, "\n") + "\n</ul></section>\n"
}

// seoCountryLang mirrors COUNTRY_TO_LANGUAGE in astrolytix/i18n.js
// (TestRazborCountryMapMatchesSite compares them when the site repo is a
// sibling checkout). Change both together.
var seoCountryLang = map[string]string{
	"ES": "es", "MX": "es", "AR": "es", "CO": "es", "PE": "es", "VE": "es", "CL": "es",
	"EC": "es", "GT": "es", "CU": "es", "BO": "es", "DO": "es", "HN": "es", "PY": "es",
	"SV": "es", "NI": "es", "CR": "es", "PA": "es", "UY": "es",
	"FR": "fr", "BE": "fr", "MC": "fr", "SN": "fr", "CI": "fr", "ML": "fr", "BF": "fr",
	"NE": "fr", "TG": "fr", "BJ": "fr", "GA": "fr", "CG": "fr", "CD": "fr", "CM": "fr",
	"MG": "fr", "HT": "fr",
	"DE": "de", "AT": "de", "LI": "de",
	"IT": "it", "SM": "it", "VA": "it",
	"BR": "pt", "PT": "pt", "AO": "pt", "MZ": "pt", "GW": "pt", "TL": "pt", "CV": "pt",
	"RU": "ru", "BY": "ru", "KZ": "ru", "KG": "ru", "TJ": "ru", "UZ": "ru", "TM": "ru",
	"CN": "zh", "TW": "zh", "HK": "zh", "MO": "zh", "SG": "zh",
	"JP": "ja",
	"KR": "ko", "KP": "ko",
	"IN": "hi", "NP": "hi", "FJ": "hi",
	"SA": "ar", "EG": "ar", "AE": "ar", "IQ": "ar", "MA": "ar", "DZ": "ar", "SD": "ar",
	"YE": "ar", "SY": "ar", "TN": "ar", "JO": "ar", "LY": "ar", "LB": "ar", "OM": "ar",
	"KW": "ar", "QA": "ar", "BH": "ar", "PS": "ar", "MR": "ar",
}

const (
	seoLangStorageKey = "astrolytix_language"                     // i18n.js STORAGE_KEY
	seoGeoIPAPI       = "https://get.geojs.io/v1/ip/country.json" // i18n.js GEOIP_API
)

func razborLangJS(cur, rel string, langs []string) string {
	keys := make([]string, 0, len(seoCountryLang))
	for k := range seoCountryLang {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var m []string
	for _, k := range keys {
		m = append(m, k+":"+strconv.Quote(seoCountryLang[k]))
	}
	var ls []string
	for _, l := range langs {
		ls = append(ls, strconv.Quote(l))
	}
	return `(function(){var L=[` + strings.Join(ls, ",") + `],C=` + strconv.Quote(cur) + `,K=` + strconv.Quote(seoLangStorageKey) + `,G="astrolytix_geo_lang";` +
		`document.querySelectorAll('footer .langs a[hreflang]').forEach(function(a){a.addEventListener('click',function(){try{localStorage.setItem(K,a.getAttribute('hreflang'))}catch(e){}})});` +
		`if(/bot|crawl|spider|slurp|lighthouse|inspectiontool|headless/i.test(navigator.userAgent||''))return;` +
		`function go(l){if(l&&l!==C&&L.indexOf(l)>=0)location.replace(` + strconv.Quote(seoBaseURL+"/") + `+l+` + strconv.Quote("/"+rel) + `+location.hash)}` +
		`var s=null;try{s=localStorage.getItem(K)}catch(e){}if(s){go(s);return}` +
		`var g=null;try{g=sessionStorage.getItem(G)}catch(e){}if(g){go(g);return}` +
		`var M={` + strings.Join(m, ",") + `};` +
		`fetch(` + strconv.Quote(seoGeoIPAPI) + `).then(function(r){if(!r.ok)throw 0;return r.json()}).then(function(d){var l=M[String(d.country||'').toUpperCase()]||'en';try{sessionStorage.setItem(G,l)}catch(e){}go(l)}).catch(function(){})})();`
}

// UI labels of the razbor pages, for the languages razbors are translated
// into (A209: en + ru, es, de, ar, pt); others fall back to English.
var razborStr = map[string]map[string]string{
	"watch": {
		"en": "Watch the full video on YouTube", "ru": "Смотреть весь разбор на YouTube", "es": "Ver el video completo en YouTube",
		"de": "Das ganze Video auf YouTube ansehen", "ar": "شاهد الفيديو كاملًا على يوتيوب", "pt": "Assista ao vídeo completo no YouTube",
	},
	"subscribe": {
		"en": "Subscribe to the channel", "ru": "Подписаться на канал", "es": "Suscríbete al canal",
		"de": "Kanal abonnieren", "ar": "اشترك في القناة", "pt": "Inscreva-se no canal",
	},
	"contents": {
		"en": "Contents", "ru": "Содержание", "es": "Contenido", "de": "Inhalt", "ar": "المحتويات", "pt": "Conteúdo",
	},
	"watch_from": {
		"en": "Watch from {time}", "ru": "Смотреть с {time}", "es": "Ver desde {time}",
		"de": "Ab {time} ansehen", "ar": "شاهد من {time}", "pt": "Assista a partir de {time}",
	},
	"clip": {
		"en": "Short video: {title}", "ru": "Короткое видео: {title}", "es": "Video corto: {title}",
		"de": "Kurzes Video: {title}", "ar": "فيديو قصير: {title}", "pt": "Vídeo curto: {title}",
	},
	"section": {
		"en": "Video walk-throughs", "ru": "Видеоразборы", "es": "Análisis en video",
		"de": "Video-Analysen", "ar": "تحليلات بالفيديو", "pt": "Análises em vídeo",
	},
}

var razborLangs = []string{"en", "ru", "es", "de", "ar", "pt"}

func razborT(key, lang string, repl map[string]string) string {
	m, ok := razborStr[key]
	if !ok {
		return key
	}
	s := tr(m, lang)
	for k, v := range repl {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}
