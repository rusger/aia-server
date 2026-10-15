package main

import (
	"encoding/binary"
	"math"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// the real ffmpeg-backed functions, captured before any test swaps the package hooks for fakes
var realRadioCallPhoneFn = radioCallPhoneFn

func TestRadioSentencesEN(t *testing.T) {
	long := "When Saturn transits over my natal Moon in the eighth house, which my previous astrologer said was dangerous, " +
		"should I postpone the wedding that we planned for next spring with all our relatives?"
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"What does Saturn over my Moon mean?", []string{"What does Saturn over my Moon mean?"}},
		{"My name is Olga. I am 34! What should I do?", []string{"My name is Olga.", "I am 34!", "What should I do?"}},
		{"Mr. Smith said my Moon is at 12.5 degrees. Is that bad?", []string{"Mr. Smith said my Moon is at 12.5 degrees.", "Is that bad?"}},
		{"Things like work, e.g. my boss, upset me. Why?", []string{"Things like work, e.g. my boss, upset me.", "Why?"}},
		{"I read J. R. R. Tolkien, i.e. fantasy. Is it fine?", []string{"I read J. R. R. Tolkien, i.e. fantasy.", "Is it fine?"}},
		{"Dr. Rao told me at 3 p.m. that it was bad. What now?", []string{"Dr. Rao told me at 3 p.m. that it was bad.", "What now?"}},
		{`He said "go away." Should I?`, []string{`He said "go away."`, "Should I?"}},
		{"Really?! Yes... I think so.", []string{"Really?!", "Yes...", "I think so."}},
		{"Version 2.0 is out.It works", []string{"Version 2.0 is out.It works"}},
		{"  Spaces   everywhere.   Second one  ", []string{"Spaces   everywhere.", "Second one"}},
		{"", nil},
		{long, []string{
			// 33 words: split at the comma closest to the middle
			"When Saturn transits over my natal Moon in the eighth house, which my previous astrologer said was dangerous,",
			"should I postpone the wedding that we planned for next spring with all our relatives?"}},
		{strings.Repeat("word ", 30) + "end.", []string{strings.Repeat("word ", 30) + "end."}}, // no comma — stays whole
	} {
		if got := radioSentencesEN(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("radioSentencesEN(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	for _, s := range radioSentencesEN(long + " " + long) {
		if n := len(strings.Fields(s)); n > radioInterpMaxWords {
			t.Errorf("piece of %d words: %q", n, s)
		}
	}
}

func TestRadioParseSpeech(t *testing.T) {
	log := `Duration: 00:00:06.00, start: 0.000000
[silencedetect @ 0x1] silence_start: 0
[silencedetect @ 0x1] silence_end: 0.4 | silence_duration: 0.4
[silencedetect @ 0x1] silence_start: 1.4
[silencedetect @ 0x1] silence_end: 1.7 | silence_duration: 0.3
[silencedetect @ 0x1] silence_start: 2.7
[silencedetect @ 0x1] silence_end: 4 | silence_duration: 1.3
[silencedetect @ 0x1] silence_start: 5
size=N/A time=00:00:06.00 bitrate=N/A speed= 500x`
	want := [][2]float64{{0.4, 2.7}, {4, 5}}
	if got := radioParseSpeech(log); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// speech up to the end, no leading silence
	log2 := "Duration: 00:00:03.50\n[silencedetect] silence_start: 1\n[silencedetect] silence_end: 2.3\nsize=N/A time=00:00:03.50 bitrate"
	if got := radioParseSpeech(log2); !reflect.DeepEqual(got, [][2]float64{{0, 1}, {2.3, 3.5}}) {
		t.Fatalf("got %v", got)
	}
	if got := radioParseSpeech("Duration: 00:00:02.00\nsilence_start: 0\ntime=00:00:02.00"); len(got) != 0 {
		t.Fatalf("all silence → no speech, got %v", got)
	}
}

func TestRadioInterpEnvelopeExpr(t *testing.T) {
	if e := radioInterpEnvelope(nil, 0.75, 0.15); e != "1" {
		t.Fatalf("no intervals → %q", e)
	}
	want := "min(1,if(between(t,0.85,1),1-(1-0.75)*(t-0.85)/0.15,if(between(t,1,2.24),0.75," +
		"if(between(t,2.24,2.39),0.75+(1-0.75)*(t-2.24)/0.15,1))))"
	if e := radioInterpEnvelope([][2]float64{{1, 2.24}}, 0.75, 0.15); e != want {
		t.Fatalf("envelope\n got %s\nwant %s", e, want)
	}
	f := radioInterpFilter([][2]float64{{0, 1.24}, {2.73, 6.38}})
	for _, part := range []string{"volume=1.4,volume='min(min(1,", "between(t,1,2.24),0.75", "between(t,3.73,7.38),0.75",
		"loudnorm=I=-19:TP=-2,adelay=1000|1000", "amix=inputs=2:duration=longest:normalize=0,alimiter=limit=0.89"} {
		if !strings.Contains(f, part) {
			t.Errorf("filter lacks %q:\n%s", part, f)
		}
	}
	if strings.Count(f, "loudnorm") != 1 {
		t.Errorf("no loudnorm on the sum (§A2):\n%s", f)
	}
}

func radioNeedFFmpeg(t *testing.T) {
	t.Helper()
	for _, b := range []string{"ffmpeg", "ffprobe"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip(b + " not installed")
		}
	}
}

func radioFF(t *testing.T, args ...string) {
	t.Helper()
	if b, err := exec.Command("ffmpeg", append([]string{"-y", "-nostdin", "-loglevel", "error"}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg %v: %v %s", args, err, b)
	}
}

// radioGen writes a mono wav of [dur] s: a sine of [hz] at [amp] inside [on] intervals, silence elsewhere.
func radioGen(t *testing.T, out string, dur, hz, amp float64, on [][2]float64) {
	t.Helper()
	var g []string
	for _, iv := range on {
		g = append(g, "between(t,"+radioNum(iv[0])+","+radioNum(iv[1])+")")
	}
	gate := "1"
	if on != nil {
		gate = "gt(" + strings.Join(g, "+") + ",0)"
	}
	if len(on) == 0 && on != nil {
		gate = "0"
	}
	expr := gate + "*" + radioNum(amp) + "*sin(2*PI*" + radioNum(hz) + "*t)"
	radioFF(t, "-filter_complex", "aevalsrc=exprs='"+expr+"':s=48000:d="+radioNum(dur), "-c:a", "pcm_s16le", out)
}

// radioPCM decodes [path] to mono float samples at 48 kHz.
func radioPCM(t *testing.T, path string) []float32 {
	t.Helper()
	b, err := exec.Command("ffmpeg", "-nostdin", "-loglevel", "error", "-i", path, "-ac", "1", "-ar", "48000",
		"-f", "f32le", "-").Output()
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	s := make([]float32, len(b)/4)
	for i := range s {
		s[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:]))
	}
	return s
}

func radioRMSdB(s []float32, from, to float64) float64 {
	a, b := int(from*48000), int(to*48000)
	if b > len(s) {
		b = len(s)
	}
	var sum float64
	for _, x := range s[a:b] {
		sum += float64(x) * float64(x)
	}
	return 10 * math.Log10(sum/float64(b-a)+1e-20)
}

func radioNear(a, b [][2]float64, tol float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if math.Abs(a[i][0]-b[i][0]) > tol || math.Abs(a[i][1]-b[i][1]) > tol {
			return false
		}
	}
	return true
}

func TestRadioInterpSpeechRealFFmpeg(t *testing.T) {
	radioNeedFFmpeg(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "interp.wav")
	// lead silence 0.4, a 0.3 s pause (merged: < 0.5), a 1.3 s window
	radioGen(t, f, 5.5, 440, 0.5, [][2]float64{{0.4, 1.4}, {1.7, 2.7}, {4.0, 5.0}})
	sp, err := radioInterpSpeech(f)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][2]float64{{0.4, 2.7}, {4.0, 5.0}}; !radioNear(sp, want, 0.03) {
		t.Fatalf("speech %v, want ≈ %v", sp, want)
	}
	silent := filepath.Join(dir, "silent.wav")
	radioGen(t, silent, 2, 440, 0.5, [][2]float64{})
	if _, err := radioInterpSpeech(silent); err == nil {
		t.Fatal("a silent interpreter must be an error (the original airs)")
	}
}

func TestRadioInterpJoinRealFFmpeg(t *testing.T) {
	radioNeedFFmpeg(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.wav"), filepath.Join(dir, "b.wav")
	radioGen(t, a, 1.0, 440, 0.5, nil)
	radioGen(t, b, 1.5, 660, 0.5, nil)
	out := filepath.Join(dir, "joined.m4a")
	if err := radioInterpJoin([]string{a, b}, out); err != nil {
		t.Fatal(err)
	}
	sp, err := radioInterpSpeech(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][2]float64{{0, 1.0}, {2.3, 3.8}}; !radioNear(sp, want, 0.06) {
		t.Fatalf("joined speech %v, want ≈ %v (1.3 s gap)", sp, want)
	}
}

// TestRadioInterpStemLevels — §A2 verification rule: the caller and the interpreter are measured as stems through the
// same graph. Under the interpreter the caller must sit within ~3 dB of the interpreter; in the windows the caller is
// at its ×1.4 level (1/0.75 above its ducked level). Measured on the Mac (ffmpeg 7.1): caller −15.2 dB vs interpreter
// −13.5…−14.0 dB under the interpreter; windows −12.7 dB.
func TestRadioInterpStemLevels(t *testing.T) {
	radioNeedFFmpeg(t)
	dir := t.TempDir()
	raw, phone := filepath.Join(dir, "raw.wav"), filepath.Join(dir, "caller.m4a")
	radioGen(t, raw, 12, 800, 0.3, nil)
	if _, err := realRadioCallPhoneFn(raw, phone); err != nil {
		t.Fatal(err)
	}
	interp := filepath.Join(dir, "interp.wav")
	radioGen(t, interp, 10.1, 500, 0.3, [][2]float64{{0, 2.5}, {3.8, 6.3}, {7.6, 10.1}})
	sp, err := radioInterpSpeech(interp)
	if err != nil {
		t.Fatal(err)
	}
	silentCaller, silentInterp := filepath.Join(dir, "sc.wav"), filepath.Join(dir, "si.wav")
	radioGen(t, silentCaller, 12, 800, 0, nil)
	radioGen(t, silentInterp, 10.1, 500, 0, nil)
	callerStem, interpStem := filepath.Join(dir, "caller_stem.m4a"), filepath.Join(dir, "interp_stem.m4a")
	if err := radioInterpRender(phone, silentInterp, sp, callerStem); err != nil {
		t.Fatal(err)
	}
	if err := radioInterpRender(silentCaller, interp, sp, interpStem); err != nil {
		t.Fatal(err)
	}
	in, cs, is := radioPCM(t, phone), radioPCM(t, callerStem), radioPCM(t, interpStem)
	// interpreter speech on the output timeline: [1.0,3.5] [4.8,7.3] [8.6,11.1]
	for _, w := range [][2]float64{{1.5, 3.0}, {5.3, 6.8}, {9.1, 10.6}} {
		c, i := radioRMSdB(cs, w[0], w[1]), radioRMSdB(is, w[0], w[1])
		t.Logf("under the interpreter %v: caller %.2f dB, interpreter %.2f dB", w, c, i)
		if math.Abs(c-i) > 3 {
			t.Errorf("under the interpreter %v: caller %.2f dB vs interpreter %.2f dB — more than 3 dB apart", w, c, i)
		}
	}
	under := radioRMSdB(cs, 5.3, 6.8)
	for _, w := range [][2]float64{{0.2, 0.7}, {3.75, 4.55}, {7.55, 8.35}} {
		win, orig := radioRMSdB(cs, w[0], w[1]), radioRMSdB(in, w[0], w[1])
		t.Logf("window %v: caller %.2f dB (input %.2f dB, ducked %.2f dB)", w, win, orig, under)
		if d := win - under; math.Abs(d-20*math.Log10(1/radioInterpCallerLow)) > 0.6 {
			t.Errorf("window %v: caller %.2f dB above its ducked level, want %.2f", w, d, 20*math.Log10(1/radioInterpCallerLow))
		}
		// ×1.4, plus alimiter's default auto-level make-up of 1/limit (level=1, as in the approved reference script)
		if want := 20 * math.Log10(radioInterpCallerWin/0.89); math.Abs(win-orig-want) > 0.5 {
			t.Errorf("window %v: caller %.2f dB above the phone clip, want ≈ %.2f (×1.4 / 0.89)", w, win-orig, want)
		}
	}
}
