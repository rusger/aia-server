package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// usage of turn 1 of the probe 25.09.2026 (gpt-realtime-2.1-mini) → $0.0126 at list prices
const probeUsage = `{"total_tokens":3369,"input_tokens":2699,"output_tokens":670,
 "input_token_details":{"text_tokens":2632,"audio_tokens":67,"image_tokens":0,"cached_tokens":0,
   "cached_tokens_details":{"text_tokens":0,"audio_tokens":0,"image_tokens":0}},
 "output_token_details":{"text_tokens":173,"audio_tokens":497,"reasoning_tokens":50}}`

func openVoiceTestDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	voiceSchemaReady.Store(false)
	ensureVoiceSchema()
}

func voiceReq(method, path, body string, c *JWTClaims) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if c != nil {
		r = r.WithContext(context.WithValue(r.Context(), "claims", c))
	}
	return r
}

func TestVoicePricing(t *testing.T) {
	var u voiceUsage
	if err := json.Unmarshal([]byte(probeUsage), &u); err != nil {
		t.Fatal(err)
	}
	cost := voiceCostUSD(voiceModel, u)
	if cost < 0.0125 || cost > 0.0127 {
		t.Fatalf("probe turn 1 cost = %.5f, want ≈ 0.0126", cost)
	}
	// finance.go prices the two logged rows to the same total
	fin := financeTokenCostUSD(voiceModel, 67, 497, 0, false) + financeTokenCostUSD(voiceModel+"-text", 2632, 173, 0, false)
	if d := fin - cost; d > 1e-6 || d < -1e-6 {
		t.Fatalf("finance %.6f vs handler %.6f", fin, cost)
	}
	// the full model is dearer, cached input is cheap
	if full := voiceCostUSD("gpt-realtime-2.1", u); full <= cost*3 {
		t.Fatalf("full model cost %.5f should be > 3× mini %.5f", full, cost)
	}
	var cached voiceUsage
	json.Unmarshal([]byte(probeUsage), &cached)
	cached.InputTokenDetails.CachedTokens = 2600
	cached.InputTokenDetails.CachedTokensDetails.TextTokens = 2600
	if c2 := voiceCostUSD(voiceModel, cached); c2 >= cost {
		t.Fatalf("cached context must be cheaper: %.5f vs %.5f", c2, cost)
	}
}

func TestVoiceAllowlistAndStatus(t *testing.T) {
	openVoiceTestDB(t)
	os.Setenv("VOICE_ALLOWED_EMAILS", "Owner@Example.com, second@example.com")
	defer os.Unsetenv("VOICE_ALLOWED_EMAILS")
	if !voiceAllowed("owner@example.com") || voiceAllowed("nobody@example.com") || voiceAllowed("") {
		t.Fatal("allowlist parse")
	}
	call := func(email string) map[string]interface{} {
		w := httptest.NewRecorder()
		voiceStatusHandler(w, voiceReq("GET", "/api/voice/status", "", &JWTClaims{Email: email, DeviceID: "d1"}))
		var out map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if out := call("owner@example.com"); out["enabled"] != true || out["balance"].(map[string]interface{})["unlimited"] != true {
		t.Fatalf("owner: %v", out)
	}
	if out := call("nobody@example.com"); out["enabled"] != false {
		t.Fatalf("stranger must be disabled: %v", out)
	}
	if err := voiceGrant("nobody@example.com", 0.10); err != nil {
		t.Fatal(err)
	}
	out := call("nobody@example.com")
	bal := out["balance"].(map[string]interface{})
	if out["enabled"] != true || bal["remaining_usd"].(float64) < 0.0999 || bal["remaining_minutes"].(float64) < 2.0 {
		t.Fatalf("granted $0.10 → enabled, ≈2 min: %v", out)
	}
	w := httptest.NewRecorder()
	voiceStatusHandler(w, voiceReq("GET", "/api/voice/status", "", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no claims: %d", w.Code)
	}
}

func TestVoiceTicket(t *testing.T) {
	openVoiceTestDB(t)
	os.Setenv("VOICE_ALLOWED_EMAILS", "owner@example.com")
	defer os.Unsetenv("VOICE_ALLOWED_EMAILS")
	oldMint, oldInj := voiceMintSecret, voiceMintInjected
	defer func() { voiceMintSecret, voiceMintInjected = oldMint, oldInj }()
	var gotSession map[string]interface{}
	voiceMintSecret = func(session map[string]interface{}) (string, int64, error) {
		gotSession = session
		return "ek_test_123", 1790000000, nil
	}
	voiceMintInjected = true
	call := func(body string, c *JWTClaims) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		voiceTicketHandler(w, voiceReq("POST", "/api/voice/ticket", body, c))
		return w
	}
	owner := &JWTClaims{Email: "owner@example.com", DeviceID: "d1"}
	if w := call(`{"instructions":"x"}`, &JWTClaims{Email: "nobody@example.com"}); w.Code != http.StatusForbidden {
		t.Fatalf("stranger: %d %s", w.Code, w.Body.String())
	}
	if w := call(`{"instructions":"`+strings.Repeat("а", voiceMaxInstructions+1)+`"}`, owner); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too long: %d", w.Code)
	}
	w := call(`{"instructions":"Натальная карта: Асцендент Телец.","voice":"Cedar","lang":"ru","chat_type":"guru"}`, owner)
	if w.Code != http.StatusOK {
		t.Fatalf("ticket: %d %s", w.Code, w.Body.String())
	}
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["client_secret"] != "ek_test_123" || out["model"] != voiceModel || out["voice"] != "cedar" {
		t.Fatalf("response: %v", out)
	}
	instr := gotSession["instructions"].(string)
	if !strings.HasPrefix(instr, voiceHardRules) || !strings.HasSuffix(instr, "Асцендент Телец.") {
		t.Fatalf("hard rules must precede the chat prompt: %q", instr[:80])
	}
	audio := gotSession["audio"].(map[string]interface{})
	if audio["output"].(map[string]interface{})["voice"] != "cedar" || gotSession["type"] != "realtime" {
		t.Fatalf("session: %v", gotSession)
	}
	// an unknown voice falls back to the default; the secret never appears in logs (checked by eye: only email/chat/voice/len are logged)
	w = call(`{"instructions":"x","voice":"nova"}`, owner)
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["voice"] != voiceDefaultVoice {
		t.Fatalf("voice fallback: %v", out["voice"])
	}
}

func TestVoiceUsageDebitAndDedup(t *testing.T) {
	openVoiceTestDB(t)
	os.Unsetenv("VOICE_ALLOWED_EMAILS")
	if err := voiceGrant("payer@example.com", 0.05); err != nil {
		t.Fatal(err)
	}
	call := func(body string) map[string]interface{} {
		w := httptest.NewRecorder()
		voiceUsageHandler(w, voiceReq("POST", "/api/voice/usage", body, &JWTClaims{Email: "payer@example.com", DeviceID: "d1"}))
		if w.Code != http.StatusOK {
			t.Fatalf("usage: %d %s", w.Code, w.Body.String())
		}
		var out map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	out := call(`{"response_id":"resp_1","usage":` + probeUsage + `}`)
	bal := out["balance"].(map[string]interface{})
	cost := out["cost_usd"].(float64)
	// $0.05 − 2 × $0.0126 = $0.0248 left
	if out["duplicate"] != false || bal["remaining_usd"].(float64) < 0.0247 || bal["remaining_usd"].(float64) > 0.0249 {
		t.Fatalf("after 1st reply: cost %.5f balance %v", cost, bal)
	}
	again := call(`{"response_id":"resp_1","usage":` + probeUsage + `}`)
	if again["duplicate"] != true || again["balance"].(map[string]interface{})["remaining_usd"] != bal["remaining_usd"] {
		t.Fatalf("same response_id must not debit twice: %v", again)
	}
	out2 := call(`{"response_id":"resp_2","usage":` + probeUsage + `}`)
	b2 := out2["balance"].(map[string]interface{})
	if out2["enabled"] != false || b2["exhausted"] != true || b2["remaining_usd"].(float64) != 0 {
		t.Fatalf("balance exhausted → disabled, never negative: %v", out2)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM voice_usage`).Scan(&n)
	if n != 2 {
		t.Fatalf("voice_usage rows = %d", n)
	}
	w := httptest.NewRecorder()
	voiceUsageHandler(w, voiceReq("POST", "/api/voice/usage", `{"usage":{}}`, &JWTClaims{Email: "payer@example.com"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing response_id: %d", w.Code)
	}
}
