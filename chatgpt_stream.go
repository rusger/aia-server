package main

// Streaming AI proxy (owner decision 2026-08-29, onboarding wow-moment):
// same contract as /api/chatgpt — JWT, model enforcement, rate/daily limits,
// crisis screen, api_calls accounting — but the answer is relayed to the
// client token-by-token over SSE instead of buffered for minutes.
//
// Wire protocol (deliberately tiny, not raw OpenAI SSE):
//   data: {"c":"<content delta>"}   — text chunk
//   data: {"done":true}             — clean end of stream
//   data: {"error":"<message>"}     — terminal mid-stream failure
// Pre-stream failures (auth, quotas, upstream 4xx/5xx) are plain JSON with
// the appropriate status code, so old error handling keeps working.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func chatGPTStreamProxy(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*JWTClaims)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"error":"Unauthorized"}`)
		return
	}
	if OPENAI_API_KEY == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"success":false,"error":"ChatGPT service not configured on server"}`)
		return
	}

	var req ChatGPTProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"success":false,"error":"Invalid request format"}`)
		return
	}

	deviceID := claims.DeviceID
	crisisHit, crisisLang := detectCrisis(lastUserMessage(req.Messages))
	req.Model = enforceModelForUser(claims.Email, deviceID, req.Model)

	// Same gate battery as chatGPTProxy (kept as a parallel copy on purpose:
	// the buffered handler is the hot path and stays untouched).
	if !ipLimiter.GetLimiter(getClientIP(r)).Allow() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"success":false,"error":"Too many requests from your network. Please wait."}`)
		return
	}
	if !deviceLimiter.GetLimiter(deviceID).Allow() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"success":false,"error":"Rate limit exceeded. Please try again."}`)
		return
	}
	callType, overhead := normalizeAICallType(req.CallType)
	if limit, tier := aiDailyLimitForUser(claims.Email, deviceID); limit > 0 {
		resetAt := time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02") + "T00:00:00Z"
		if !overhead && dailyChatGPTCount(deviceID) >= limit {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(ChatGPTProxyResponse{
				Success: false,
				Error:   "Daily AI limit reached. Upgrade to Pro for higher limits.",
				Code:    "daily_limit", Tier: tier, ResetAt: resetAt,
			})
			return
		}
		if dailyAICallCount(deviceID) >= limit*aiOverheadFactor {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(ChatGPTProxyResponse{
				Success: false,
				Error:   "Daily AI limit reached. Upgrade to Pro for higher limits.",
				Code:    "daily_limit", Tier: tier, ResetAt: resetAt,
			})
			return
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"success":false,"error":"Streaming unsupported"}`)
		return
	}

	openAIRequest := map[string]interface{}{
		"model":          req.Model,
		"messages":       req.Messages,
		"stream":         true,
		"stream_options": map[string]interface{}{"include_usage": true},
	}
	if req.Temperature > 0 {
		openAIRequest["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		openAIRequest["max_tokens"] = req.MaxTokens
	}
	body, err := json.Marshal(openAIRequest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"success":false,"error":"Failed to prepare request"}`)
		return
	}

	upstream, err := http.NewRequest("POST",
		"https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"success":false,"error":"Failed to create request"}`)
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(upstream)
	if err != nil {
		log.Printf("❌ OpenAI stream connect error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `{"success":false,"error":"Failed to connect to ChatGPT"}`)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		log.Printf("❌ OpenAI stream error status %d: %s", resp.StatusCode, string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"success":false,"error":"ChatGPT API error: %d"}`, resp.StatusCode)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// nginx honours this per-response: without it the proxy buffers the whole
	// stream and the client sees one late blob — the exact thing we're fixing.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	emit := func(v interface{}) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	if crisisHit {
		log.Printf("🆘 Crisis markers detected (stream): device=%s lang=%s", deviceID, crisisLang)
		emit(map[string]string{"c": crisisNotice(crisisLang) + "\n\n———\n\n"})
	}

	var promptTokens, completionTokens, totalTokens, cachedTokens int
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens        int `json:"prompt_tokens"`
				CompletionTokens    int `json:"completion_tokens"`
				TotalTokens         int `json:"total_tokens"`
				PromptTokensDetails *struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if chunk.Usage != nil {
			promptTokens = chunk.Usage.PromptTokens
			completionTokens = chunk.Usage.CompletionTokens
			totalTokens = chunk.Usage.TotalTokens
			if chunk.Usage.PromptTokensDetails != nil {
				cachedTokens = chunk.Usage.PromptTokensDetails.CachedTokens
			}
		}
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			emit(map[string]string{"c": chunk.Choices[0].Delta.Content})
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("⚠️ OpenAI stream interrupted for device %s: %v", deviceID, err)
		emit(map[string]string{"error": "stream interrupted"})
		return
	}

	log.Printf("✅ ChatGPT stream done: device=%s tokens=%d prompt (%d cached) + %d completion",
		deviceID, promptTokens, cachedTokens, completionTokens)
	logAPICallWithTokens(deviceID, callType, req.Model,
		promptTokens, completionTokens, totalTokens, cachedTokens)
	emit(map[string]bool{"done": true})
}
