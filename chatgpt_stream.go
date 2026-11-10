package main

// Streaming AI proxy (owner decision 2026-08-29, onboarding wow-moment):
// same contract as /api/chatgpt — JWT, model enforcement, rate/daily limits,
// crisis screen, api_calls accounting — but the answer is relayed to the
// client token-by-token over SSE instead of buffered for minutes.
//
// Wire protocol (deliberately tiny, not raw OpenAI SSE):
//   data: {"i":N,"c":"<content delta>"}   — text chunk
//   data: {"i":N,"done":true}             — clean end of stream
//   data: {"i":N,"error":"<message>"}     — terminal mid-stream failure
//   : ping                                — keep-alive comment while the model thinks
// "i" is the event sequence number (07.11.2026) used by the resume protocol in
// chatgpt_resume.go; the app's parser ignores unknown keys and non-"data:"
// lines (chatgpt_service.dart), so older clients are unaffected. Pre-stream
// failures (auth, quotas, upstream 4xx/5xx) are plain JSON with the
// appropriate status code, so old error handling keeps working.
//
// Since 07.11.2026 the OpenAI read runs in its own goroutine and appends to a
// streamBuf; the handler only follows that buffer. The upstream request is
// not bound to r.Context() on purpose: a client that drops mid-answer does not
// kill the generation, and with a stream_id it can resume it.

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
		streamJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}
	if OPENAI_API_KEY == "" {
		streamJSONError(w, http.StatusInternalServerError, "ChatGPT service not configured on server", "")
		return
	}

	var req ChatGPTProxyRequest
	if err := decodeAIRequest(w, r, &req); err != nil { // gzip-aware, capped: chat_upload.go
		status := http.StatusBadRequest
		if err == errAIRequestTooLarge {
			status = http.StatusRequestEntityTooLarge
		}
		streamJSONError(w, status, "Invalid request format", "")
		return
	}
	if req.StreamID != "" && !streamIDRe.MatchString(req.StreamID) {
		streamJSONError(w, http.StatusBadRequest, "Invalid stream_id", "")
		return
	}

	deviceID := claims.DeviceID
	crisisHit, crisisLang := detectCrisis(lastUserMessage(req.Messages))
	req.Model = enforceModelForUser(claims.Email, deviceID, req.Model)

	// Same gate battery as chatGPTProxy (kept as a parallel copy on purpose:
	// the buffered handler is the hot path and stays untouched).
	if !ipLimiter.GetLimiter(getClientIP(r)).Allow() {
		streamJSONError(w, http.StatusTooManyRequests, "Too many requests from your network. Please wait.", "")
		return
	}
	if !deviceLimiter.GetLimiter(deviceID).Allow() {
		streamJSONError(w, http.StatusTooManyRequests, "Rate limit exceeded. Please try again.", "")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		streamJSONError(w, http.StatusInternalServerError, "Streaming unsupported", "")
		return
	}

	// Idempotent repeat (same device, same stream_id): the answer is already
	// being generated or is finished — replay it, do not touch quota or OpenAI.
	// Checked before the daily limit so a retry never fails on the quota the
	// original call is about to consume.
	now := time.Now()
	var key string
	if req.StreamID != "" {
		key = streamKey(deviceID, req.StreamID)
		if b := streams.lookupOrRestore(deviceID, req.StreamID, now); b != nil {
			log.Printf("↩️ ChatGPT stream repeat: device=%s — replaying, no second model call", deviceID)
			streamSSEHeaders(w)
			streamFollow(r.Context(), w, flusher, b, -1, true)
			return
		}
	}

	callType, overhead := normalizeAICallType(req.CallType)
	if limit, tier := aiDailyLimitForUser(claims.Email, deviceID); limit > 0 {
		resetAt := time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02") + "T00:00:00Z"
		if (!overhead && dailyChatGPTCount(deviceID) >= limit) || dailyAICallCount(deviceID) >= limit*aiOverheadFactor {
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
		streamJSONError(w, http.StatusInternalServerError, "Failed to prepare request", "")
		return
	}

	// Claim the stream_id before talking to OpenAI: two concurrent POSTs with
	// the same id must produce one generation (the loser follows the winner).
	var buf *streamBuf
	if key != "" {
		var existed bool
		if buf, existed = streams.register(key, now); existed {
			log.Printf("↩️ ChatGPT stream repeat (raced): device=%s — following, no second model call", deviceID)
			streamSSEHeaders(w)
			streamFollow(r.Context(), w, flusher, buf, -1, true)
			return
		}
		if !overhead { // a user-facing answer waits for the app's ack (pending_answers.go)
			buf.persistAs(deviceID, req.StreamID, callType)
		}
	} else {
		buf = newStreamBuf(now) // old client: not resumable, same pipeline
	}

	upstream, err := http.NewRequest("POST",
		"https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		streams.drop(key)
		streamJSONError(w, http.StatusInternalServerError, "Failed to create request", "")
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("Authorization", "Bearer "+OPENAI_API_KEY)

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(upstream)
	if err != nil {
		streams.drop(key) // pre-stream failure: a retry with the same id may try again
		log.Printf("❌ OpenAI stream connect error: %v", err)
		streamJSONError(w, http.StatusBadGateway, "Failed to connect to ChatGPT", "")
		return
	}
	if resp.StatusCode != 200 {
		streams.drop(key)
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		log.Printf("❌ OpenAI stream error status %d: %s", resp.StatusCode, string(b))
		streamJSONError(w, http.StatusBadGateway, fmt.Sprintf("ChatGPT API error: %d", resp.StatusCode), "")
		return
	}

	streamSSEHeaders(w)
	go chatGPTStreamGenerate(buf, resp.Body, deviceID, callType, req.Model, req.AnswerID, crisisHit, crisisLang)
	streamFollow(r.Context(), w, flusher, buf, -1, true)
}

// chatGPTStreamGenerate reads one OpenAI SSE response into buf and books the
// call once at the end — whether or not anyone is still listening.
func chatGPTStreamGenerate(buf *streamBuf, body io.ReadCloser, deviceID, callType, model, answerID string, crisisHit bool, crisisLang string) {
	defer body.Close()
	emit := func(v map[string]interface{}) { buf.append(v, time.Now()) }

	if crisisHit {
		log.Printf("🆘 Crisis markers detected (stream): device=%s lang=%s", deviceID, crisisLang)
		emit(map[string]interface{}{"c": crisisNotice(crisisLang) + "\n\n———\n\n"})
	}

	var promptTokens, completionTokens, totalTokens, cachedTokens int
	scanner := bufio.NewScanner(body)
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
			emit(map[string]interface{}{"c": chunk.Choices[0].Delta.Content})
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("⚠️ OpenAI stream interrupted for device %s: %v", deviceID, err)
		emit(map[string]interface{}{"error": "stream interrupted"})
		return
	}

	log.Printf("✅ ChatGPT stream done: device=%s tokens=%d prompt (%d cached) + %d completion",
		deviceID, promptTokens, cachedTokens, completionTokens)
	logAPICallForAnswer(deviceID, callType, model, answerID,
		promptTokens, completionTokens, totalTokens, cachedTokens)
	emit(map[string]interface{}{"done": true})
}
