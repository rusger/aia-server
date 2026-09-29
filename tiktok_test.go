package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestTikTokChunkPlan(t *testing.T) {
	if c, n := tiktokChunkPlan(0); c != 0 || n != 0 {
		t.Fatalf("empty: %d %d", c, n)
	}
	if c, n := tiktokChunkPlan(5_000_000); c != 5_000_000 || n != 1 {
		t.Fatalf("small file must be one chunk: %d %d", c, n)
	}
	if c, n := tiktokChunkPlan(64 << 20); c != 64<<20 || n != 1 {
		t.Fatalf("64 MB is still one chunk: %d %d", c, n)
	}
	if c, n := tiktokChunkPlan(100 << 20); c != 32<<20 || n != 3 {
		t.Fatalf("100 MB → floor(100/32)=3 chunks, last absorbs the 4 MB remainder: %d %d", c, n)
	}
	if c, n := tiktokChunkPlan(96 << 20); c != 32<<20 || n != 3 {
		t.Fatalf("96 MB → exactly 3 chunks: %d %d", c, n)
	}
	if c, n := tiktokChunkPlan((64 << 20) + 1); c != 32<<20 || n != 2 {
		t.Fatalf("just over 64 MB → 2 chunks (last ~32 MB+1): %d %d", c, n)
	}
}

func TestTikTokInitPayload(t *testing.T) {
	var req tiktokPublishRequest
	body := `{"title":"My horoscope","privacy_level":"SELF_ONLY","disable_duet":true,"video_size":5000000,"brand_organic_toggle":true,"is_aigc":true}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	p := tiktokInitPayload(req)
	post := p["post_info"].(map[string]interface{})
	if post["is_aigc"] != true {
		t.Fatalf("is_aigc must reach TikTok as true: %v", post["is_aigc"])
	}
	want := map[string]interface{}{
		"title": "My horoscope", "privacy_level": "SELF_ONLY",
		"disable_comment": false, "disable_duet": true, "disable_stitch": false,
		"brand_content_toggle": false, "brand_organic_toggle": true, "is_aigc": true,
	}
	if !reflect.DeepEqual(post, want) {
		t.Fatalf("post_info:\n got %v\nwant %v", post, want)
	}
	src := p["source_info"].(map[string]interface{})
	wantSrc := map[string]interface{}{
		"source": "FILE_UPLOAD", "video_size": int64(5000000), "chunk_size": int64(5000000), "total_chunk_count": int64(1),
	}
	if !reflect.DeepEqual(src, wantSrc) {
		t.Fatalf("source_info:\n got %#v\nwant %#v", src, wantSrc)
	}

	// an older app build does not send the field: it stays false
	var old tiktokPublishRequest
	if err := json.Unmarshal([]byte(`{"title":"t","privacy_level":"SELF_ONLY","video_size":1}`), &old); err != nil {
		t.Fatal(err)
	}
	if got := tiktokInitPayload(old)["post_info"].(map[string]interface{})["is_aigc"]; got != false {
		t.Fatalf("absent is_aigc must be false: %v", got)
	}
}

func TestTikTokNeedsRefresh(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	if tiktokNeedsRefresh(now.Add(time.Hour), now) {
		t.Fatal("an hour left — no refresh")
	}
	if !tiktokNeedsRefresh(now.Add(2*time.Minute), now) {
		t.Fatal("2 minutes left — refresh")
	}
	if !tiktokNeedsRefresh(now.Add(-time.Minute), now) {
		t.Fatal("expired — refresh")
	}
}

func TestTikTokAPIError(t *testing.T) {
	if c, _ := tiktokAPIError([]byte(`{"data":{},"error":{"code":"ok","message":""}}`)); c != "ok" {
		t.Fatalf("ok envelope: %s", c)
	}
	c, m := tiktokAPIError([]byte(`{"error":{"code":"access_token_invalid","message":"The access token is invalid"}}`))
	if c != "access_token_invalid" || m == "" {
		t.Fatalf("error envelope: %s %s", c, m)
	}
	if c, _ := tiktokAPIError([]byte(`<html>`)); c != "bad_response" {
		t.Fatalf("non-json: %s", c)
	}
	if c, _ := tiktokAPIError([]byte(`{"data":{"publish_id":"x"}}`)); c != "ok" {
		t.Fatalf("no error field means ok: %s", c)
	}
}
