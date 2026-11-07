package main

import (
	"encoding/json"
	"reflect"
	"strconv"
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

func TestTikTokAvatarExpiry(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	live := "https://p16-sign.tiktokcdn-us.com/a/b~c.jpeg?lk3s=x&nonce=1&x-expires=" + itoa(now.Add(48*time.Hour).Unix()) + "&x-signature=abc"
	soon := "https://p16-sign.tiktokcdn-us.com/a/b~c.jpeg?x-expires=" + itoa(now.Add(30*time.Minute).Unix()) + "&x-signature=abc"
	dead := "https://p16-sign.tiktokcdn-us.com/a/b~c.jpeg?x-expires=" + itoa(now.Add(-time.Hour).Unix()) + "&x-signature=abc"
	plain := "https://example.com/avatar.jpg"
	if _, ok := tiktokAvatarExpiry(plain); ok {
		t.Fatal("unsigned link has no expiry")
	}
	if _, ok := tiktokAvatarExpiry("https://x/?x-expires=abc"); ok {
		t.Fatal("garbage stamp is not an expiry")
	}
	if exp, ok := tiktokAvatarExpiry(live); !ok || !exp.Equal(now.Add(48*time.Hour)) {
		t.Fatalf("expiry parse: %v %v", exp, ok)
	}
	for _, c := range []struct {
		u    string
		dead bool
	}{{live, false}, {soon, true}, {dead, true}, {plain, false}, {"", false}} {
		if got := tiktokAvatarDead(c.u, now); got != c.dead {
			t.Fatalf("dead(%q) = %v, want %v", c.u, got, c.dead)
		}
	}
	if tiktokAvatarServable(dead, now) != "" || tiktokAvatarServable(soon, now) != "" {
		t.Fatal("a dead or about-to-die link must not reach the app")
	}
	if tiktokAvatarServable(live, now) != live || tiktokAvatarServable(plain, now) != plain {
		t.Fatal("live links pass through unchanged")
	}
}

func TestTikTokAvatarStale(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	live := "https://p16-sign.tiktokcdn-us.com/a.jpeg?x-expires=" + itoa(now.Add(72*time.Hour).Unix())
	dead := "https://p16-sign.tiktokcdn-us.com/a.jpeg?x-expires=" + itoa(now.Add(-time.Hour).Unix())
	cases := []struct {
		name  string
		a     tiktokAccount
		stale bool
	}{
		{"never checked, live link", tiktokAccount{AvatarURL: live}, true},
		{"live link checked 1h ago", tiktokAccount{AvatarURL: live, AvatarCheckedAt: now.Add(-time.Hour)}, false},
		{"live link checked 25h ago", tiktokAccount{AvatarURL: live, AvatarCheckedAt: now.Add(-25 * time.Hour)}, true},
		{"dead link checked 10 min ago (TikTok down — no storm)", tiktokAccount{AvatarURL: dead, AvatarCheckedAt: now.Add(-10 * time.Minute)}, false},
		{"dead link checked 61 min ago", tiktokAccount{AvatarURL: dead, AvatarCheckedAt: now.Add(-61 * time.Minute)}, true},
		{"no avatar checked 10 min ago", tiktokAccount{AvatarCheckedAt: now.Add(-10 * time.Minute)}, false},
		{"no avatar checked 2h ago", tiktokAccount{AvatarCheckedAt: now.Add(-2 * time.Hour)}, true},
	}
	for _, c := range cases {
		if got := tiktokAvatarStale(&c.a, now); got != c.stale {
			t.Fatalf("%s: stale = %v, want %v", c.name, got, c.stale)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
