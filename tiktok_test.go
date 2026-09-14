package main

import (
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
	if c, n := tiktokChunkPlan(100 << 20); c != 32<<20 || n != 4 {
		t.Fatalf("100 MB → 4 chunks of 32 MB: %d %d", c, n)
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
