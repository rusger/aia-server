package main

// app_latest.go — GET /api/app/latest: последняя выпущенная версия приложения (владелец 15.10.2026).
//
// У Google Play нет надёжного источника версии без ключей, а владелец всегда выкладывает в Play ту же версию, что в
// App Store. При подаче в App Store (my_first_app/docs/RELEASE_IOS.md) Claude пишет версию в файл APP_LATEST_FILE;
// приложение на Android сравнивает с ней свою и показывает «Последняя» / «Обновить». iOS смотрит App Store напрямую.

import (
	"encoding/json"
	"net/http"
	"os"
)

func appLatestFile() string { return envDefault("APP_LATEST_FILE", "./app_latest.json") }

// GET /api/app/latest → {version, build, released, android_url, ios_url}; нет файла или он битый — 404.
func appLatestHandler(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(appLatestFile())
	var doc struct {
		Version string `json:"version"`
	}
	if err != nil || json.Unmarshal(raw, &doc) != nil || doc.Version == "" {
		http.Error(w, `{"error":"no release info"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(raw)
}
