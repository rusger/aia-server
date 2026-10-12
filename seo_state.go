package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
)

// seoState remembers, per published URL, a hash of the page CONTENT and the
// date that content last changed. The nightly seo-gen used to stamp every
// page, sitemap <lastmod> and JSON-LD dateModified with the generation date,
// which told search engines "all 273 pages changed today" every day — a
// signal they learn to ignore. Now a page's date moves only when its
// title/description/body actually differ from the last run.
//
// Stored next to the pages as <outdir>/.seo-state.json (dot-file: nginx
// serves it, but nothing links to it; it holds only hashes and dates).
type seoState struct {
	Pages map[string]seoPageState `json:"pages"`
	dirty bool
}

type seoPageState struct {
	Hash     string `json:"hash"`
	Modified string `json:"modified"` // YYYY-MM-DD (UTC)
}

const seoStateFile = ".seo-state.json"

func newSeoState() *seoState { return &seoState{Pages: map[string]seoPageState{}} }

// loadSeoState reads the state file; a missing file is an empty state (first
// run), any other error is returned — a corrupt file must not silently reset
// every date to today.
func loadSeoState(path string) (*seoState, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newSeoState(), nil
	}
	if err != nil {
		return nil, err
	}
	s := newSeoState()
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, err
	}
	if s.Pages == nil {
		s.Pages = map[string]seoPageState{}
	}
	return s, nil
}

func (s *seoState) save(path string) error {
	if !s.dirty {
		return nil
	}
	// Deterministic output: sorted keys, so the file itself only changes
	// when something changed.
	keys := make([]string, 0, len(s.Pages))
	for k := range s.Pages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]seoPageState, len(s.Pages))
	for _, k := range keys {
		ordered[k] = s.Pages[k]
	}
	raw, err := json.MarshalIndent(struct {
		Pages map[string]seoPageState `json:"pages"`
	}{ordered}, "", " ")
	if err != nil {
		return err
	}
	return writeAtomic(path, raw)
}

// lastmod returns the date to publish for url whose content hashes to hash:
// the stored date when the hash is unchanged, otherwise today (and the state
// is updated).
func (s *seoState) lastmod(url, hash, today string) string {
	if p, ok := s.Pages[url]; ok && p.Hash == hash && p.Modified != "" {
		return p.Modified
	}
	s.Pages[url] = seoPageState{Hash: hash, Modified: today}
	s.dirty = true
	return today
}

// contentHash hashes the parts of a page that carry meaning (title,
// description, body) — never the date stamp itself, or every page would
// "change" every day again.
func contentHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
