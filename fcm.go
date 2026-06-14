package main

// FCM (Firebase Cloud Messaging) outbound push for ANDROID devices, via the
// HTTP v1 API. iOS keeps using APNs directly (see push.go); this file is the
// Android transport. Auth is a service-account JSON (Firebase Admin SDK key):
// we mint an OAuth2 access token (RS256 JWT → token endpoint) and POST messages
// to fcm.googleapis.com/v1/projects/<project_id>/messages:send.
//
// Build: compiled alongside the other server files (see build.sh).

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type fcmConfig struct {
	projectID   string
	clientEmail string
	key         *rsa.PrivateKey
}

var (
	fcmCfg     *fcmConfig
	fcmCfgErr  error
	fcmCfgOnce sync.Once

	fcmTokenMu      sync.Mutex
	fcmAccessToken  string
	fcmTokenExpires time.Time
)

// serviceAccountJSON is the subset of the Firebase Admin SDK key we need.
type serviceAccountJSON struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
}

func loadFCMConfig() (*fcmConfig, error) {
	fcmCfgOnce.Do(func() {
		path := getEnv("FCM_SERVICE_ACCOUNT_PATH", "")
		if path == "" {
			fcmCfgErr = fmt.Errorf("FCM not configured: set FCM_SERVICE_ACCOUNT_PATH")
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			fcmCfgErr = fmt.Errorf("reading FCM service account %s: %w", path, err)
			return
		}
		var sa serviceAccountJSON
		if err := json.Unmarshal(raw, &sa); err != nil {
			fcmCfgErr = fmt.Errorf("parsing FCM service account JSON: %w", err)
			return
		}
		if sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
			fcmCfgErr = fmt.Errorf("FCM service account JSON missing project_id/client_email/private_key")
			return
		}
		block, _ := pem.Decode([]byte(sa.PrivateKey))
		if block == nil {
			fcmCfgErr = fmt.Errorf("FCM private_key is not valid PEM")
			return
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fcmCfgErr = fmt.Errorf("parsing FCM private key: %w", err)
			return
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			fcmCfgErr = fmt.Errorf("FCM private key is not RSA")
			return
		}
		fcmCfg = &fcmConfig{projectID: sa.ProjectID, clientEmail: sa.ClientEmail, key: rsaKey}
		log.Printf("✓ FCM configured (project=%s)", sa.ProjectID)
	})
	return fcmCfg, fcmCfgErr
}

// fcmAccessTokenValue returns a cached OAuth2 access token (refreshed ~5 min
// before expiry), minted from the service account via a signed JWT.
func fcmAccessTokenValue(c *fcmConfig) (string, error) {
	fcmTokenMu.Lock()
	defer fcmTokenMu.Unlock()

	if fcmAccessToken != "" && time.Now().Before(fcmTokenExpires.Add(-5*time.Minute)) {
		return fcmAccessToken, nil
	}

	now := time.Now()
	header := base64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := base64url([]byte(fmt.Sprintf(
		`{"iss":"%s","scope":"https://www.googleapis.com/auth/firebase.messaging","aud":"https://oauth2.googleapis.com/token","iat":%d,"exp":%d}`,
		c.clientEmail, now.Unix(), now.Add(time.Hour).Unix())))
	signingInput := header + "." + claims

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing FCM JWT: %w", err)
	}
	assertion := signingInput + "." + base64url(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	resp, err := apnsHTTPClient.PostForm("https://oauth2.googleapis.com/token", form)
	if err != nil {
		return "", fmt.Errorf("FCM token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("FCM token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("FCM token parse failed: %v", err)
	}
	fcmAccessToken = tr.AccessToken
	fcmTokenExpires = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	return fcmAccessToken, nil
}

// sendFCM delivers a notification to one Android FCM registration token.
func sendFCM(deviceToken, title, body, payload string) error {
	c, err := loadFCMConfig()
	if err != nil {
		return err
	}
	accessToken, err := fcmAccessTokenValue(c)
	if err != nil {
		return err
	}

	msg := map[string]interface{}{
		"token": deviceToken,
		"notification": map[string]string{
			"title": title,
			"body":  body,
		},
		"android": map[string]interface{}{
			"priority": "high",
		},
	}
	if payload != "" {
		// The app reads data["payload"] to deep-link on tap.
		msg["data"] = map[string]string{"payload": payload}
	}
	jsonBody, err := json.Marshal(map[string]interface{}{"message": msg})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", c.projectID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := apnsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("FCM request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("FCM %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
}

// sendPushToToken dispatches to the right transport for a device's platform:
// Android → FCM, everything else (iOS / unknown) → APNs.
func sendPushToToken(platform, token, title, body, payload string) error {
	if strings.EqualFold(platform, "Android") {
		return sendFCM(token, title, body, payload)
	}
	return sendAPNs(token, title, body, payload)
}
