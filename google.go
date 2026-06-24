package main

// ---------------------------------------------------------------------------
// Google Play Real-time Developer Notifications (RTDN)
//
// Google Play publishes subscription lifecycle events to a Cloud Pub/Sub topic.
// A Pub/Sub *push* subscription POSTs each message to this endpoint. This is the
// Android equivalent of Apple's App Store Server Notifications V2 webhook and is
// the only way to see silent auto-renewals / churn for Google subscribers (the
// client only syncs purchases when the app happens to be opened).
//
// v1 scope: record every subscription event into google_notifications so the
// renewal-rate stats can cover Android too. Entitlement sync (downgrade on
// EXPIRED, extend on RENEWED) is a deliberate follow-up — it needs a
// purchase_token -> user mapping and is not required for the stats.
//
// Security: Pub/Sub push has no IP allow-list, so the subscription is created
// with a secret query token (?token=GOOGLE_RTDN_SECRET) that we check here.
// ---------------------------------------------------------------------------

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
)

var GOOGLE_RTDN_SECRET = getEnv("GOOGLE_RTDN_SECRET", "")

var googleNotifTableOnce sync.Once

func ensureGoogleNotificationsTable() {
	googleNotifTableOnce.Do(func() {
		_, err := db.Exec(`
			CREATE TABLE IF NOT EXISTS google_notifications (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				message_id TEXT UNIQUE,
				notification_type INTEGER,
				notification_name TEXT,
				subscription_id TEXT,
				purchase_token TEXT,
				package_name TEXT,
				event_time_millis INTEGER,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_google_notif_token ON google_notifications(purchase_token);
		`)
		if err != nil {
			log.Printf("google_notifications table init error: %v", err)
		}
	})
}

// googleNotificationName maps the Google Play subscriptionNotification type code
// to a readable name. Kept aligned with Apple semantics for the renewal stats:
//
//	renewed:  RENEWED, RECOVERED, RESTARTED
//	expired:  EXPIRED
//	failed:   ON_HOLD, IN_GRACE_PERIOD (billing retry)
//	canceled: CANCELED (auto-renew off, still entitled until expiry)
//	revoked:  REVOKED (refund/chargeback)
var googleNotificationName = map[int]string{
	1:  "SUBSCRIPTION_RECOVERED",
	2:  "SUBSCRIPTION_RENEWED",
	3:  "SUBSCRIPTION_CANCELED",
	4:  "SUBSCRIPTION_PURCHASED",
	5:  "SUBSCRIPTION_ON_HOLD",
	6:  "SUBSCRIPTION_IN_GRACE_PERIOD",
	7:  "SUBSCRIPTION_RESTARTED",
	8:  "SUBSCRIPTION_PRICE_CHANGE_CONFIRMED",
	9:  "SUBSCRIPTION_DEFERRED",
	10: "SUBSCRIPTION_PAUSED",
	11: "SUBSCRIPTION_PAUSE_SCHEDULE_CHANGED",
	12: "SUBSCRIPTION_REVOKED",
	13: "SUBSCRIPTION_EXPIRED",
}

type pubsubPushEnvelope struct {
	Message struct {
		Data      string `json:"data"` // base64-encoded DeveloperNotification JSON
		MessageID string `json:"messageId"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

type googleDeveloperNotification struct {
	Version         string `json:"version"`
	PackageName     string `json:"packageName"`
	EventTimeMillis string `json:"eventTimeMillis"`

	SubscriptionNotification *struct {
		Version          string `json:"version"`
		NotificationType int    `json:"notificationType"`
		PurchaseToken    string `json:"purchaseToken"`
		SubscriptionID   string `json:"subscriptionId"`
	} `json:"subscriptionNotification"`

	TestNotification *struct {
		Version string `json:"version"`
	} `json:"testNotification"`
}

// googlePlayNotification receives Cloud Pub/Sub push messages carrying Google
// Play RTDN. It always ACKs (200) once the token is valid so Pub/Sub does not
// redeliver — a wrong token returns 403 so a misconfigured subscription is loud.
func googlePlayNotification(w http.ResponseWriter, r *http.Request) {
	if GOOGLE_RTDN_SECRET != "" && r.URL.Query().Get("token") != GOOGLE_RTDN_SECRET {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var env pubsubPushEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		// Not a Pub/Sub envelope we understand — ACK to avoid redelivery storms.
		log.Printf("RTDN: bad envelope: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(env.Message.Data)
	if err != nil {
		log.Printf("RTDN: base64 decode failed: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	var note googleDeveloperNotification
	if err := json.Unmarshal(decoded, &note); err != nil {
		log.Printf("RTDN: bad notification json: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	if note.TestNotification != nil {
		log.Printf("RTDN: TEST notification received (package=%s) — pipeline OK", note.PackageName)
		w.WriteHeader(http.StatusOK)
		return
	}

	if sn := note.SubscriptionNotification; sn != nil {
		ensureGoogleNotificationsTable()
		eventMillis, _ := strconv.ParseInt(note.EventTimeMillis, 10, 64)
		name := googleNotificationName[sn.NotificationType]
		if name == "" {
			name = "UNKNOWN_" + strconv.Itoa(sn.NotificationType)
		}
		_, err := db.Exec(`
			INSERT OR IGNORE INTO google_notifications
			  (message_id, notification_type, notification_name, subscription_id, purchase_token, package_name, event_time_millis)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			env.Message.MessageID, sn.NotificationType, name, sn.SubscriptionID, sn.PurchaseToken, note.PackageName, eventMillis)
		if err != nil {
			log.Printf("RTDN: insert failed: %v", err)
		} else {
			log.Printf("RTDN: stored %s (sub=%s)", name, sn.SubscriptionID)
		}
	}

	w.WriteHeader(http.StatusOK)
}
