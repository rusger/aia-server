//go:build ignore
// +build ignore

package main

import (
    "database/sql"
    "flag"
    "fmt"
    "log"
    "os"
    "strings"
    "text/tabwriter"
    "time"

    _ "modernc.org/sqlite"
)

func main() {
    // Define subcommands
    getCmd := flag.NewFlagSet("get", flag.ExitOnError)
    getDeviceID := getCmd.String("id", "", "Device ID to query")

    updateCmd := flag.NewFlagSet("update", flag.ExitOnError)
    updateDeviceID := updateCmd.String("id", "", "Device ID to update")
    updateType := updateCmd.String("type", "", "Subscription type (free/paid)")
    updateLength := updateCmd.String("length", "", "Subscription length (monthly/yearly)")

    listCmd := flag.NewFlagSet("list", flag.ExitOnError)
    listLimit := listCmd.Int("limit", 50, "Number of records to show")

    grantCmd := flag.NewFlagSet("grant", flag.ExitOnError)
    grantEmail := grantCmd.String("email", "", "Account e-mail (the address the user logs in with)")
    grantType := grantCmd.String("type", "paid", "Subscription type (paid/free)")
    grantLength := grantCmd.String("length", "yearly", "Subscription length (monthly/yearly/lifetime)")
    grantDays := grantCmd.Int("days", 0, "Grant exactly N days instead of the length's period")

    superCmd := flag.NewFlagSet("super", flag.ExitOnError)
    superDeviceID := superCmd.String("id", "", "Device ID to update")
    superEnable := superCmd.Bool("enable", false, "Enable super tier")
    superDisable := superCmd.Bool("disable", false, "Disable super tier")

    // Check for subcommand
    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }

    // Open database
    db, err := sql.Open("sqlite", "./users.db")
    if err != nil {
        log.Fatalf("Failed to open database: %v", err)
    }
    defer db.Close()

    // Parse subcommand
    switch os.Args[1] {
    case "get":
        getCmd.Parse(os.Args[2:])
        if *getDeviceID == "" {
            fmt.Println("Error: -id is required")
            getCmd.Usage()
            os.Exit(1)
        }
        getUserInfo(db, *getDeviceID)

    case "update":
        updateCmd.Parse(os.Args[2:])
        if *updateDeviceID == "" || *updateType == "" || *updateLength == "" {
            fmt.Println("Error: -id, -type, and -length are required")
            updateCmd.Usage()
            os.Exit(1)
        }
        updateUser(db, *updateDeviceID, *updateType, *updateLength)

    case "list":
        listCmd.Parse(os.Args[2:])
        listUsers(db, *listLimit)

    case "grant":
        grantCmd.Parse(os.Args[2:])
        if *grantEmail == "" {
            fmt.Println("Error: -email is required")
            grantCmd.Usage()
            os.Exit(1)
        }
        grantByEmail(db, *grantEmail, *grantType, *grantLength, *grantDays)

    case "super":
        superCmd.Parse(os.Args[2:])
        if *superDeviceID == "" {
            fmt.Println("Error: -id is required")
            superCmd.Usage()
            os.Exit(1)
        }
        if !*superEnable && !*superDisable {
            fmt.Println("Error: -enable or -disable is required")
            superCmd.Usage()
            os.Exit(1)
        }
        if *superEnable && *superDisable {
            fmt.Println("Error: cannot use both -enable and -disable")
            os.Exit(1)
        }
        updateSuper(db, *superDeviceID, *superEnable)

    default:
        printUsage()
        os.Exit(1)
    }
}

func printUsage() {
    fmt.Println("Astrolog User Management CLI")
    fmt.Println("\nUsage:")
    fmt.Println("  admin_cli <command> [options]")
    fmt.Println("\nCommands:")
    fmt.Println("  get     Get user subscription info")
    fmt.Println("  update  Update user subscription (by device id)")
    fmt.Println("  grant   Give an account a subscription by e-mail (friends, support) — the same")
    fmt.Println("          write as POST /api/admin/grant-subscription, without its 2FA")
    fmt.Println("  super   Toggle super tier (uses more powerful AI model)")
    fmt.Println("  list    List all users")
    fmt.Println("\nExamples:")
    fmt.Println("  admin_cli get -id 263C369F-0823-41A5-A08A-39A63FD34C08")
    fmt.Println("  admin_cli update -id 263C369F-0823-41A5-A08A-39A63FD34C08 -type paid -length yearly")
    fmt.Println("  admin_cli super -id 263C369F-0823-41A5-A08A-39A63FD34C08 -enable")
    fmt.Println("  admin_cli super -id 263C369F-0823-41A5-A08A-39A63FD34C08 -disable")
    fmt.Println("  admin_cli grant -email friend@example.com                 (paid, one year)")
    fmt.Println("  admin_cli grant -email friend@example.com -length lifetime")
    fmt.Println("  admin_cli grant -email friend@example.com -days 30")
    fmt.Println("  admin_cli grant -email friend@example.com -type free        (take it back)")
    fmt.Println("  admin_cli list -limit 100")
    fmt.Println("\nNote: The ID is the device ID from the user's phone.")
    fmt.Println("The app learns of a grant at its next GET /api/user/info (at most every 5 minutes while")
    fmt.Println("open; at once on login or on the purchase screen) — the server is the only authority.")
    fmt.Println("\nSuper Tier: When enabled, user gets access to o1 model instead of gpt-4o (~6x cost)")
}

func getUserInfo(db *sql.DB, deviceID string) {
    var subscriptionType, subscriptionLength string
    var createdAt, updatedAt string
    var isSuper int

    query := `SELECT subscription_type, subscription_length, created_at, updated_at, COALESCE(is_super, 0)
              FROM users WHERE device_id = ?`

    err := db.QueryRow(query, deviceID).Scan(&subscriptionType, &subscriptionLength, &createdAt, &updatedAt, &isSuper)
    if err == sql.ErrNoRows {
        fmt.Printf("❌ User not found with device_id: %s\n", deviceID)
        os.Exit(1)
    } else if err != nil {
        log.Fatalf("Database error: %v", err)
    }

    superStatus := "No"
    if isSuper == 1 {
        superStatus = "Yes ⚡"
    }

    fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
    fmt.Println("│                    USER INFORMATION                     │")
    fmt.Println("└─────────────────────────────────────────────────────────┘")
    fmt.Printf("\n  Device ID:            %s\n", deviceID)
    fmt.Printf("  Subscription Type:    %s\n", subscriptionType)
    fmt.Printf("  Subscription Length:  %s\n", subscriptionLength)
    fmt.Printf("  Super Tier:           %s\n", superStatus)
    fmt.Printf("  Created At:           %s\n", createdAt)
    fmt.Printf("  Updated At:           %s\n", updatedAt)
    fmt.Println()
}

func updateUser(db *sql.DB, deviceID, subscriptionType, subscriptionLength string) {
    // Validate subscription_type
    if subscriptionType != "free" && subscriptionType != "paid" {
        fmt.Printf("❌ Invalid subscription type: %s (must be 'free' or 'paid')\n", subscriptionType)
        os.Exit(1)
    }

    // Validate subscription_length
    if subscriptionLength != "monthly" && subscriptionLength != "yearly" {
        fmt.Printf("❌ Invalid subscription length: %s (must be 'monthly' or 'yearly')\n", subscriptionLength)
        os.Exit(1)
    }

    // Check if user exists first
    var exists int
    err := db.QueryRow("SELECT COUNT(*) FROM users WHERE device_id = ?", deviceID).Scan(&exists)
    if err != nil {
        log.Fatalf("Database error: %v", err)
    }

    if exists == 0 {
        fmt.Printf("❌ User not found with device_id: %s\n", deviceID)
        fmt.Println("   User must register through the app first.")
        os.Exit(1)
    }

    // Update user — mark as admin-granted so the client knows there is no
    // self-serve renewal channel for this subscription.
    query := `UPDATE users
              SET subscription_type = ?, subscription_length = ?, last_payment_method = 'admin', updated_at = CURRENT_TIMESTAMP
              WHERE device_id = ?`

    result, err := db.Exec(query, subscriptionType, subscriptionLength, deviceID)
    if err != nil {
        log.Fatalf("Failed to update user: %v", err)
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        fmt.Printf("❌ User not found with device_id: %s\n", deviceID)
        os.Exit(1)
    }

    fmt.Println("\n✓ User updated successfully")
    fmt.Printf("  Device ID:            %s\n", deviceID)
    fmt.Printf("  Subscription Type:    %s\n", subscriptionType)
    fmt.Printf("  Subscription Length:  %s\n", subscriptionLength)
    fmt.Println()

    // Show updated info
    getUserInfo(db, deviceID)
}

func listUsers(db *sql.DB, limit int) {
    query := `SELECT device_id, subscription_type, subscription_length, COALESCE(is_super, 0), created_at, updated_at
              FROM users ORDER BY created_at DESC LIMIT ?`

    rows, err := db.Query(query, limit)
    if err != nil {
        log.Fatalf("Database error: %v", err)
    }
    defer rows.Close()

    fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
    fmt.Println("│                      USER LIST                          │")
    fmt.Println("└─────────────────────────────────────────────────────────┘\n")

    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "DEVICE ID\tTYPE\tLENGTH\tSUPER\tCREATED AT\tUPDATED AT")
    fmt.Fprintln(w, "───────────────────────────────────────\t─────\t────────\t─────\t───────────────────────\t───────────────────────")

    count := 0
    superCount := 0
    for rows.Next() {
        var deviceID, subscriptionType, subscriptionLength, createdAt, updatedAt string
        var isSuper int
        if err := rows.Scan(&deviceID, &subscriptionType, &subscriptionLength, &isSuper, &createdAt, &updatedAt); err != nil {
            log.Printf("Error scanning row: %v", err)
            continue
        }
        superStr := ""
        if isSuper == 1 {
            superStr = "⚡"
            superCount++
        }
        fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", deviceID, subscriptionType, subscriptionLength, superStr, createdAt, updatedAt)
        count++
    }

    w.Flush()
    fmt.Printf("\nTotal: %d users (%d super)\n\n", count, superCount)
}

func updateSuper(db *sql.DB, deviceID string, enable bool) {
    // Check if user exists first
    var exists int
    err := db.QueryRow("SELECT COUNT(*) FROM users WHERE device_id = ?", deviceID).Scan(&exists)
    if err != nil {
        log.Fatalf("Database error: %v", err)
    }

    if exists == 0 {
        fmt.Printf("❌ User not found with device_id: %s\n", deviceID)
        fmt.Println("   User must register through the app first.")
        os.Exit(1)
    }

    // Update is_super
    isSuper := 0
    if enable {
        isSuper = 1
    }

    query := `UPDATE users SET is_super = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?`
    result, err := db.Exec(query, isSuper, deviceID)
    if err != nil {
        log.Fatalf("Failed to update user: %v", err)
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        fmt.Printf("❌ User not found with device_id: %s\n", deviceID)
        os.Exit(1)
    }

    action := "disabled"
    if enable {
        action = "enabled ⚡"
    }
    fmt.Printf("\n✓ Super tier %s for user\n", action)

    // Show updated info
    getUserInfo(db, deviceID)
}

// grantByEmail mirrors adminGrantSubscription in astrolog_api.go (this file is
// built on its own — `go build admin_cli.go` — so the SQL is repeated here,
// not shared): the account's subscription window, the 'admin' payment method
// the renewal-channel logic keys on, and an audit row in purchase_history.
// A row is created when the e-mail has never logged in (completeEmailLogin
// then takes the «existing user» path and keeps the plan). Entitlement
// itself is read by getUserInfo / userEntitlement from these columns alone —
// trials, device identity groups and referral rewards are not touched, and
// a paid row simply wins over them (owner 04.10.2026).
func grantByEmail(db *sql.DB, email, subscriptionType, subscriptionLength string, days int) {
    email = strings.ToLower(strings.TrimSpace(email))
    if email == "" || !strings.Contains(email, "@") {
        fmt.Printf("❌ Invalid e-mail: %q\n", email)
        os.Exit(1)
    }
    if subscriptionType != "free" && subscriptionType != "paid" {
        fmt.Printf("❌ Invalid subscription type: %s (must be 'free' or 'paid')\n", subscriptionType)
        os.Exit(1)
    }
    if subscriptionLength != "monthly" && subscriptionLength != "yearly" && subscriptionLength != "lifetime" {
        fmt.Printf("❌ Invalid subscription length: %s (must be 'monthly', 'yearly' or 'lifetime')\n", subscriptionLength)
        os.Exit(1)
    }
    if days < 0 {
        fmt.Println("❌ -days must be positive")
        os.Exit(1)
    }

    now := time.Now()
    var expiry time.Time
    switch {
    case days > 0:
        expiry = now.AddDate(0, 0, days)
    case subscriptionLength == "lifetime":
        expiry = now.AddDate(100, 0, 0) // effectively permanent, as the endpoint does
    case subscriptionLength == "yearly":
        expiry = now.AddDate(1, 0, 0)
    default:
        expiry = now.AddDate(0, 1, 0)
    }
    // the endpoint's wording: a paid grant is 'admin'; a 'free' downgrade has no payment to attribute
    paymentMethod := "admin"
    if subscriptionType != "paid" {
        paymentMethod = ""
    }

    tx, err := db.Begin()
    if err != nil {
        log.Fatalf("Database error: %v", err)
    }
    defer tx.Rollback()

    var existingID int
    var deviceID sql.NullString
    err = tx.QueryRow(`SELECT id, current_device_id FROM users WHERE email = ?`, email).Scan(&existingID, &deviceID)
    created := false
    switch {
    case err == sql.ErrNoRows:
        created = true
        if _, err = tx.Exec(`INSERT INTO users (email, subscription_type, subscription_length, subscription_expiry, last_payment_method)
                              VALUES (?, ?, ?, ?, ?)`,
            email, subscriptionType, subscriptionLength, expiry, paymentMethod); err != nil {
            log.Fatalf("Failed to create user: %v", err)
        }
    case err != nil:
        log.Fatalf("Database error: %v", err)
    default:
        if _, err = tx.Exec(`UPDATE users SET subscription_type = ?, subscription_length = ?, subscription_expiry = ?,
                              last_payment_method = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?`,
            subscriptionType, subscriptionLength, expiry, paymentMethod, email); err != nil {
            log.Fatalf("Failed to update user: %v", err)
        }
    }
    if subscriptionType == "paid" {
        // the audit row: a nanosecond tx id keeps re-grants apart under the (email, tx, store) unique index
        if _, err = tx.Exec(`INSERT OR IGNORE INTO purchase_history
            (email, device_id, product_id, transaction_id, purchase_date, expiry_date, subscription_type, subscription_length, store)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            email, deviceID.String, "admin_grant_"+subscriptionLength, fmt.Sprintf("admin-%d", now.UnixNano()),
            now, expiry, subscriptionType, subscriptionLength, "admin"); err != nil {
            log.Fatalf("Failed to write purchase_history: %v", err)
        }
    }
    if err = tx.Commit(); err != nil {
        log.Fatalf("Commit failed: %v", err)
    }

    verb := "updated"
    if created {
        verb = "created (the account did not exist yet — the plan is waiting for the first login)"
    }
    fmt.Printf("\n✓ Account %s\n", verb)
    fmt.Printf("  E-mail:               %s\n", email)
    fmt.Printf("  Subscription Type:    %s\n", subscriptionType)
    fmt.Printf("  Subscription Length:  %s\n", subscriptionLength)
    fmt.Printf("  Expires:              %s\n", expiry.UTC().Format("2006-01-02 15:04:05 UTC"))
    fmt.Printf("  Payment Method:       %s\n", paymentMethod)
    if deviceID.Valid && deviceID.String != "" {
        fmt.Printf("  Current Device:       %s\n", deviceID.String)
    }
    fmt.Println()
}
