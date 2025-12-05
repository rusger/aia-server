//go:build ignore
// +build ignore

package main

import (
    "database/sql"
    "flag"
    "fmt"
    "log"
    "os"
    "text/tabwriter"

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
    fmt.Println("  update  Update user subscription")
    fmt.Println("  super   Toggle super tier (uses more powerful AI model)")
    fmt.Println("  list    List all users")
    fmt.Println("\nExamples:")
    fmt.Println("  admin_cli get -id 263C369F-0823-41A5-A08A-39A63FD34C08")
    fmt.Println("  admin_cli update -id 263C369F-0823-41A5-A08A-39A63FD34C08 -type paid -length yearly")
    fmt.Println("  admin_cli super -id 263C369F-0823-41A5-A08A-39A63FD34C08 -enable")
    fmt.Println("  admin_cli super -id 263C369F-0823-41A5-A08A-39A63FD34C08 -disable")
    fmt.Println("  admin_cli list -limit 100")
    fmt.Println("\nNote: The ID is the device ID from the user's phone.")
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

    // Update user
    query := `UPDATE users
              SET subscription_type = ?, subscription_length = ?, updated_at = CURRENT_TIMESTAMP
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
