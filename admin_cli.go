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
    getUserID := getCmd.String("id", "", "User ID to query")

    updateCmd := flag.NewFlagSet("update", flag.ExitOnError)
    updateUserID := updateCmd.String("id", "", "User ID to update")
    updateType := updateCmd.String("type", "", "Subscription type (free/paid)")
    updateLength := updateCmd.String("length", "", "Subscription length (monthly/yearly)")

    listCmd := flag.NewFlagSet("list", flag.ExitOnError)
    listLimit := listCmd.Int("limit", 50, "Number of records to show")

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
        if *getUserID == "" {
            fmt.Println("Error: -id is required")
            getCmd.Usage()
            os.Exit(1)
        }
        getUserInfo(db, *getUserID)

    case "update":
        updateCmd.Parse(os.Args[2:])
        if *updateUserID == "" || *updateType == "" || *updateLength == "" {
            fmt.Println("Error: -id, -type, and -length are required")
            updateCmd.Usage()
            os.Exit(1)
        }
        updateUser(db, *updateUserID, *updateType, *updateLength)

    case "list":
        listCmd.Parse(os.Args[2:])
        listUsers(db, *listLimit)

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
    fmt.Println("  list    List all users")
    fmt.Println("\nExamples:")
    fmt.Println("  admin_cli get -id 5c8f4981-43ad-4fcb-92a9-515d7efec8f8")
    fmt.Println("  admin_cli update -id 5c8f4981-43ad-4fcb-92a9-515d7efec8f8 -type paid -length yearly")
    fmt.Println("  admin_cli list -limit 100")
}

func getUserInfo(db *sql.DB, userID string) {
    var subscriptionType, subscriptionLength string
    var createdAt, updatedAt string

    query := `SELECT subscription_type, subscription_length, created_at, updated_at
              FROM users WHERE user_id = ?`

    err := db.QueryRow(query, userID).Scan(&subscriptionType, &subscriptionLength, &createdAt, &updatedAt)
    if err == sql.ErrNoRows {
        fmt.Printf("❌ User not found: %s\n", userID)
        os.Exit(1)
    } else if err != nil {
        log.Fatalf("Database error: %v", err)
    }

    fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
    fmt.Println("│                    USER INFORMATION                     │")
    fmt.Println("└─────────────────────────────────────────────────────────┘")
    fmt.Printf("\n  User ID:              %s\n", userID)
    fmt.Printf("  Subscription Type:    %s\n", subscriptionType)
    fmt.Printf("  Subscription Length:  %s\n", subscriptionLength)
    fmt.Printf("  Created At:           %s\n", createdAt)
    fmt.Printf("  Updated At:           %s\n", updatedAt)
    fmt.Println()
}

func updateUser(db *sql.DB, userID, subscriptionType, subscriptionLength string) {
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
    err := db.QueryRow("SELECT COUNT(*) FROM users WHERE user_id = ?", userID).Scan(&exists)
    if err != nil {
        log.Fatalf("Database error: %v", err)
    }

    if exists == 0 {
        fmt.Printf("❌ User not found: %s\n", userID)
        fmt.Println("   Create the user first before updating.")
        os.Exit(1)
    }

    // Update user
    query := `UPDATE users
              SET subscription_type = ?, subscription_length = ?, updated_at = CURRENT_TIMESTAMP
              WHERE user_id = ?`

    result, err := db.Exec(query, subscriptionType, subscriptionLength, userID)
    if err != nil {
        log.Fatalf("Failed to update user: %v", err)
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        fmt.Printf("❌ User not found: %s\n", userID)
        os.Exit(1)
    }

    fmt.Println("\n✓ User updated successfully")
    fmt.Printf("  User ID:              %s\n", userID)
    fmt.Printf("  Subscription Type:    %s\n", subscriptionType)
    fmt.Printf("  Subscription Length:  %s\n", subscriptionLength)
    fmt.Println()

    // Show updated info
    getUserInfo(db, userID)
}

func listUsers(db *sql.DB, limit int) {
    query := `SELECT user_id, subscription_type, subscription_length, created_at, updated_at
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
    fmt.Fprintln(w, "USER ID\tTYPE\tLENGTH\tCREATED AT\tUPDATED AT")
    fmt.Fprintln(w, "───────────────────────────────────────\t─────\t────────\t───────────────────────\t───────────────────────")

    count := 0
    for rows.Next() {
        var userID, subscriptionType, subscriptionLength, createdAt, updatedAt string
        if err := rows.Scan(&userID, &subscriptionType, &subscriptionLength, &createdAt, &updatedAt); err != nil {
            log.Printf("Error scanning row: %v", err)
            continue
        }
        fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", userID, subscriptionType, subscriptionLength, createdAt, updatedAt)
        count++
    }

    w.Flush()
    fmt.Printf("\nTotal: %d users\n\n", count)
}
