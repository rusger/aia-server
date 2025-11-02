# Astrolog Admin CLI - User Management Tool

## Overview

The Admin CLI tool allows you to manage user subscriptions directly from the server command line.

## Installation

### 1. Install Required Dependency

The admin CLI requires the `github.com/google/uuid` package:

```bash
cd /Users/ruslangerasimov/aia/aia-server
go get github.com/google/uuid
```

### 2. Build the Admin CLI

```bash
# Build the admin CLI executable
go build -o admin_cli admin_cli.go

# Make it executable (Linux/Mac)
chmod +x admin_cli
```

## Usage

### Commands

#### 1. Get User Information

Check a user's subscription status and details:

```bash
./admin_cli get -id <USER_ID>
```

**Example:**
```bash
./admin_cli get -id 5c8f4981-43ad-4fcb-92a9-515d7efec8f8
```

**Output:**
```
┌─────────────────────────────────────────────────────────┐
│                    USER INFORMATION                     │
└─────────────────────────────────────────────────────────┘

  User ID:              5c8f4981-43ad-4fcb-92a9-515d7efec8f8
  Subscription Type:    free
  Subscription Length:  monthly
  Created At:           2025-11-02 10:30:45
  Updated At:           2025-11-02 10:30:45
```

#### 2. Update User Subscription

Manually modify a user's subscription:

```bash
./admin_cli update -id <USER_ID> -type <free|paid> -length <monthly|yearly>
```

**Example:**
```bash
./admin_cli update -id 5c8f4981-43ad-4fcb-92a9-515d7efec8f8 -type paid -length yearly
```

**Valid Values:**
- **type**: `free` or `paid`
- **length**: `monthly` or `yearly`

#### 3. List All Users

View all registered users:

```bash
./admin_cli list [-limit N]
```

**Example:**
```bash
# Show last 50 users (default)
./admin_cli list

# Show last 100 users
./admin_cli list -limit 100
```

**Output:**
```
┌─────────────────────────────────────────────────────────┐
│                      USER LIST                          │
└─────────────────────────────────────────────────────────┘

USER ID                               TYPE    LENGTH    CREATED AT              UPDATED AT
───────────────────────────────────  ─────   ────────  ─────────────────────  ─────────────────────
5c8f4981-43ad-4fcb-92a9-515d7efec8f8 free    monthly   2025-11-02 10:30:45    2025-11-02 10:30:45
b99291f0-8386-4123-8ceb-77bd9fad7d28 paid    yearly    2025-11-02 09:15:20    2025-11-02 11:45:30

Total: 2 users
```

## Common Scenarios

### Scenario 1: User Requests Manual Subscription Upgrade

When a user contacts you to upgrade their subscription:

```bash
# 1. First, check their current status
./admin_cli get -id <USER_ID>

# 2. Update to paid subscription
./admin_cli update -id <USER_ID> -type paid -length yearly

# 3. Verify the update
./admin_cli get -id <USER_ID>
```

### Scenario 2: Check Subscription Status

To verify a user's current subscription:

```bash
./admin_cli get -id <USER_ID>
```

### Scenario 3: View All Users

To see a list of all registered users:

```bash
./admin_cli list -limit 100
```

## Troubleshooting

### Error: "Database not found"

Make sure you're running the admin CLI from the same directory as `users.db`:

```bash
cd /Users/ruslangerasimov/aia/aia-server
./admin_cli <command>
```

### Error: "User not found"

The user ID doesn't exist in the database. Double-check the ID or have the user register first through the app.

### Error: "Invalid subscription type/length"

Only these values are allowed:
- **type**: `free` or `paid`
- **length**: `monthly` or `yearly`

## Technical Details

### Database Location

The admin CLI reads from: `./users.db` (SQLite database)

### Database Schema

```sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    subscription_type TEXT NOT NULL DEFAULT 'free',
    subscription_length TEXT NOT NULL DEFAULT 'monthly',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Security Notes

1. **Direct Database Access**: This tool directly modifies the database. Always double-check the user ID before making changes.
2. **Backup Recommended**: Consider backing up `users.db` before bulk operations.
3. **Server Access Only**: This tool should only be run on the server where `users.db` is located.

## ID Synchronization Fix

### The Problem

Previously, users could have different IDs in the app vs database due to client-side UUID generation.

### The Solution

The system now uses **server-generated IDs only**:

1. **New Registration Flow**:
   - App calls `/api/user/create` (no user_id parameter)
   - Server generates UUID and creates user atomically
   - Server returns the generated user_id
   - App saves this ID locally and uses it consistently

2. **Benefits**:
   - Single source of truth (server)
   - No ID mismatches
   - Thread-safe for concurrent registrations
   - Guaranteed unique IDs

3. **Backward Compatibility**:
   - Old `/api/user/register` endpoint still exists for updates
   - Existing users with client-generated IDs continue to work
   - New users always get server-generated IDs
