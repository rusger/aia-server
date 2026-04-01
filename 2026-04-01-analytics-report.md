# Astrolytix Database Analysis (Dec 17, 2025 - Apr 1, 2026)

## 1. User Growth

| Month | New Registrations | Cumulative |
|-------|:-:|:-:|
| Dec 2025 | 20 | 20 |
| Jan 2026 | 60 | 80 |
| Feb 2026 | 112 | 192 |
| Mar 2026 | 190 | 382 |

**Total: 382 users** -- strong exponential growth, roughly doubling each month. March was the strongest month with 190 sign-ups (50% of all users).

Peak registration weeks: W05 (45 users), W09 (55), W11 (53).

## 2. Subscriptions & Revenue

- **374 free** / **8 paid** (2.1% conversion rate)
- 7 monthly, 1 yearly (admin account)
- All purchases via Apple App Store, zero Google Play purchases
- **1 real paying user** (`yoginvip@gmail.com`, purchased Feb 24)
- The rest appear to be test accounts: `test666chatgpt999`, `chatgpt666test999`, `sales@ramsider.com`, `astrolytix.tester2`
- 0 super users

## 3. API Usage Overview

| Metric | Total | Excl. Dev Devices |
|--------|------:|------:|
| Total API calls | 105,865 | 35,124 |
| Unique devices | 182 | 178 |

**Breakdown by type:**

| Type | Calls | Share |
|------|------:|------:|
| astrolog (natal charts) | 93,943 | 88.8% |
| transit-year | 9,318 | 8.8% |
| chatgpt (AI chat) | 2,604 | 2.5% |

**Monthly real-user calls** (excl. dev):

| Month | Calls | Active Devices |
|-------|------:|:-:|
| Dec 2025 | 10,156 | 17 |
| Jan 2026 | 7,329 | 15 |
| Feb 2026 | 4,332 | 59 |
| Mar 2026 | 13,241 | 120 |

March saw the most real activity -- both in raw calls and unique devices.

## 4. Usage Per Device

| Bucket | Devices | Total Calls |
|--------|------:|------:|
| 1 call | 1 | 1 |
| 2-5 calls | 18 | 63 |
| 6-10 calls | 38 | 291 |
| 11-50 calls | 69 | 1,623 |
| 51-100 calls | 21 | 1,553 |
| 101-500 calls | 26 | 5,074 |
| 501-1,000 calls | 3 | 2,399 |
| 1,000+ calls | 6 | 94,861 |

**Average: 197 calls/device** (real users). The 6 devices with 1,000+ calls account for 90% of all traffic -- most are dev devices.

## 5. Top Real Users (excl. dev)

**Note:** No emails available for these users -- they registered via the older device-only path. Email is only collected during auth code verification or purchase flow.

| Device | Total Calls | Astrolog | Transit | Chat | Active Period |
|--------|------:|------:|------:|------:|------|
| `44D819A7...` | 9,875 | 9,765 | 20 | 90 | Dec 15 - Mar 2 |
| `5406C426...` | 7,885 | 5,758 | 1,369 | 758 | Jan 13 - Mar 18 |
| `780351E5...` | 5,374 | 5,289 | 36 | 49 | Jan 1 - Jan 13 |
| `W1VV36H...` | 1,532 | 1,402 | 41 | 89 | Feb 6 - Mar 31 |
| `528465E2...` | 867 | 750 | 82 | 35 | Mar 18 - Apr 1 |
| `AP3A...5c7a` | 822 | 689 | 47 | 86 | Feb 4 - Mar 30 |

## 6. Retention

| Months Active | Devices |
|:-:|:-:|
| 1 month only | 156 (88%) |
| 2 months | 18 (10%) |
| 3 months | 3 (1.7%) |
| 4 months | 1 (0.6%) |

**Retention is very low** -- 88% of devices are active for only 1 month. Only 22 out of 178 real devices returned for a second month.

## 7. Peak Day & Anomalies

**Biggest anomaly: March 6, 2026 -- 55,200 calls** (52% of all-time traffic in a single day). This was almost entirely the MacBook (`Ruslans-MacBook-Pro`) making 54,904 astrolog calls -- likely a load test or automated script.

**Other peak days:**

| Date | Calls | Main Source |
|------|------:|------|
| Dec 20 | 4,013 | Device `44D819A7` (4,007) |
| Jan 11 | 3,402 | Device `780351E5` (3,396) |
| Mar 8 | 3,294 | MacBook dev (3,199) |
| Dec 24 | 2,299 | Device `44D819A7` (2,299) |

Most peak days are driven by single "power users" or dev testing, not organic traffic spikes.

## 8. Usage Patterns

**Hourly (UTC):** Peak at 15:00 UTC (22,799 calls), secondary peaks at 16:00 and 18:00. Low activity 02:00-04:00 UTC. This suggests the user base is primarily in UTC+3 to UTC+5 timezone (evening usage 18:00-21:00 local).

**Day of week:** Friday dominates massively (59,877 calls) due to the March 6 anomaly (which was a Friday). Excluding that, weekends (Sun: 11,899, Sat: 9,585) are busier than weekdays -- expected for a consumer astrology app.

## 9. ChatGPT / AI Token Usage

| Model | Calls | Total Tokens |
|-------|------:|------:|
| gpt-4o-mini | 968 | 904K |
| gpt-4o | 845 | 308K |
| gpt-4.1-mini | 759 | 4.9M |
| o1 | 32 | 0 |

Total token spend: ~6.1M tokens across 2,604 chat calls. Average 5,010 tokens/chat request. The switch to `gpt-4.1-mini` is recent but already consuming the most tokens per call (6,430 avg vs 934 for gpt-4o-mini).

## 10. Key Takeaways

1. **Strong registration growth** (doubling monthly), but **very weak retention** (88% churn after 1 month)
2. **1 real paying customer** out of 382 users -- the other "paid" accounts are test/sandbox
3. **Traffic is heavily skewed**: 6 devices produce 90% of calls, and most are dev devices
4. **Real organic usage** (excl. dev): ~35K calls from 178 devices over 3.5 months
5. **March 6 anomaly**: 54,904 calls from MacBook -- likely load testing, inflates all March metrics
6. **Core feature is natal charts** (89%) -- transit-year and chatgpt are secondary
7. **No Google Play purchases yet** -- all revenue through Apple
8. **Top power users have no emails** -- device-only registration path means no way to contact them
