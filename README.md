This project is a multi-layered anti-bot system built on Cloudflare Workers.
It is designed to detect, challenge, or block automated traffic with minimal latency, while allowing legitimate users to pass through seamlessly.

The system uses a scoring mechanism, caching layers, and telemetry logging to evaluate incoming requests. It integrates with Cloudflare Turnstile for human verification when required.

---

## Features

* **Layered Bot Detection**

  * User-Agent analysis (headless browsers, scrapers, automation tools).
  * Header integrity checks (missing, spoofed, or automation-related headers).
  * IP reputation and rate-limiting.
  * Fingerprint tracking with TTL.
  * ASN and hosting provider detection.
  * Timing analysis for suspiciously fast requests.
  * Country-based allow/deny rules.

* **Performance Optimizations**

  * Batching cache reads/writes.
  * Multi-backend cache support (KV, Redis, D1).
  * Pre-verified request bypassing.
  * Static asset bypass.

* **Telemetry and Logging**

  * Structured access logs.
  * Error logging with stack traces.
  * Support for KV, Redis, and D1 for analytics and storage.

* **Challenges**

  * Suspicious requests are presented with Cloudflare Turnstile.
  * Verified fingerprints are cached for faster future access.

---

## Database Schema

A recommended schema for storing telemetry, review queues, blocks, feedback, and error logs.

```sql
-- Telemetry
CREATE TABLE telemetry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  action TEXT NOT NULL,
  score INTEGER NOT NULL,
  confidence REAL NOT NULL,
  layers TEXT,
  processing_time REAL,
  url TEXT,
  method TEXT,
  country TEXT,
  asn INTEGER,
  user_agent TEXT
);

-- Review queue
CREATE TABLE review_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  score INTEGER NOT NULL,
  confidence REAL NOT NULL,
  layers TEXT,
  url TEXT,
  user_agent TEXT
);

-- Blocks log
CREATE TABLE blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  score INTEGER NOT NULL,
  confidence REAL,
  reason TEXT,
  url TEXT,
  user_agent TEXT,
  country TEXT
);

-- Feedback
CREATE TABLE feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  score INTEGER NOT NULL,
  action TEXT NOT NULL,
  feedback_type TEXT NOT NULL,
  user_report TEXT
);

-- Error logs
CREATE TABLE error_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  ip_hash TEXT,
  fingerprint TEXT,
  url TEXT,
  method TEXT,
  error TEXT,
  stack TEXT,
  processing_time REAL,
  user_agent TEXT,
  country TEXT
);

-- Cache (for D1 fallback)
CREATE TABLE cache (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_cache_expires ON cache(expires_at);
```

---

## Strengths

* Multi-layered detection covers common bot signatures and patterns.
* Performance-optimized with caching and batch operations.
* Flexible storage backends (KV, Redis, D1).
* Structured logging for analytics and monitoring.
* Integration with Cloudflare Turnstile for human verification.

---

## Known Limitations

* Thresholds (`suspiciousScore`, `maxScore`) are static and may need tuning per deployment.
* ASN provider list is static and may become outdated.
* Referrer whitelisting can be spoofed.
* Fingerprinting method is simplistic and may be bypassed by advanced bots.
* Timing checks may generate false positives for very fast legitimate connections.

---

## Areas for Improvement

* Implement adaptive thresholds using historical telemetry data.
* Expand ASN and hosting provider detection with external feeds.
* Strengthen fingerprinting by incorporating canvas, timezone, or TLS JA3 signatures.
* Add machine learning feedback loop from the `feedback` table.
* Improve country allow/deny logic with dynamic reputation scoring.
* Add confidence scoring per detection layer instead of a flat score sum.

---

## Deployment

1. Clone the repository.
2. Configure environment variables:

   * `KV_BOT_CACHE`, `KV_ACCESS_LOGS`, `KV_ERROR_LOGS`
   * `REDIS_ENDPOINT`, `REDIS_TOKEN` (optional)
   * `DB` / `ANALYTICS_DB` (optional, for D1)
   * `HASH_SALT`
3. Deploy to Cloudflare Workers.
4. Set up Cloudflare Turnstile site key and secret for challenges.

---

Mau gue tambahin juga contoh **flow diagram (request → detection layers → decision → action)** ke README ini biar lebih jelas secara visual?
