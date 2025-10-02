Antibot: a Cloudflare Workers-based anti-bot gateway adapted specifically for high-conversion funnels (landing pages, lead capture forms, checkout flows). The goal is to block or challenge malicious automated traffic while minimizing false positives and preserving conversion rates for legitimate users.

## Key Design Principles

* Favor challenge over outright block for borderline cases.
* Minimize friction for verified users by using short-lived verification caches.
* Make thresholds adaptive and observable via telemetry.
* Prioritize performance: low latency, batched cache operations, and static asset bypass.
* Maintain privacy by hashing IPs and limiting stored PII.

## Example Configuration (Funnel Usage)

This configuration is optimized as a baseline for funnel deployments.  
Values can be adjusted later by reviewing telemetry logs collected in the database.

```js
const DEFAULT_CONFIG = {
  maxScore: 100,              // Only block when extremely confident
  suspiciousScore: 60,       // Trigger challenge if >= 60
  cacheTime: 14400,          // 4 hours for verified fingerprints
  allowedCountries: ['ID','US','SG','MY','PH','VN','AU','GB'],
  rateLimit: 30,             // slightly higher to avoid blocking bursts
  rateLimitWindow: 60,       // seconds
  fastRequestThreshold: 20,  // ms
  fingerprintTTL: 86400,     // 24h
  rateLimitTTL: 60,
  staticAssetPattern: /\.(js|css|png|jpe?g|webp|gif|ico|svg|woff2?|ttf|eot|map|json|txt|webm|mp4|mp3)$/i,
  highQualitySources: [
    'facebook.com', 'facebookexternalhit.com',
    'google.com', 'googleadservices.com', 'doubleclick.net',
    't.co', 'tiktok.com', 'instagram.com', 'linkedin.com',
    'ads.youtube.com', 'bing.com', 'whatsapp.com'
  ]
};
```

Notes:

* `suspiciousScore` raised to reduce false positives — suspicious traffic will be challenged with Turnstile.
* `maxScore` set conservatively high so only strongly malicious requests are blocked.
* `cacheTime` increased so verified users have a smoother funnel experience.
* `allowedCountries` expanded to match global campaigns — adjust to your campaign geography.

## Funnel-Specific Adjustments and Best Practices

1. **Always prefer a challenge for suspicious traffic**

   * For funnels, present Cloudflare Turnstile rather than immediately blocking. This protects conversion.

2. **Whitelist ad / tracking domains and landing referrers**

   * Ensure ad platforms, click trackers, and redirectors used by campaigns are in `highQualitySources`.

3. **Relax rate limits for known conversion flows**

   * Increase `rateLimit` for endpoints that legitimately receive many quick requests (e.g., payment webhooks should be handled differently).

4. **Longer fingerprint TTL for funnels**

   * Use longer `fingerprintTTL` to keep returning users verified across sessions (balance with privacy policy).

5. **Graceful challenge UI**

   * Present Turnstile on a lightweight intermediate page that explains why verification is required and continues to the funnel upon success.

6. **Monitoring and rollback**

   * Send all challenge and block events to telemetry and review queue.
   * Implement alerts when conversion drops or challenge rate spikes, with an automatic rollback toggle.

7. **A/B testing**

   * Run A/B experiments (control vs. anti-bot enabled) to measure conversion impact.

8. **Logs and privacy**

   * Hash IPs and avoid storing PII. Document retention policies for telemetry and logs.

## Detection Layers (summary)

* Country allow/deny
* User-Agent checks (headless, http clients)
* Header completeness and security headers
* IP reputation and ASN checks
* Fingerprint usage and duplicates
* Timing/behavioral analysis

Each layer contributes to a weighted confidence score. For funnel usage, keep scores and weights conservative.

## Telemetry and Review

Telemetry is critical for tuning thresholds without damaging conversion. Use the provided schema to record events, queue suspicious items for manual review, and capture feedback for potential model improvements.

### Database Schema

The schema includes tables for telemetry, review queue, blocks, feedback, error logs, and cache (for D1 fallback). While the system is currently **rule-based**, the `feedback` table is intended for **future ML integration**. This allows storing human feedback and user reports that can later be used to adjust scoring logic or train models.

```sql
-- Telemetry table
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

-- Feedback for ML (future use)
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

-- Cache table (if using D1 as cache fallback)
CREATE TABLE cache (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_cache_expires ON cache(expires_at);
```

## Suggested Metrics & Dashboards

* Verified vs challenged vs blocked rate
* Conversion rate by bucket (verified/challenged/blocked)
* Challenge pass rate (Turnstile success rate)
* Blocks by reason (UA, headers, fingerprint, ASN, country)
* Telemetry volume and processing latency
* Alerts: sudden jump in challenges; conversion drop > X% over Y minutes

## Future Plans

Currently, detection is fully rule-based. Planned improvements include:

* **Feedback loop integration**: use the `feedback` table to refine scoring logic.
* **Adaptive thresholds**: adjust `suspiciousScore` and `maxScore` dynamically based on telemetry.
* **JA3/TLS fingerprinting**: add TLS-level fingerprints for stronger client identification.
* **Behavioral signals**: incorporate interaction timing, request sequences, and browser features.
* **Stronger fingerprints**: expand beyond headers to include environmental and protocol-level markers.

## Security and Privacy

* Hash IPs using a salted hash; store salt securely outside the DB.
* Do not log PII (email, form payloads) into telemetry.
* Implement retention and deletion policies for telemetry and logs.
* Rate-limit access to logs and analytics dashboards.

## Deployment

1. Set environment variables for KV, Redis, D1, and secrets (HASH_SALT, TURNSTILE keys).
2. Deploy Cloudflare Worker using Wrangler or the Cloudflare dashboard.
3. Wire Turnstile for challenge endpoints.
4. Configure analytics DB and retention policies.

## Testing

* Create automated tests for UA patterns, header omissions, fingerprint collisions, and rate-limiting behavior.
* Run load tests against a staging funnel to measure latency impact.
* Test Turnstile flows and verify cookies/session persistence across the funnel.

## Contribution Guidelines

* Use feature branches and open PRs for changes.
* Include unit tests for detection rules when possible.
* Label PRs that change scoring thresholds as `breaking` and require QA on staging funnel.
* Add telemetry dashboards changes alongside detection changes.

## Operational Playbook

* If conversions drop significantly after a deploy, use the rollback flag to revert to previous config.
* If challenge rate spikes, temporarily relax `suspiciousScore` and escalate investigation.
* Maintain a review queue with human triage for false-positives.

## Example: Funnel-Safe Decision Strategy

1. Static assets bypass.
2. High-quality referrers bypass.
3. Run detection layers and compute score.
4. If score >= `maxScore` (100): block and log to `blocks`.
5. If score >= `suspiciousScore` (60): present Turnstile. Log to `telemetry` and `review_queue` if failed or disputed.
6. Else: allow and cache fingerprint for faster access.
