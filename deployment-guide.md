# Anti-Bot Gateway Deployment Guide

## Setup Instructions

### 1. Cloudflare Prerequisites
- Cloudflare account with Workers enabled
- Domain managed by Cloudflare
- Turnstile configured for your domain

### 2. Create KV Namespace
```bash
wrangler kv:namespace create "ANTI_BOT_KV"
wrangler kv:namespace create "ANTI_BOT_KV" --preview
```

### 3. Configure Turnstile
1. Go to Cloudflare Dashboard → Security → Turnstile
2. Create a new site
3. Set to "Invisible" mode
4. Add your domain
5. Copy Site Key and Secret Key

### 4. Update wrangler.toml
- Replace `your-kv-namespace-id` with actual KV namespace ID
- Replace `your-turnstile-site-key` with your Turnstile site key
- Set `LANDING_URL` to your actual landing page

### 5. Set Secrets
```bash
wrangler secret put TURNSTILE_SECRET_KEY
wrangler secret put WEBHOOK_URL
```

### 6. Deploy
```bash
wrangler publish
```

### 7. DNS Configuration
Add a CNAME record:
- Name: `gateway` (or your preferred subdomain)
- Target: `your-worker-name.your-subdomain.workers.dev`

## Environment Variables

### Required
- `TURNSTILE_SITE_KEY`: Your Turnstile site key
- `TURNSTILE_SECRET_KEY`: Your Turnstile secret key (secret)
- `LANDING_URL`: URL to redirect valid users

### Optional
- `WEBHOOK_URL`: URL for external logging (secret)

## Bot Detection Features

### Score-based System
- **0-39**: Allow (redirect to landing)
- **40-69**: Challenge (show Turnstile)
- **70+**: Block (deny access)

### Detection Methods
1. **Country Filtering**: Only allows Indonesia traffic
2. **User Agent Analysis**: Detects bot patterns, headless browsers
3. **Header Analysis**: Checks for missing/suspicious headers
4. **IP Reputation**: Rate limiting and reputation checks
5. **Fingerprint Analysis**: Detects duplicate fingerprints
6. **Timing Analysis**: Detects automated requests
7. **ASN Analysis**: Flags hosting providers/VPS

### Caching System
- Verified users cached for 1 hour
- Rate limiting per IP
- Fingerprint tracking
- IP reputation caching

## Monitoring & Logging

### KV Storage Logs
- `log:*`: Access logs with score and reasons
- `error:*`: Error logs
- `verified:*`: Verified user cache
- `ip:*`: IP reputation cache
- `fp:*`: Fingerprint counters
- `rate:*`: Rate limiting counters

### External Logging
Configure `WEBHOOK_URL` to send logs to external services:
- Google Sheets (via Apps Script)
- Slack notifications
- Custom analytics endpoints

## Performance Optimization

### Response Times
- Target: < 100ms
- Cache hits: < 10ms
- Challenges: < 200ms

### Optimization Tips
1. Enable KV caching for verified users
2. Use async operations where possible
3. Minimize external API calls
4. Use lightweight detection methods first

## Security Considerations

### Bot Evasion Prevention
- Multiple detection layers
- Score-based system prevents single-point bypass
- Honeypot trap for automated scrapers
- Fingerprint-based tracking

### Rate Limiting
- 10 requests per minute per IP
- Progressive scoring for repeat offenders
- Temporary IP reputation caching

### Privacy
- No personal data stored
- IP addresses hashed for logging
- Automatic log expiration (24 hours)

## Troubleshooting

### Common Issues
1. **High false positives**: Adjust score thresholds
2. **Performance issues**: Check KV response times
3. **Turnstile failures**: Verify site key and domain
4. **Country blocking**: Confirm CF country detection

### Debug Mode
Check KV logs for detailed analysis:
```bash
wrangler kv:key list --binding ANTI_BOT_KV --prefix "log:"
```

## Customization

### Adjusting Detection
- Modify score thresholds in `AntiBot` constructor
- Add/remove detection methods
- Customize country allowlist
- Update bot patterns

### UI Customization
- Modify HTML templates in worker code
- Add custom styling
- Implement branded challenge pages
- Add multi-language support

## Production Checklist

- [ ] KV namespace created and configured
- [ ] Turnstile site key and secret set
- [ ] Landing URL configured
- [ ] DNS record pointing to worker
- [ ] Webhooks configured for logging
- [ ] Score thresholds tuned for your traffic
- [ ] Monitoring and alerting set up
- [ ] Rate limiting tested
- [ ] False positive testing completed