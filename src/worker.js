// Enhanced Anti-Bot Gateway for Cloudflare Workers - Performance Optimized
// Multi-layered detection with optimized caching and minimal I/O

// Global config cache - refreshed periodically
let _antiBotConfig = null;
let _configLastRefresh = 0;
const CONFIG_REFRESH_INTERVAL = 30000; // 30 seconds

// Default configuration
const DEFAULT_CONFIG = {
  maxScore: 75,
  suspiciousScore: 45,
  cacheTime: 7200,
  allowedCountries: ['ID'],
  rateLimit: 15,
  rateLimitWindow: 60, // seconds
  fastRequestThreshold: 25, // ms
  fingerprintTTL: 7200,
  rateLimitTTL: 60,
  staticAssetPattern: /\.(js|css|png|jpe?g|webp|gif|ico|svg|woff2?|ttf|eot|map|json|txt|webm|mp4|mp3)$/i,
  highQualitySources: ['instagram.com', 'tiktok.com', 'whatsapp.com', 'facebook.com']
};

class EnhancedAntiBot {
  constructor(env, ctx, config) {
    this.env = env;
    this.ctx = ctx;
    this.config = config || DEFAULT_CONFIG;
  }

  async handleRequest(request) {
    const startTime = performance.now(); // Gunakan performance API
    
    try {
      const url = new URL(request.url);
      
      // Skip static assets immediately (no bot detection)
      if (this.config.staticAssetPattern.test(url.pathname)) {
        return this.forwardToOrigin(request);
      }
      
      // Handle Turnstile verification
      if (url.pathname === '/verify' && request.method === 'POST') {
        return this.handleTurnstileVerification(request, startTime);
      }
      
      // Main bot detection
      const result = await this.detectBot(request, startTime);
      
      if (result.action === 'allow') {
        return this.forwardToOrigin(request);
      } else if (result.action === 'challenge') {
        return this.showTurnstileChallenge(request, result.score);
      } else {
        return this.blockRequest(request, result.reason, result.score);
      }
      
    } catch (error) {
      this.logErrorAsync(error, request, null, null, startTime);
      return this.showTurnstileChallenge(request, 50); // Fallback to challenge
    }
  }

  async forwardToOrigin(request) {
    const newRequest = new Request(request);
    newRequest.headers.set('X-AntiBot-Status', 'verified');
    return fetch(newRequest);
  }

  async detectBot(request, startTime) {
    // Pre-verified requests bypass
    if (request.headers.get('X-AntiBot-Status') === 'verified') {
      return { action: 'allow', score: 0, reason: 'pre_verified' };
    }

    // High-quality traffic sources bypass
    const referrer = request.headers.get('Referer') || '';
    if (this.config.highQualitySources.some(src => referrer.includes(src))) {
      return { action: 'allow', score: 0, reason: 'high_quality_source' };
    }

    const clientIP = this.getClientIP(request);
    const userAgent = request.headers.get('User-Agent') || '';
    
    // Generate hashes in parallel
    const [ipHash, fingerprint] = await Promise.all([
      this.hashIP(clientIP),
      this.generateFingerprint(request)
    ]);
    
    // Batch cache reads for performance - single I/O operation
    const cacheKeys = [
      `verified:${fingerprint}`,
      `rate:${ipHash}`,
      `ip:${ipHash}`,
      `fp:${fingerprint}`
    ];
    
    const cacheResults = await this.batchGetCache(cacheKeys);
    const [cachedResult, rateLimitCount, ipReputation, fpCount] = cacheResults;

    // Check verified cache first
    if (cachedResult) {
      this.logAccessAsync(request, 'CACHE_HIT', 0, ['cached'], ipHash, fingerprint, startTime);
      return { action: 'allow', score: 0, reason: 'cached' };
    }

    let score = 0;
    const reasons = [];

    // Parallel detection methods for performance
    const detectionPromises = [
      this.checkCountry(request),
      this.analyzeUserAgent(userAgent),
      this.analyzeHeaders(request),
      this.analyzeIP(ipHash, rateLimitCount, ipReputation),
      this.analyzeFingerprint(fingerprint, fpCount),
      this.analyzeTimings(startTime),
      this.analyzeASN(request.cf?.asn, request.cf?.asOrganization)
    ];

    const detectionResults = await Promise.all(detectionPromises);

    // Aggregate scores and reasons
    for (const result of detectionResults) {
      score += result.score;
      if (result.suspicious && result.reasons) {
        reasons.push(...result.reasons);
      }
    }

    // Batch async updates for performance
    this.batchUpdateAsync(ipHash, fingerprint, rateLimitCount, fpCount);

    // Decision logic
    let action = 'allow';
    if (score >= this.config.maxScore) {
      action = 'block';
    } else if (score >= this.config.suspiciousScore) {
      action = 'challenge';
    } else {
      // Cache verified users
      const conversionCookie = request.headers.get('Cookie')?.includes('conversion=true');
      const cacheTime = conversionCookie ? this.config.cacheTime * 2 : this.config.cacheTime;
      this.setCacheAsync(`verified:${fingerprint}`, 'true', cacheTime);
    }

    // Async logging with pre-calculated values
    this.logAccessAsync(request, action.toUpperCase(), score, reasons, ipHash, fingerprint, startTime);

    return { action, score, reason: reasons.join(',') };
  }

  checkCountry(request) {
    const country = request.cf?.country || 'UNKNOWN';
    if (!this.config.allowedCountries.includes(country)) {
      return {
        score: 100,
        suspicious: true,
        reasons: [`blocked_country:${country}`]
      };
    }
    return { score: 0, suspicious: false, reasons: [] };
  }

  analyzeUserAgent(userAgent) {
    let score = 0;
    const reasons = [];

    // Bot patterns with weighted scoring
    const botPatterns = [
      { pattern: /bot|crawler|spider|scraper|automated/i, score: 65, reason: 'bot_pattern' },
      { pattern: /headless|phantom|selenium|playwright|puppeteer/i, score: 85, reason: 'headless_browser' },
      { pattern: /curl|wget|python|java|go-http|okhttp/i, score: 75, reason: 'http_client' },
      { pattern: /httpclient|apache-httpclient|urllib/i, score: 70, reason: 'automation_tool' },
      { pattern: /postman|insomnia|rest-client/i, score: 55, reason: 'api_client' },
      // Ads bot patterns
      { pattern: /mediapartners|adsbot|googlebot-ads|bingbot-ads/i, score: 100, reason: 'ads_bot' },
      { pattern: /semrush|ahrefs|majestic|seoscanners|scraping/i, score: 95, reason: 'seo_scraper' },
      { pattern: /click|impression|conversion|tracker|pixel/i, score: 85, reason: 'tracking_bot' }
    ];

    for (const { pattern, score: patternScore, reason } of botPatterns) {
      if (pattern.test(userAgent)) {
        score += patternScore;
        reasons.push(reason);
        break; // Only count the first match to avoid double scoring
      }
    }

    // Missing or suspicious UA
    if (!userAgent || userAgent.length < 15) {
      score += 45;
      reasons.push('missing_ua');
    }

    // Outdated browsers (potential bot)
    if (userAgent.includes('Chrome/')) {
      const chromeVersion = userAgent.match(/Chrome\/(\d+)/);
      if (chromeVersion && parseInt(chromeVersion[1]) < 90) {
        score += 25;
        reasons.push('outdated_browser');
      }
    }

    return { score, suspicious: score > 0, reasons };
  }

  analyzeHeaders(request) {
    let score = 0;
    const reasons = [];

    // Critical missing headers
    const criticalHeaders = [
      { name: 'Accept', score: 25 },
      { name: 'Accept-Language', score: 20 },
      { name: 'Accept-Encoding', score: 20 }
    ];

    for (const { name, score: headerScore } of criticalHeaders) {
      if (!request.headers.get(name)) {
        score += headerScore;
        reasons.push(`missing_${name.toLowerCase().replace('-', '_')}`);
      }
    }

    // Language preference check
    const acceptLanguage = request.headers.get('Accept-Language');
    if (acceptLanguage && !acceptLanguage.includes('id') && !acceptLanguage.includes('en')) {
      score += 15;
      reasons.push('non_local_language');
    }

    // Security headers that browsers send
    const securityHeaders = ['Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-Dest'];
    let missingSecHeaders = 0;
      
    for (const header of securityHeaders) {
      if (!request.headers.get(header)) {
        missingSecHeaders++;
      }
    }

    if (missingSecHeaders >= 2) {
      score += 30;
      reasons.push('missing_security_headers');
    }

    // Suspicious automation headers
    const automationHeaders = ['X-Requested-With', 'X-Forwarded-For', 'X-Real-IP'];
    for (const header of automationHeaders) {
      if (request.headers.get(header)) {
        score += 15;
        reasons.push(`automation_header:${header}`);
        break; // Only count first automation header
      }
    }

    // Tracking headers (common in ads bots)
    const trackingHeaders = [
      'X-Ads-Token',
      'X-Tracking-ID',
      'X-Pixel-Data',
      'X-Conversion-Track'
    ];
    
    for (const header of trackingHeaders) {
      if (request.headers.get(header)) {
        score += 65;
        reasons.push(`tracking_header:${header}`);
        break; // Only count first tracking header
      }
    }

    return { score, suspicious: score > 0, reasons };
  }

  analyzeIP(ipHash, rateLimitCount, ipReputation) {
    let score = 0;
    const reasons = [];

    // Check IP reputation
    if (ipReputation) {
      try {
        const rep = JSON.parse(ipReputation);
        if (rep.suspicious) {
          score += 35;
          reasons.push('ip_reputation');
        }
      } catch (e) {
        // Invalid reputation data, ignore
      }
    }

    // Rate limiting check
    if (rateLimitCount) {
      const count = parseInt(rateLimitCount);
      if (count > this.config.rateLimit) {
        const excessScore = Math.min((count - this.config.rateLimit) * 6, 45);
        score += excessScore;
        reasons.push(`rate_limit:${count}`);
      }
    }

    return { score, suspicious: score > 0, reasons };
  }

  analyzeFingerprint(fingerprint, fpCount) {
    let score = 0;
    const reasons = [];

    // Check fingerprint usage count
    if (fpCount) {
      const count = parseInt(fpCount);
      if (count > 5) {
        score += 75;
        reasons.push(`duplicate_fingerprint:${count}`);
      }
    }

    return { score, suspicious: score > 0, reasons };
  }

  analyzeTimings(startTime) {
    let score = 0;
    const reasons = [];

    const processingTime = performance.now() - startTime;
      
    // Too fast requests (likely automated)
    if (processingTime < this.config.fastRequestThreshold) {
      score += 30;
      reasons.push('too_fast');
    }

    return { score, suspicious: score > 0, reasons };
  }

  analyzeASN(asn, asOrganization) {
    let score = 0;
    const reasons = [];

    // Known hosting/VPS/cloud providers
    const suspiciousProviders = [
      { name: 'Amazon', score: 30 },
      { name: 'Google Cloud', score: 30 },
      { name: 'Microsoft', score: 25 },
      { name: 'DigitalOcean', score: 35 },
      { name: 'Linode', score: 35 },
      { name: 'Vultr', score: 35 },
      { name: 'Hetzner', score: 30 },
      { name: 'OVH', score: 25 },
      { name: 'Alibaba', score: 30 }
    ];

    if (asOrganization) {
      for (const { name, score: providerScore } of suspiciousProviders) {
        if (asOrganization.includes(name)) {
          score += providerScore;
          reasons.push(`hosting_provider:${name}`);
          break; // Only one provider per ASN
        }
      }
    }

    return { score, suspicious: score > 0, reasons };
  }

  // Optimized fingerprint generation
  async generateFingerprint(request) {
    const userAgent = request.headers.get('User-Agent') || '';
    const acceptLanguage = request.headers.get('Accept-Language') || '';
    const acceptEncoding = request.headers.get('Accept-Encoding') || '';
    const cfRay = request.headers.get('CF-Ray') || '';
      
    const fingerprint = `${userAgent}:${acceptLanguage}:${acceptEncoding}:${cfRay}`;
    return await this.sha256Hash(fingerprint);
  }

  async hashIP(ip) {
    const salt = this.env.HASH_SALT || 'default_salt_2024';
    return await this.sha256Hash(ip + salt);
  }

  async sha256Hash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
  }

  getClientIP(request) {
    return request.headers.get('CF-Connecting-IP') || 
           request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 
           request.headers.get('X-Real-IP') || 
           '0.0.0.0';
  }

  // Optimized batch cache operations
  async batchGetCache(keys) {
    try {
      // Try KV first for ultra-fast reads
      if (this.env.KV_BOT_CACHE) {
        const values = await this.env.KV_BOT_CACHE.get(keys, { type: 'json' });
        return values || new Array(keys.length).fill(null);
      }
    } catch (e) {
      // KV failed, try Redis
    }
    
    try {
      // Try Redis MGET for better performance
      if (this.env.REDIS_ENDPOINT) {
        const response = await fetch(`${this.env.REDIS_ENDPOINT}/mget`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.env.REDIS_TOKEN || ''}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ keys })
        });
          
        if (response.ok) {
          const data = await response.json();
          return data.values || new Array(keys.length).fill(null);
        }
      }
    } catch (e) {
      // Redis failed, try D1
    }

    // Fallback to parallel D1 queries
    try {
      if (this.env.DB) {
        const promises = keys.map(key => 
          this.env.DB.prepare(
            'SELECT value FROM cache WHERE key = ? AND expires_at > ?'
          ).bind(key, Date.now()).first('value')
        );
          
        const results = await Promise.all(promises);
        return results.map(result => result || null);
      }
    } catch (e) {
      // D1 failed, return nulls
    }

    return new Array(keys.length).fill(null);
  }

  async setCache(key, value, ttl = 3600) {
    const expiresAt = Date.now() + (ttl * 1000);
      
    try {
      // Try KV first for best performance
      if (this.env.KV_BOT_CACHE) {
        await this.env.KV_BOT_CACHE.put(key, value, { expirationTtl: ttl });
        return;
      }
    } catch (e) {
      // KV failed, try Redis
    }
      
    try {
      // Try Redis next
      if (this.env.REDIS_ENDPOINT) {
        await fetch(`${this.env.REDIS_ENDPOINT}/set/${key}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.env.REDIS_TOKEN || ''}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ value, ttl })
        });
        return;
      }
    } catch (e) {
      // Redis failed, try D1
    }

    try {
      // Fallback to D1
      if (this.env.DB) {
        await this.env.DB.prepare(
          'INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)'
        ).bind(key, value, expiresAt).run();
      }
    } catch (e) {
      // D1 failed, ignore
    }
  }

  // Batch async updates for performance
  batchUpdateAsync(ipHash, fingerprint, rateLimitCount, fpCount) {
    this.ctx.waitUntil(this.batchUpdate(ipHash, fingerprint, rateLimitCount, fpCount));
  }

  async batchUpdate(ipHash, fingerprint, rateLimitCount, fpCount) {
    const updates = [];

    // Rate limit update
    const newRateCount = rateLimitCount ? parseInt(rateLimitCount) + 1 : 1;
    updates.push(this.setCache(`rate:${ipHash}`, newRateCount.toString(), this.config.rateLimitTTL));

    // Fingerprint count update
    const newFpCount = fpCount ? parseInt(fpCount) + 1 : 1;
    updates.push(this.setCache(`fp:${fingerprint}`, newFpCount.toString(), this.config.fingerprintTTL));

    // Execute all updates in parallel
    await Promise.all(updates);
  }

  // Async wrapper methods for non-blocking operations
  setCacheAsync(key, value, ttl) {
    this.ctx.waitUntil(this.setCache(key, value, ttl));
  }

  logAccessAsync(request, action, score, reasons, ipHash, fingerprint, startTime) {
    this.ctx.waitUntil(this.logAccess(request, action, score, reasons, ipHash, fingerprint, startTime));
  }

  logErrorAsync(error, request, ipHash, fingerprint, startTime) {
    this.ctx.waitUntil(this.logError(error, request, ipHash, fingerprint, startTime));
  }

  async logAccess(request, action, score, reasons, ipHash, fingerprint, startTime) {
    const processingTime = performance.now() - startTime;
    const url = new URL(request.url);
    const path = url.pathname;
    const referrer = request.headers.get('Referer') || '';
    const country = request.cf?.country || '';
    const userAgent = request.headers.get('User-Agent') || '';

    // Prepare log data
    const logData = {
      timestamp: new Date().toISOString(),
      ipHash,
      fingerprint,
      action,
      score,
      reasons: reasons.join(','),
      path,
      referrer,
      country,
      userAgent,
      processingTime: processingTime.toFixed(2)
    };

    // Fast logging to KV if available
    if (this.env.KV_ACCESS_LOGS) {
      try {
        const logId = `log_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
        await this.env.KV_ACCESS_LOGS.put(logId, JSON.stringify(logData));
      } catch (e) {}
    }
    
    // Structured logging to D1 if available
    if (this.env.ANALYTICS_DB) {
      try {
        this.ctx.waitUntil(
          this.env.ANALYTICS_DB.prepare(
            `INSERT INTO access_log 
            (timestamp, ip_hash, fingerprint, action, score, reasons, path, referrer, country, user_agent, processing_time) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            logData.timestamp,
            logData.ipHash,
            logData.fingerprint,
            logData.action,
            logData.score,
            logData.reasons,
            logData.path,
            logData.referrer,
            logData.country,
            logData.userAgent,
            logData.processingTime
          ).run()
        );
      } catch (e) {}
    }
  }

  async logError(error, request, ipHash, fingerprint, startTime) {
    const processingTime = performance.now() - startTime;
    const url = new URL(request.url);
    const path = url.pathname;
    const referrer = request.headers.get('Referer') || '';
    const country = request.cf?.country || '';
    const userAgent = request.headers.get('User-Agent') || '';

    // Prepare error log
    const errorLog = {
      timestamp: new Date().toISOString(),
      ipHash: ipHash || 'unknown',
      fingerprint: fingerprint || 'unknown',
      path,
      referrer,
      country,
      userAgent,
      processingTime: processingTime.toFixed(2),
      error: error.message || error.toString(),
      stack: error.stack || ''
    };

    // Fast error logging to KV
    if (this.env.KV_ERROR_LOGS) {
      try {
        const logId = `err_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
        await this.env.KV_ERROR_LOGS.put(logId, JSON.stringify(errorLog));
      } catch (e) {}
    }
    
    // Structured error logging to D1
    if (this.env.ANALYTICS_DB) {
      try {
        this.ctx.waitUntil(
          this.env.ANALYTICS_DB.prepare(
            `INSERT INTO error_log 
            (timestamp, ip_hash, fingerprint, path, referrer, country, user_agent, processing_time, error, stack) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            errorLog.timestamp,
            errorLog.ipHash,
            errorLog.fingerprint,
            errorLog.path,
            errorLog.referrer,
            errorLog.country,
            errorLog.userAgent,
            errorLog.processingTime,
            errorLog.error,
            errorLog.stack
          ).run()
        );
      } catch (e) {}
    }
  }

  async handleTurnstil
