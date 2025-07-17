// Advanced Anti-Bot Gateway for Cloudflare Workers
// Optimized for landing page protection with < 100ms response time

const crypto = globalThis.crypto || require('crypto').webcrypto;

class AntiBot {
  constructor(env, ctx) {
    // Validasi environment variables
    if (!env.TURNSTILE_SECRET_KEY) throw new Error("Missing TURNSTILE_SECRET_KEY");
    if (!env.TURNSTILE_SITE_KEY) throw new Error("Missing TURNSTILE_SITE_KEY");
    if (!env.ANTI_BOT_KV) throw new Error("ANTI_BOT_KV binding is required");
    
    this.env = env;
    this.ctx = ctx;
    this.maxScore = 70; // Threshold for blocking
    this.suspiciousScore = 40; // Threshold for Turnstile challenge
    this.cacheTime = 3600; // 1 hour cache
    this.allowedCountries = ['ID']; // Indonesia only
  }

  async handleRequest(request) {
    this.startTime = Date.now(); // Set start time per request
    
    try {
      const url = new URL(request.url);
      
      // Handle honeypot
      if (url.pathname === '/verify.js') {
        return this.handleHoneypot(request);
      }
      
      // Handle Turnstile verification
      if (url.pathname === '/verify' && request.method === 'POST') {
        return this.handleTurnstileVerification(request);
      }
      
      // Main bot detection
      const result = await this.detectBot(request);
      
      if (result.action === 'allow') {
        return this.redirectToLanding(request);
      } else if (result.action === 'challenge') {
        return this.showTurnstileChallenge(request, result.score);
      } else {
        return this.blockRequest(request, result.reason, result.score);
      }
      
    } catch (error) {
      await this.logError(error, request);
      return this.showTurnstileChallenge(request, 50); // Fallback to challenge
    }
  }

  async detectBot(request) {
    const startTime = Date.now(); // Start time for this function
    const clientIP = this.getClientIP(request);
    const userAgent = request.headers.get('User-Agent') || '';
    const fingerprint = await this.generateFingerprint(request);
    
    // Check cache first
    const cachedResult = await this.env.ANTI_BOT_KV.get(`verified:${fingerprint}`);
    if (cachedResult) {
      await this.logAccess(request, 'CACHE_HIT', 0);
      return { action: 'allow', score: 0, reason: 'cached' };
    }

    let score = 0;
    const reasons = [];

    // 1. Country check
    const cf = request.cf || {};
    const country = cf.country || 'UNKNOWN';
    if (!this.allowedCountries.includes(country)) {
      score += 100;
      reasons.push(`blocked_country:${country}`);
    }

    // 2. User Agent analysis
    const uaScore = this.analyzeUserAgent(userAgent);
    score += uaScore.score;
    if (uaScore.suspicious) reasons.push(`suspicious_ua:${uaScore.reason}`);

    // 3. Header analysis
    const headerScore = this.analyzeHeaders(request);
    score += headerScore.score;
    if (headerScore.suspicious) reasons.push(`suspicious_headers:${headerScore.reason}`);

    // 4. IP reputation check
    const ipScore = await this.analyzeIP(clientIP);
    score += ipScore.score;
    if (ipScore.suspicious) reasons.push(`suspicious_ip:${ipScore.reason}`);

    // 5. Fingerprint analysis
    const fpScore = await this.analyzeFingerprint(fingerprint);
    score += fpScore.score;
    if (fpScore.suspicious) reasons.push(`suspicious_fingerprint:${fpScore.reason}`);

    // 6. Timing analysis (using the time taken by this function)
    const processingTime = Date.now() - startTime;
    const timingScore = this.analyzeTimings(processingTime);
    score += timingScore.score;
    if (timingScore.suspicious) reasons.push(`suspicious_timing:${timingScore.reason}`);

    // 7. ASN analysis
    const asn = cf.asn || 0;
    const asOrganization = cf.asOrganization || '';
    const asnScore = this.analyzeASN(asn, asOrganization);
    score += asnScore.score;
    if (asnScore.suspicious) reasons.push(`suspicious_asn:${asnScore.reason}`);

    // Decision logic
    let action = 'allow';
    if (score >= this.maxScore) {
      action = 'block';
    } else if (score >= this.suspiciousScore) {
      action = 'challenge';
    }

    // Log the decision
    await this.logAccess(request, action.toUpperCase(), score, reasons);

    return { action, score, reason: reasons.join(',') };
  }

  analyzeUserAgent(userAgent) {
    let score = 0;
    const reasons = [];

    // Bot patterns
    const botPatterns = [
      /bot|crawler|spider|scraper|automated|headless/i,
      /curl|wget|python|java|go-http|okhttp/i,
      /phantom|selenium|playwright|puppeteer/i,
      /httpclient|apache-httpclient|urllib/i,
      /postman|insomnia|rest-client/i
    ];

    for (const pattern of botPatterns) {
      if (pattern.test(userAgent)) {
        score += 60;
        reasons.push('bot_pattern');
        break;
      }
    }

    // Missing or suspicious UA
    if (!userAgent || userAgent.length < 10) {
      score += 40;
      reasons.push('missing_ua');
    }

    // Outdated browsers (potential bot)
    if (userAgent.includes('Chrome/')) {
      const chromeVersion = userAgent.match(/Chrome\/(\d+)/);
      if (chromeVersion && parseInt(chromeVersion[1]) < 90) {
        score += 20;
        reasons.push('outdated_browser');
      }
    }

    // Suspicious characteristics
    if (userAgent.includes('HeadlessChrome')) {
      score += 80;
      reasons.push('headless_chrome');
    }

    if (userAgent.includes('PhantomJS')) {
      score += 80;
      reasons.push('phantomjs');
    }

    return { score, suspicious: score > 0, reason: reasons.join(',') };
  }

  analyzeHeaders(request) {
    let score = 0;
    const reasons = [];

    // Missing common headers
    const requiredHeaders = ['Accept', 'Accept-Language', 'Accept-Encoding'];
    for (const header of requiredHeaders) {
      if (!request.headers.get(header)) {
        score += 15;
        reasons.push(`missing_${header.toLowerCase()}`);
      }
    }

    // Suspicious header values
    const acceptLanguage = request.headers.get('Accept-Language');
    if (acceptLanguage && !acceptLanguage.includes('id')) {
      score += 10;
      reasons.push('non_id_language');
    }

    // Check for automation headers
    const automationHeaders = [
      'X-Requested-With',
      'X-Forwarded-For',
      'X-Real-IP',
      'X-Originating-IP'
    ];

    for (const header of automationHeaders) {
      if (request.headers.get(header)) {
        score += 10;
        reasons.push(`automation_header:${header}`);
      }
    }

    // Missing security headers that browsers usually send
    if (!request.headers.get('Sec-Fetch-Site')) {
      score += 20;
      reasons.push('missing_sec_fetch');
    }

    if (!request.headers.get('Sec-Fetch-Mode')) {
      score += 20;
      reasons.push('missing_sec_fetch_mode');
    }

    return { score, suspicious: score > 0, reason: reasons.join(',') };
  }

  async analyzeIP(clientIP) {
    let score = 0;
    const reasons = [];

    // Check IP reputation cache
    const ipReputation = await this.env.ANTI_BOT_KV.get(`ip:${clientIP}`);
    if (ipReputation) {
      const rep = JSON.parse(ipReputation);
      if (rep.suspicious) {
        score += 30;
        reasons.push('ip_reputation');
      }
    }

    // Check for rate limiting using atomic operations
    const rateLimitKey = `rate:${clientIP}`;
    let currentCount = 1;
    
    // Try to create the key if not exists
    const result = await this.env.ANTI_BOT_KV.put(
      rateLimitKey, 
      "1", 
      { 
        expirationTtl: 60, 
        onlyIfEmpty: true 
      }
    );
    
    if (result === null) {
      // Key already exists, increment
      const existing = await this.env.ANTI_BOT_KV.get(rateLimitKey);
      if (existing) {
        currentCount = parseInt(existing) + 1;
        await this.env.ANTI_BOT_KV.put(rateLimitKey, currentCount.toString(), { expirationTtl: 60 });
      }
    }
    
    if (currentCount > 10) {
      score += 40;
      reasons.push('rate_limit');
    }

    return { score, suspicious: score > 0, reason: reasons.join(',') };
  }

  async analyzeFingerprint(fingerprint) {
    let score = 0;
    const reasons = [];

    // Check for duplicate fingerprints
    const fpCount = await this.env.ANTI_BOT_KV.get(`fp:${fingerprint}`);
    if (fpCount) {
      const count = parseInt(fpCount);
      if (count > 3) { // Same fingerprint used more than 3 times
        score += 35;
        reasons.push('duplicate_fingerprint');
      }
    }

    // Update fingerprint counter
    await this.env.ANTI_BOT_KV.put(`fp:${fingerprint}`, 
      fpCount ? (parseInt(fpCount) + 1).toString() : '1', 
      { expirationTtl: 3600 }
    );

    return { score, suspicious: score > 0, reason: reasons.join(',') };
  }

  analyzeTimings(processingTime) {
    let score = 0;
    const reasons = [];
    
    // Too fast (likely automated)
    if (processingTime < 100) {
      score += 25;
      reasons.push('too_fast');
    }

    return { score, suspicious: score > 0, reason: reasons.join(',') };
  }

  analyzeASN(asn, asOrganization) {
    let score = 0;
    const reasons = [];

    // Known hosting/VPS providers
    const suspiciousASNs = [
      'Amazon', 'Google Cloud', 'Microsoft', 'DigitalOcean',
      'Linode', 'Vultr', 'Hetzner', 'OVH'
    ];

    if (asOrganization) {
      for (const provider of suspiciousASNs) {
        if (asOrganization.includes(provider)) {
          score += 20;
          reasons.push(`hosting_provider:${provider}`);
          break;
        }
      }
    }

    return { score, suspicious: score > 0, reason: reasons.join(',') };
  }

  async generateFingerprint(request) {
    const clientIP = this.getClientIP(request);
    const userAgent = request.headers.get('User-Agent') || '';
    const acceptLanguage = request.headers.get('Accept-Language') || '';
    const acceptEncoding = request.headers.get('Accept-Encoding') || '';
    
    const data = `${clientIP}:${userAgent}:${acceptLanguage}:${acceptEncoding}`;
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  }

  getClientIP(request) {
    return request.headers.get('CF-Connecting-IP') || 
           request.headers.get('X-Forwarded-For') || 
           request.headers.get('X-Real-IP') || 
           '0.0.0.0';
  }

  async handleHoneypot(request) {
    // Log honeypot access (likely bot)
    await this.logAccess(request, 'HONEYPOT', 100);
    
    // Return fake JavaScript that does nothing
    return new Response(`
      // Anti-bot verification
      (function() {
        var d = document;
        var s = d.createElement('script');
        s.src = '/static/verify.min.js';
        d.head.appendChild(s);
      })();
    `, {
      headers: {
        'Content-Type': 'application/javascript',
        'Cache-Control': 'no-cache'
      }
    });
  }

  async handleTurnstileVerification(request) {
    try {
      const contentType = request.headers.get('Content-Type');
      if (!contentType || !contentType.includes('application/x-www-form-urlencoded')) {
        return this.blockRequest(request, 'invalid_content_type', 100);
      }

      const formData = await request.formData();
      const token = formData.get('cf-turnstile-response');
      
      if (!token) {
        return this.blockRequest(request, 'missing_turnstile_token', 100);
      }

      // Verify Turnstile token
      const verifyResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `secret=${encodeURIComponent(this.env.TURNSTILE_SECRET_KEY)}&response=${encodeURIComponent(token)}&remoteip=${encodeURIComponent(this.getClientIP(request))}`
      });

      const verifyResult = await verifyResponse.json();

      if (verifyResult.success) {
        // Cache successful verification
        const fingerprint = await this.generateFingerprint(request);
        await this.env.ANTI_BOT_KV.put(`verified:${fingerprint}`, 'true', { expirationTtl: this.cacheTime });
        
        await this.logAccess(request, 'TURNSTILE_PASSED', 0);
        return this.redirectToLanding(request);
      } else {
        await this.logAccess(request, 'TURNSTILE_FAILED', 100);
        return this.blockRequest(request, 'turnstile_failed', 100);
      }
    } catch (error) {
      await this.logError(error, request);
      return this.blockRequest(request, 'turnstile_error', 100);
    }
  }

  showTurnstileChallenge(request, score) {
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verifikasi Keamanan</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
            .logo { font-size: 24px; font-weight: bold; color: #2c3e50; margin-bottom: 20px; }
            .message { color: #7f8c8d; margin-bottom: 30px; }
            .cf-turnstile { margin: 20px 0; }
            .submit-btn { background: #3498db; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .submit-btn:hover { background: #2980b9; }
            .footer { margin-top: 20px; font-size: 12px; color: #bdc3c7; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">🛡️ Verifikasi Keamanan</div>
            <div class="message">Untuk melanjutkan, silakan verifikasi bahwa Anda bukan robot.</div>
            
            <form method="POST" action="/verify" id="verifyForm">
                <div class="cf-turnstile" data-sitekey="${this.env.TURNSTILE_SITE_KEY}" data-theme="light"></div>
                <button type="submit" class="submit-btn">Verifikasi</button>
            </form>
            
            <div class="footer">Sistem keamanan otomatis • Score: ${score}</div>
        </div>
        
        <script>
            document.getElementById('verifyForm').addEventListener('submit', function(e) {
                const turnstileResponse = document.querySelector('[name="cf-turnstile-response"]');
                if (!turnstileResponse || !turnstileResponse.value) {
                    e.preventDefault();
                    alert('Silakan selesaikan verifikasi terlebih dahulu.');
                }
            });
        </script>
    </body>
    </html>
    `;

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-cache'
      }
    });
  }

  redirectToLanding(request) {
    const landingUrl = this.env.LANDING_URL || 'https://example.com/landing';
    
    return Response.redirect(landingUrl, 302);
  }

  blockRequest(request, reason, score) {
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Akses Ditolak</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
            .error { color: #e74c3c; font-size: 48px; margin-bottom: 20px; }
            .message { color: #7f8c8d; margin-bottom: 30px; }
            .reason { background: #ecf0f1; padding: 10px; border-radius: 5px; font-family: monospace; color: #2c3e50; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error">🚫</div>
            <h1>Akses Ditolak</h1>
            <div class="message">Maaf, akses Anda telah diblokir oleh sistem keamanan.</div>
            <div class="reason">Alasan: ${reason} (Score: ${score})</div>
        </div>
    </body>
    </html>
    `;

    return new Response(html, {
      status: 403,
      headers: {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-cache'
      }
    });
  }

  async logAccess(request, action, score, reasons = []) {
    const logData = {
      timestamp: new Date().toISOString(),
      ip: this.getClientIP(request),
      country: request.cf?.country || 'UNKNOWN',
      userAgent: request.headers.get('User-Agent') || '',
      action: action,
      score: score,
      reasons: reasons,
      asn: request.cf?.asn || 0,
      asOrganization: request.cf?.asOrganization || '',
      url: request.url,
      method: request.method,
      processingTime: Date.now() - this.startTime
    };

    try {
      // Log to KV (for debugging)
      await this.env.ANTI_BOT_KV.put(
        `log:${Date.now()}:${Math.random().toString(36).substring(2, 11)}`, 
        JSON.stringify(logData),
        { expirationTtl: 86400 } // 24 hours
      );

      // Optional: Log to external service (Google Sheets, etc.)
      if (this.env.WEBHOOK_URL) {
        this.ctx.waitUntil(
          fetch(this.env.WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(logData)
          }).catch(err => console.error('Webhook error:', err))
        );
      }
    } catch (error) {
      console.error('Failed to log access:', error);
    }
  }

  async logError(error, request) {
    const errorData = {
      timestamp: new Date().toISOString(),
      ip: this.getClientIP(request),
      error: error.message,
      stack: error.stack,
      url: request.url,
      userAgent: request.headers.get('User-Agent') || ''
    };

    try {
      await this.env.ANTI_BOT_KV.put(
        `error:${Date.now()}:${Math.random().toString(36).substring(2, 11)}`, 
        JSON.stringify(errorData),
        { expirationTtl: 86400 }
      );
    } catch (err) {
      console.error('Failed to log error:', err);
    }
  }
}

export default {
  async fetch(request, env, ctx) {
    const antiBot = new AntiBot(env, ctx);
    return antiBot.handleRequest(request);
  }
};
