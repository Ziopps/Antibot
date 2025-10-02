let _antiBotConfig = null;
let _configLastRefresh = 0;
const CONFIG_REFRESH_INTERVAL = 30000;

// Default configuration with layered thresholds
const DEFAULT_CONFIG = {
  // Scoring thresholds
  blockScore: 85,
  captchaScore: 60,
  jsCharlengeScore: 40,
  reviewScore: 75,
  
  // Cache & rate limiting
  cacheTime: 7200,
  rateLimitWindow: 60,
  rateLimitQuota: 15,
  connectionQuota: 10,
  burstQuota: 5,
  
  // Geographic
  allowedCountries: ['ID'],
  geoVelocityThreshold: 500, // km/hour
  
  // Behavioral
  minInteractionTime: 500, // ms
  maxRequestSpeed: 25, // ms
  fingerprintTTL: 7200,
  
  // Static assets
  staticAssetPattern: /\.(js|css|png|jpe?g|webp|gif|ico|svg|woff2?|ttf|eot|map|json|txt|webm|mp4|mp3)$/i,
  
  // Trusted sources
  highQualitySources: ['instagram.com', 'tiktok.com', 'whatsapp.com', 'facebook.com'],
  
  // Machine learning feedback
  mlFeedbackEnabled: true,
  falsePositiveThreshold: 0.15
};

class LayeredAntiBot {
  constructor(env, ctx, config) {
    this.env = env;
    this.ctx = ctx;
    this.config = config || DEFAULT_CONFIG;
  }

  async handleRequest(request) {
    const startTime = performance.now();
    
    try {
      const url = new URL(request.url);
      
      // Skip static assets
      if (this.config.staticAssetPattern.test(url.pathname)) {
        return this.forwardToOrigin(request);
      }
      
      // Handle verification endpoints
      if (url.pathname === '/verify' && request.method === 'POST') {
        return this.handleVerification(request, startTime);
      }
      
      if (url.pathname === '/feedback' && request.method === 'POST') {
        return this.handleFeedback(request);
      }
      
      // Main layered detection
      const result = await this.layeredDetection(request, startTime);
      
      return this.executeResponse(request, result, startTime);
      
    } catch (error) {
      // Silent fail
    }
  }

  logErrorAsync(error, request, ipHash, fingerprint, startTime) {
    this.ctx.waitUntil(this.logError(error, request, ipHash, fingerprint, startTime));
  }

  async logError(error, request, ipHash, fingerprint, startTime) {
    const processingTime = startTime ? performance.now() - startTime : 0;
    
    const errorLog = {
      timestamp: new Date().toISOString(),
      ipHash: ipHash || 'unknown',
      fingerprint: fingerprint || 'unknown',
      url: request.url,
      method: request.method,
      error: error.message || error.toString(),
      stack: error.stack || '',
      processingTime: processingTime.toFixed(2),
      userAgent: request.headers.get('User-Agent') || '',
      country: request.cf?.country || ''
    };
    
    // Write to error logs
    if (this.env.KV_ERROR_LOGS) {
      const logId = `err_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      await this.env.KV_ERROR_LOGS.put(logId, JSON.stringify(errorLog));
    }
    
    if (this.env.ANALYTICS_DB) {
      try {
        await this.env.ANALYTICS_DB.prepare(
          `INSERT INTO error_log (timestamp, ip_hash, fingerprint, url, method, error, stack, processing_time, user_agent, country)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          errorLog.timestamp,
          errorLog.ipHash,
          errorLog.fingerprint,
          errorLog.url,
          errorLog.method,
          errorLog.error,
          errorLog.stack,
          errorLog.processingTime,
          errorLog.userAgent,
          errorLog.country
        ).run();
      } catch (e) {
        console.error('Error logging failed:', e);
      }
    }
  }

  // Cache Operations
  async getCache(key) {
    try {
      // Try KV first (fastest)
      if (this.env.KV_BOT_CACHE) {
        const value = await this.env.KV_BOT_CACHE.get(key);
        if (value !== null) return value;
      }
    } catch (e) {
      // KV failed, try next
    }
    
    try {
      // Try Redis
      if (this.env.REDIS_ENDPOINT) {
        const response = await fetch(`${this.env.REDIS_ENDPOINT}/get/${key}`, {
          headers: {
            'Authorization': `Bearer ${this.env.REDIS_TOKEN || ''}`
          }
        });
        
        if (response.ok) {
          const data = await response.json();
          return data.value || null;
        }
      }
    } catch (e) {
      // Redis failed, try D1
    }
    
    try {
      // Fallback to D1
      if (this.env.DB) {
        const result = await this.env.DB.prepare(
          'SELECT value FROM cache WHERE key = ? AND expires_at > ?'
        ).bind(key, Date.now()).first();
        
        return result?.value || null;
      }
    } catch (e) {
      // All failed
    }
    
    return null;
  }

  async setCache(key, value, ttl = 3600) {
    const expiresAt = Date.now() + (ttl * 1000);
    
    try {
      // Try KV first
      if (this.env.KV_BOT_CACHE) {
        await this.env.KV_BOT_CACHE.put(key, value, { expirationTtl: ttl });
        return;
      }
    } catch (e) {
      // KV failed
    }
    
    try {
      // Try Redis
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
      // Redis failed
    }
    
    try {
      // Fallback to D1
      if (this.env.DB) {
        await this.env.DB.prepare(
          'INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)'
        ).bind(key, value, expiresAt).run();
      }
    } catch (e) {
      // All failed, ignore
    }
  }

  setCacheAsync(key, value, ttl) {
    this.ctx.waitUntil(this.setCache(key, value, ttl));
  }
}

// Worker Entry Point
export default {
  async fetch(request, env, ctx) {
    // Load config (with caching)
    const now = Date.now();
    if (!_antiBotConfig || (now - _configLastRefresh) > CONFIG_REFRESH_INTERVAL) {
      try {
        if (env.KV_CONFIG) {
          const config = await env.KV_CONFIG.get('antibot_config', { type: 'json' });
          if (config) {
            _antiBotConfig = { ...DEFAULT_CONFIG, ...config };
            _configLastRefresh = now;
          }
        }
      } catch (e) {
        // Use default config
      }
      
      if (!_antiBotConfig) {
        _antiBotConfig = DEFAULT_CONFIG;
        _configLastRefresh = now;
      }
    }
    
    const antiBot = new LayeredAntiBot(env, ctx, _antiBotConfig);
    return antiBot.handleRequest(request);
  }
};
      this.logErrorAsync(error, request, null, null, startTime);
      return this.adaptiveChallenge(request, 50, 'error_fallback');
    }
  }

  async layeredDetection(request, startTime) {
    // Pre-verified bypass
    const verifiedToken = request.headers.get('X-AntiBot-Token');
    if (verifiedToken && await this.validateToken(verifiedToken)) {
      return { action: 'allow', score: 0, layer: 'token', confidence: 1.0 };
    }

    // Layer 1: Network/IP Layer
    const layer1 = await this.networkLayer(request);
    if (layer1.action === 'block') return layer1;

    // Layer 2: Transport/TLS Layer
    const layer2 = await this.transportLayer(request);
    
    // Layer 3: Protocol/HTTP Layer
    const layer3 = await this.protocolLayer(request);
    
    // Layer 4: Client Integrity Layer
    const layer4 = await this.clientIntegrityLayer(request);
    
    // Layer 5: Behavioral Layer
    const layer5 = await this.behavioralLayer(request, startTime);
    
    // Aggregate scoring with weighted layers
    const aggregateScore = this.calculateAggregateScore([
      { result: layer1, weight: 1.5 },  // Network critical
      { result: layer2, weight: 1.3 },  // TLS important
      { result: layer3, weight: 1.2 },  // HTTP protocol
      { result: layer4, weight: 1.0 },  // Client checks
      { result: layer5, weight: 0.8 }   // Behavior (can be spoofed)
    ]);

    // Calculate confidence
    const confidence = this.calculateConfidence(aggregateScore);
    
    return {
      action: this.determineAction(aggregateScore.score, confidence),
      score: aggregateScore.score,
      confidence: confidence,
      layers: aggregateScore.details,
      layer: 'aggregate'
    };
  }

  // LAYER 1: Network/IP Layer
  async networkLayer(request) {
    const clientIP = this.getClientIP(request);
    const ipHash = await this.hashIP(clientIP);
    const country = request.cf?.country || 'UNKNOWN';
    const asn = request.cf?.asn;
    const asOrg = request.cf?.asOrganization || '';
    
    let score = 0;
    const signals = [];

    // Country check
    if (!this.config.allowedCountries.includes(country)) {
      score += 100;
      signals.push({ type: 'geo_block', severity: 'critical', value: country });
    }

    // IP reputation
    const ipRep = await this.checkIPReputation(ipHash);
    if (ipRep.malicious) {
      score += 80;
      signals.push({ type: 'ip_reputation', severity: 'high', value: ipRep.score });
    }

    // ASN checks - hosting providers
    const hostingProviders = [
      { pattern: /amazon|aws/i, score: 35, name: 'AWS' },
      { pattern: /google cloud|gcp/i, score: 35, name: 'GCP' },
      { pattern: /microsoft|azure/i, score: 30, name: 'Azure' },
      { pattern: /digitalocean/i, score: 40, name: 'DigitalOcean' },
      { pattern: /linode|akamai/i, score: 38, name: 'Linode' },
      { pattern: /vultr/i, score: 40, name: 'Vultr' },
      { pattern: /hetzner/i, score: 35, name: 'Hetzner' },
      { pattern: /ovh/i, score: 30, name: 'OVH' },
      { pattern: /alibaba/i, score: 35, name: 'Alibaba' },
      { pattern: /datacenter|hosting|vps|cloud|server/i, score: 25, name: 'Generic Hosting' }
    ];

    for (const provider of hostingProviders) {
      if (provider.pattern.test(asOrg)) {
        score += provider.score;
        signals.push({ type: 'hosting_asn', severity: 'medium', value: provider.name });
        break;
      }
    }

    // Rate limiting with token bucket
    const rateLimit = await this.checkRateLimits(ipHash);
    if (rateLimit.exceeded) {
      score += Math.min(rateLimit.excess * 8, 60);
      signals.push({ type: 'rate_limit', severity: 'high', value: rateLimit.count });
    }

    // Connection quota
    const connQuota = await this.checkConnectionQuota(ipHash);
    if (connQuota.exceeded) {
      score += 45;
      signals.push({ type: 'connection_flood', severity: 'high', value: connQuota.count });
    }

    // Geo-velocity (impossible travel)
    const geoVelocity = await this.checkGeoVelocity(ipHash, country);
    if (geoVelocity.suspicious) {
      score += 55;
      signals.push({ type: 'geo_velocity', severity: 'high', value: geoVelocity.speed });
    }

    // VPN/Proxy detection
    const proxyDetection = await this.detectProxy(clientIP, request);
    if (proxyDetection.detected) {
      score += 50;
      signals.push({ type: 'proxy_detected', severity: 'high', value: proxyDetection.type });
    }

    return {
      action: score >= 100 ? 'block' : 'continue',
      score,
      signals,
      layer: 'network'
    };
  }

  // LAYER 2: Transport/TLS Layer
  async transportLayer(request) {
    let score = 0;
    const signals = [];

    // JA3 fingerprint
    const ja3 = request.cf?.botManagement?.ja3Hash;
    if (ja3) {
      const ja3Rep = await this.checkJA3Reputation(ja3);
      if (ja3Rep.suspicious) {
        score += 40;
        signals.push({ type: 'ja3_suspicious', severity: 'medium', value: ja3.substring(0, 16) });
      }
    }

    // TLS version check
    const tlsVersion = request.cf?.tlsVersion;
    if (tlsVersion && (tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.1')) {
      score += 35;
      signals.push({ type: 'outdated_tls', severity: 'medium', value: tlsVersion });
    }

    // HTTP version anomalies
    const httpVersion = request.cf?.httpProtocol;
    if (httpVersion === 'HTTP/1.0') {
      score += 25;
      signals.push({ type: 'http_version', severity: 'low', value: httpVersion });
    }

    // Cipher suite analysis
    const tlsCipher = request.cf?.tlsCipher;
    if (tlsCipher && this.isSuspiciousCipher(tlsCipher)) {
      score += 20;
      signals.push({ type: 'suspicious_cipher', severity: 'low', value: tlsCipher });
    }

    // Connection timing
    const timing = await this.analyzeConnectionTiming(request);
    if (timing.suspicious) {
      score += 30;
      signals.push({ type: 'timing_anomaly', severity: 'medium', value: timing.pattern });
    }

    return { score, signals, layer: 'transport' };
  }

  // LAYER 3: Protocol/HTTP Layer
  async protocolLayer(request) {
    let score = 0;
    const signals = [];

    // User-Agent analysis
    const ua = request.headers.get('User-Agent') || '';
    const uaAnalysis = this.analyzeUserAgent(ua);
    score += uaAnalysis.score;
    signals.push(...uaAnalysis.signals);

    // Header coherence checks
    const headerCoherence = this.checkHeaderCoherence(request);
    score += headerCoherence.score;
    signals.push(...headerCoherence.signals);

    // HTTP/2 specific checks
    if (request.cf?.httpProtocol === 'HTTP/2') {
      const http2Analysis = this.analyzeHTTP2(request);
      score += http2Analysis.score;
      signals.push(...http2Analysis.signals);
    }

    // Critical missing headers
    const criticalHeaders = ['Accept', 'Accept-Language', 'Accept-Encoding'];
    let missingCount = 0;
    for (const header of criticalHeaders) {
      if (!request.headers.get(header)) {
        missingCount++;
      }
    }
    if (missingCount >= 2) {
      score += 40;
      signals.push({ type: 'missing_headers', severity: 'high', value: missingCount });
    }

    // Security headers (Sec-Fetch-*)
    const secHeaders = ['Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-Dest'];
    let missingSecCount = 0;
    for (const header of secHeaders) {
      if (!request.headers.get(header)) {
        missingSecCount++;
      }
    }
    if (missingSecCount >= 2) {
      score += 35;
      signals.push({ type: 'missing_sec_headers', severity: 'medium', value: missingSecCount });
    }

    // Automation headers
    const automationHeaders = [
      'X-Requested-With',
      'X-Forwarded-For',
      'X-Real-IP',
      'X-Automated',
      'X-Bot-Token'
    ];
    for (const header of automationHeaders) {
      if (request.headers.get(header)) {
        score += 20;
        signals.push({ type: 'automation_header', severity: 'medium', value: header });
        break;
      }
    }

    // Ads/tracking headers
    const trackingHeaders = [
      'X-Ads-Token',
      'X-Tracking-ID',
      'X-Pixel-Data',
      'X-Conversion-Track',
      'X-Attribution'
    ];
    for (const header of trackingHeaders) {
      if (request.headers.get(header)) {
        score += 70;
        signals.push({ type: 'ads_tracking', severity: 'critical', value: header });
        break;
      }
    }

    // Header order analysis
    const headerOrder = this.analyzeHeaderOrder(request);
    if (headerOrder.suspicious) {
      score += 25;
      signals.push({ type: 'header_order', severity: 'low', value: 'anomalous' });
    }

    return { score, signals, layer: 'protocol' };
  }

  // LAYER 4: Client Integrity Layer
  async clientIntegrityLayer(request) {
    let score = 0;
    const signals = [];

    // Browser fingerprint analysis
    const fingerprint = await this.generateFingerprint(request);
    const fpAnalysis = await this.analyzeFingerprintReuse(fingerprint);
    
    if (fpAnalysis.overused) {
      score += 70;
      signals.push({ type: 'fingerprint_reuse', severity: 'high', value: fpAnalysis.count });
    }

    // Check for webdriver flags
    const cookies = request.headers.get('Cookie') || '';
    if (cookies.includes('webdriver=') || cookies.includes('selenium=')) {
      score += 85;
      signals.push({ type: 'webdriver_detected', severity: 'critical', value: 'cookie' });
    }

    // Canvas/WebGL fingerprint (if available from client JS)
    const clientData = await this.extractClientData(request);
    if (clientData) {
      const deviceAnalysis = this.analyzeDeviceSignals(clientData);
      score += deviceAnalysis.score;
      signals.push(...deviceAnalysis.signals);
    }

    // Navigator consistency
    const navConsistency = this.checkNavigatorConsistency(request);
    score += navConsistency.score;
    signals.push(...navConsistency.signals);

    return { score, signals, layer: 'client' };
  }

  // LAYER 5: Behavioral Layer
  async behavioralLayer(request, startTime) {
    let score = 0;
    const signals = [];

    // Request timing
    const processingTime = performance.now() - startTime;
    if (processingTime < this.config.maxRequestSpeed) {
      score += 35;
      signals.push({ type: 'too_fast', severity: 'medium', value: processingTime.toFixed(2) });
    }

    // Mouse/interaction data from cookies
    const cookies = request.headers.get('Cookie') || '';
    const hasInteraction = cookies.includes('_interaction=');
    if (!hasInteraction && request.method === 'POST') {
      score += 40;
      signals.push({ type: 'no_interaction', severity: 'medium', value: 'post_without_interaction' });
    }

    // Session coherence
    const sessionData = await this.analyzeSession(request);
    if (sessionData.suspicious) {
      score += 30;
      signals.push({ type: 'session_anomaly', severity: 'medium', value: sessionData.reason });
    }

    // Referrer analysis
    const referrer = request.headers.get('Referer') || '';
    const referrerAnalysis = this.analyzeReferrer(referrer, request.url);
    score += referrerAnalysis.score;
    signals.push(...referrerAnalysis.signals);

    // Resource loading patterns
    const resourcePattern = await this.analyzeResourcePattern(request);
    if (resourcePattern.suspicious) {
      score += 25;
      signals.push({ type: 'resource_pattern', severity: 'low', value: resourcePattern.pattern });
    }

    return { score, signals, layer: 'behavioral' };
  }

  // Scoring & Decision Logic
  calculateAggregateScore(layerResults) {
    let totalScore = 0;
    let totalWeight = 0;
    const details = {};

    for (const { result, weight } of layerResults) {
      const weightedScore = result.score * weight;
      totalScore += weightedScore;
      totalWeight += weight;
      
      details[result.layer] = {
        score: result.score,
        weighted: weightedScore,
        signals: result.signals || []
      };
    }

    return {
      score: Math.round(totalScore / totalWeight),
      details
    };
  }

  calculateConfidence(aggregateScore) {
    // Confidence based on signal consistency across layers
    const layers = Object.values(aggregateScore.details);
    const signalCount = layers.reduce((sum, layer) => sum + layer.signals.length, 0);
    
    // More signals = higher confidence
    let confidence = Math.min(signalCount / 10, 1.0);
    
    // Penalty for conflicting signals
    const scores = layers.map(l => l.score);
    const variance = this.calculateVariance(scores);
    if (variance > 30) {
      confidence *= 0.7; // Lower confidence on conflicting signals
    }

    return confidence;
  }

  determineAction(score, confidence) {
    // High confidence decisions
    if (confidence >= 0.8) {
      if (score >= this.config.blockScore) return 'block';
      if (score >= this.config.captchaScore) return 'captcha';
      if (score >= this.config.jsChallenge Score) return 'js_challenge';
      return 'allow';
    }
    
    // Medium confidence - more conservative
    if (confidence >= 0.5) {
      if (score >= this.config.blockScore + 10) return 'block';
      if (score >= this.config.captchaScore) return 'captcha';
      if (score >= this.config.jsChallengeScore) return 'js_challenge';
      return 'allow';
    }
    
    // Low confidence - review or challenge
    if (score >= this.config.reviewScore) {
      return 'review'; // Flag for manual review
    }
    if (score >= this.config.jsChallengeScore) {
      return 'js_challenge';
    }
    
    return 'allow';
  }

  async executeResponse(request, result, startTime) {
    // Log telemetry
    await this.logTelemetry(request, result, startTime);

    switch (result.action) {
      case 'allow':
        return this.forwardToOrigin(request, result);
        
      case 'js_challenge':
        return this.jsChallenge(request, result);
        
      case 'captcha':
        return this.captchaChallenge(request, result);
        
      case 'block':
        return this.blockRequest(request, result);
        
      case 'review':
        // Allow but flag for review
        await this.flagForReview(request, result);
        return this.forwardToOrigin(request, result);
        
      default:
        return this.adaptiveChallenge(request, result.score, result.layer);
    }
  }

  async forwardToOrigin(request, result) {
    const newRequest = new Request(request);
    newRequest.headers.set('X-AntiBot-Status', 'verified');
    newRequest.headers.set('X-AntiBot-Score', result.score.toString());
    newRequest.headers.set('X-AntiBot-Confidence', result.confidence.toFixed(2));
    
    // Cache verified fingerprint
    if (result.score < this.config.jsChallengeScore) {
      const fingerprint = await this.generateFingerprint(request);
      this.setCacheAsync(`verified:${fingerprint}`, JSON.stringify(result), this.config.cacheTime);
    }
    
    return fetch(newRequest);
  }

  jsChallenge(request, result) {
    return new Response(this.generateJSChallengePage(result), {
      status: 403,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Challenge-Type': 'js'
      }
    });
  }

  captchaChallenge(request, result) {
    return new Response(this.generateCaptchaPage(result), {
      status: 403,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Challenge-Type': 'captcha'
      }
    });
  }

  blockRequest(request, result) {
    this.logBlockAsync(request, result);
    
    return new Response(this.generateBlockPage(result), {
      status: 403,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Block-Reason': result.layers ? Object.keys(result.layers).join(',') : 'unknown'
      }
    });
  }

  adaptiveChallenge(request, score, layer) {
    // Adaptive response based on score
    if (score < 40) {
      return this.jsChallenge(request, { score, layer });
    } else if (score < 70) {
      return this.captchaChallenge(request, { score, layer });
    } else {
      return this.blockRequest(request, { score, layer });
    }
  }

  // Helper Methods
  analyzeUserAgent(ua) {
    let score = 0;
    const signals = [];

    if (!ua || ua.length < 15) {
      score += 50;
      signals.push({ type: 'missing_ua', severity: 'high', value: ua.length });
      return { score, signals };
    }

    const botPatterns = [
      { pattern: /bot|crawler|spider|scraper|automated/i, score: 70, reason: 'bot_pattern' },
      { pattern: /headless|phantom|selenium|playwright|puppeteer/i, score: 90, reason: 'headless' },
      { pattern: /curl|wget|python|java|go-http|okhttp/i, score: 80, reason: 'http_client' },
      { pattern: /httpclient|apache|urllib|requests/i, score: 75, reason: 'automation' },
      { pattern: /postman|insomnia|rest-client|api/i, score: 60, reason: 'api_tool' },
      { pattern: /mediapartners|adsbot|googlebot-ads|bingbot-ads/i, score: 100, reason: 'ads_bot' },
      { pattern: /semrush|ahrefs|majestic|moz|screaming/i, score: 95, reason: 'seo_bot' },
      { pattern: /click|impression|conversion|tracker|pixel/i, score: 85, reason: 'tracking_bot' }
    ];

    for (const { pattern, score: patternScore, reason } of botPatterns) {
      if (pattern.test(ua)) {
        score += patternScore;
        signals.push({ type: 'ua_pattern', severity: 'critical', value: reason });
        break;
      }
    }

    // Outdated browser
    if (ua.includes('Chrome/')) {
      const match = ua.match(/Chrome\/(\d+)/);
      if (match && parseInt(match[1]) < 90) {
        score += 30;
        signals.push({ type: 'outdated_browser', severity: 'medium', value: match[1] });
      }
    }

    return { score, signals };
  }

  checkHeaderCoherence(request) {
    let score = 0;
    const signals = [];

    const ua = request.headers.get('User-Agent') || '';
    const accept = request.headers.get('Accept') || '';
    const acceptLang = request.headers.get('Accept-Language') || '';
    const country = request.cf?.country || '';

    // Accept header should match UA (browser should accept HTML)
    if (ua.includes('Mozilla') && !accept.includes('text/html')) {
      score += 35;
      signals.push({ type: 'accept_mismatch', severity: 'medium', value: 'no_html' });
    }

    // Language vs Geo mismatch
    if (country === 'ID' && acceptLang && !acceptLang.includes('id') && !acceptLang.includes('en')) {
      score += 20;
      signals.push({ type: 'lang_geo_mismatch', severity: 'low', value: acceptLang });
    }

    // Chrome UA should have Sec-CH-UA
    if (ua.includes('Chrome/') && !request.headers.get('Sec-CH-UA')) {
      score += 25;
      signals.push({ type: 'missing_client_hints', severity: 'medium', value: 'sec_ch_ua' });
    }

    return { score, signals };
  }

  analyzeHTTP2(request) {
    let score = 0;
    const signals = [];

    // HTTP/2 should have pseudo-headers (handled by Cloudflare, but check for anomalies)
    // Bots often don't implement HTTP/2 correctly
    
    // Check for HTTP/2 with HTTP/1.1 patterns
    const connection = request.headers.get('Connection');
    if (connection) {
      score += 30;
      signals.push({ type: 'http2_with_connection', severity: 'medium', value: connection });
    }

    return { score, signals };
  }

  analyzeHeaderOrder(request) {
    // Real browsers send headers in specific order
    // This is a simplified check
    const headers = Array.from(request.headers.keys());
    
    // Common browser order: host, connection, user-agent, accept...
    const expectedOrder = ['host', 'user-agent', 'accept'];
    let orderMatch = true;
    
    let lastIndex = -1;
    for (const expected of expectedOrder) {
      const index = headers.findIndex(h => h.toLowerCase() === expected);
      if (index !== -1 && index < lastIndex) {
        orderMatch = false;
        break;
      }
      lastIndex = index;
    }

    return { suspicious: !orderMatch };
  }

  checkNavigatorConsistency(request) {
    let score = 0;
    const signals = [];

    // Check for navigator.webdriver indicators in cookies
    const cookies = request.headers.get('Cookie') || '';
    if (cookies.includes('_navigator_webdriver=true')) {
      score += 90;
      signals.push({ type: 'webdriver_flag', severity: 'critical', value: 'cookie' });
    }

    return { score, signals };
  }

  analyzeDeviceSignals(clientData) {
    let score = 0;
    const signals = [];

    // Canvas fingerprint inconsistency
    if (clientData.canvasHash && await this.isCommonBotCanvas(clientData.canvasHash)) {
      score += 60;
      signals.push({ type: 'bot_canvas', severity: 'high', value: clientData.canvasHash.substring(0, 16) });
    }

    // Impossible device specs
    if (clientData.hardwareConcurrency === 0 || clientData.hardwareConcurrency > 128) {
      score += 40;
      signals.push({ type: 'impossible_hardware', severity: 'medium', value: clientData.hardwareConcurrency });
    }

    // Missing plugins (deprecated but still a signal)
    if (clientData.plugins === 0 && clientData.browserVersion < 100) {
      score += 20;
      signals.push({ type: 'no_plugins', severity: 'low', value: '0' });
    }

    return { score, signals };
  }

  analyzeReferrer(referrer, currentUrl) {
    let score = 0;
    const signals = [];

    if (!referrer) {
      // Direct access - slightly suspicious for POST requests
      if (currentUrl.includes('?') || currentUrl.includes('submit')) {
        score += 15;
        signals.push({ type: 'no_referrer_post', severity: 'low', value: 'direct' });
      }
      return { score, signals };
    }

    // High quality source bypass
    if (this.config.highQualitySources.some(src => referrer.includes(src))) {
      return { score: 0, signals: [] };
    }

    // Suspicious referrers
    const suspiciousPatterns = [
      { pattern: /bit\.ly|tinyurl|short/i, score: 30, reason: 'url_shortener' },
      { pattern: /ads|advert|click|track/i, score: 40, reason: 'ad_referrer' },
      { pattern: /spam|malware|phish/i, score: 80, reason: 'malicious_referrer' }
    ];

    for (const { pattern, score: patternScore, reason } of suspiciousPatterns) {
      if (pattern.test(referrer)) {
        score += patternScore;
        signals.push({ type: 'suspicious_referrer', severity: 'medium', value: reason });
        break;
      }
    }

    return { score, signals };
  }

  async analyzeResourcePattern(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Bots often skip resource loading (images, CSS, JS)
    const clientIP = this.getClientIP(request);
    const ipHash = await this.hashIP(clientIP);
    
    const resourceKey = `resources:${ipHash}`;
    const resources = await this.getCache(resourceKey);
    
    if (resources) {
      const parsed = JSON.parse(resources);
      // Real users load various resources
      if (parsed.count > 10 && parsed.types.length < 2) {
        return { suspicious: true, pattern: 'single_type_only' };
      }
    }

    return { suspicious: false };
  }

  async analyzeConnectionTiming(request) {
    // Analyze timing patterns from CF-Ray
    const cfRay = request.headers.get('CF-Ray') || '';
    if (!cfRay) return { suspicious: false };

    const clientIP = this.getClientIP(request);
    const ipHash = await this.hashIP(clientIP);
    
    const timingKey = `timing:${ipHash}`;
    const lastRequest = await this.getCache(timingKey);
    
    if (lastRequest) {
      const timeDiff = Date.now() - parseInt(lastRequest);
      
      // Too regular (bot-like)
      if (timeDiff > 0 && timeDiff < 100) {
        return { suspicious: true, pattern: 'too_regular' };
      }
      
      // Impossible speed
      if (timeDiff < 10) {
        return { suspicious: true, pattern: 'impossible_speed' };
      }
    }
    
    this.setCacheAsync(timingKey, Date.now().toString(), 10);
    return { suspicious: false };
  }

  isSuspiciousCipher(cipher) {
    // Weak or uncommon ciphers
    const suspiciousCiphers = [
      'RC4',
      'DES',
      '3DES',
      'NULL',
      'EXPORT',
      'anon'
    ];
    
    return suspiciousCiphers.some(c => cipher.includes(c));
  }

  // Rate Limiting & Quotas
  async checkRateLimits(ipHash) {
    const rateKey = `rate:${ipHash}`;
    const count = await this.getCache(rateKey);
    
    if (!count) {
      this.setCacheAsync(rateKey, '1', this.config.rateLimitWindow);
      return { exceeded: false, count: 1, excess: 0 };
    }
    
    const currentCount = parseInt(count);
    const newCount = currentCount + 1;
    this.setCacheAsync(rateKey, newCount.toString(), this.config.rateLimitWindow);
    
    const exceeded = newCount > this.config.rateLimitQuota;
    const excess = exceeded ? newCount - this.config.rateLimitQuota : 0;
    
    return { exceeded, count: newCount, excess };
  }

  async checkConnectionQuota(ipHash) {
    const connKey = `conn:${ipHash}`;
    const count = await this.getCache(connKey);
    
    if (!count) {
      this.setCacheAsync(connKey, '1', 1); // 1 second window
      return { exceeded: false, count: 1 };
    }
    
    const currentCount = parseInt(count);
    const newCount = currentCount + 1;
    this.setCacheAsync(connKey, newCount.toString(), 1);
    
    return {
      exceeded: newCount > this.config.connectionQuota,
      count: newCount
    };
  }

  async checkGeoVelocity(ipHash, currentCountry) {
    const geoKey = `geo:${ipHash}`;
    const lastGeo = await this.getCache(geoKey);
    
    if (!lastGeo) {
      this.setCacheAsync(geoKey, JSON.stringify({
        country: currentCountry,
        timestamp: Date.now()
      }), 3600);
      return { suspicious: false, speed: 0 };
    }
    
    const parsed = JSON.parse(lastGeo);
    const timeDiff = (Date.now() - parsed.timestamp) / 1000 / 3600; // hours
    
    if (parsed.country !== currentCountry && timeDiff < 1) {
      // Rough distance calculation (simplified)
      const distance = this.calculateDistance(parsed.country, currentCountry);
      const speed = distance / timeDiff;
      
      if (speed > this.config.geoVelocityThreshold) {
        return { suspicious: true, speed: Math.round(speed) };
      }
    }
    
    // Update location
    this.setCacheAsync(geoKey, JSON.stringify({
      country: currentCountry,
      timestamp: Date.now()
    }), 3600);
    
    return { suspicious: false, speed: 0 };
  }

  calculateDistance(country1, country2) {
    // Simplified distance map (km)
    const distances = {
      'ID-SG': 900,
      'ID-MY': 1200,
      'ID-US': 15000,
      'ID-EU': 11000,
      'ID-AU': 5000,
      'ID-JP': 5500,
      'ID-CN': 4500
    };
    
    const key1 = `${country1}-${country2}`;
    const key2 = `${country2}-${country1}`;
    
    return distances[key1] || distances[key2] || 10000; // Default 10000km
  }

  async detectProxy(clientIP, request) {
    // Check for known proxy headers
    const proxyHeaders = [
      'Via',
      'X-Forwarded-For',
      'X-Forwarded-Host',
      'Forwarded',
      'X-ProxyUser-IP'
    ];
    
    for (const header of proxyHeaders) {
      if (request.headers.get(header)) {
        return { detected: true, type: 'proxy_header' };
      }
    }
    
    // Check IP reputation for known VPN/proxy
    const ipRep = await this.checkIPReputation(await this.hashIP(clientIP));
    if (ipRep.vpn || ipRep.proxy) {
      return { detected: true, type: ipRep.vpn ? 'vpn' : 'proxy' };
    }
    
    return { detected: false };
  }

  async checkIPReputation(ipHash) {
    const repKey = `iprep:${ipHash}`;
    const cached = await this.getCache(repKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Default reputation
    const reputation = {
      malicious: false,
      vpn: false,
      proxy: false,
      score: 0
    };
    
    // Cache for 1 hour
    this.setCacheAsync(repKey, JSON.stringify(reputation), 3600);
    
    return reputation;
  }

  async checkJA3Reputation(ja3) {
    const ja3Key = `ja3:${ja3}`;
    const cached = await this.getCache(ja3Key);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Known bot JA3 hashes (example)
    const knownBotJA3s = [
      'f42a3a1e35e6eb77ee35479b01c2d555',
      'bc6c386f480ee97b9d9e52d472b772d8'
    ];
    
    const suspicious = knownBotJA3s.includes(ja3);
    
    const reputation = { suspicious };
    this.setCacheAsync(ja3Key, JSON.stringify(reputation), 86400);
    
    return reputation;
  }

  async analyzeFingerprintReuse(fingerprint) {
    const fpKey = `fp:${fingerprint}`;
    const count = await this.getCache(fpKey);
    
    if (!count) {
      this.setCacheAsync(fpKey, '1', this.config.fingerprintTTL);
      return { overused: false, count: 1 };
    }
    
    const currentCount = parseInt(count);
    const newCount = currentCount + 1;
    this.setCacheAsync(fpKey, newCount.toString(), this.config.fingerprintTTL);
    
    return {
      overused: newCount > 10,
      count: newCount
    };
  }

  async extractClientData(request) {
    // Extract client-side data from cookies or headers
    const cookies = request.headers.get('Cookie') || '';
    
    const clientData = {};
    
    // Parse client hints
    const canvasMatch = cookies.match(/_canvas=([^;]+)/);
    if (canvasMatch) {
      clientData.canvasHash = decodeURIComponent(canvasMatch[1]);
    }
    
    const hwMatch = cookies.match(/_hw=([^;]+)/);
    if (hwMatch) {
      clientData.hardwareConcurrency = parseInt(decodeURIComponent(hwMatch[1]));
    }
    
    const pluginsMatch = cookies.match(/_plugins=([^;]+)/);
    if (pluginsMatch) {
      clientData.plugins = parseInt(decodeURIComponent(pluginsMatch[1]));
    }
    
    const versionMatch = cookies.match(/_browser=([^;]+)/);
    if (versionMatch) {
      clientData.browserVersion = parseInt(decodeURIComponent(versionMatch[1]));
    }
    
    return Object.keys(clientData).length > 0 ? clientData : null;
  }

  async isCommonBotCanvas(canvasHash) {
    // Known bot canvas fingerprints
    const botCanvases = [
      'a1b2c3d4e5f6',
      '00000000000',
      'fffffffffffff'
    ];
    
    return botCanvases.includes(canvasHash);
  }

  extractSessionId(cookies) {
    const match = cookies.match(/(?:session|_session)=([^;]+)/);
    return match ? match[1] : null;
  }

  async getSessionChurnRate(sessionId) {
    const churnKey = `churn:${sessionId}`;
    const count = await this.getCache(churnKey);
    return count ? parseInt(count) : 0;
  }

  // Fingerprinting
  async generateFingerprint(request) {
    const components = [
      request.headers.get('User-Agent') || '',
      request.headers.get('Accept-Language') || '',
      request.headers.get('Accept-Encoding') || '',
      request.headers.get('Accept') || '',
      request.headers.get('Sec-CH-UA') || '',
      request.headers.get('Sec-CH-UA-Platform') || '',
      request.cf?.asn || '',
      request.cf?.country || ''
    ];
    
    const fingerprint = components.join(':');
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
           request.headers.get('X-Real-IP') ||
           '0.0.0.0';
  }

  calculateVariance(numbers) {
    if (numbers.length === 0) return 0;
    const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    const variance = numbers.reduce((sum, num) => sum + Math.pow(num - mean, 2), 0) / numbers.length;
    return Math.sqrt(variance);
  }

  // Token validation
  async validateToken(token) {
    const tokenKey = `token:${token}`;
    const valid = await this.getCache(tokenKey);
    return valid === 'true';
  }

  // Challenge Pages
  generateJSChallengePage(result) {
    return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifikasi Browser</title>
  <style>
    body { font-family: system-ui; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
    .container { background: white; padding: 2rem; border-radius: 1rem; box-shadow: 0 20px 60px rgba(0,0,0,0.3); text-align: center; max-width: 500px; }
    .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #667eea; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 2rem auto; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    h1 { color: #333; margin: 0 0 1rem; }
    p { color: #666; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="container">
    <div class="spinner"></div>
    <h1>Memverifikasi Browser Anda</h1>
    <p>Mohon tunggu, kami sedang memverifikasi bahwa Anda adalah pengguna asli...</p>
    <p style="font-size: 0.85em; color: #999;">Score: ${result.score} | Layer: ${result.layer}</p>
  </div>
  <script>
    // Browser integrity checks
    const collectBrowserData = () => {
      const data = {
        canvas: getCanvasFingerprint(),
        webgl: getWebGLFingerprint(),
        hardware: navigator.hardwareConcurrency || 0,
        plugins: navigator.plugins.length,
        languages: navigator.languages.join(','),
        platform: navigator.platform,
        memory: navigator.deviceMemory || 0,
        webdriver: navigator.webdriver || false,
        timestamp: Date.now(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: window.screen.width + 'x' + window.screen.height,
        colorDepth: window.screen.colorDepth,
        interaction: performance.now()
      };
      return data;
    };

    const getCanvasFingerprint = () => {
      try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Browser Check', 2, 2);
        return canvas.toDataURL().slice(-50);
      } catch { return 'error'; }
    };

    const getWebGLFingerprint = () => {
      try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return 'unsupported';
        const ext = gl.getExtension('WEBGL_debug_renderer_info');
        return ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL).slice(0, 30) : 'unknown';
      } catch { return 'error'; }
    };

    // Mouse movement tracking
    let mouseMovements = 0;
    document.addEventListener('mousemove', () => { mouseMovements++; });

    // Prove we can execute JS
    setTimeout(async () => {
      const data = collectBrowserData();
      
      // Solve proof-of-work
      const challenge = Math.random().toString(36).substring(2);
      let nonce = 0;
      while (nonce < 100000) {
        const hash = await crypto.subtle.digest('SHA-256', 
          new TextEncoder().encode(challenge + nonce)
        );
        const hashArray = Array.from(new Uint8Array(hash));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        if (hashHex.startsWith('0')) break;
        nonce++;
      }

      // Send verification
      const response = await fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...data,
          mouseMovements,
          challenge,
          nonce,
          processingTime: performance.now()
        })
      });

      if (response.ok) {
        const result = await response.json();
        if (result.token) {
          // Set verification cookie
          document.cookie = '_verified=' + result.token + '; path=/; max-age=7200; secure; samesite=strict';
          // Store client data
          document.cookie = '_canvas=' + encodeURIComponent(data.canvas) + '; path=/; max-age=7200';
          document.cookie = '_hw=' + data.hardware + '; path=/; max-age=7200';
          document.cookie = '_interaction=true; path=/; max-age=7200';
          window.location.reload();
        }
      }
    }, 1000);
  </script>
</body>
</html>`;
  }

  generateCaptchaPage(result) {
    const siteKey = this.env.TURNSTILE_SITE_KEY || 'YOUR_SITE_KEY';
    
    return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifikasi Keamanan</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    body { font-family: system-ui; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
    .container { background: white; padding: 3rem; border-radius: 1rem; box-shadow: 0 20px 60px rgba(0,0,0,0.3); text-align: center; max-width: 500px; }
    h1 { color: #333; margin: 0 0 1rem; }
    p { color: #666; line-height: 1.6; margin-bottom: 2rem; }
    .cf-turnstile { margin: 2rem auto; }
    .info { font-size: 0.85em; color: #999; margin-top: 2rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Verifikasi Keamanan</h1>
    <p>Untuk melindungi website dari bot dan spam, mohon selesaikan verifikasi di bawah ini.</p>
    
    <form id="verifyForm" method="POST" action="/verify">
      <div class="cf-turnstile" data-sitekey="${siteKey}" data-callback="onSuccess"></div>
    </form>
    
    <div class="info">
      Security Score: ${result.score} | Confidence: ${(result.confidence * 100).toFixed(0)}%
    </div>
  </div>
  
  <script>
    function onSuccess(token) {
      fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          token,
          type: 'turnstile',
          timestamp: Date.now()
        })
      }).then(r => r.json()).then(data => {
        if (data.success) {
          document.cookie = '_verified=' + data.verifyToken + '; path=/; max-age=7200; secure; samesite=strict';
          window.location.reload();
        }
      });
    }
  </script>
</body>
</html>`;
  }

  generateBlockPage(result) {
    return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Akses Ditolak</title>
  <style>
    body { font-family: system-ui; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%); }
    .container { background: white; padding: 3rem; border-radius: 1rem; box-shadow: 0 20px 60px rgba(0,0,0,0.3); text-align: center; max-width: 500px; }
    h1 { color: #d32f2f; margin: 0 0 1rem; }
    .icon { font-size: 4rem; margin-bottom: 1rem; }
    p { color: #666; line-height: 1.6; }
    .reason { background: #ffebee; padding: 1rem; border-radius: 0.5rem; margin: 1.5rem 0; font-size: 0.9em; color: #c62828; }
    .footer { font-size: 0.85em; color: #999; margin-top: 2rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">🚫</div>
    <h1>Akses Ditolak</h1>
    <p>Maaf, permintaan Anda telah diblokir oleh sistem keamanan kami.</p>
    
    <div class="reason">
      <strong>Alasan:</strong> Aktivitas mencurigakan terdeteksi<br>
      <strong>Kode:</strong> ${result.score} (${result.layer})
    </div>
    
    <p>Jika Anda yakin ini adalah kesalahan, silakan hubungi administrator website.</p>
    
    <div class="footer">
      Dilindungi oleh Enhanced Anti-Bot Gateway<br>
      Request ID: ${Date.now().toString(36)}
    </div>
  </div>
</body>
</html>`;
  }

  // Verification Handler
  async handleVerification(request, startTime) {
    try {
      const body = await request.json();
      
      // Verify proof-of-work or Turnstile
      if (body.type === 'turnstile') {
        const valid = await this.verifyTurnstile(body.token);
        if (valid) {
          const verifyToken = await this.generateVerifyToken();
          return Response.json({ success: true, verifyToken });
        }
      } else {
        // JS challenge verification
        const valid = this.verifyJSChallenge(body);
        if (valid) {
          const verifyToken = await this.generateVerifyToken();
          // Cache verification
          this.setCacheAsync(`token:${verifyToken}`, 'true', this.config.cacheTime);
          return Response.json({ success: true, token: verifyToken });
        }
      }
      
      return Response.json({ success: false }, { status: 403 });
      
    } catch (error) {
      return Response.json({ success: false, error: 'Invalid request' }, { status: 400 });
    }
  }

  async verifyTurnstile(token) {
    const secretKey = this.env.TURNSTILE_SECRET_KEY;
    if (!secretKey) return false;
    
    try {
      const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: secretKey, response: token })
      });
      
      const data = await response.json();
      return data.success === true;
    } catch {
      return false;
    }
  }

  verifyJSChallenge(body) {
    // Verify browser data integrity
    if (!body.canvas || !body.hardware || body.webdriver === true) {
      return false;
    }
    
    // Verify proof-of-work
    if (!body.nonce || body.nonce > 100000) {
      return false;
    }
    
    // Verify processing time (should take some time)
    if (body.processingTime < 500) {
      return false;
    }
    
    // Verify mouse movements
    if (body.mouseMovements < 1) {
      return false;
    }
    
    return true;
  }

  async generateVerifyToken() {
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    return Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Feedback Handler (for ML training)
  async handleFeedback(request) {
    if (!this.config.mlFeedbackEnabled) {
      return Response.json({ success: false }, { status: 404 });
    }
    
    try {
      const body = await request.json();
      
      // Store feedback for training
      if (this.env.ANALYTICS_DB) {
        await this.env.ANALYTICS_DB.prepare(
          `INSERT INTO feedback (timestamp, fingerprint, score, action, feedback_type, user_report)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(
          new Date().toISOString(),
          body.fingerprint || '',
          body.score || 0,
          body.action || '',
          body.type || 'user_report',
          body.details || ''
        ).run();
      }
      
      return Response.json({ success: true });
    } catch (error) {
      return Response.json({ success: false }, { status: 400 });
    }
  }

  async flagForReview(request, result) {
    if (!this.env.ANALYTICS_DB) return;
    
    try {
      const clientIP = this.getClientIP(request);
      const ipHash = await this.hashIP(clientIP);
      const fingerprint = await this.generateFingerprint(request);
      
      await this.env.ANALYTICS_DB.prepare(
        `INSERT INTO review_queue (timestamp, ip_hash, fingerprint, score, confidence, layers, url, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        new Date().toISOString(),
        ipHash,
        fingerprint,
        result.score,
        result.confidence,
        JSON.stringify(result.layers),
        request.url,
        request.headers.get('User-Agent') || ''
      ).run();
    } catch (error) {
      // Silently fail
    }
  }

  // Telemetry & Logging
  async logTelemetry(request, result, startTime) {
    const processingTime = performance.now() - startTime;
    const clientIP = this.getClientIP(request);
    const ipHash = await this.hashIP(clientIP);
    const fingerprint = await this.generateFingerprint(request);
    
    const telemetry = {
      timestamp: new Date().toISOString(),
      ipHash,
      fingerprint,
      action: result.action,
      score: result.score,
      confidence: result.confidence,
      layers: result.layers,
      processingTime: processingTime.toFixed(2),
      url: request.url,
      method: request.method,
      country: request.cf?.country || '',
      asn: request.cf?.asn || '',
      userAgent: request.headers.get('User-Agent') || ''
    };
    
    // Async logging
    this.ctx.waitUntil(this.writeTelemetry(telemetry));
  }

  async writeTelemetry(telemetry) {
    // Write to Analytics DB
    if (this.env.ANALYTICS_DB) {
      try {
        await this.env.ANALYTICS_DB.prepare(
          `INSERT INTO telemetry 
          (timestamp, ip_hash, fingerprint, action, score, confidence, layers, processing_time, url, method, country, asn, user_agent)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          telemetry.timestamp,
          telemetry.ipHash,
          telemetry.fingerprint,
          telemetry.action,
          telemetry.score,
          telemetry.confidence,
          JSON.stringify(telemetry.layers),
          telemetry.processingTime,
          telemetry.url,
          telemetry.method,
          telemetry.country,
          telemetry.asn,
          telemetry.userAgent
        ).run();
      } catch (error) {
        console.error('Telemetry write failed:', error);
      }
    }
    
    // Also write to KV for real-time access
    if (this.env.KV_TELEMETRY) {
      const logId = `telem_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      await this.env.KV_TELEMETRY.put(logId, JSON.stringify(telemetry), {
        expirationTtl: 86400 // 24 hours
      });
    }
  }

  logBlockAsync(request, result) {
    this.ctx.waitUntil(this.logBlock(request, result));
  }

  async logBlock(request, result) {
    if (!this.env.ANALYTICS_DB) return;
    
    try {
      const clientIP = this.getClientIP(request);
      const ipHash = await this.hashIP(clientIP);
      
      await this.env.ANALYTICS_DB.prepare(
        `INSERT INTO blocks (timestamp, ip_hash, score, confidence, reason, url, user_agent, country)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        new Date().toISOString(),
        ipHash,
        result.score,
        result.confidence || 0,
        result.layer || 'unknown',
        request.url,
        request.headers.get('User-Agent') || '',
        request.cf?.country || ''
      ).run();
    } catch (error) {Session(request) {
    const cookies = request.headers.get('Cookie') || '';
    
    // Check session cookie presence
    const hasSession = cookies.includes('session=') || cookies.includes('_session=');
    
    if (!hasSession && request.method === 'POST') {
      return { suspicious: true, reason: 'no_session_post' };
    }

    // Cookie churn detection (too many session changes)
    const sessionId = this.extractSessionId(cookies);
    if (sessionId) {
      const churnRate = await this.getSessionChurnRate(sessionId);
      if (churnRate > 5) {
        return { suspicious: true, reason: 'high_churn' };
      }
    }

    return { suspicious: false };
  }

  async analyze
