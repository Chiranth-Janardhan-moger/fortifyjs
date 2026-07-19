'use strict';
class IPRateLimiter {
  constructor(windowMs = 300000, maxCapacity = 10000, maxEventsPerKey = 1000) {
    this.windowMs = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 300000;
    this.maxCapacity = Number.isFinite(maxCapacity) && maxCapacity > 0 ? maxCapacity : 10000;
    this.maxEventsPerKey = Number.isFinite(maxEventsPerKey) && maxEventsPerKey > 0 ? maxEventsPerKey : 1000;
    this.ips = new Map();
  }

  pruneExpired(now) {
    for (const [ip, timestamps] of this.ips) {
      const validTimestamps = timestamps.filter(t => now - t < this.windowMs);
      if (validTimestamps.length === 0) {
        this.ips.delete(ip);
      } else {
        this.ips.set(ip, validTimestamps);
      }
    }
  }
  
  recordSuspicious(ip) {
    const now = Date.now();
    if (!this.ips.has(ip)) {
      if (this.ips.size >= this.maxCapacity) {
        this.pruneExpired(now);
      }
      if (this.ips.size >= this.maxCapacity) {
        this.ips.delete(this.ips.keys().next().value);
      }
      this.ips.set(ip, []);
    }
    const timestamps = this.ips.get(ip);
    
    // Cleanup old timestamps for this IP
    const validTimestamps = timestamps.filter(t => now - t < this.windowMs);
    validTimestamps.push(now);
    if (validTimestamps.length > this.maxEventsPerKey) {
      validTimestamps.splice(0, validTimestamps.length - this.maxEventsPerKey);
    }
    this.ips.delete(ip);
    this.ips.set(ip, validTimestamps);
    return validTimestamps.length;
  }

}

function rateLimiterFactory(options = {}) {
  const windowMs = options.windowMs || 15 * 60 * 1000;
  const max = options.max || 100;
  const limiter = new IPRateLimiter(windowMs, 10000, max);
  
  return function rateLimitMiddleware(req, res, next) {
    const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
    const currentHits = limiter.recordSuspicious(ip);
    
    if (currentHits >= max) {
      if (res.status && res.json) {
        res.status(429).json({ error: 'Too many requests' });
      } else {
        // Fallback for non-Express adapters if needed
        res.statusCode = 429;
        res.end(JSON.stringify({ error: 'Too many requests' }));
      }
      return;
    }
    next();
  };
}

module.exports = { IPRateLimiter, rateLimiterFactory };
