'use strict';
const { MemoryStore } = require('./store');

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
  const keyGenerator = options.keyGenerator || (req => req.ip || (req.connection && req.connection.remoteAddress) || (req.socket && req.socket.remoteAddress) || '127.0.0.1');
  const standardHeaders = options.standardHeaders !== false;
  const customStore = options.store;
  const memoryStore = customStore || new MemoryStore({ cleanupIntervalMs: windowMs });
  const localLimiter = new IPRateLimiter(windowMs, 10000, max + 1000);
  
  return async function rateLimitMiddleware(req, res, next) {
    const key = keyGenerator(req);
    
    if (customStore) {
      try {
        const { count, resetTime } = await customStore.increment(key, windowMs);
        const remaining = Math.max(0, max - count);
        
        if (standardHeaders && res.setHeader) {
          res.setHeader('RateLimit-Limit', max);
          res.setHeader('RateLimit-Remaining', remaining);
          res.setHeader('RateLimit-Reset', Math.ceil(resetTime / 1000));
        }

        if (count > max) {
          if (typeof options.handler === 'function') {
            return options.handler(req, res, next, options);
          }
          if (res.status && res.json) {
            return res.status(429).json({ error: 'Too many requests', retryAfter: Math.ceil((resetTime - Date.now()) / 1000) });
          } else {
            res.statusCode = 429;
            return res.end(JSON.stringify({ error: 'Too many requests' }));
          }
        }
        return next();
      } catch (err) {
        // Fail open if store fails, or proceed with fallback
      }
    }

    // Default synchronous in-memory tracking
    const currentHits = localLimiter.recordSuspicious(key);
    const remaining = Math.max(0, max - currentHits);
    
    if (standardHeaders && res.setHeader) {
      res.setHeader('RateLimit-Limit', max);
      res.setHeader('RateLimit-Remaining', remaining);
    }
    
    if (currentHits > max) {
      if (typeof options.handler === 'function') {
        return options.handler(req, res, next, options);
      }
      if (res.status && res.json) {
        return res.status(429).json({ error: 'Too many requests' });
      } else {
        res.statusCode = 429;
        return res.end(JSON.stringify({ error: 'Too many requests' }));
      }
    }
    next();
  };
}

module.exports = { IPRateLimiter, rateLimiterFactory, MemoryStore };
