const request = require('supertest');
const express = require('express');
const { shield } = require('../src/presets');

describe('Shield Integration Tests', () => {
  const createServer = (tier = 'basic', overrides = {}) => {
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    // A cookie parser might be needed for CSRF, but let's see if fortifyjs handles it or expects it.
    // For simplicity, we just pass the headers.
    
    app.use(shield(tier, overrides));
    
    app.all('/test', (req, res) => {
      res.status(200).send('OK');
    });
    
    return app;
  };

  describe('1. Basic Tier - Benign Request', () => {
    it('should allow benign request and call next()', async () => {
      const app = createServer('basic');
      const res = await request(app).get('/test');
      expect(res.status).toBe(200);
      expect(res.text).toBe('OK');
    });
  });

  describe('2. Medium Tier - SQLi Detection', () => {
    it('should block SQLi in query with 403', async () => {
      const app = createServer('medium');
      const res = await request(app)
        .get('/test')
        .query({ id: "1' OR '1'='1" });
      expect(res.status).toBe(403);
    });
  });

  describe('3. Hard Tier - CSRF', () => {
    it('should block missing CSRF token on POST', async () => {
      const app = createServer('hard');
      // POST without CSRF token
      const res = await request(app)
        .post('/test')
        .send({ data: 'test' });
      expect(res.status).toBe(403);
    });
  });

  describe('4. Advanced Tier - Behavioral', () => {
    it('should block suspicious behavioral patterns', async () => {
      const app = createServer('advanced');
      
      // Simulate suspicious behavior (e.g., rapid changing User-Agents, or specific attacks that trigger behavioral scoring)
      // Usually fortifyjs behavioral blocks if multiple suspicious things happen.
      // Let's send a payload that is marginally suspicious multiple times, or something that triggers it.
      // Wait, behavioral might need some state across requests.
      // Or we can just send something very suspicious but not explicitly a hard signature.
      // Another way: many 404s or error patterns, but let's try a weird request.
      // For now, let's just trigger a known behavioral block, like an unusual payload.
      
      const res = await request(app)
        .post('/test')
        .set('User-Agent', 'curl/7.68.0') // Command line agent
        .set('Accept', '*/*')
        .send({ "something": "../../../etc/passwd\u0000" }); // Combining path traversal and null byte
        
      expect(res.status).toBe(403);
    });
  });

  describe('5. Rate Limiting on Tiers', () => {
    const tiers = ['basic', 'medium', 'hard', 'advanced'];
    tiers.forEach(tier => {
      it(`should rate limit after threshold in ${tier} tier`, async () => {
        const app = createServer(tier, {
          rateLimit: { max: 2, windowMs: 60000 }
        });
        
        await request(app).get('/test');
        await request(app).get('/test');
        const res = await request(app).get('/test');
        
        expect(res.status).toBe(429); // Too Many Requests
      });
    });
  });

  describe('6. CORS Preflight', () => {
    it('should handle OPTIONS request before detection', async () => {
      const app = createServer('basic', {
        cors: { origin: 'https://example.com' }
      });
      
      // Options should return 204 or 200 without checking payload
      const res = await request(app)
        .options('/test')
        .set('Origin', 'https://example.com')
        .set('Access-Control-Request-Method', 'POST');
        
      expect(res.status).toBe(204);
      expect(res.headers['access-control-allow-origin']).toBe('https://example.com');
    });
  });

  describe('7. Security Headers', () => {
    it('should set all 12 security headers', async () => {
      const app = createServer('basic');
      const res = await request(app).get('/test');
      
      expect(res.headers).toHaveProperty('content-security-policy');
      expect(res.headers).toHaveProperty('x-content-type-options');
      expect(res.headers).toHaveProperty('x-frame-options');
      expect(res.headers).toHaveProperty('x-xss-protection');
      expect(res.headers).toHaveProperty('strict-transport-security');
      expect(res.headers).toHaveProperty('referrer-policy');
      expect(res.headers).toHaveProperty('permissions-policy');
      expect(res.headers).toHaveProperty('x-dns-prefetch-control');
      expect(res.headers).toHaveProperty('x-permitted-cross-domain-policies');
      expect(res.headers).toHaveProperty('cross-origin-opener-policy');
      expect(res.headers).toHaveProperty('cross-origin-resource-policy');
      expect(res.headers).toHaveProperty('cross-origin-embedder-policy');
    });
  });

  describe('8. Bot Detector', () => {
    it('should block known bot user agents', async () => {
      const app = createServer('medium'); // medium tier blocks bots
      
      const res = await request(app)
        .get('/test')
        .set('User-Agent', 'scrapy'); // scrapy is in the medium preset blockList
        
      expect(res.status).toBe(403);
    });
  });

  describe('9. Shield Interference (Order-dependent bugs)', () => {
    it('should not let bot detector bypass detection', async () => {
      const app = createServer('medium');
      // If a request is not a bot but has SQLi, it should still be blocked.
      const res = await request(app)
        .get('/test')
        .set('User-Agent', 'Mozilla/5.0')
        .query({ id: "1' OR '1'='1" });
        
      expect(res.status).toBe(403);
    });
  });

  describe('10. Disabling Individual Shields via Options', () => {
    it('should allow POST when csrf is false in hard tier', async () => {
      const app = createServer('hard', { csrf: false });
      
      const res = await request(app)
        .post('/test')
        .set('User-Agent', 'Mozilla/5.0')
        .send({ data: 'test' });
        
      // Expect 200 because CSRF is disabled
      if (res.status !== 200) {
        console.error('Unexpected 403 Response:', res.body, res.text, res.headers);
      }
      expect(res.status).toBe(200);
    });
  });
});
