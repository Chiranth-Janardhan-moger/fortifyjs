'use strict';

const { DetectionEngine } = require('../core/engine');

/**
 * Creates a Next.js middleware and API route wrapper for FortifyJS.
 * 
 * @param {Object} options - FortifyJS configuration options
 * @returns {Object} { middleware, withFortify }
 */
function nextjsAdapter(options = {}) {
  const engine = new DetectionEngine(options);

  // 1. Next.js Middleware (Edge Runtime compatible)
  // Usage: export const middleware = fortify.middleware;
  const middleware = async (request) => {
    // NextRequest uses standard Web Request API
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Scan Path
    let result = engine.detect(path, { source: 'path' });
    if (result.label !== 'benign' && result.label !== 'anomaly') {
      return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }

    // Scan Query Params
    for (const [key, value] of url.searchParams.entries()) {
      result = engine.detect(value, { source: 'query' });
      if (result.label !== 'benign' && result.label !== 'anomaly') {
        return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Scan Headers (excluding safe/standard headers to save time/false positives)
    const safeHeaders = ['host', 'connection', 'accept', 'accept-encoding', 'content-length'];
    for (const [key, value] of request.headers.entries()) {
      if (!safeHeaders.includes(key.toLowerCase())) {
        result = engine.detect(value, { source: 'header' });
        if (result.label !== 'benign' && result.label !== 'anomaly') {
          return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }
      }
    }

    // We don't read the body in middleware by default as it consumes the stream,
    // which breaks subsequent route handlers. Body scanning is handled in API routes.

    return null; // Signals Next.js to continue to the next middleware/route
  };

  // 2. Next.js API Route Wrapper (Pages Router)
  // Usage: export default fortify.withFortify(async (req, res) => { ... })
  const withFortify = (handler) => {
    return async (req, res) => {
      // Check query
      if (req.query) {
        for (const key in req.query) {
          const value = req.query[key];
          const valStr = typeof value === 'string' ? value : JSON.stringify(value);
          const result = engine.detect(valStr, { source: 'query' });
          if (result.label !== 'benign' && result.label !== 'anomaly') {
            return res.status(403).json({ error: 'Forbidden' });
          }
        }
      }

      // Check body
      if (req.body) {
        const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        const result = engine.detect(bodyStr, { source: 'body' });
        if (result.label !== 'benign' && result.label !== 'anomaly') {
          return res.status(403).json({ error: 'Forbidden' });
        }
      }

      return handler(req, res);
    };
  };

  return { middleware, withFortify, engine };
}

module.exports = nextjsAdapter;
