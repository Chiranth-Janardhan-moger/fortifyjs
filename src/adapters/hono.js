'use strict';

const { shield } = require('../presets');

/**
 * Hono middleware for fortifyjs
 * @param {Object} options 
 * @returns {Function}
 */
function honoMiddleware(options = {}) {
  const middlewareStack = shield(options.tier || 'basic', options);

  return async (c, next) => {
    // Create an express-like mock object for the request
    const req = {
      ip: c.env?.remoteAddress || '127.0.0.1',
      path: c.req.path,
      method: c.req.method,
      query: c.req.query(),
      headers: c.req.header(),
      body: {}, // We'll try to parse JSON if applicable
      cookies: {}
    };

    // Parse cookies from headers
    if (req.headers.cookie) {
      req.headers.cookie.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        req.cookies[parts.shift().trim()] = decodeURI(parts.join('='));
      });
    }

    // Try to safely parse body
    if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
      try {
        req.body = await c.req.json();
      } catch (e) {
        // ignore
      }
    }

    let blockedResponse = null;

    // Create a mock response object
    const res = {
      statusCode: 200,
      headers: {},
      setHeader(key, value) {
        this.headers[key.toLowerCase()] = value;
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      send(body) {
        blockedResponse = c.body(body, this.statusCode, this.headers);
      },
      json(body) {
        this.headers['content-type'] = 'application/json';
        blockedResponse = c.json(body, this.statusCode, this.headers);
      }
    };

    return new Promise((resolve, reject) => {
      middlewareStack(req, res, async (err) => {
        if (err) return reject(err);
        if (blockedResponse) return resolve(blockedResponse);
        
        // Pass to next Hono middleware
        await next();
        resolve();
      });
    });
  };
}

module.exports = { honoMiddleware };
