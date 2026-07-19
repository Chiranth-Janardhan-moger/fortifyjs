'use strict';

const crypto = require('crypto');

/**
 * Creates the CSRF protection shield middleware
 * @param {Object} options - Shield configuration
 * @returns {Function} middleware(req, res, next)
 */
module.exports = function createCsrfShield(options = {}) {
  const secret = options.secret || crypto.randomBytes(32).toString('hex');
  if (!options.secret) {
    console.warn('fortifyjs: CSRF secret not provided. A random secret was generated, but it will not persist across restarts.');
  }

  const cookieName = options.cookieName || '_fortify_csrf';
  const headerName = options.headerName || 'x-csrf-token';
  const bodyField = options.bodyField || '_csrf';
  const sameSite = options.sameSite || 'Lax';
  const secure = options.secure !== undefined ? options.secure : process.env.NODE_ENV === 'production';
  const ignoreMethods = options.ignoreMethods || ['GET', 'HEAD', 'OPTIONS'];
  const ignoreRoutes = options.ignoreRoutes || [];

  function signToken(token) {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(token);
    return `${token}.${hmac.digest('hex')}`;
  }

  function verifyToken(signedToken) {
    if (!signedToken || typeof signedToken !== 'string') return false;
    const parts = signedToken.split('.');
    if (parts.length !== 2) return false;
    const [token, signature] = parts;
    const expectedSigned = signToken(token);
    if (expectedSigned.length !== signedToken.length) return false;
    return crypto.timingSafeEqual(Buffer.from(expectedSigned), Buffer.from(signedToken));
  }

  function matchRoute(path, patterns) {
    for (const pattern of patterns) {
      if (pattern.endsWith('/*')) {
        const prefix = pattern.slice(0, -2);
        if (path.startsWith(prefix)) return true;
      } else if (path === pattern) {
        return true;
      }
    }
    return false;
  }

  return function csrfShield(req, res, next) {
    // Basic route ignore (e.g. webhooks)
    if (ignoreRoutes.length > 0 && req.path && matchRoute(req.path, ignoreRoutes)) {
      return next();
    }

    // Parse cookies if not already parsed
    // We assume cookie-parser might not be present, so we do basic parsing
    let cookies = req.cookies || {};
    if (!req.cookies && req.headers.cookie) {
      cookies = Object.fromEntries(
        req.headers.cookie.split('; ').map(c => c.split('='))
      );
    }

    const currentSignedToken = cookies[cookieName];

    // Expose csrfToken generator for views
    req.csrfToken = function() {
      const newToken = crypto.randomBytes(16).toString('hex');
      const newSignedToken = signToken(newToken);
      
      let cookieHeader = `${cookieName}=${newSignedToken}; Path=/; HttpOnly; SameSite=${sameSite}`;
      if (secure) cookieHeader += '; Secure';
      
      res.setHeader('Set-Cookie', cookieHeader);
      return newSignedToken;
    };

    // If method is safe, we don't enforce, just optionally generate/refresh token if missing
    if (ignoreMethods.includes(req.method)) {
      if (!currentSignedToken) {
        req.csrfToken(); // trigger generation
      }
      return next();
    }

    // Mutation method: Enforce token
    let incomingToken = null;
    
    // Check header
    if (req.headers[headerName.toLowerCase()]) {
      incomingToken = req.headers[headerName.toLowerCase()];
    } else if (req.headers['x-xsrf-token']) {
      incomingToken = req.headers['x-xsrf-token'];
    }
    
    // Check body
    if (!incomingToken && req.body && typeof req.body === 'object') {
      incomingToken = req.body[bodyField];
    }

    if (!incomingToken) {
      const err = new Error('CSRF token missing');
      err.status = 403;
      err.code = 'EBADCSRFTOKEN';
      return next(err);
    }

    if (!currentSignedToken || currentSignedToken !== incomingToken || !verifyToken(incomingToken)) {
      const err = new Error('CSRF token invalid');
      err.status = 403;
      err.code = 'EBADCSRFTOKEN';
      return next(err);
    }

    next();
  };
};
