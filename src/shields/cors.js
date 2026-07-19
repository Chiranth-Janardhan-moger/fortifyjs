'use strict';

/**
 * Creates the CORS engine shield middleware
 * @param {Object} options - Shield configuration
 * @returns {Function} middleware(req, res, next)
 */
module.exports = function createCorsShield(options = {}) {
  const allowOrigin = options.origin || '*';
  const allowMethods = options.methods || 'GET,HEAD,PUT,PATCH,POST,DELETE';
  const allowedHeaders = options.allowedHeaders;
  const exposedHeaders = options.exposedHeaders;
  const credentials = options.credentials || false;
  const maxAge = options.maxAge;

  if (credentials === true && allowOrigin === '*') {
    throw new Error('CORS: Cannot use credentials=true with origin="*"');
  }

  function handleOrigin(reqOrigin, originConfig, cb) {
    if (typeof originConfig === 'function') {
      originConfig(reqOrigin, cb);
    } else if (Array.isArray(originConfig)) {
      cb(null, originConfig.includes(reqOrigin) ? reqOrigin : false);
    } else if (originConfig === '*') {
      cb(null, '*');
    } else if (typeof originConfig === 'string') {
      cb(null, originConfig === reqOrigin ? reqOrigin : false);
    } else if (originConfig instanceof RegExp) {
      cb(null, originConfig.test(reqOrigin) ? reqOrigin : false);
    } else {
      cb(null, false);
    }
  }

  return function corsShield(req, res, next) {
    const origin = req.headers.origin;

    // Set Vary header for dynamic origin
    if (allowOrigin !== '*') {
      res.setHeader('Vary', 'Origin');
    }

    if (!origin) {
      return next(); // Not a CORS request
    }

    handleOrigin(origin, allowOrigin, (err, matchedOrigin) => {
      if (err) return next(err);

      if (!matchedOrigin) {
        if (req.method === 'OPTIONS') {
          res.statusCode = 204;
          return res.end();
        }
        return next();
      }

      res.setHeader('Access-Control-Allow-Origin', matchedOrigin);

      if (credentials) {
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }

      if (exposedHeaders) {
        const exposed = Array.isArray(exposedHeaders) ? exposedHeaders.join(',') : exposedHeaders;
        res.setHeader('Access-Control-Expose-Headers', exposed);
      }

      if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Methods', Array.isArray(allowMethods) ? allowMethods.join(',') : allowMethods);
        
        let requestHeaders = allowedHeaders;
        if (!requestHeaders && req.headers['access-control-request-headers']) {
          requestHeaders = req.headers['access-control-request-headers'];
        }
        
        if (requestHeaders) {
          const headersStr = Array.isArray(requestHeaders) ? requestHeaders.join(',') : requestHeaders;
          res.setHeader('Access-Control-Allow-Headers', headersStr);
        }

        if (maxAge !== undefined) {
          res.setHeader('Access-Control-Max-Age', maxAge.toString());
        }

        res.statusCode = 204;
        res.setHeader('Content-Length', '0');
        return res.end();
      }

      next();
    });
  };
};
