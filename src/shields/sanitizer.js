'use strict';

const DEFAULT_STRIP_FIELDS = [
  'isadmin',
  'role',
  'roles',
  'permissions',
  'isverified',
  'verified',
  'credit',
  'balance',
  'passwordhash',
  'salt'
];

/**
 * Strips sensitive/forbidden keys from an object recursively
 * @param {Object} obj 
 * @param {Object} options 
 * @returns {Object} { sanitized, strippedKeys, wasForbidden }
 */
function sanitizeObject(obj, options = {}) {
  const stripList = (options.stripFields || DEFAULT_STRIP_FIELDS).map(f => String(f).toLowerCase());
  const strippedKeys = [];
  const visited = new WeakSet();

  function clean(target) {
    if (!target || typeof target !== 'object') return target;
    if (visited.has(target)) return target;
    visited.add(target);

    if (Array.isArray(target)) {
      return target.map(item => clean(item));
    }

    const result = {};
    for (const key of Object.keys(target)) {
      const lowerKey = key.toLowerCase();
      const isForbidden = stripList.some(field => {
        if (field.startsWith('*') && field.endsWith('*')) {
          return lowerKey.includes(field.slice(1, -1));
        } else if (field.endsWith('*')) {
          return lowerKey.startsWith(field.slice(0, -1));
        }
        return lowerKey === field;
      });

      if (isForbidden) {
        strippedKeys.push(key);
      } else {
        result[key] = clean(target[key]);
      }
    }
    return result;
  }

  const sanitized = clean(obj);
  return {
    sanitized,
    strippedKeys,
    wasForbidden: strippedKeys.length > 0
  };
}

/**
 * Express / Connect middleware for mass assignment sanitization
 * @param {Object} options
 * @returns {Function} middleware(req, res, next)
 */
function sanitizerFactory(options = {}) {
  const rejectOnForbidden = options.rejectOnForbidden === true;

  return function sanitizerMiddleware(req, res, next) {
    if (req.body && typeof req.body === 'object') {
      const { sanitized, strippedKeys, wasForbidden } = sanitizeObject(req.body, options);
      if (wasForbidden) {
        if (rejectOnForbidden) {
          return res.status(400).json({
            success: false,
            error: 'Forbidden parameter in request body',
            code: 'MASS_ASSIGNMENT_VIOLATION',
            fields: strippedKeys
          });
        }
        req.body = sanitized;
        req.fortifyStrippedKeys = strippedKeys;
      }
    }

    if (req.query && typeof req.query === 'object') {
      const { sanitized, strippedKeys, wasForbidden } = sanitizeObject(req.query, options);
      if (wasForbidden) {
        if (rejectOnForbidden) {
          return res.status(400).json({
            success: false,
            error: 'Forbidden parameter in request query',
            code: 'MASS_ASSIGNMENT_VIOLATION',
            fields: strippedKeys
          });
        }
        req.query = sanitized;
      }
    }

    next();
  };
}

module.exports = {
  sanitizerFactory,
  sanitizeObject,
  DEFAULT_STRIP_FIELDS
};
