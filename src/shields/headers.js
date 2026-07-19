'use strict';

const DEFAULT_OPTIONS = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"]
    }
  },
  xContentTypeOptions: 'nosniff',
  xFrameOptions: 'DENY',
  xXssProtection: '0',
  hsts: { maxAge: 15552000, includeSubDomains: true },
  referrerPolicy: 'no-referrer',
  permissionsPolicy: 'camera=(), microphone=(), geolocation=()',
  xDnsPrefetchControl: 'off',
  xPermittedCrossDomainPolicies: 'none',
  crossOriginOpenerPolicy: 'same-origin',
  crossOriginResourcePolicy: 'same-origin',
  crossOriginEmbedderPolicy: 'require-corp'
};

function buildCspString(directives) {
  if (!directives || typeof directives !== 'object') return '';
  const parts = [];
  for (const [key, value] of Object.entries(directives)) {
    const directiveName = key.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
    const directiveValue = Array.isArray(value) ? value.join(' ') : value;
    parts.push(`${directiveName} ${directiveValue}`);
  }
  return parts.join('; ');
}

function buildHstsString(options) {
  if (typeof options === 'string') return options;
  let str = `max-age=${options.maxAge || 15552000}`;
  if (options.includeSubDomains) str += '; includeSubDomains';
  if (options.preload) str += '; preload';
  return str;
}

/**
 * Creates the Security Headers shield middleware
 * @param {Object} options - Shield configuration
 * @returns {Function} middleware(req, res, next)
 */
module.exports = function createHeadersShield(options = {}) {
  const config = { ...DEFAULT_OPTIONS, ...options };

  let cspString = '';
  if (config.contentSecurityPolicy !== false) {
    cspString = buildCspString(config.contentSecurityPolicy?.directives || config.contentSecurityPolicy);
  }

  let hstsString = '';
  if (config.hsts !== false) {
    hstsString = buildHstsString(config.hsts);
  }

  return function headersShield(req, res, next) {
    if (config.contentSecurityPolicy !== false && cspString) {
      res.setHeader('Content-Security-Policy', cspString);
    }
    if (config.xContentTypeOptions !== false) {
      res.setHeader('X-Content-Type-Options', config.xContentTypeOptions || DEFAULT_OPTIONS.xContentTypeOptions);
    }
    if (config.xFrameOptions !== false) {
      res.setHeader('X-Frame-Options', config.frameguard || config.xFrameOptions || DEFAULT_OPTIONS.xFrameOptions);
    }
    if (config.xXssProtection !== false) {
      res.setHeader('X-XSS-Protection', config.xXssProtection || DEFAULT_OPTIONS.xXssProtection);
    }
    if (config.hsts !== false && hstsString) {
      res.setHeader('Strict-Transport-Security', hstsString);
    }
    if (config.referrerPolicy !== false) {
      res.setHeader('Referrer-Policy', config.referrerPolicy || DEFAULT_OPTIONS.referrerPolicy);
    }
    if (config.permissionsPolicy !== false) {
      res.setHeader('Permissions-Policy', config.permissionsPolicy || DEFAULT_OPTIONS.permissionsPolicy);
    }
    if (config.xDnsPrefetchControl !== false) {
      res.setHeader('X-DNS-Prefetch-Control', config.xDnsPrefetchControl || DEFAULT_OPTIONS.xDnsPrefetchControl);
    }
    if (config.xPermittedCrossDomainPolicies !== false) {
      res.setHeader('X-Permitted-Cross-Domain-Policies', config.xPermittedCrossDomainPolicies || DEFAULT_OPTIONS.xPermittedCrossDomainPolicies);
    }
    if (config.crossOriginOpenerPolicy !== false) {
      res.setHeader('Cross-Origin-Opener-Policy', config.crossOriginOpenerPolicy || DEFAULT_OPTIONS.crossOriginOpenerPolicy);
    }
    if (config.crossOriginResourcePolicy !== false) {
      res.setHeader('Cross-Origin-Resource-Policy', config.crossOriginResourcePolicy || DEFAULT_OPTIONS.crossOriginResourcePolicy);
    }
    if (config.crossOriginEmbedderPolicy !== false) {
      res.setHeader('Cross-Origin-Embedder-Policy', config.crossOriginEmbedderPolicy || DEFAULT_OPTIONS.crossOriginEmbedderPolicy);
    }

    next();
  };
};
