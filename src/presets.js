'use strict';

const { DetectionEngine } = require('./core/engine');
const { expressMiddleware } = require('./adapters/express');
const { Logger } = require('./logger');

const PRESETS = {
  basic: {
    level: 'balanced',
    headers: true,
    rateLimit: { max: 100, windowMs: 15 * 60 * 1000 },
    cors: { origin: 'same-origin' },
    csrf: false,
    botDetection: { enabled: true, action: 'flag' },
    behavioral: { enabled: true, entropyOnly: true },
    dashboard: false,
    logging: { level: 'info', format: 'text' }
  },
  medium: {
    level: 'balanced',
    headers: true,
    rateLimit: { max: 200, windowMs: 15 * 60 * 1000 },
    cors: { origin: 'same-origin' }, // user overrides this typically
    csrf: false,
    botDetection: { enabled: true, action: 'block', blockList: ['scrapy', 'python-requests'] },
    behavioral: { enabled: true },
    fileUpload: { enabled: true },
    dashboard: false,
    logging: { level: 'warn', format: 'json' }
  },
  hard: {
    level: 'strict',
    headers: true,
    rateLimit: { max: 100, windowMs: 15 * 60 * 1000 },
    cors: { origin: 'same-origin' },
    csrf: { cookieName: '_fortify_csrf' },
    botDetection: { enabled: true, action: 'block' },
    behavioral: { enabled: true, learningRequests: 5000 },
    adaptive: { enabled: true },
    fileUpload: { enabled: true },
    dashboard: { enabled: false }, // available but off by default
    logging: { level: 'warn', format: 'json' }
  },
  advanced: {
    level: 'strict',
    headers: true,
    rateLimit: { max: 100, windowMs: 15 * 60 * 1000 },
    cors: { origin: 'same-origin' },
    csrf: { cookieName: '_fortify_csrf' },
    botDetection: { enabled: true, action: 'block' },
    behavioral: { enabled: true, learningRequests: 5000 },
    adaptive: { enabled: true },
    fileUpload: { enabled: true, scanFilenameForInjection: true },
    dashboard: { enabled: true, path: '/admin/security' },
    logging: { level: 'debug', format: 'json' }
  }
};

function isObject(item) {
  return (item && typeof item === 'object' && !Array.isArray(item));
}

function deepMerge(target, source) {
  let output = Object.assign({}, target);
  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach(key => {
      if (isObject(source[key])) {
        if (!(key in target)) Object.assign(output, { [key]: source[key] });
        else output[key] = deepMerge(target[key], source[key]);
      } else {
        Object.assign(output, { [key]: source[key] });
      }
    });
  }
  return output;
}

/**
 * Main factory for fortifyjs middleware
 * @param {string|Object} tier 
 * @param {Object} overrides 
 * @returns {Function} Express middleware stack
 */
function shield(tier = 'basic', overrides = {}) {
  if (typeof tier === 'object') {
    overrides = tier;
    tier = 'basic';
  }

  const preset = PRESETS[tier];
  if (!preset) {
    throw new Error(`Unknown tier: "${tier}". Use: basic, medium, hard, advanced`);
  }

  const config = deepMerge(preset, overrides);
  
  // Create shared logger
  const loggerOptions = typeof config.logging === 'object' ? config.logging : {};
  const logger = new Logger(loggerOptions);

  // Load shields (lazy load to avoid circular deps if needed)
  const { rateLimiterFactory } = require('./shields/rate-limiter');
  const headersFactory = require('./shields/headers');
  const corsFactory = require('./shields/cors');
  const csrfFactory = require('./shields/csrf');
  const botFactory = require('./shields/bot-detector');
  const { fileUploadShieldFactory } = require('./shields/file-upload');
  const dashboardFactory = require('./dashboard/handler').createDashboardHandler;
  const { AdaptiveBlocker } = require('./analyzers/adaptive');

  // Build the stack
  const stack = [];

  if (config.rateLimit) {
    stack.push(rateLimiterFactory(typeof config.rateLimit === 'object' ? config.rateLimit : {}));
  }

  if (config.headers) {
    stack.push(headersFactory(typeof config.headers === 'object' ? config.headers : {}));
  }

  if (config.cors) {
    stack.push(corsFactory(typeof config.cors === 'object' ? config.cors : {}));
  }

  if (config.csrf) {
    stack.push(csrfFactory(typeof config.csrf === 'object' ? config.csrf : {}));
  }

  if (config.botDetection && config.botDetection.enabled) {
    stack.push(botFactory(config.botDetection));
  }

  if (config.adaptive && config.adaptive.enabled) {
    const adaptiveBlocker = new AdaptiveBlocker(typeof config.adaptive === 'object' ? config.adaptive : {});
    stack.push(adaptiveBlocker.middleware());
  }

  if (config.fileUpload && config.fileUpload.enabled) {
    stack.push(fileUploadShieldFactory(config.fileUpload));
  }

  if (config.dashboard && config.dashboard.enabled) {
    stack.push(dashboardFactory(config.dashboard, logger));
  }

  if (config.sanitize) {
    const { sanitizerFactory } = require('./shields/sanitizer');
    stack.push(sanitizerFactory(typeof config.sanitize === 'object' ? config.sanitize : {}));
  }

  // Build detector
  const detectorOptions = {
    level: config.level,
    behavioral: config.behavioral,
    onBlocked: config.onBlocked,
    allowRoutes: config.allowRoutes,
    allowParams: config.allowParams,
    routeLevels: config.routeLevels,
    whitelist: config.whitelist,
    mode: config.mode
  };
  
  // Note: We use expressMiddleware factory here
  // For other frameworks, this `shield()` factory would need to return the respective adapter's composition
  // To keep it simple for v1, `shield()` returns Express middleware, and Fastify users use `fastifyPlugin` directly
  
  const detectorMiddleware = expressMiddleware({
    ...detectorOptions,
    logAttacks: (msg, evt) => logger.warn(msg, { meta: evt })
  });
  
  stack.push(detectorMiddleware);

  return function fortifyjsStack(req, res, next) {
    if (config.allowRoutes && Array.isArray(config.allowRoutes)) {
      const pathname = req.path || (req.url ? req.url.split('?')[0] : '');
      if (config.allowRoutes.includes(pathname)) {
        return next();
      }
    }

    let index = 0;
    function runNext(err) {
      if (err) return next(err);
      if (index >= stack.length) return next();
      const middleware = stack[index++];
      try {
        const result = middleware(req, res, runNext);
        if (result && typeof result.catch === 'function') {
          result.catch(next);
        }
      } catch (e) {
        next(e);
      }
    }
    runNext();
  };
}

module.exports = { shield, PRESETS };