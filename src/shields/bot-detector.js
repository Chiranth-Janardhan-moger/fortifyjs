'use strict';

const KNOWN_GOOD_BOTS = [
  'googlebot',
  'bingbot',
  'slurp',
  'duckduckbot',
  'baiduspider'
];

const KNOWN_BAD_BOTS = [
  'scrapy',
  'python-requests',
  'go-http-client',
  'java/',
  'libwww-perl',
  'wget',
  'curl'
];

/**
 * Creates the bot detection shield middleware
 * @param {Object} options - Shield configuration
 * @returns {Function} middleware(req, res, next)
 */
module.exports = function createBotDetectorShield(options = {}) {
  const enabled = options.enabled !== false;
  const allowSearchEngines = options.allowSearchEngines !== false;
  const blockList = options.blockList || KNOWN_BAD_BOTS;
  const allowList = options.allowList || [];
  const action = options.action || 'block'; // 'block' or 'flag'

  return function botDetectorShield(req, res, next) {
    if (!enabled) return next();

    const ua = req.headers['user-agent'] || '';
    const uaLower = ua.toLowerCase();
    
    let isBot = false;
    let botReason = '';

    // 1. Check allow list
    if (ua && allowList.some(b => uaLower.includes(b.toLowerCase()))) {
      return next();
    }

    // 2. Check search engines
    if (ua && allowSearchEngines && KNOWN_GOOD_BOTS.some(b => uaLower.includes(b))) {
      return next();
    }

    // 3. Empty User-Agent
    if (!ua || ua.trim() === '') {
      isBot = true;
      botReason = 'empty-user-agent';
    }
    // 4. Check blocklist
    else if (blockList.some(b => uaLower.includes(b.toLowerCase()))) {
      isBot = true;
      botReason = 'known-bad-bot';
    }
    // 5. Headless browsers
    else if (uaLower.includes('headless') || uaLower.includes('phantomjs') || uaLower.includes('puppeteer')) {
      isBot = true;
      botReason = 'headless-browser';
    }
    // 6. Missing typical browser headers combined with suspicious UA
    else if (!req.headers['accept'] && !req.headers['accept-language'] && !req.headers['accept-encoding']) {
      isBot = true;
      botReason = 'missing-browser-headers';
    }

    if (isBot) {
      req.isBot = true;
      req.botReason = botReason;

      if (action === 'block') {
        const err = new Error('Bot traffic detected');
        err.status = 403;
        err.code = 'EBOTBLOCKED';
        err.reason = botReason;
        return next(err);
      }
    }

    next();
  };
};
