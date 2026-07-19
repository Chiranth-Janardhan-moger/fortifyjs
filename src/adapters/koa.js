'use strict';

const { shield } = require('../presets');

/**
 * Koa middleware for fortifyjs
 * @param {Object} options 
 * @returns {Function}
 */
function koaMiddleware(options = {}) {
  const middlewareStack = shield(options.tier || 'basic', options);

  return async function(ctx, next) {
    // Mimic the req/res interface for our middleware
    const req = ctx.req;
    const res = ctx.res;

    // Polyfill properties
    req.ip = ctx.ip;
    req.path = ctx.path;
    req.query = ctx.query;
    req.body = ctx.request.body || {};
    req.cookies = {}; // Koa uses ctx.cookies.get(), but we can do a simple parse of headers
    if (ctx.headers.cookie) {
      ctx.headers.cookie.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        req.cookies[parts.shift().trim()] = decodeURI(parts.join('='));
      });
    }

    // Override res methods used by middleware
    const originalEnd = res.end;
    let blocked = false;

    res.status = function(code) {
      ctx.status = code;
      return res;
    };
    res.send = function(body) {
      ctx.body = body;
      blocked = true;
    };
    res.json = function(body) {
      ctx.body = body;
      blocked = true;
    };

    return new Promise((resolve, reject) => {
      middlewareStack(req, res, (err) => {
        if (err) return reject(err);
        if (blocked) return resolve();
        resolve(next());
      });
    });
  };
}

module.exports = { koaMiddleware };
