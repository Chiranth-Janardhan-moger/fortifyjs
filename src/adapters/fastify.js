'use strict';

const { shield } = require('../presets');

/**
 * Fastify plugin for fortifyjs
 * @param {Object} fastify 
 * @param {Object} options 
 * @param {Function} done 
 */
function fastifyPlugin(fastify, options, done) {
  // We use the shield factory to get an Express-style middleware stack
  // Fastify can consume Express middleware using @fastify/middie or fastify-express,
  // but since we want zero dependencies, we will wrap the Express middleware pattern manually.
  
  const middlewareStack = shield(options.tier || 'basic', options);

  fastify.addHook('onRequest', (request, reply, next) => {
    // Mimic the req/res interface for our middleware
    const req = request.raw;
    const res = reply.raw;
    
    // Polyfill properties that Express adds which our shields might expect
    req.ip = request.ip;
    req.path = request.routeOptions.url || request.raw.url.split('?')[0];
    req.query = request.query || {};
    req.body = request.body || {};
    req.cookies = request.cookies || {};
    req.params = request.params || {};

    // For sending responses from middleware (e.g., blocking)
    const originalSend = res.end;
    res.status = function(code) {
      reply.code(code);
      return res;
    };
    res.send = function(body) {
      reply.send(body);
    };
    res.json = function(body) {
      reply.send(body);
    };

    middlewareStack(req, res, (err) => {
      if (err) return next(err);
      next();
    });
  });

  done();
}

// Support fastify-plugin syntax
fastifyPlugin[Symbol.for('skip-override')] = true;

module.exports = fastifyPlugin;
