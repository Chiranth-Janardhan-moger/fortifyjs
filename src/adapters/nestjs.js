'use strict';
const { expressMiddleware } = require('./express');
function nestjsMiddleware(options = {}) {
  return expressMiddleware(options);
}

function createNestMiddleware(options = {}) {
  const middleware = nestjsMiddleware(options);
  return class fortifyjsNestMiddleware {
    use(req, res, next) {
      return middleware(req, res, next);
    }
  };
}
module.exports = { nestjsMiddleware, createNestMiddleware };
