'use strict';

const { shield } = require('../presets');

/**
 * Generic Node.js http.Server adapter
 * @param {Object} options 
 * @returns {Function} (req, res, next)
 */
function genericAdapter(options = {}) {
  // Directly returns the standard connect-style middleware (req, res, next)
  return shield(options.tier || 'basic', options);
}

module.exports = { genericAdapter };
