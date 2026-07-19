'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOG_LEVELS = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4
};

class Logger {
  constructor(options = {}) {
    this.level = LOG_LEVELS[options.level || 'info'];
    this.format = options.format || 'json'; // json, text
    this.maxLogs = options.maxLogs || 500;
    this.transport = options.transport || null;
    
    // Rate limiting: max N logs per second
    this.rateLimit = options.rateLimit || { max: 100, windowMs: 1000 };
    this.logCounts = new Map();

    this.inMemoryLogs = [];
  }

  _checkRateLimit(category) {
    const now = Date.now();
    const windowStart = now - this.rateLimit.windowMs;
    
    // Cleanup old entries
    for (const [key, data] of this.logCounts.entries()) {
      if (data.timestamp < windowStart) {
        this.logCounts.delete(key);
      }
    }

    let record = this.logCounts.get(category);
    if (!record) {
      record = { count: 0, timestamp: now };
      this.logCounts.set(category, record);
    } else if (record.timestamp < windowStart) {
      record.count = 0;
      record.timestamp = now;
    }

    record.count++;
    return record.count <= this.rateLimit.max;
  }

  log(levelName, message, meta = {}) {
    const levelVal = LOG_LEVELS[levelName];
    if (this.level < levelVal || this.level === 0) return;

    if (!this._checkRateLimit('global')) {
      return; // Rate limited
    }

    const event = {
      timestamp: new Date().toISOString(),
      id: crypto.randomBytes(8).toString('hex'),
      level: levelName,
      message,
      ...meta
    };

    this.inMemoryLogs.unshift(event);
    if (this.inMemoryLogs.length > this.maxLogs) {
      this.inMemoryLogs.pop();
    }

    if (this.transport && typeof this.transport === 'function') {
      try {
        this.transport(event);
      } catch (e) {
        // ignore transport errors
      }
    } else if (!this.transport && this.format === 'json') {
      if (levelName === 'error') {
        console.error(JSON.stringify(event));
      } else if (levelName === 'warn') {
        console.warn(JSON.stringify(event));
      } else {
        console.log(JSON.stringify(event));
      }
    } else if (!this.transport && this.format === 'text') {
      const msg = `[${event.timestamp}] ${levelName.toUpperCase()}: ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
      if (levelName === 'error') console.error(msg);
      else if (levelName === 'warn') console.warn(msg);
      else console.log(msg);
    }
  }

  error(message, meta) { this.log('error', message, meta); }
  warn(message, meta) { this.log('warn', message, meta); }
  info(message, meta) { this.log('info', message, meta); }
  debug(message, meta) { this.log('debug', message, meta); }

  getLogs(limit = 100) {
    return this.inMemoryLogs.slice(0, limit);
  }

  clearLogs() {
    this.inMemoryLogs = [];
  }
}

module.exports = { Logger };
