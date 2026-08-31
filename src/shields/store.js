'use strict';

/**
 * Base Store contract for distributed rate limiting & state storage.
 */
class BaseStore {
  async get(key) { throw new Error('Not implemented'); }
  async set(key, value, ttlMs) { throw new Error('Not implemented'); }
  async increment(key, ttlMs) { throw new Error('Not implemented'); }
  async delete(key) { throw new Error('Not implemented'); }
  async clear() { throw new Error('Not implemented'); }
}

/**
 * High-performance, zero-dependency in-memory store with TTL and bounded capacity.
 */
class MemoryStore extends BaseStore {
  constructor(options = {}) {
    super();
    this.maxEntries = options.maxEntries || 10000;
    this.entries = new Map();
    this.cleanupIntervalMs = options.cleanupIntervalMs || 60000;
    
    // Background garbage collection
    this.timer = setInterval(() => this.purgeExpired(), this.cleanupIntervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  purgeExpired() {
    const now = Date.now();
    for (const [key, record] of this.entries.entries()) {
      if (record.expiresAt && record.expiresAt <= now) {
        this.entries.delete(key);
      }
    }
  }

  async get(key) {
    const record = this.entries.get(key);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return null;
    }
    return record.value;
  }

  async set(key, value, ttlMs = 60000) {
    // If at capacity, evict oldest entry
    if (this.entries.size >= this.maxEntries && !this.entries.has(key)) {
      const firstKey = this.entries.keys().next().value;
      if (firstKey !== undefined) this.entries.delete(firstKey);
    }

    const expiresAt = ttlMs ? Date.now() + ttlMs : null;
    this.entries.set(key, { value, expiresAt });
    return true;
  }

  async increment(key, ttlMs = 60000) {
    const now = Date.now();
    let record = this.entries.get(key);

    if (!record || (record.expiresAt && record.expiresAt <= now)) {
      if (this.entries.size >= this.maxEntries && !this.entries.has(key)) {
        const firstKey = this.entries.keys().next().value;
        if (firstKey !== undefined) this.entries.delete(firstKey);
      }
      record = { value: 1, expiresAt: now + ttlMs };
      this.entries.set(key, record);
      return { count: 1, resetTime: record.expiresAt };
    }

    record.value += 1;
    return { count: record.value, resetTime: record.expiresAt };
  }

  async delete(key) {
    return this.entries.delete(key);
  }

  async clear() {
    this.entries.clear();
  }

  destroy() {
    if (this.timer) {
      clearInterval(this.timer);
    }
    this.entries.clear();
  }
}

module.exports = {
  BaseStore,
  MemoryStore
};
