'use strict';

class AdaptiveBlocker {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60000;
    this.threshold = options.threshold || 5;
    this.blockDurationMs = options.blockDurationMs || 300000;
    this.anomalies = new Map();
    this.blocks = new Map();
  }

  recordAnomaly(ip) {
    const now = Date.now();
    this.cleanup(now);

    if (this.isBlocked(ip, now)) {
      return true;
    }

    if (!this.anomalies.has(ip)) {
      this.anomalies.set(ip, []);
    }

    const timestamps = this.anomalies.get(ip);
    timestamps.push(now);

    const windowStart = now - this.windowMs;
    while (timestamps.length > 0 && timestamps[0] < windowStart) {
      timestamps.shift();
    }

    if (timestamps.length > this.threshold) {
      this.blocks.set(ip, now + this.blockDurationMs);
      this.anomalies.delete(ip);
      return true;
    }

    return false;
  }

  isBlocked(ip, now = Date.now()) {
    const expiry = this.blocks.get(ip);
    if (!expiry) return false;
    
    if (now >= expiry) {
      this.blocks.delete(ip);
      return false;
    }
    
    return true;
  }

  cleanup(now = Date.now()) {
    for (const [ip, expiry] of this.blocks.entries()) {
      if (now >= expiry) {
        this.blocks.delete(ip);
      }
    }
    const windowStart = now - this.windowMs;
    for (const [ip, timestamps] of this.anomalies.entries()) {
      while (timestamps.length > 0 && timestamps[0] < windowStart) {
        timestamps.shift();
      }
      if (timestamps.length === 0) {
        this.anomalies.delete(ip);
      }
    }
  }

  middleware() {
    return (req, res, next) => {
      const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
      
      if (this.isBlocked(ip)) {
        return res.status(429).json({ error: 'IP temporarily blocked due to repeated anomalies' });
      }

      res.on('finish', () => {
        const detections = req.fortifyjsDetections || [];
        // We consider it an anomaly if there are any detections that are malicious (detected = true) or labeled anomaly.
        const hasAnomaly = detections.some(d => d.detected || d.label === 'anomaly');
        if (hasAnomaly) {
          this.recordAnomaly(ip);
        }
      });

      next();
    };
  }
}

module.exports = { AdaptiveBlocker };
