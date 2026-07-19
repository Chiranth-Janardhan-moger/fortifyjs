'use strict';

class ForensicsReporter {
  constructor(maxSize = 1000) {
    this.maxSize = maxSize;
    this.buffer = [];
    this.pointer = 0;
  }

  logBlock(details = {}) {
    const {
      ip = 'unknown',
      method = 'UNKNOWN',
      path = '/',
      detector = 'unknown',
      confidence = 0,
      payload = '',
      matchedStrings = []
    } = details;

    let sanitizedPayload = typeof payload === 'string' ? payload : String(payload);

    if (Array.isArray(matchedStrings) && matchedStrings.length > 0) {
      matchedStrings.forEach(str => {
        if (str && typeof str === 'string') {
          sanitizedPayload = sanitizedPayload.split(str).join('*'.repeat(str.length));
        }
      });
    } else {
      // Basic fallback masking if no specific matched strings provided but payload contains typical patterns
      sanitizedPayload = sanitizedPayload.replace(/(<script>|UNION SELECT|DROP TABLE|--|;)/gi, '***');
    }

    // truncate to 200 chars
    if (sanitizedPayload.length > 200) {
      sanitizedPayload = sanitizedPayload.substring(0, 200) + '...';
    }

    const entry = {
      timestamp: new Date().toISOString(),
      ip,
      method,
      path,
      detector,
      confidence,
      payloadPreview: sanitizedPayload
    };

    if (this.buffer.length < this.maxSize) {
      this.buffer.push(entry);
    } else {
      this.buffer[this.pointer] = entry;
      this.pointer = (this.pointer + 1) % this.maxSize;
    }
  }

  getReport() {
    if (this.buffer.length < this.maxSize) {
      return [...this.buffer];
    }
    const result = [];
    for (let i = 0; i < this.maxSize; i++) {
      result.push(this.buffer[(this.pointer + i) % this.maxSize]);
    }
    return result;
  }
  
  clear() {
    this.buffer = [];
    this.pointer = 0;
  }
}

module.exports = { ForensicsReporter };
