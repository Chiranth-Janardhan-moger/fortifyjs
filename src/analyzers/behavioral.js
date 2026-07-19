'use strict';

/**
 * Calculates Shannon entropy of a string
 * @param {string} str 
 * @returns {number}
 */
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

class BehavioralAnalyzer {
  /**
   * @param {Object} options 
   */
  constructor(options = {}) {
    this.options = {
      entropyThreshold: 4.5,
      maxEncodingDepth: 3,
      specialCharRatio: 0.5,
      learningRequests: 1000,
      onAnomaly: null,
      ...options
    };
    
    this.learningData = {
      requestCount: 0,
      routes: {} 
    };
  }

  /**
   * Analyzes payload for anomalies
   * @param {string} normalizedPayload 
   * @param {Object} context 
   * @returns {Array<Object>}
   */
  analyze(normalizedPayload, context = {}) {
    const signals = [];
    const {
      decodingIterations = 0,
      paramName = '',
      source = 'query',
      contentType = '',
      route = '',
      method = 'GET'
    } = context;

    const payload = normalizedPayload || '';
    const len = payload.length;

    // 6.1 Entropy
    if (len > 5) {
      const entropy = shannonEntropy(payload);
      if (entropy > this.options.entropyThreshold) {
        signals.push({ id: 'high-entropy-payload', confidence: 0.40, label: 'anomaly' });
      }
    }

    // 6.2 Encoding Depth
    if (decodingIterations >= 5) {
      signals.push({ id: 'extreme-encoding', confidence: 0.70, label: 'anomaly' });
    } else if (decodingIterations >= 3) {
      signals.push({ id: 'deep-encoding', confidence: 0.50, label: 'anomaly' });
    }

    // 6.3 Structural Anomaly
    if (len > 0) {
      let specialChars = 0;
      let hasNullByte = false;
      let hasControlChar = false;
      let hasUnusualUnicode = false;

      for (let i = 0; i < len; i++) {
        const code = payload.charCodeAt(i);
        if (code === 0) hasNullByte = true;
        else if (code > 0 && code < 32 && code !== 9 && code !== 10 && code !== 13) hasControlChar = true;
        
        if (!(code >= 48 && code <= 57) && !(code >= 65 && code <= 90) && !(code >= 97 && code <= 122) && code !== 32) {
          specialChars++;
        }

        if (code >= 0x0400 && code <= 0x04FF) hasUnusualUnicode = true; // Cyrillic
        if (code >= 0x2200 && code <= 0x22FF) hasUnusualUnicode = true; // Math Operators
        if (code >= 0xFF00 && code <= 0xFFEF) hasUnusualUnicode = true; // Fullwidth
      }

      if (specialChars / len > this.options.specialCharRatio) {
        signals.push({ id: 'high-special-char-ratio', confidence: 0.35, label: 'anomaly' });
      }
      if (hasNullByte) {
        signals.push({ id: 'null-bytes-present', confidence: 0.50, label: 'anomaly' });
      }
      if (hasControlChar) {
        signals.push({ id: 'control-chars-present', confidence: 0.40, label: 'anomaly' });
      }
      if (hasUnusualUnicode) {
        signals.push({ id: 'unusual-unicode', confidence: 0.45, label: 'anomaly' });
      }
    }

    // 6.4 Payload Length
    if (source === 'query' && len > 500) {
      signals.push({ id: 'oversized-query-param', confidence: 0.30, label: 'anomaly' });
    }
    if (source === 'cookie' && len > 4096) {
      signals.push({ id: 'oversized-cookie', confidence: 0.35, label: 'anomaly' });
    }
    if (source === 'header' && len > 8192) {
      signals.push({ id: 'oversized-header', confidence: 0.35, label: 'anomaly' });
    }

    // Excessively deep JSON nesting (>10 levels)
    if (source === 'body' && contentType && contentType.includes('application/json')) {
      let maxDepth = 0;
      let currentDepth = 0;
      for (let i = 0; i < len; i++) {
        if (payload[i] === '{' || payload[i] === '[') {
          currentDepth++;
          if (currentDepth > maxDepth) maxDepth = currentDepth;
        } else if (payload[i] === '}' || payload[i] === ']') {
          currentDepth--;
        }
      }
      if (maxDepth > 10) {
        signals.push({ id: 'excessively-deep-json', confidence: 0.80, label: 'anomaly' });
      }
    }

    // Abnormal content-length vs actual body size
    if (source === 'body' && context.contentLengthHeader) {
      const declaredLen = parseInt(context.contentLengthHeader, 10);
      if (!isNaN(declaredLen)) {
        // Flag if difference is more than 50% or minimum 50 bytes
        if (Math.abs(declaredLen - len) > Math.max(50, declaredLen * 0.5)) {
          signals.push({ id: 'abnormal-content-length', confidence: 0.60, label: 'anomaly' });
        }
      }
    }

    // Unusually high entropy strings (encoded shellcode)
    if (len > 20) {
      const entropy = shannonEntropy(payload);
      if (entropy > this.options.entropyThreshold + 1.5) { // e.g. > 6.0
        signals.push({ id: 'high-entropy-shellcode', confidence: 0.70, label: 'anomaly' });
      } else if (entropy > this.options.entropyThreshold) {
        // Prevent duplicate high-entropy-payload signal if we already pushed one in 6.1
        if (!signals.some(s => s.id === 'high-entropy-payload')) {
          signals.push({ id: 'high-entropy-payload', confidence: 0.40, label: 'anomaly' });
        }
      }
    }

    // 6.5 Content-Type Mismatch
    if (source === 'body' && contentType) {
      const isJson = contentType.includes('application/json');
      const isForm = contentType.includes('application/x-www-form-urlencoded') || contentType.includes('text/plain');
      
      const looksLikeJson = (payload.startsWith('{') && payload.endsWith('}')) || (payload.startsWith('[') && payload.endsWith(']'));
      if (looksLikeJson && isForm) {
        signals.push({ id: 'content-type-mismatch', confidence: 0.55, label: 'anomaly' });
      }

      const looksLikeXml = payload.includes('<!DOCTYPE') || payload.includes('<?xml');
      if (looksLikeXml && isJson) {
        signals.push({ id: 'xml-in-json-endpoint', confidence: 0.60, label: 'anomaly' });
      }
    }

    // 6.6 Request Fingerprinting
    if (route) {
      const routeKey = `${method} ${route}`;
      if (!this.learningData.routes[routeKey]) {
        this.learningData.routes[routeKey] = {
          params: new Set(),
          maxLengths: {},
          contentTypes: new Set()
        };
      }
      
      const rData = this.learningData.routes[routeKey];
      
      if (this.learningData.requestCount < this.options.learningRequests) {
        // Learning Mode
        if (paramName) {
          rData.params.add(paramName);
          rData.maxLengths[paramName] = Math.max(rData.maxLengths[paramName] || 0, len);
        }
        if (contentType) rData.contentTypes.add(contentType);
      } else {
        // Enforcement Mode
        if (paramName && !rData.params.has(paramName)) {
          signals.push({ id: 'unknown-parameter', confidence: 0.30, label: 'anomaly' });
        }
        if (paramName && rData.maxLengths[paramName] && len > (rData.maxLengths[paramName] * 3)) {
          signals.push({ id: 'value-length-deviation', confidence: 0.35, label: 'anomaly' });
        }
        if (contentType && rData.contentTypes.size > 0 && !rData.contentTypes.has(contentType)) {
          signals.push({ id: 'unexpected-content-type', confidence: 0.40, label: 'anomaly' });
        }
      }
    }

    // Repeated rapid requests from same fingerprint and Scanner fingerprints
    const fingerprint = context.ip ? (context.userAgent ? `${context.ip}|${context.userAgent}` : context.ip) : null;
    
    if (fingerprint) {
      if (!this.learningData.fingerprints) {
        this.learningData.fingerprints = {};
      }
      const now = Date.now();
      const fpData = this.learningData.fingerprints[fingerprint] || { count: 0, firstSeen: now, routes: new Set() };
      
      // Time window of 10 seconds for rapid requests
      if (now - fpData.firstSeen > 10000) {
        fpData.count = 1;
        fpData.firstSeen = now;
        fpData.routes.clear();
      } else {
        fpData.count++;
      }
      
      if (route) {
        fpData.routes.add(route);
      }
      
      this.learningData.fingerprints[fingerprint] = fpData;

      if (fpData.count > 50) {
        signals.push({ id: 'repeated-rapid-requests', confidence: 0.75, label: 'anomaly' });
      }
      
      if (fpData.routes.size > 15) {
        signals.push({ id: 'scanner-fingerprint', confidence: 0.80, label: 'anomaly' });
      }
    }
    
    if (signals.length > 0 && typeof this.options.onAnomaly === 'function') {
      try {
        this.options.onAnomaly(signals, context);
      } catch (e) {
        // ignore callback errors
      }
    }

    return signals;
  }
  
  incrementRequestCount() {
    if (this.learningData.requestCount < this.options.learningRequests) {
      this.learningData.requestCount++;
    }
  }
}

module.exports = { BehavioralAnalyzer };
