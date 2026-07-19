'use strict';
const { shield } = require('./presets');
const { DetectionEngine } = require('./core/engine');
const { Normalizer } = require('./core/normalizer');
const { expressMiddleware, fortifyjs, secureRouter } = require('./adapters/express');
const { createNestMiddleware, nestjsMiddleware } = require('./adapters/nestjs');
const fastifyPlugin = require('./adapters/fastify');
const { koaMiddleware } = require('./adapters/koa');
const { honoMiddleware } = require('./adapters/hono');
const { genericAdapter } = require('./adapters/generic');
const DEFAULT_THRESHOLD = 0.5;

function samplePayload(sample) {
  if (typeof sample === 'string') return sample;
  if (sample && typeof sample === 'object') {
    return sample.payload !== undefined ? sample.payload : (sample.query !== undefined ? sample.query : JSON.stringify(sample));
  }
  return String(sample);
}

function expectedMaliciousLabel(label) {
  if (typeof label === 'boolean') return label;
  const str = String(label).toLowerCase();
  return str !== 'benign' && str !== 'safe' && str !== 'false' && str !== '0';
}

function resolveDetectionSettings(options) {
  const threshold = typeof options.threshold === 'number' ? options.threshold : DEFAULT_THRESHOLD;
  return { threshold };
}

class fortifyjsQueryError extends Error {
  constructor(result) {
    super(`fortifyjs detected a SQL injection attempt (confidence: ${result.confidence.toFixed(2)})`);
    this.name = 'fortifyjsQueryError';
    this.result = result;
  }
}

function scanSqlQuery(query, options = {}) {
  if (typeof query !== 'string') {
    throw new TypeError('query must be a string');
  }
  const detector = options.detector || new DetectionEngine({
    maxPayloadLength: options.maxPayloadLength,
    maxDecodeIterations: options.maxDecodeIterations
  });
  return detector.detect(query);
}

function assertSafeSqlQuery(query, options = {}) {
  const result = scanSqlQuery(query, options);
  const { threshold } = resolveDetectionSettings(options);
  if (result.label === 'sqli' && result.confidence >= threshold) {
    throw new fortifyjsQueryError(result);
  }
  return result;
}
function evaluatePayloads(samples, options = {}) {
  if (!Array.isArray(samples)) {
    throw new TypeError('samples must be an array');
  }

  const detector = options.detector || new DetectionEngine({
    maxPayloadLength: options.maxPayloadLength,
    maxDecodeIterations: options.maxDecodeIterations
  });
  const { threshold } = resolveDetectionSettings(options);
  const results = [];
  const summary = {
    total: samples.length,
    blocked: 0,
    allowed: 0,
    labeled: 0,
    falsePositives: 0,
    falseNegatives: 0,
    truePositives: 0,
    trueNegatives: 0,
    falsePositiveRate: 0,
    falseNegativeRate: 0
  };

  for (const sample of samples) {
    const payload = String(samplePayload(sample));
    const expectedMalicious = typeof sample === 'object' && sample !== null
      ? expectedMaliciousLabel(sample.label ?? sample.expected ?? sample.kind)
      : null;
    const result = detector.detect(payload);
    const blocked = result.label !== 'benign' && result.confidence >= threshold;
    if (blocked) summary.blocked++;
    else summary.allowed++;

    if (expectedMalicious !== null) {
      summary.labeled++;
      if (blocked && expectedMalicious) summary.truePositives++;
      else if (blocked && !expectedMalicious) summary.falsePositives++;
      else if (!blocked && expectedMalicious) summary.falseNegatives++;
      else summary.trueNegatives++;
    }

    results.push({ payload, expectedMalicious, blocked, result });
  }

  const benignCount = summary.trueNegatives + summary.falsePositives;
  const maliciousCount = summary.truePositives + summary.falseNegatives;
  summary.falsePositiveRate = benignCount === 0 ? 0 : summary.falsePositives / benignCount;
  summary.falseNegativeRate = maliciousCount === 0 ? 0 : summary.falseNegatives / maliciousCount;

  return { threshold, summary, results };
}

module.exports = {
  shield,
  DetectionEngine,
  Normalizer,
  evaluatePayloads,
  fortifyjsQueryError,
  expressMiddleware,
  createNestMiddleware,
  fortifyjs,
  secureRouter,
  nestjsMiddleware,
  scanSqlQuery,
  assertSafeSqlQuery,
  evaluatePayloads,
  fastifyPlugin,
  koaMiddleware,
  honoMiddleware,
  genericAdapter
};