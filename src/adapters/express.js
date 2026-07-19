'use strict';
const { DetectionEngine } = require('../core/engine');
const { IPRateLimiter } = require('../shields/rate-limiter');
const crypto = require('crypto');

const DEFAULT_THRESHOLD = 0.5;
const DEFAULT_SUSPICIOUS_THRESHOLD = 0.2;
const DEFAULT_MAX_LOGS = 500;
const DEFAULT_MAX_PAYLOAD_LENGTH = 50000;
const DEFAULT_MAX_DECODE_ITERATIONS = 8;
const DEFAULT_MAX_DEPTH = 20;
const DEFAULT_MAX_FIELDS = 1000;
const DETECTION_LEVELS = Object.freeze({
  strict: Object.freeze({
    threshold: 0.25,
    suspiciousThreshold: 0.1,
    maxSuspiciousRequests: 2
  }),
  balanced: Object.freeze({
    threshold: DEFAULT_THRESHOLD,
    suspiciousThreshold: DEFAULT_SUSPICIOUS_THRESHOLD,
    maxSuspiciousRequests: 3
  }),
  permissive: Object.freeze({
    threshold: 0.85,
    suspiciousThreshold: 0.5,
    maxSuspiciousRequests: 5
  })
});
const HTTP_METHODS = ['all', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const DEFAULT_REDACT_KEYS = ['password', 'passwd', 'pwd', 'token', 'secret', 'authorization', 'cookie', 'api_key', 'apikey'];
function sanitizeForLog(value) {
  return String(value)
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

function truncateForLog(value, maxLength = 500) {
  const text = sanitizeForLog(value);
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...[truncated ${text.length - maxLength} chars]`;
}

function readRequestProperty(obj, key, fallback = undefined) {
  try {
    const value = obj?.[key];
    return value === undefined ? fallback : value;
  } catch (_) {
    return fallback;
  }
}

function isURLSearchParams(value) {
  return typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams;
}

function isMap(value) {
  return value instanceof Map;
}

function isSet(value) {
  return value instanceof Set;
}

function collectionEntries(value) {
  if (isURLSearchParams(value) || isMap(value)) return [...value.entries()];
  if (isSet(value)) return [...value.values()].map((entryValue, index) => [String(index), entryValue]);
  return null;
}

function schemaKeys(source) {
  if (isURLSearchParams(source) || isMap(source)) {
    return [...new Set([...source.keys()].map(key => String(key)))];
  }
  return Object.keys(source);
}

function schemaHasKey(source, key) {
  if (isURLSearchParams(source)) return source.has(key);
  if (isMap(source)) return source.has(key);
  return Object.prototype.hasOwnProperty.call(source, key);
}

function getIp(req) {
  const ip = readRequestProperty(req, 'ip', null);
  if (ip) return ip;
  const connection = readRequestProperty(req, 'connection', null);
  return readRequestProperty(connection, 'remoteAddress', 'unknown') || 'unknown';
}

function getRequestUrl(req) {
  return readRequestProperty(req, 'originalUrl', null) || readRequestProperty(req, 'url', '') || '';
}

function getRoutePath(req) {
  const route = readRequestProperty(req, 'route', null);
  const routePathValue = route ? readRequestProperty(route, 'path', null) : null;
  if (routePathValue) {
    const routePath = Array.isArray(routePathValue) ? routePathValue.join('|') : String(routePathValue);
    return `${readRequestProperty(req, 'baseUrl', '') || ''}${routePath}`;
  }
  return readRequestProperty(req, 'path', null) || getRequestUrl(req).split('?')[0] || '';
}

function sanitizeRequestId(value) {
  if (value === null || value === undefined) return null;
  return truncateForLog(value, 128);
}

function defaultRawRequestId(req) {
  return req.id || req.requestId || req.headers?.['x-request-id'] || req.headers?.['x-correlation-id'] || null;
}

function callbackErrorMessage(error) {
  try {
    return sanitizeForLog(error && error.message ? error.message : String(error));
  } catch (_) {
    return '[unavailable]';
  }
}

function callbackErrorContext(error, context = {}) {
  return {
    type: 'fortifyjs.callback_error',
    timestamp: new Date().toISOString(),
    hook: context.hook || 'unknown',
    message: callbackErrorMessage(error),
    eventType: context.event?.type || null,
    eventLabel: context.event?.label || null,
    eventPath: context.event?.path || null
  };
}

function isSensitivePath(path, redactKeys = DEFAULT_REDACT_KEYS) {
  const lowered = String(path || '').toLowerCase();
  return redactKeys.some(key => lowered.includes(String(key).toLowerCase()));
}

function payloadPreview(payload, path, options = {}) {
  if (isSensitivePath(path, options.redactKeys)) return '[redacted]';
  return truncateForLog(payload, options.maxLogPayloadLength ?? 300);
}

function payloadFingerprint(payload) {
  const normalized = String(payload)
    .toLowerCase()
    .replace(/[a-z]+/g, 'a')
    .replace(/\d+/g, '0')
    .replace(/\s+/g, ' ')
    .slice(0, 1000);
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

function createDetectionEvent(req, payload, detection, options = {}) {
  const matches = detection.matches || [];
  const action = options.dryRun ? 'observe' : (detection.action || 'block');
  return {
    type: 'fortifyjs.threat',
    detected: true,
    timestamp: new Date().toISOString(),
    action,
    blocked: action === 'block',
    dryRun: options.dryRun === true,
    requestId: options.getRequestId(req),
    method: readRequestProperty(req, 'method', null),
    url: getRequestUrl(req),
    route: getRoutePath(req),
    ip: getIp(req),
    label: detection.label,
    confidence: detection.confidence,
    path: detection.path,
    matches,
    matchedSignalIds: matches.map(match => match.id),
    payloadPreview: payloadPreview(payload, detection.path, options),
    payloadLength: String(payload).length,
    reason: detection.reason || null
  };
}

function formatEvent(event, format = 'text') {
  if (format === 'json') return event;
  const safe = (value, fallback = '-') => {
    if (value === null || value === undefined || value === '') return fallback;
    return sanitizeForLog(value);
  };
  return `[fortifyjs] ${event.action === 'observe' ? 'Attack Observed' : 'Attack Blocked'}: ${safe(event.label)} from IP: ${safe(event.ip)} | requestId: ${safe(event.requestId)} | path: ${safe(event.path)} | confidence: ${safe(event.confidence)} | Payload: ${safe(event.payloadPreview)}`;
}

function createLearningEvent(req, payload, result, path, options = {}) {
  const matchedSignalIds = (result.matches || []).map(match => match.id);
  const fingerprint = payloadFingerprint(payload);
  return {
    type: 'fortifyjs.learning',
    timestamp: new Date().toISOString(),
    requestId: options.getRequestId(req),
    method: readRequestProperty(req, 'method', null),
    url: getRequestUrl(req),
    route: getRoutePath(req),
    ip: getIp(req),
    label: result.label,
    confidence: result.confidence,
    path,
    matches: result.matches || [],
    matchedSignalIds,
    clusterKey: `${result.label}:${matchedSignalIds.join('+') || 'unknown'}:${fingerprint}`,
    payloadPreview: payloadPreview(payload, path, options),
    payloadLength: String(payload).length
  };
}

function normalizeDetectionLevel(level = 'balanced') {
  const normalized = String(level || 'balanced').toLowerCase();
  if (!DETECTION_LEVELS[normalized]) {
    throw new Error(`Unknown fortifyjs detection level: ${level}`);
  }
  return normalized;
}

function resolveDetectionSettings(options = {}) {
  const level = normalizeDetectionLevel(options.level ?? options.detectionLevel ?? 'balanced');
  const defaults = DETECTION_LEVELS[level];
  return {
    level,
    threshold: options.threshold ?? defaults.threshold,
    suspiciousThreshold: options.suspiciousThreshold ?? defaults.suspiciousThreshold,
    maxSuspiciousRequests: options.maxSuspiciousRequests ?? defaults.maxSuspiciousRequests
  };
}

function normalizeMode(mode) {
  if (mode === undefined || mode === null) return null;
  const normalized = String(mode).toLowerCase();
  if (['block', 'blocking', 'enforce', 'enforced'].includes(normalized)) return 'block';
  if (['log', 'observe', 'monitor', 'dry-run', 'dryrun'].includes(normalized)) return 'log';
  throw new Error(`Unknown fortifyjs mode: ${mode}`);
}

function toList(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function mergeLists(...values) {
  return values.flatMap(toList);
}

function isPlainRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof RegExp);
}

function matchesPattern(pattern, value, req) {
  const text = String(value || '');
  if (typeof pattern === 'function') return pattern(text, req) === true;
  if (pattern instanceof RegExp) {
    pattern.lastIndex = 0;
    return pattern.test(text);
  }
  const expected = String(pattern);
  if (expected.endsWith('*')) return text.startsWith(expected.slice(0, -1));
  return text === expected;
}

function patternMatchesAny(patterns, value, req) {
  return patterns.some(pattern => matchesPattern(pattern, value, req));
}

function routeAllowPatterns(options = {}) {
  const allowlist = options.allowlist || {};
  return mergeLists(options.allowRoutes, options.allowedRoutes, allowlist.routes);
}

function paramAllowPatterns(req, options = {}) {
  const allowlist = options.allowlist || {};
  const values = mergeLists(
    options.allowParams,
    options.allowedParams,
    options.allowParameters,
    allowlist.params,
    allowlist.parameters
  );
  const patterns = [];

  for (const value of values) {
    if (isPlainRecord(value)) {
      for (const [routePattern, routePatterns] of Object.entries(value)) {
        if (requestMatchesPattern(req, routePattern)) patterns.push(...toList(routePatterns));
      }
    } else {
      patterns.push(value);
    }
  }

  return patterns;
}

function requestMatchesPattern(req, pattern) {
  return schemaCandidates(req).some(candidate => matchesPattern(pattern, candidate, req));
}

function isRouteAllowed(req, options = {}) {
  return routeAllowPatterns(options).some(pattern => requestMatchesPattern(req, pattern));
}

function isParamAllowed(req, path, options = {}) {
  return patternMatchesAny(paramAllowPatterns(req, options), path, req);
}

function routeDetectionMaps(options = {}) {
  const allowlist = options.allowlist || {};
  return [
    options.routeLevels,
    options.routeDetectionLevels,
    options.routeThresholds,
    allowlist.routeLevels
  ].filter(isPlainRecord);
}

function resolveRouteDetectionOverride(req, options = {}) {
  for (const map of routeDetectionMaps(options)) {
    for (const [pattern, override] of Object.entries(map)) {
      if (requestMatchesPattern(req, pattern)) return override;
    }
  }
  return null;
}

function resolveRequestDetectionSettings(req, options = {}, baseSettings = resolveDetectionSettings(options)) {
  const override = resolveRouteDetectionOverride(req, options);
  if (!override) return baseSettings;
  if (typeof override === 'string') return resolveDetectionSettings({ level: override });
  return resolveDetectionSettings(override);
}

function normalizeMaxLogs(maxLogs) {
  const numeric = Number(maxLogs ?? DEFAULT_MAX_LOGS);
  return Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : DEFAULT_MAX_LOGS;
}

function createMemoryLogStore(maxLogs = DEFAULT_MAX_LOGS) {
  const limit = normalizeMaxLogs(maxLogs);
  const entries = [];
  return {
    maxLogs: limit,
    add(event) {
      entries.push({ ...event });
      if (entries.length > limit) entries.splice(0, entries.length - limit);
    },
    list() {
      return entries.slice();
    },
    clear() {
      entries.length = 0;
    }
  };
}

function parsePositiveInteger(value, fallback = null) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function createLogsHandler(logStore, options = {}) {
  return (req, res) => {
    const allLogs = logStore && typeof logStore.list === 'function' ? logStore.list() : [];
    const queryLimit = readRequestProperty(readRequestProperty(req, 'query', {}), 'limit', null);
    const limit = parsePositiveInteger(queryLimit, parsePositiveInteger(options.limit, null));
    const logs = limit ? allLogs.slice(-limit) : allLogs;
    return res.status(200).json(logs);
  };
}

function normalizeSchemaRule(rule) {
  if (!rule) return null;
  if (Array.isArray(rule)) return { allowed: rule, required: [], allowUnknown: false };
  const required = rule.required || [];
  return {
    allowed: rule.allowed || rule.fields || required,
    required,
    allowUnknown: rule.allowUnknown === true
  };
}

function pathnameFromRequest(req) {
  return (getRequestUrl(req).split('?')[0] || readRequestProperty(req, 'path', '') || '').replace(/\/+$/, '') || '/';
}

function schemaCandidates(req) {
  const method = String(readRequestProperty(req, 'method', '') || '').toUpperCase();
  const route = getRoutePath(req);
  const path = pathnameFromRequest(req);
  const candidates = [...new Set([route, path].filter(Boolean))];
  return [
    ...candidates.map(candidate => `${method} ${candidate}`),
    ...candidates
  ];
}

function resolveSchema(req, options = {}) {
  if (options.schema) return options.schema;
  if (!options.schemas) return null;
  for (const key of schemaCandidates(req)) {
    if (options.schemas[key]) return options.schemas[key];
  }
  return null;
}

function validateSchemaSource(sourceName, source, rule) {
  const normalized = normalizeSchemaRule(rule);
  if (!normalized) return null;

  const required = new Set(normalized.required);

  if (!source || typeof source !== 'object' || Buffer.isBuffer(source)) {
    for (const key of required) {
      return {
        payload: key,
        detection: {
          label: 'schema_violation',
          confidence: 1,
          path: `${sourceName}.${key}`,
          reason: 'missing_required_field',
          matches: [{ id: 'schema-missing-required-field', label: 'schema', confidence: 1 }]
        }
      };
    }
    return null;
  }

  let keys;
  try {
    keys = schemaKeys(source);
  } catch (_) {
    return {
      payload: `[Unreadable ${sourceName}]`,
      detection: {
        label: 'schema_violation',
        confidence: 1,
        path: sourceName,
        reason: 'unreadable_object',
        matches: [{ id: 'schema-unreadable-object', label: 'schema', confidence: 1 }]
      }
    };
  }
  const allowed = new Set(normalized.allowed);

  if (!normalized.allowUnknown && allowed.size > 0) {
    for (const key of keys) {
      if (!allowed.has(key)) {
        return {
          payload: key,
          detection: {
            label: 'schema_violation',
            confidence: 1,
            path: `${sourceName}.${key}`,
            reason: 'unexpected_field',
            matches: [{ id: 'schema-unexpected-field', label: 'schema', confidence: 1 }]
          }
        };
      }
    }
  }

  for (const key of required) {
    if (!schemaHasKey(source, key)) {
      return {
        payload: key,
        detection: {
          label: 'schema_violation',
          confidence: 1,
          path: `${sourceName}.${key}`,
          reason: 'missing_required_field',
          matches: [{ id: 'schema-missing-required-field', label: 'schema', confidence: 1 }]
        }
      };
    }
  }

  return null;
}

function validateSchema(req, schema) {
  if (!schema) return null;
  return (
    validateSchemaSource('query', req.query, schema.query) ||
    validateSchemaSource('body', req.body, schema.body) ||
    validateSchemaSource('params', req.params, schema.params) ||
    validateSchemaSource('headers', req.headers, schema.headers) ||
    validateSchemaSource('cookies', req.cookies, schema.cookies)
  );
}

function expressMiddleware(options = {}) {
  const detector = options.detector || new DetectionEngine({
    maxPayloadLength: options.maxPayloadLength,
    maxDecodeIterations: options.maxDecodeIterations
  });
  const detectionSettings = resolveDetectionSettings(options);
  const learning = options.learning === true ? { enabled: true } : (options.learning || {});
  const mode = normalizeMode(options.mode);
  const dryRun = typeof options.dryRun === 'boolean'
    ? options.dryRun
    : (mode === 'log'
      ? true
      : (mode === 'block' ? false : (learning.enabled === true || options.learning === true || detectionSettings.level === 'permissive')));
  const maxSuspiciousRequests = detectionSettings.maxSuspiciousRequests;
  const maxRateLimitEventsPerKey = Math.max(options.maxRateLimitEventsPerKey ?? 1000, maxSuspiciousRequests);
  const rateLimiter = new IPRateLimiter(
    options.rateLimitWindowMs ?? 300000,
    options.maxRateLimitCapacity ?? 10000,
    maxRateLimitEventsPerKey
  );
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxFields = options.maxFields ?? DEFAULT_MAX_FIELDS;
  const blockStatus = options.blockStatus ?? 403;
  const scanQuery = options.scanQuery !== false;
  const scanBody = options.scanBody !== false;
  const scanHeaders = options.scanHeaders !== false;
  const scanCookies = options.scanCookies !== false;
  const scanParams = options.scanParams !== false;
  const scanKeys = options.scanKeys !== false;
  const scanRawBody = options.scanRawBody !== false;
  const skip = typeof options.skip === 'function' ? options.skip : null;
  const onThreat = typeof options.onThreat === 'function' ? options.onThreat : null;
  const onLearningEvent = typeof options.onLearningEvent === 'function'
    ? options.onLearningEvent
    : (typeof learning.onEvent === 'function' ? learning.onEvent : null);
  const learningEnabled = learning.enabled === true || options.learning === true || onLearningEvent !== null;
  const logFormat = options.logFormat || (options.jsonLogs ? 'json' : 'text');
  const logger = typeof options.logAttacks === 'function'
    ? options.logAttacks
    : (options.logAttacks ? console.warn : null);
  const requestIdGetter = typeof options.getRequestId === 'function' ? options.getRequestId : defaultRawRequestId;
  const rateLimitKeyGetter = typeof options.rateLimitKey === 'function' ? options.rateLimitKey : getIp;
  const onCallbackError = typeof options.onCallbackError === 'function' ? options.onCallbackError : null;
  const hasProvidedLogStore = Boolean(options.logStore);
  const logStore = options.logStore || createMemoryLogStore(options.maxLogs);
  const storeLogs = Boolean(
    options.logRequests ||
    options.logs ||
    options.exposeLogs ||
    options.storeLogs ||
    dryRun ||
    (hasProvidedLogStore && !options._internalLogStore) ||
    learningEnabled
  );

  const reportCallbackError = (error, context = {}) => {
    if (!onCallbackError) return;

    const safeContext = callbackErrorContext(error, context);
    try {
      const result = onCallbackError(error, safeContext);
      Promise.resolve(result).catch(() => {});
    } catch (_) {
      // User error reporting must never affect request handling.
    }
  };

  const safeCall = (hook, callback, args, context = {}) => {
    if (typeof callback !== 'function') return undefined;

    try {
      const result = callback(...args);
      Promise.resolve(result).catch(error => reportCallbackError(error, { ...context, hook }));
      return result;
    } catch (error) {
      reportCallbackError(error, { ...context, hook });
      return undefined;
    }
  };

  const safeRequestId = (req) => {
    try {
      return sanitizeRequestId(requestIdGetter(req));
    } catch (error) {
      reportCallbackError(error, { hook: 'getRequestId' });
      return null;
    }
  };

  const safeRateLimitKey = async (req, fallback) => {
    try {
      const key = rateLimitKeyGetter(req);
      const resolvedKey = await key;
      return String(resolvedKey || fallback || 'unknown');
    } catch (error) {
      reportCallbackError(error, { hook: 'rateLimitKey' });
      return String(fallback || 'unknown');
    }
  };

  const eventOptions = {
    dryRun,
    redactKeys: options.redactKeys || DEFAULT_REDACT_KEYS,
    maxLogPayloadLength: options.maxLogPayloadLength,
    getRequestId: safeRequestId
  };

  const writeLog = (event) => {
    if (storeLogs && logStore && typeof logStore.add === 'function') logStore.add(event);
    if (logger) safeCall('logAttacks', logger, [formatEvent(event, logFormat), event], { event });
  };

  const emitLearning = (req, payload, result, path) => {
    if (!learningEnabled) return;
    const event = createLearningEvent(req, payload, result, path, eventOptions);
    req.fortifyjsLearning = req.fortifyjsLearning || [];
    req.fortifyjsLearning.push(event);
    if (storeLogs && logStore && typeof logStore.add === 'function') logStore.add(event);
    safeCall('onLearningEvent', onLearningEvent, [event, req], { event });
  };

  const middleware = async (req, res, next) => {
    try {
      if (skip) {
        try {
          const skipResult = skip(req);
          const shouldSkip = await skipResult;
          if (shouldSkip) return next();
        } catch (error) {
          reportCallbackError(error, { hook: 'skip' });
        }
      }

      if (isRouteAllowed(req, options)) return next();

      const ip = getIp(req);
      const rateLimitKey = await safeRateLimitKey(req, ip);
    const requestDetectionSettings = resolveRequestDetectionSettings(req, options, detectionSettings);
    const scannedSources = req.fortifyjsScannedSources instanceof Set
      ? req.fortifyjsScannedSources
      : new Set();
    req.fortifyjsScannedSources = scannedSources;
    
    let scannedFields = 0;

    const reportDetection = (payload, detection) => {
      const event = createDetectionEvent(req, payload, detection, eventOptions);
      req.fortifyjsDetections = req.fortifyjsDetections || [];
      req.fortifyjsDetections.push(event);
      req.fortifyjs = req.fortifyjs || event;
      safeCall('onThreat', onThreat, [event, req], { event });
      writeLog(event);
      return { isMalicious: true, label: detection.label };
    };

    const scanString = async (str, path) => {
      if (typeof str !== 'string' || str.length === 0) return false;
      if (isParamAllowed(req, path, options)) return false;
      const result = detector.detect(str);
      let finalLabel = result.label;
      let finalConfidence = result.confidence;
      let isMalicious = result.label !== 'benign' && result.confidence >= requestDetectionSettings.threshold;

      if (!isMalicious && result.label !== 'benign' && result.confidence >= requestDetectionSettings.suspiciousThreshold) {
        emitLearning(req, str, result, path);
        const suspiciousCount = rateLimiter.recordSuspicious(rateLimitKey);
        if (suspiciousCount >= requestDetectionSettings.maxSuspiciousRequests) {
          isMalicious = true;
          finalLabel = "rate_limit_escalation";
          finalConfidence = requestDetectionSettings.threshold;
          writeLog({
            type: 'fortifyjs.rate_limit',
            timestamp: new Date().toISOString(),
            action: dryRun ? 'observe' : 'block',
            blocked: !dryRun,
            dryRun,
            requestId: eventOptions.getRequestId(req),
            method: readRequestProperty(req, 'method', null),
            url: getRequestUrl(req),
            route: getRoutePath(req),
            ip: getIp(req),
            label: finalLabel,
            confidence: finalConfidence,
            path,
            matches: result.matches || [],
            matchedSignalIds: (result.matches || []).map(match => match.id),
            payloadPreview: payloadPreview(str, path, eventOptions),
            payloadLength: String(str).length,
            reason: 'repeated_suspicious_probe'
          });
        }
      }

      if (isMalicious) {
        return reportDetection(str, {
          label: finalLabel,
          confidence: finalConfidence,
          path,
          matches: result.matches
        });
      }
      return false;
    };

    const deepScan = async (obj, path, currentDepth = 0, seen = new WeakSet()) => {
      if (!obj || typeof obj !== 'object') return false;
      if (currentDepth > maxDepth) {
         return reportDetection("[JSON Depth Exceeded]", { label: "dos", confidence: 1, path, reason: 'max_depth_exceeded' });
      }
      if (seen.has(obj)) return false;
      seen.add(obj);
      let attackFound = false;

      const scanEntry = async (key, val, childPath, scanKey = true) => {
        scannedFields++;
        if (scannedFields > maxFields) {
          return reportDetection("[Field Limit Exceeded]", { label: "dos", confidence: 1, path, reason: 'max_fields_exceeded' });
        }

        if (scanKey) {
          const keyAttack = scanKeys ? await scanString(String(key), `${childPath}.__key`) : false;
          if (keyAttack) {
            if (!dryRun) return keyAttack;
            attackFound = attackFound || keyAttack;
          }
        }

        if (typeof val === 'string') {
          const valAttack = await scanString(val, childPath);
          if (valAttack) {
            if (!dryRun) return valAttack;
            attackFound = attackFound || valAttack;
          }
        } else if (Buffer.isBuffer(val)) {
          const valAttack = await scanString(val.toString('utf8'), childPath);
          if (valAttack) {
            if (!dryRun) return valAttack;
            attackFound = attackFound || valAttack;
          }
        } else if (typeof val === 'object' && val !== null) {
          const nestedAttack = await deepScan(val, childPath, currentDepth + 1, seen);
          if (nestedAttack) {
            if (!dryRun) return nestedAttack;
            attackFound = attackFound || nestedAttack;
          }
        }

        return false;
      };

      let entries;
      try {
        entries = collectionEntries(obj);
      } catch (_) {
        return reportDetection("[Object Enumeration Failed]", {
          label: "dos",
          confidence: 1,
          path,
          reason: 'object_enumeration_failed',
          matches: [{ id: 'object-enumeration-failed', label: 'dos', confidence: 1 }]
        });
      }

      if (entries) {
        const scanEntryKeys = !isSet(obj);
        for (const [key, val] of entries) {
          const stringKey = String(key);
          const childPath = scanEntryKeys ? `${path}.${stringKey}` : `${path}[${stringKey}]`;
          const entryAttack = await scanEntry(stringKey, val, childPath, scanEntryKeys);
          if (entryAttack) {
            if (!dryRun) return entryAttack;
            attackFound = attackFound || entryAttack;
          }
        }
        return attackFound;
      }

      let keys;

      try {
        keys = Object.keys(obj);
      } catch (_) {
        return reportDetection("[Object Enumeration Failed]", {
          label: "dos",
          confidence: 1,
          path,
          reason: 'object_enumeration_failed',
          matches: [{ id: 'object-enumeration-failed', label: 'dos', confidence: 1 }]
        });
      }

      for (const key of keys) {
        const childPath = Array.isArray(obj) ? `${path}[${key}]` : `${path}.${key}`;
        let val;
        try {
          val = obj[key];
        } catch (_) {
          return reportDetection("[Object Property Access Failed]", {
            label: "dos",
            confidence: 1,
            path: childPath,
            reason: 'object_property_access_failed',
            matches: [{ id: 'object-property-access-failed', label: 'dos', confidence: 1 }]
          });
        }

        const entryAttack = await scanEntry(key, val, childPath);
        if (entryAttack) {
          if (!dryRun) return entryAttack;
          attackFound = attackFound || entryAttack;
        }
      }
      return attackFound;
    };

    let schemaResult;
    try {
      schemaResult = validateSchema(req, resolveSchema(req, options));
    } catch (_) {
      schemaResult = {
        payload: '[Schema Source Read Failed]',
        detection: {
          label: 'dos',
          confidence: 1,
          path: 'schema',
          reason: 'schema_source_read_failed',
          matches: [{ id: 'schema-source-read-failed', label: 'dos', confidence: 1 }]
        }
      };
    }

    if (schemaResult) {
      const attack = reportDetection(schemaResult.payload, schemaResult.detection);
      if (!dryRun) return res.status(blockStatus).json({
        error: 'Forbidden',
        message: 'Malicious payload detected by fortifyjs',
        details: { label: attack.label }
      });
    }

    const sources = [];
    const sourceReadFailures = [];
    const addSource = (enabled, sourceName, readSource, options = {}) => {
      if (!enabled) return;
      try {
        const source = readSource();
        if (options.skipUndefined && source === undefined) return;
        sources.push([sourceName, source]);
      } catch (_) {
        sourceReadFailures.push(sourceName);
      }
    };

    addSource(scanQuery, 'query', () => req.query);
    addSource(scanBody, 'body', () => req.body);
    addSource(scanRawBody, 'rawBody', () => req.rawBody, { skipUndefined: true });
    addSource(scanHeaders, 'headers', () => req.headers);
    addSource(scanParams, 'params', () => req.params);
    addSource(scanCookies, 'cookies', () => req.cookies);

    for (const sourceName of sourceReadFailures) {
      const attack = reportDetection(`[${sourceName} Source Read Failed]`, {
        label: 'dos',
        confidence: 1,
        path: sourceName,
        reason: 'source_read_failed',
        matches: [{ id: 'source-read-failed', label: 'dos', confidence: 1 }]
      });
      if (!dryRun) return res.status(blockStatus).json({
        error: 'Forbidden',
        message: 'Malicious payload detected by fortifyjs',
        details: { label: attack.label }
      });
    }

    for (const [sourceName, source] of sources) {
      if (scannedSources.has(sourceName)) continue;
      if (!source) continue;
      
      let attack = false;
      if (Buffer.isBuffer(source)) {
         attack = await scanString(source.toString('utf8'), sourceName);
      } else if (typeof source === 'string') {
         attack = await scanString(source, sourceName);
      } else if (typeof source === 'object') {
         attack = await deepScan(source, sourceName);
      }

      if (attack) {
        if (!dryRun) return res.status(blockStatus).json({
          error: 'Forbidden',
          message: 'Malicious payload detected by fortifyjs',
          details: { label: attack.label }
        });
      }
      scannedSources.add(sourceName);
    }
    next();
    } catch (error) {
      next(error);
    }
  };

  middleware.logStore = logStore;
  middleware.logsHandler = (handlerOptions = {}) => createLogsHandler(logStore, handlerOptions);
  return middleware;
}
function mergeOptions(base, override) {
  return { ...base, ...(override || {}) };
}

class fortifyjsQueryError extends Error {
  constructor(result) {
    super('Unsafe SQL query detected by fortifyjs');
    this.name = 'fortifyjsQueryError';
    this.result = result;
  }
}
function samplePayload(sample) {
  if (typeof sample === 'string') return sample;
  if (!sample || typeof sample !== 'object') return '';
  return sample.payload ?? sample.text ?? sample.value ?? '';
}

function expectedMaliciousLabel(label) {
  if (label === undefined || label === null) return null;
  const normalized = String(label).toLowerCase();
  if (['benign', 'safe', 'normal', 'clean'].includes(normalized)) return false;
  if (['sqli', 'xss', 'nosql', 'malicious', 'attack', 'blocked'].includes(normalized)) return true;
  return null;
}
function fortifyjs(options = {}) {
  const logStore = options.logStore || createMemoryLogStore(options.maxLogs);
  const baseOptions = {
    ...options,
    logStore,
    _internalLogStore: !options.logStore,
    detector: options.detector || new DetectionEngine({
      maxPayloadLength: options.maxPayloadLength,
      maxDecodeIterations: options.maxDecodeIterations
    })
  };

  return {
    global(overrides = {}) {
      return expressMiddleware(mergeOptions(baseOptions, overrides));
    },
    route(overrides = {}) {
      return expressMiddleware(mergeOptions({
        ...baseOptions,
        scanParams: true
      }, overrides));
    },
    verify(overrides = {}) {
      return this.route(overrides);
    },
    middleware(overrides = {}) {
      return expressMiddleware(mergeOptions(baseOptions, overrides));
    },
    nestjs(overrides = {}) {
      return nestjsMiddleware(mergeOptions(baseOptions, overrides));
    },
    logs() {
      return logStore.list();
    },
    clearLogs() {
      logStore.clear();
    },
    logsHandler(handlerOptions = {}) {
      return createLogsHandler(logStore, handlerOptions);
    },
    mountLogs(app, path = baseOptions.logsPath || '/admin/fortifyjs/logs', handlerOptions = {}) {
      if (!app || typeof app.get !== 'function') {
        throw new TypeError('mountLogs(app) requires an Express-compatible app with app.get().');
      }
      app.get(path, createLogsHandler(logStore, handlerOptions));
      return app;
    },
    logStore,
    detector: baseOptions.detector
  };
}
function isPlainOptions(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && typeof value !== 'function';
}

function secureRouter(options = {}) {
  let express;
  try {
    express = require('express');
  } catch (e) {
    throw new Error('secureRouter() requires express to be installed in the host application.');
  }

  const router = express.Router(options.routerOptions || {});
  const guard = fortifyjs(options);
  router.use(guard.global({ ...(options.globalOptions || {}), scanParams: false }));
  if (options.exposeLogs) {
    router.get(options.logsPath || '/admin/fortifyjs/logs', guard.logsHandler());
  }
  const routeGuard = (routeOptions = {}) => guard.route({
    ...routeOptions,
    schema: routeOptions.schema,
    scanQuery: false,
    scanBody: false,
    scanHeaders: false,
    scanCookies: false,
    scanRawBody: false,
    scanParams: routeOptions.scanParams !== false
  });
  const consumeRouteOptions = (handlers) => {
    let routeOptions = options.routeOptions || {};
    if (handlers.length > 0 && isPlainOptions(handlers[0])) {
      routeOptions = mergeOptions(routeOptions, handlers.shift());
    }
    return routeOptions;
  };

  for (const method of HTTP_METHODS) {
    const original = router[method].bind(router);
    router[method] = (path, ...handlers) => {
      const routeOptions = consumeRouteOptions(handlers);

      return original(
        path,
        routeGuard(routeOptions),
        ...handlers
      );
    };
  }

  router.fortifyjs = guard;
  return router;
}
module.exports = { expressMiddleware, fortifyjs, secureRouter, expectedMaliciousLabel, samplePayload };
