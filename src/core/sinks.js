'use strict';

const path = require('path');
const { DetectionEngine } = require('./engine');
const { isPrivateIP } = require('../detectors/ssrf');
const { scanPrompt, assertSafePrompt, FortifyPromptError } = require('../shields/llm-guard');

class FortifySinkError extends Error {
  constructor(message, sinkType, result = null) {
    super(`FortifyJS Sink Violation [${sinkType}]: ${message}`);
    this.name = 'FortifySinkError';
    this.sinkType = sinkType;
    this.status = 403;
    this.code = `FORTIFY_SINK_${sinkType.toUpperCase()}`;
    this.result = result;
  }
}

/**
 * Asserts that an OS command string is safe from command injection.
 * @param {string} command 
 * @param {Object} options 
 * @returns {Object} detection result
 */
function assertSafeCommand(command, options = {}) {
  if (typeof command !== 'string') {
    throw new TypeError('command must be a string');
  }

  const detector = options.detector || new DetectionEngine({ mode: 'command' });
  const result = detector.detect(command);
  const threshold = options.threshold !== undefined ? options.threshold : 0.45;

  if (result.label === 'cmdi' && result.confidence >= threshold) {
    throw new FortifySinkError('Unsafe OS command injection pattern detected', 'COMMAND', result);
  }

  // Enforce strict shell chaining metacharacter invariants
  if (/[;&|`]|\$\(/.test(command)) {
    throw new FortifySinkError('Shell metacharacter (; & | ` $) detected in command', 'COMMAND', result);
  }

  return result;
}

/**
 * Asserts that a file path is safe and contained within an allowed root directory.
 * @param {string} userPath 
 * @param {Object} options { rootDir: string }
 * @returns {string} normalized resolved safe path
 */
function assertSafePath(userPath, options = {}) {
  if (typeof userPath !== 'string') {
    throw new TypeError('path must be a string');
  }

  const detector = options.detector || new DetectionEngine();
  const result = detector.detect(userPath, { source: 'filename' });
  const threshold = options.threshold !== undefined ? options.threshold : 0.45;

  // Check traversal patterns and anomaly detections
  if ((result.label === 'path-traversal' || result.label === 'anomaly') && result.confidence >= threshold) {
    throw new FortifySinkError('Path traversal sequence detected in file path', 'PATH', result);
  }

  // Check for raw traversal patterns (including single ..)
  if (/(?:^|[\\\/])\.\.(?:[\\\/]|$)/.test(userPath) || userPath.includes('..')) {
    throw new FortifySinkError('Path traversal sequence (..) detected in file path', 'PATH');
  }

  // Check for null-byte injection
  if (userPath.includes('\0') || userPath.includes('%00')) {
    throw new FortifySinkError('Null byte injection detected in path', 'PATH');
  }

  // Check root containment if rootDir is provided
  if (options.rootDir) {
    const resolvedRoot = path.resolve(options.rootDir);
    const resolvedTarget = path.resolve(resolvedRoot, userPath);
    if (!resolvedTarget.startsWith(resolvedRoot + path.sep) && resolvedTarget !== resolvedRoot) {
      throw new FortifySinkError(`Path '${userPath}' escapes root directory '${options.rootDir}'`, 'PATH');
    }
    return resolvedTarget;
  }

  return userPath;
}

/**
 * Asserts that a URL is safe from SSRF and does not target private IP subnets or cloud metadata.
 * @param {string} targetUrl 
 * @param {Object} options { allowPrivate: boolean, allowedProtocols: string[] }
 * @returns {Object} parsed URL object
 */
function assertSafeUrl(targetUrl, options = {}) {
  if (typeof targetUrl !== 'string') {
    throw new TypeError('url must be a string');
  }

  const allowedProtocols = options.allowedProtocols || ['http:', 'https:'];
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (e) {
    throw new FortifySinkError(`Invalid URL format: ${targetUrl}`, 'URL');
  }

  if (!allowedProtocols.includes(parsed.protocol)) {
    throw new FortifySinkError(`Dangerous or disallowed URL protocol '${parsed.protocol}'`, 'URL');
  }

  if (options.allowPrivate !== true) {
    const hostname = parsed.hostname;
    if (isPrivateIP(hostname)) {
      throw new FortifySinkError(`Blocked access to private network / cloud metadata address: ${hostname}`, 'URL');
    }
  }

  const detector = options.detector || new DetectionEngine();
  const result = detector.detect(targetUrl);
  if (result.label === 'ssrf' && result.confidence >= (options.threshold || 0.5)) {
    throw new FortifySinkError(`SSRF attack pattern detected in target URL`, 'URL', result);
  }

  return parsed;
}

/**
 * Asserts that a MongoDB / NoSQL query object does not contain operator injection ($where, $gt, etc.).
 * @param {Object} query 
 * @param {Object} options 
 * @returns {Object} query
 */
function assertSafeNoSql(query, options = {}) {
  if (!query || typeof query !== 'object') return query;

  const forbiddenOperators = options.forbiddenOperators || ['$where', '$regex', '$expr', '$function', '$accumulator'];
  const visited = new WeakSet();

  function inspectNode(node) {
    if (!node || typeof node !== 'object') return;
    if (visited.has(node)) return;
    visited.add(node);

    if (Array.isArray(node)) {
      for (const item of node) inspectNode(item);
      return;
    }

    for (const key of Object.keys(node)) {
      if (forbiddenOperators.includes(key)) {
        throw new FortifySinkError(`Forbidden NoSQL query operator '${key}' detected`, 'NOSQL');
      }
      if (typeof key === 'string' && key.startsWith('$') && options.disallowAllOperators) {
        throw new FortifySinkError(`Disallowed query operator '${key}' detected`, 'NOSQL');
      }
      inspectNode(node[key]);
    }
  }

  inspectNode(query);
  return query;
}

/**
 * Asserts that a redirect destination is safe from Open Redirect vulnerabilities.
 * @param {string} destination 
 * @param {Object} options { allowedHosts: string[], allowRelative: boolean }
 * @returns {string} destination
 */
function assertSafeRedirect(destination, options = {}) {
  if (typeof destination !== 'string') {
    throw new TypeError('destination must be a string');
  }

  const allowRelative = options.allowRelative !== false;
  const allowedHosts = (options.allowedHosts || []).map(h => h.toLowerCase());

  // Check for protocol-relative bypass (//evil.com)
  if (destination.startsWith('//') || destination.startsWith('\\\\')) {
    throw new FortifySinkError('Protocol-relative URL redirect forbidden', 'REDIRECT');
  }

  // Relative paths
  if (destination.startsWith('/') && !destination.startsWith('/\\')) {
    if (allowRelative) return destination;
    throw new FortifySinkError('Relative redirect forbidden by policy', 'REDIRECT');
  }

  // Absolute URL validation
  let parsed;
  try {
    parsed = new URL(destination);
  } catch (e) {
    throw new FortifySinkError(`Invalid redirect destination: ${destination}`, 'REDIRECT');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new FortifySinkError(`Disallowed redirect protocol: ${parsed.protocol}`, 'REDIRECT');
  }

  if (allowedHosts.length > 0 && !allowedHosts.includes(parsed.hostname.toLowerCase())) {
    throw new FortifySinkError(`Redirect domain '${parsed.hostname}' is not in allowedHosts list`, 'REDIRECT');
  }

  return destination;
}

module.exports = {
  FortifySinkError,
  FortifyPromptError,
  assertSafeCommand,
  assertSafePath,
  assertSafeUrl,
  assertSafeNoSql,
  assertSafeRedirect,
  assertSafePrompt,
  scanPrompt
};
