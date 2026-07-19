'use strict';

const { Normalizer } = require('./normalizer');
const { matchSignals, combineConfidence } = require('./confidence');
const { Whitelist } = require('./whitelist');
const { BehavioralAnalyzer } = require('../analyzers/behavioral');
const sqliDetector = require('../detectors/sqli');
const xssDetector = require('../detectors/xss');
const nosqliDetector = require('../detectors/nosqli');
const cmdiDetector = require('../detectors/cmdi');
const pathTraversalDetector = require('../detectors/path-traversal');
const ssrfDetector = require('../detectors/ssrf');
const xxeDetector = require('../detectors/xxe');
const prototypePollutionDetector = require('../detectors/prototype-pollution');
const hppDetector = require('../detectors/hpp');
const openRedirectDetector = require('../detectors/open-redirect');
const crlfDetector = require('../detectors/crlf');
const templateInjectionDetector = require('../detectors/template-injection');
const ldapDetector = require('../detectors/ldap');
const graphqlDetector = require('../detectors/graphql');

function classifyInputType(payload) {
  const str = String(payload).trim();
  const upper = str.toUpperCase();
  
  const startsWithSqlKeyword = /^(?:SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|ALTER)\b/.test(upper);
  
  // Simple heuristic for quote breakouts
  const hasUnmatchedQuote = (str.match(/'/g) || []).length % 2 !== 0;
  const hasCommentBreakout = /'--|'\/\*/.test(str);
  
  if (startsWithSqlKeyword && !hasUnmatchedQuote && !hasCommentBreakout) {
    return 'complete-statement';
  }
  return 'fragment';
}

class DetectionEngine {
  constructor(options = {}) {
    this.options = options;
    this.detectors = [
      sqliDetector, 
      xssDetector, 
      nosqliDetector, 
      cmdiDetector, 
      pathTraversalDetector, 
      ssrfDetector, 
      xxeDetector, 
      prototypePollutionDetector, 
      hppDetector, 
      openRedirectDetector,
      crlfDetector,
      templateInjectionDetector,
      ldapDetector,
      graphqlDetector
    ];
    this.behavioralAnalyzer = new BehavioralAnalyzer(options.behavioral || {});
    this.whitelist = new Whitelist();
    if (options.whitelist) {
      if (Array.isArray(options.whitelist.exact)) {
        options.whitelist.exact.forEach(e => this.whitelist.addExact(e));
      }
      if (Array.isArray(options.whitelist.prefix)) {
        options.whitelist.prefix.forEach(p => this.whitelist.addPrefix(p));
      }
      if (Array.isArray(options.whitelist.pattern)) {
        options.whitelist.pattern.forEach(r => this.whitelist.addPattern(r));
      }
    }
  }

  detect(payload, context = {}) {
    if (this.whitelist.isWhitelisted(payload)) {
      return { label: 'benign', confidence: 0, whitelisted: true };
    }
    const variants = Normalizer.payloadVariants(payload, this.options);
    let allMatches = [];
    let maxConfidence = 0;
    let maxLabel = 'benign';
    let scores = {};

    let activeDetectors = this.detectors;
    if (context && context.source) {
      if (context.source === 'filename') {
        activeDetectors = this.detectors.filter(d => ['path-traversal', 'file-upload'].includes(d.name));
      } else if (context.source === 'header') {
        const headerChecks = ['crlf', 'xss', 'sqli', 'nosqli', 'cmdi', 'template-injection', 'ldap', 'graphql'];
        activeDetectors = this.detectors.filter(d => headerChecks.includes(d.name));
      }
    }

    const classification = classifyInputType(payload);
    const isQueryMode = this.options.mode === 'query';

    for (const detector of activeDetectors) {
      let signals = detector.getSignals();
      if (isQueryMode && detector.name === 'sqli') {
        signals = signals.filter(s => s.id !== 'sql-structural-boolean');
      }

      const matches = matchSignals(variants, signals, detector.label);
      const confidence = combineConfidence(matches);
      allMatches.push(...matches);
      scores[detector.name] = matches.length;
      if (confidence > maxConfidence) {
        maxConfidence = confidence;
        maxLabel = detector.label;
      }
    }

    const primaryVariant = variants.length > 0 ? variants[0] : payload;
    const anomalySignals = this.behavioralAnalyzer.analyze(primaryVariant, context);
    
    if (anomalySignals.length > 0) {
      const anomalyConfidence = combineConfidence(anomalySignals);
      allMatches.push(...anomalySignals);
      scores['behavioral'] = anomalySignals.length;
      
      if (anomalyConfidence > maxConfidence) {
        maxConfidence = anomalyConfidence;
        maxLabel = 'anomaly';
      }
    }

    if (context.route) {
      this.behavioralAnalyzer.incrementRequestCount();
    }

    let totalConfidence = Math.min(1.0, combineConfidence(allMatches));

    if (isQueryMode) {
      if (classification === 'complete-statement') {
        totalConfidence = totalConfidence * 0.3;
        maxConfidence = maxConfidence * 0.3;
      }
    }

    const blockThreshold = this.options.blockThreshold !== undefined ? this.options.blockThreshold : 0.5;
    const minimumSignals = this.options.minimumSignals !== undefined ? this.options.minimumSignals : 1;

    let finalLabel = totalConfidence === 0 ? 'benign' : maxLabel;

    if (finalLabel !== 'benign' && finalLabel !== 'anomaly') {
      let requiredSignals = minimumSignals;
      if (finalLabel === 'path-traversal') {
        requiredSignals = Math.max(requiredSignals, 2);
      }

      if (maxConfidence < blockThreshold || allMatches.length < requiredSignals) {
        finalLabel = 'anomaly';
      }
    }

    return {
      label: finalLabel,
      confidence: totalConfidence,
      scores,
      matches: allMatches
    };
  }
}
module.exports = { DetectionEngine };
