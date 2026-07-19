'use strict';

const { BehavioralAnalyzer } = require('../src/analyzers/behavioral');

describe('Behavioral Analyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new BehavioralAnalyzer({
      entropyThreshold: 4.5,
      maxEncodingDepth: 3,
      specialCharRatio: 0.4
    });
  });

  it('detects high entropy payloads', () => {
    // Base64 encoded or encrypted strings usually have high entropy
    const payload = 'rO0ABXNyACp5c29zZXJpYWwucGF5bG9hZHMudXRpbC5HYWRnZXRzJFN0dWJUcmFuc2xldHhuAQAAAAAAAAABAgAN';
    const signals = analyzer.analyze(payload, { decodingIterations: 0, source: 'body' });
    expect(signals.some(s => s.id === 'high-entropy-payload')).toBe(true);
  });

  it('allows low entropy normal text', () => {
    const payload = 'This is a normal English sentence with low entropy.';
    const signals = analyzer.analyze(payload, { decodingIterations: 0, source: 'body' });
    expect(signals.some(s => s.id === 'high-entropy-payload')).toBe(false);
  });

  it('detects deep encoding', () => {
    const signals = analyzer.analyze('test', { decodingIterations: 4, source: 'query' });
    expect(signals.some(s => s.id === 'deep-encoding')).toBe(true);
  });

  it('detects structural anomalies (special char ratio)', () => {
    const payload = '!!@@##$$%%^^&&**()_+|~=`{}[]:;"\'<>,.?/';
    const signals = analyzer.analyze(payload, { decodingIterations: 0, source: 'query' });
    expect(signals.some(s => s.id === 'high-special-char-ratio')).toBe(true);
  });

  it('detects null bytes and control characters', () => {
    const signals1 = analyzer.analyze('test\x00payload', { decodingIterations: 0, source: 'body' });
    expect(signals1.some(s => s.id === 'null-bytes-present')).toBe(true);

    const signals2 = analyzer.analyze('test\x07payload', { decodingIterations: 0, source: 'body' });
    expect(signals2.some(s => s.id === 'control-chars-present')).toBe(true);
  });

  it('detects payload length anomalies', () => {
    const payload = 'A'.repeat(5000);
    const signals1 = analyzer.analyze(payload, { decodingIterations: 0, source: 'cookie' });
    expect(signals1.some(s => s.id === 'oversized-cookie')).toBe(true);

    const signals2 = analyzer.analyze(payload, { decodingIterations: 0, source: 'query', paramName: 'q' });
    expect(signals2.some(s => s.id === 'oversized-query-param')).toBe(true);
  });
});
