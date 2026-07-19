'use strict';
const { DetectionEngine } = require('../../src/index');

describe('Scenario: Search Functionality Attacks', () => {
  let engine;
  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const runPayload = (payload) => engine.detect(payload);

  it('detects UNION schema dump', () => {
    const result = runPayload("' UNION SELECT table_name FROM information_schema.tables--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Column count probe', () => {
    const result = runPayload("' OR 1=1 ORDER BY 1--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Double-quote tautology', () => {
    const result = runPayload('" OR ""="');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Reflected XSS img tag', () => {
    const result = runPayload("<img src=1 onerror=alert(1)>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Tag breakout XSS', () => {
    const result = runPayload('"><svg/onload=alert(1)>');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects NoSQL injection in filter', () => {
    const result = runPayload('{"category":{"$gt":""}}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects URL-encoded SQLi', () => {
    const result = runPayload("%27%20OR%201%3D1--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('allows benign search', () => {
    const result = runPayload("laptop");
    expect(result.label).toBe('benign');
  });

  it('allows benign with apostrophe', () => {
    const result = runPayload("blue women's shoes size 8");
    expect(result.label).toBe('benign');
  });

  it('allows benign quoted search', () => {
    const result = runPayload('"exact phrase" search');
    expect(result.label).toBe('benign');
  });
});
