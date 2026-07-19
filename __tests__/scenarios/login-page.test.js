'use strict';
const { DetectionEngine } = require('../../src/index');

describe('Scenario: Login Page Attacks', () => {
  let engine;
  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const runPayload = (payload) => engine.detect(payload);

  it('detects classic auth bypass', () => {
    const result = runPayload("admin'--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects boolean auth bypass', () => {
    const result = runPayload("admin' OR '1'='1'--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects MySQL comment auth bypass', () => {
    const result = runPayload("' OR 1=1#");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects block comment bypass', () => {
    const result = runPayload("admin'/*");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects UNION data extraction', () => {
    const result = runPayload("' UNION SELECT username, password FROM users--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SQLi in password', () => {
    const result = runPayload("' OR '1'='1");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects time-based blind SQLi', () => {
    const result = runPayload("1' AND SLEEP(5)#");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects NoSQL operator injection', () => {
    const result = runPayload('{"$gt":""}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects NoSQL not-equal bypass', () => {
    const result = runPayload('{"$ne":null}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects NoSQL regex extraction', () => {
    const result = runPayload('{"$regex":"^admin"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects JS URI in redirect', () => {
    const result = runPayload('javascript:alert(document.cookie)');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects data URI redirect', () => {
    const result = runPayload('data:text/html,<script>alert(1)</script>');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects reflected XSS in error msg', () => {
    const result = runPayload('<script>alert(1)</script>');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('allows benign username', () => {
    const result = runPayload("admin");
    expect(result.label).toBe('benign');
  });

  it('allows benign strong password', () => {
    const result = runPayload("MyS3cure!Pass#2026");
    expect(result.label).toBe('benign');
  });
});
