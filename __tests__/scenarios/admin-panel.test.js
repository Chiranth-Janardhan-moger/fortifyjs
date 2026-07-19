'use strict';
const { DetectionEngine } = require('../../src/index');

describe('Scenario: Admin Panel Attacks', () => {
  let engine;
  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const runPayload = (payload) => engine.detect(payload);

  it('detects Command injection (semicolon)', () => {
    const result = runPayload("ls -la; cat /etc/passwd");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Command chaining (AND)', () => {
    const result = runPayload("ping 127.0.0.1 && cat /etc/passwd");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Pipe command injection', () => {
    const result = runPayload("ping 127.0.0.1 | cat /etc/shadow");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Backtick command substitution', () => {
    const result = runPayload("`whoami`");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Dollar-paren command sub', () => {
    const result = runPayload("$(cat /etc/passwd)");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Prototype pollution escalation', () => {
    const result = runPayload('{"__proto__":{"isAdmin":true}}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SQLi in bulk operation', () => {
    const result = runPayload("1,2,3); DROP TABLE users;--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('allows benign admin command', () => {
    const result = runPayload("status");
    expect(result.label).toBe('benign');
  });

  it('allows benign config update', () => {
    const result = runPayload('{"mode":"production"}');
    expect(result.label).toBe('benign');
  });

  it('allows benign admin search', () => {
    const result = runPayload("recent account activity");
    expect(result.label).toBe('benign');
  });
});
