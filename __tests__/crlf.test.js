'use strict';

const { DetectionEngine } = require('../src/core/engine');

describe('CRLF Injection Detector', () => {
  let engine;

  beforeEach(() => {
    engine = new DetectionEngine({ blockThreshold: 0 });
  });

  const testPayload = (payload, expectedLabel) => {
    const result = engine.detect(payload);
    expect(result.label).toBe(expectedLabel);
  };

  it('detects standard CRLF with Set-Cookie', () => {
    testPayload('\r\nSet-Cookie: evil=1', 'crlf');
  });

  it('detects URL encoded CRLF with Location', () => {
    testPayload('%0d%0aLocation: http://evil.com', 'crlf');
  });

  it('detects LF only with Bcc', () => {
    testPayload('\nBcc: attacker@evil.com', 'crlf');
  });

  it('detects CR only with Content-Type', () => {
    testPayload('\rContent-Type: text/html', 'crlf');
  });

  it('detects UTF-8 overlong encoded CRLF with Host', () => {
    testPayload('%E5%98%8A%E5%98%8DHost: evil.com', 'crlf');
  });

  it('detects Unicode encoded CRLF with Content-Length', () => {
    testPayload('\\u000d\\u000aContent-Length: 0', 'crlf');
  });

  it('detects CRLF with spaces before header', () => {
    testPayload('\r\n  X-Forwarded-For: 127.0.0.1', 'crlf');
  });

  it('detects log injection with info tag', () => {
    testPayload('\r\n[info] User admin logged in', 'crlf');
  });

  it('detects log injection with date', () => {
    testPayload('%0d%0a2023-10-01 12:00:00 malicious entry', 'crlf');
  });

  it('detects log injection with IP', () => {
    testPayload('\n 192.168.1.1 accessed secret', 'crlf');
  });

  it('detects log injection with error tag', () => {
    testPayload('\r\n[error] Failed to load', 'crlf');
  });

  it('detects newline alone as crlf', () => {
    const result = engine.detect('\r\n');
    expect(result.scores['crlf']).toBeGreaterThan(0);
  });

  it('allows benign text without newlines', () => {
    testPayload('just some text', 'benign');
  });

  it('allows benign text with encoded space but no newline', () => {
    testPayload('hello%20world', 'benign');
  });

  it('detects CRLF with Authorization header', () => {
    testPayload('\r\nAuthorization: Basic YWRtaW46YWRtaW4=', 'crlf');
  });
  
  it('detects CRLF with X-Powered-By header', () => {
    testPayload('\r\n-Powered-By: PHP', 'crlf');
  });
});
