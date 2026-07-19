const { DetectionEngine, Normalizer, fortifyjsQueryError, assertSafeSqlQuery, evaluatePayloads, scanSqlQuery } = require('../src/index');

describe('DetectionEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new DetectionEngine();
  });

  test('should detect benign payloads', () => {
    const result = engine.detect('hello world');
    expect(result.label).toBe('benign');
    expect(result.confidence).toBe(0);
  });

  test('should detect basic SQLi', () => {
    const result = engine.detect("' OR '1'='1");
    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should detect basic XSS', () => {
    const result = engine.detect('<script>alert("XSS")</script>');
    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should not false positive on bare single quote or names', () => {
    const result1 = engine.detect("O'Brien");
    const result2 = engine.detect("SELECT * FROM users WHERE name = 'test'");
    expect(result1.label).toBe('benign');
    expect(result2.label).toBe('benign');
  });

  test('should detect comment obfuscated SQLi bypasses', () => {
    const result = engine.detect("UN/**/ION SEL/**/ECT * FROM users");
    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should detect multi-encoded payloads', () => {
    // %253Cscript%253Ealert(1)%253C%252Fscript%253E -> %3Cscript%3E... -> <script>...
    const result = engine.detect('%253Cscript%253Ealert(1)%253C%252Fscript%253E');
    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should detect legacy unicode-escaped XSS payloads', () => {
    const result = engine.detect('%u003Cscript%u003Ealert(1)%u003C/script%u003E');
    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should detect control-character split XSS payloads', () => {
    const result = engine.detect('java\u0000script:alert(1)');
    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should detect plus-separated SQLi payloads', () => {
    const result = engine.detect('UNION+SELECT+password+FROM+users');
    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should detect HTML entity encoded XSS payloads', () => {
    expect(engine.detect('&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;').label).toBe('xss');
    expect(engine.detect('&lt;script&gt;alert(1)&lt;/script&gt;').label).toBe('xss');
  });

  test('should detect comment-terminated auth bypasses', () => {
    expect(engine.detect("admin'--").label).toBe('sqli');
    expect(engine.detect("admin' --").label).toBe('sqli');
    expect(engine.detect("admin'#").label).toBe('sqli');
  });

  test('should support sink-side final SQL query scanning for second-order injection risk', () => {
    const safe = scanSqlQuery('SELECT * FROM users WHERE id = $1');

    expect(safe.label).toBe('benign');
    expect(() => assertSafeSqlQuery("SELECT * FROM users WHERE name = 'admin' OR 2>1")).toThrow(fortifyjsQueryError);
  });

  test('should attach detection details to unsafe SQL query errors', () => {
    try {
      assertSafeSqlQuery('SELECT * FROM users; DROP TABLE users');
      throw new Error('expected query guard to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(fortifyjsQueryError);
      expect(error.result.label).toBe('sqli');
      expect(error.result.confidence).toBeGreaterThanOrEqual(0.5);
    }
  });

  test('should evaluate labeled traffic samples for threshold tuning', () => {
    const report = evaluatePayloads([
      { payload: 'hello world', label: 'benign' },
      { payload: 'Please select your favorite color', label: 'benign' },
      { payload: "admin' OR 2>1", label: 'sqli' },
      { payload: '<script>alert(1)</script>', label: 'xss' }
    ]);

    expect(report.summary).toEqual(expect.objectContaining({
      total: 4,
      labeled: 4,
      falsePositives: 0,
      falseNegatives: 0,
      truePositives: 2,
      trueNegatives: 2,
      falsePositiveRate: 0,
      falseNegativeRate: 0
    }));
  });

  describe('Comprehensive 27-Vector Regression Suite', () => {
    test('Benign Text & Normal English', () => {
      const benignPayloads = [
        "hello world",
        "O'Brien",
        "SELECT * FROM users WHERE name = 'test'",
        "The script is ready",
        "javascript is a programming language",
        "I need to drop by the table",
        "Nothing to see here"
      ];
      for (const payload of benignPayloads) {
        expect(engine.detect(payload).label).toBe('benign');
      }
    });

    test('Standard SQL Injection (SQLi)', () => {
      const sqliPayloads = [
        "' OR '1'='1",
        "admin'--",
        "admin' #",
        "UNION SELECT * FROM users",
        "DROP TABLE users;",
        "UPDATE accounts SET balance=0",
        "INSERT INTO users (name) VALUES ('x')"
      ];
      for (const payload of sqliPayloads) {
        expect(engine.detect(payload).label).toBe('sqli');
      }
    });

    test('Obfuscated SQL Injection', () => {
      const obfuscatedSqli = [
        "UN/**/ION SEL/**/ECT * FROM users",
        "%55%4e%49%4f%4e%20%53%45%4c%45%43%54", // UNION SELECT
        "admin%27--" // admin'--
      ];
      for (const payload of obfuscatedSqli) {
        expect(engine.detect(payload).label).toBe('sqli');
      }
    });

    test('Cross-Site Scripting (XSS) with tags', () => {
      const xssPayloads = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')",
        "<img onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">"
      ];
      for (const payload of xssPayloads) {
        expect(engine.detect(payload).label).toBe('xss');
      }
    });

    test('XSS without HTML Tags (Attribute Injection & Pseudo-protocols)', () => {
      const attributeXss = [
        "javascript:alert(1)",
        "onmouseover=\"alert(1)",
        "onfocus=eval(1)"
      ];
      for (const payload of attributeXss) {
        expect(engine.detect(payload).label).toBe('xss');
      }
    });

  });
});
