'use strict';

const { ForensicsReporter } = require('../src/forensics/reporter');

describe('ForensicsReporter', () => {
  let reporter;

  beforeEach(() => {
    reporter = new ForensicsReporter();
  });

  // 1. Instantiation with default maxSize
  test('should initialize with default maxSize of 1000', () => {
    expect(reporter.maxSize).toBe(1000);
    expect(reporter.buffer.length).toBe(0);
    expect(reporter.pointer).toBe(0);
  });

  // 2. Instantiation with custom maxSize
  test('should initialize with custom maxSize', () => {
    const customReporter = new ForensicsReporter(5);
    expect(customReporter.maxSize).toBe(5);
  });

  // 3. logBlock successfully adds an entry
  test('should log a block with provided details', () => {
    reporter.logBlock({
      ip: '192.168.1.1',
      method: 'POST',
      path: '/api/login',
      detector: 'sqli',
      confidence: 0.95,
      payload: 'admin'
    });

    const report = reporter.getReport();
    expect(report.length).toBe(1);
    expect(report[0].ip).toBe('192.168.1.1');
    expect(report[0].method).toBe('POST');
    expect(report[0].path).toBe('/api/login');
    expect(report[0].detector).toBe('sqli');
    expect(report[0].confidence).toBe(0.95);
    expect(report[0].payloadPreview).toBe('admin');
    expect(report[0].timestamp).toBeDefined();
  });

  // 4. logBlock handles missing fields with default values
  test('should handle missing fields with default values', () => {
    reporter.logBlock();
    const report = reporter.getReport();
    expect(report.length).toBe(1);
    expect(report[0].ip).toBe('unknown');
    expect(report[0].method).toBe('UNKNOWN');
    expect(report[0].path).toBe('/');
    expect(report[0].detector).toBe('unknown');
    expect(report[0].confidence).toBe(0);
    expect(report[0].payloadPreview).toBe('');
  });

  // 5. logBlock truncates payload to 200 characters
  test('should truncate long payloads to 200 characters', () => {
    const longPayload = 'A'.repeat(300);
    reporter.logBlock({ payload: longPayload });
    const report = reporter.getReport();
    expect(report[0].payloadPreview.length).toBe(203); // 200 + 3 for '...'
    expect(report[0].payloadPreview.endsWith('...')).toBe(true);
  });

  // 6. logBlock masks provided exploit strings
  test('should mask specific exploit strings if matchedStrings is provided', () => {
    reporter.logBlock({
      payload: 'SELECT * FROM users WHERE username = "admin" AND password = "password"',
      matchedStrings: ['SELECT * FROM']
    });
    const report = reporter.getReport();
    expect(report[0].payloadPreview).toContain('************* users WHERE');
    expect(report[0].payloadPreview).not.toContain('SELECT');
  });

  // 7. logBlock applies fallback masking when matchedStrings not provided
  test('should apply fallback masking for dangerous patterns', () => {
    reporter.logBlock({ payload: 'some valid data; DROP TABLE users; --' });
    const report = reporter.getReport();
    expect(report[0].payloadPreview).not.toContain('DROP TABLE');
    expect(report[0].payloadPreview).toContain('some valid data*** *** users*** ***');
  });

  // 8. Circular buffer overwrites oldest entry when full
  test('should overwrite oldest entry when buffer reaches maxSize', () => {
    const smallReporter = new ForensicsReporter(3);
    smallReporter.logBlock({ payload: 'entry 1' });
    smallReporter.logBlock({ payload: 'entry 2' });
    smallReporter.logBlock({ payload: 'entry 3' });
    smallReporter.logBlock({ payload: 'entry 4' }); // Should overwrite entry 1

    const report = smallReporter.getReport();
    expect(report.length).toBe(3);
    expect(report[0].payloadPreview).toBe('entry 2');
    expect(report[1].payloadPreview).toBe('entry 3');
    expect(report[2].payloadPreview).toBe('entry 4');
  });

  // 9. getReport returns the correct chronological order when partially full
  test('should return chronological order when buffer is not full', () => {
    reporter.logBlock({ payload: 'first' });
    reporter.logBlock({ payload: 'second' });

    const report = reporter.getReport();
    expect(report.length).toBe(2);
    expect(report[0].payloadPreview).toBe('first');
    expect(report[1].payloadPreview).toBe('second');
  });

  // 10. clear() successfully resets the reporter
  test('should clear the buffer completely', () => {
    reporter.logBlock({ payload: 'data' });
    expect(reporter.getReport().length).toBe(1);
    
    reporter.clear();
    expect(reporter.getReport().length).toBe(0);
    expect(reporter.buffer.length).toBe(0);
    expect(reporter.pointer).toBe(0);
  });
});
