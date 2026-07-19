'use strict';

const { Whitelist } = require('../src/core/whitelist');
const { DetectionEngine } = require('../src/core/engine');

describe('Whitelist', () => {
  let whitelist;
  
  beforeEach(() => {
    whitelist = new Whitelist();
  });

  test('should match exact string', () => {
    whitelist.addExact('hello');
    expect(whitelist.isWhitelisted('hello')).toBe(true);
    expect(whitelist.isWhitelisted('hello world')).toBe(false);
  });

  test('should match prefix', () => {
    whitelist.addPrefix('hello');
    expect(whitelist.isWhitelisted('hello world')).toBe(true);
    expect(whitelist.isWhitelisted('hi world')).toBe(false);
  });

  test('should match pattern', () => {
    whitelist.addPattern(/^test[0-9]+$/);
    expect(whitelist.isWhitelisted('test123')).toBe(true);
    expect(whitelist.isWhitelisted('test')).toBe(false);
  });

  test('should support multiple exact matches', () => {
    whitelist.addExact('foo');
    whitelist.addExact('bar');
    expect(whitelist.isWhitelisted('foo')).toBe(true);
    expect(whitelist.isWhitelisted('bar')).toBe(true);
    expect(whitelist.isWhitelisted('baz')).toBe(false);
  });

  test('should support multiple prefixes', () => {
    whitelist.addPrefix('pre1');
    whitelist.addPrefix('pre2');
    expect(whitelist.isWhitelisted('pre1_test')).toBe(true);
    expect(whitelist.isWhitelisted('pre2_test')).toBe(true);
    expect(whitelist.isWhitelisted('pre3_test')).toBe(false);
  });

  test('should support multiple patterns', () => {
    whitelist.addPattern(/foo/);
    whitelist.addPattern(/bar/);
    expect(whitelist.isWhitelisted('this is foo')).toBe(true);
    expect(whitelist.isWhitelisted('this is bar')).toBe(true);
    expect(whitelist.isWhitelisted('this is baz')).toBe(false);
  });

  test('empty whitelist matches nothing', () => {
    expect(whitelist.isWhitelisted('anything')).toBe(false);
    expect(whitelist.isWhitelisted('')).toBe(false);
  });

  test('exact match is case sensitive', () => {
    whitelist.addExact('Test');
    expect(whitelist.isWhitelisted('test')).toBe(false);
  });

  test('prefix match is case sensitive', () => {
    whitelist.addPrefix('Pre');
    expect(whitelist.isWhitelisted('pre_fix')).toBe(false);
  });

  test('pattern match with case insensitivity works', () => {
    whitelist.addPattern(/test/i);
    expect(whitelist.isWhitelisted('TEST')).toBe(true);
  });

  test('DetectionEngine skips detection for exact whitelist match', () => {
    const engine = new DetectionEngine({
      whitelist: { exact: ['1=1'] }
    });
    const result = engine.detect('1=1');
    expect(result.whitelisted).toBe(true);
    expect(result.label).toBe('benign');
    expect(result.confidence).toBe(0);
  });

  test('DetectionEngine skips detection for prefix whitelist match', () => {
    const engine = new DetectionEngine({
      whitelist: { prefix: ['trusted_'] }
    });
    const result = engine.detect('trusted_<script>alert(1)</script>');
    expect(result.whitelisted).toBe(true);
    expect(result.label).toBe('benign');
    expect(result.confidence).toBe(0);
  });

  test('DetectionEngine skips detection for pattern whitelist match', () => {
    const engine = new DetectionEngine({
      whitelist: { pattern: [/^allow_.*_end$/] }
    });
    const result = engine.detect('allow_UNION SELECT_end');
    expect(result.whitelisted).toBe(true);
    expect(result.label).toBe('benign');
    expect(result.confidence).toBe(0);
  });

  test('DetectionEngine returns normal result when not whitelisted', () => {
    const engine = new DetectionEngine({
      whitelist: { exact: ['safe'] }
    });
    const result = engine.detect('unsafe payload <script>');
    expect(result.whitelisted).toBeUndefined();
  });

  test('DetectionEngine handles undefined whitelist gracefully', () => {
    const engine = new DetectionEngine({});
    const result = engine.detect('payload');
    expect(result.whitelisted).toBeUndefined();
  });
});
