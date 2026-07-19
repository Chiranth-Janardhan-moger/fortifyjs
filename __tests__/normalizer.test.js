const { Normalizer } = require('../src/core/normalizer');

describe('Normalizer', () => {
  it('should decode URL encoded payload', () => {
    expect(Normalizer.decodeDeeply('%27')).toBe("'");
  });

  it('should decode double/triple URL encoded payload', () => {
    expect(Normalizer.decodeDeeply('%252527')).toBe("'");
    expect(Normalizer.decodeDeeply('%2527')).toBe("'");
  });

  it('should safely fallback when decodeURIComponent throws', () => {
    // %c0%af is an overlong encoding for / and throws in strict decodeURIComponent
    expect(Normalizer.decodeDeeply('a%00b%c0%afc')).toBe('ab\xC0 \u0304c');
  });

  it('should decode hex entities', () => {
    expect(Normalizer.decodeDeeply('&#x27;')).toBe("'");
  });

  it('should decode decimal entities', () => {
    expect(Normalizer.decodeDeeply('&#39;')).toBe("'");
  });

  it('should decode named entities', () => {
    expect(Normalizer.decodeDeeply('&lt;script&gt;')).toBe('<script>');
  });

  it('should normalize Unicode', () => {
    expect(Normalizer.decodeDeeply('\uFEFF')).toBe('');
    expect(Normalizer.decodeDeeply('\u2000')).toBe(' ');
  });

  it('should strip null bytes', () => {
    expect(Normalizer.decodeDeeply('a\x00b')).toBe('ab');
  });

  it('should handle unicode escapes', () => {
    expect(Normalizer.decodeDeeply('\\u0027')).toBe("'");
    expect(Normalizer.decodeDeeply('\\u{27}')).toBe("'");
  });

  it('should handle hex escapes', () => {
    expect(Normalizer.decodeDeeply('\\x27')).toBe("'");
  });

  it('should preserve SQL block comments depending on mode', () => {
    expect(Normalizer.normalizePayload('SELECT/*test*/1', { sqlCommentMode: 'preserve' })).toBe('SELECT/*test*/1');
    expect(Normalizer.normalizePayload('SELECT/*test*/1', { sqlCommentMode: 'space' })).toBe('SELECT 1');
    expect(Normalizer.normalizePayload('SELECT/*test*/1', { sqlCommentMode: 'remove' })).toBe('SELECT1');
  });

  it('should preserve MySQL versioned comments', () => {
    expect(Normalizer.normalizePayload('/*!12345 UNION */', { sqlCommentMode: 'space' }).trim()).toBe('MYSQL_VERSIONED_COMMENT UNION');
  });

  it('should return multiple variants', () => {
    const variants = Normalizer.payloadVariants('SELECT/*foo*/1');
    expect(variants).toContain('SELECT/*foo*/1');
    expect(variants).toContain('SELECT 1');
    expect(variants).toContain('SELECT1');
  });

  it('should handle non-string payloads by coercing or returning empty string', () => {
    expect(Normalizer.decodeDeeply(123)).toBe('');
    expect(Normalizer.decodeDeeply(null)).toBe('');
  });

  it('should truncate large payloads safely', () => {
    const large = 'A'.repeat(100000);
    const decoded = Normalizer.decodeDeeply(large, 50000);
    expect(decoded.length).toBeLessThan(100000);
    expect(decoded).toContain('fortifyjs_TRUNCATED');
  });
});
