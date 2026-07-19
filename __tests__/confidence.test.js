const { matchSignals, combineConfidence } = require('../src/core/confidence');

describe('Confidence', () => {
  it('should match signals based on RegExp pattern', () => {
    const variants = ["test payload"];
    const signals = [{ id: 's1', pattern: /test/, confidence: 0.5 }];
    const matches = matchSignals(variants, signals, 'SQLI');
    expect(matches.length).toBe(1);
    expect(matches[0].id).toBe('s1');
  });

  it('should match signals based on test function', () => {
    const variants = ["test payload"];
    const signals = [{ id: 's2', test: (v) => v.includes('payload'), confidence: 0.4 }];
    const matches = matchSignals(variants, signals, 'XSS');
    expect(matches.length).toBe(1);
    expect(matches[0].id).toBe('s2');
  });

  it('should not duplicate matches for the same signal ID', () => {
    const variants = ["test1", "test2"];
    const signals = [{ id: 's1', pattern: /test/, confidence: 0.5 }];
    const matches = matchSignals(variants, signals, 'SQLI');
    expect(matches.length).toBe(1);
  });

  it('should combine single confidence correctly', () => {
    const matches = [{ confidence: 0.5 }];
    expect(combineConfidence(matches)).toBeCloseTo(0.5);
  });

  it('should probabilistically combine two confidences', () => {
    const matches = [{ confidence: 0.5 }, { confidence: 0.5 }];
    // 0.5 + 0.5 * (1 - 0.5) = 0.75
    expect(combineConfidence(matches)).toBeCloseTo(0.75);
  });

  it('should combine three confidences', () => {
    const matches = [{ confidence: 0.5 }, { confidence: 0.5 }, { confidence: 0.5 }];
    // 1 - (1-0.5)^3 = 0.875
    expect(combineConfidence(matches)).toBeCloseTo(0.875);
  });

  it('should never exceed 1.0 confidence', () => {
    const matches = [{ confidence: 0.9 }, { confidence: 0.9 }, { confidence: 0.9 }];
    expect(combineConfidence(matches)).toBeLessThanOrEqual(1.0);
    expect(combineConfidence(matches)).toBeCloseTo(0.999);
  });

  it('should return 0 when no matches', () => {
    expect(combineConfidence([])).toBe(0);
  });

  it('should handle zero confidence match safely', () => {
    const matches = [{ confidence: 0.5 }, { confidence: 0 }];
    expect(combineConfidence(matches)).toBeCloseTo(0.5);
  });

  it('should match multiple signals and return array', () => {
    const variants = ["SELECT * FROM users WHERE id=1"];
    const signals = [
      { id: 'sql_select', pattern: /SELECT/i, confidence: 0.5 },
      { id: 'sql_where', pattern: /WHERE/i, confidence: 0.3 }
    ];
    const matches = matchSignals(variants, signals, 'SQLI');
    expect(matches.length).toBe(2);
    expect(matches.map(m => m.id)).toEqual(['sql_select', 'sql_where']);
  });
});
