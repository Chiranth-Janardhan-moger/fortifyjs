'use strict';

const { DetectionEngine } = require('../src/core/engine');

describe('Confidence Calibration and Threshold Tuning', () => {
  let engine;

  beforeEach(() => {
    engine = new DetectionEngine();
    // clear default detectors to easily test threshold logic without noise
    engine.detectors = [];
    engine.behavioralAnalyzer = { 
      analyze: () => [],
      incrementRequestCount: () => {}
    };
  });

  const createMockDetector = (name, label, signals) => ({
    name,
    label,
    getSignals: () => signals
  });

  test('1. Should return specific attack label when maxConfidence >= blockThreshold and matches >= minimumSignals (defaults)', () => {
    engine.detectors.push(createMockDetector('test', 'test-attack', [
      { id: 't1', test: () => true, confidence: 0.6 }
    ]));
    const result = engine.detect('payload');
    expect(result.label).toBe('test-attack');
    expect(result.confidence).toBe(0.6);
  });

  test('2. Should return anomaly when maxConfidence < blockThreshold (default 0.5)', () => {
    engine.detectors.push(createMockDetector('test', 'test-attack', [
      { id: 't1', test: () => true, confidence: 0.4 }
    ]));
    const result = engine.detect('payload');
    expect(result.label).toBe('anomaly');
  });

  test('3. Should return benign when matches = 0', () => {
    const result = engine.detect('payload');
    expect(result.label).toBe('benign');
  });

  test('4. Should use custom blockThreshold and return attack if >= threshold', () => {
    engine = new DetectionEngine({ blockThreshold: 0.8 });
    engine.detectors = [createMockDetector('test', 'test-attack', [
      { id: 't1', test: () => true, confidence: 0.85 }
    ])];
    engine.behavioralAnalyzer = { analyze: () => [] };
    const result = engine.detect('payload');
    expect(result.label).toBe('test-attack');
  });

  test('5. Should use custom blockThreshold and return anomaly if < threshold', () => {
    engine = new DetectionEngine({ blockThreshold: 0.8 });
    engine.detectors = [createMockDetector('test', 'test-attack', [
      { id: 't1', test: () => true, confidence: 0.75 }
    ])];
    engine.behavioralAnalyzer = { analyze: () => [] };
    const result = engine.detect('payload');
    expect(result.label).toBe('anomaly');
  });

  test('6. Should use custom minimumSignals and return attack if >= minimumSignals', () => {
    engine = new DetectionEngine({ minimumSignals: 2 });
    engine.detectors = [createMockDetector('test', 'test-attack', [
      { id: 't1', test: () => true, confidence: 0.6 },
      { id: 't2', test: () => true, confidence: 0.6 }
    ])];
    engine.behavioralAnalyzer = { analyze: () => [] };
    const result = engine.detect('payload');
    expect(result.label).toBe('test-attack');
  });

  test('7. Should use custom minimumSignals and return anomaly if < minimumSignals', () => {
    engine = new DetectionEngine({ minimumSignals: 2 });
    engine.detectors = [createMockDetector('test', 'test-attack', [
      { id: 't1', test: () => true, confidence: 0.9 }
    ])];
    engine.behavioralAnalyzer = { analyze: () => [] };
    const result = engine.detect('payload');
    expect(result.label).toBe('anomaly');
  });

  test('8. path-traversal should return attack if matches >= 2 and maxConfidence >= blockThreshold', () => {
    engine.detectors = [createMockDetector('path-traversal', 'path-traversal', [
      { id: 'pt1', test: () => true, confidence: 0.6 },
      { id: 'pt2', test: () => true, confidence: 0.6 }
    ])];
    const result = engine.detect('payload');
    expect(result.label).toBe('path-traversal');
  });

  test('9. path-traversal should return anomaly if matches < 2 even if maxConfidence >= blockThreshold', () => {
    engine.detectors = [createMockDetector('path-traversal', 'path-traversal', [
      { id: 'pt1', test: () => true, confidence: 0.9 }
    ])];
    const result = engine.detect('payload');
    expect(result.label).toBe('anomaly');
  });

  test('10. path-traversal should return anomaly if maxConfidence < blockThreshold even if matches >= 2', () => {
    engine.detectors = [createMockDetector('path-traversal', 'path-traversal', [
      { id: 'pt1', test: () => true, confidence: 0.2 },
      { id: 'pt2', test: () => true, confidence: 0.2 }
    ])];
    const result = engine.detect('payload');
    expect(result.label).toBe('anomaly');
  });

  test('11. path-traversal should use Math.max(minimumSignals, 2) when minimumSignals = 3', () => {
    engine = new DetectionEngine({ minimumSignals: 3 });
    engine.detectors = [createMockDetector('path-traversal', 'path-traversal', [
      { id: 'pt1', test: () => true, confidence: 0.6 },
      { id: 'pt2', test: () => true, confidence: 0.6 }
    ])];
    engine.behavioralAnalyzer = { analyze: () => [] };
    const result = engine.detect('payload');
    expect(result.label).toBe('anomaly');
  });

  test('12. path-traversal should return attack when matches >= 3 and minimumSignals = 3', () => {
    engine = new DetectionEngine({ minimumSignals: 3 });
    engine.detectors = [createMockDetector('path-traversal', 'path-traversal', [
      { id: 'pt1', test: () => true, confidence: 0.6 },
      { id: 'pt2', test: () => true, confidence: 0.6 },
      { id: 'pt3', test: () => true, confidence: 0.6 }
    ])];
    engine.behavioralAnalyzer = { analyze: () => [] };
    const result = engine.detect('payload');
    expect(result.label).toBe('path-traversal');
  });
});
