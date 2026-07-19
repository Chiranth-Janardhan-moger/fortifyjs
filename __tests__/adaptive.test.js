'use strict';

const { AdaptiveBlocker } = require('../src/analyzers/adaptive');

describe('AdaptiveBlocker', () => {
  let blocker;

  beforeEach(() => {
    blocker = new AdaptiveBlocker({
      windowMs: 1000,
      threshold: 2,
      blockDurationMs: 2000
    });
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test('should initialize with default options', () => {
    const defaultBlocker = new AdaptiveBlocker();
    expect(defaultBlocker.windowMs).toBe(60000);
    expect(defaultBlocker.threshold).toBe(5);
    expect(defaultBlocker.blockDurationMs).toBe(300000);
  });

  test('should record anomaly and not block if under threshold', () => {
    blocker.recordAnomaly('1.1.1.1');
    expect(blocker.isBlocked('1.1.1.1')).toBe(false);
  });

  test('should block IP when anomalies exceed threshold', () => {
    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1'); // 3 > 2 threshold
    expect(blocker.isBlocked('1.1.1.1')).toBe(true);
  });

  test('should not block if anomalies are spread out beyond window', () => {
    blocker.recordAnomaly('1.1.1.1');
    jest.advanceTimersByTime(1100);
    blocker.recordAnomaly('1.1.1.1');
    jest.advanceTimersByTime(1100);
    blocker.recordAnomaly('1.1.1.1');
    expect(blocker.isBlocked('1.1.1.1')).toBe(false);
  });

  test('should unblock IP after block duration expires', () => {
    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1');
    expect(blocker.isBlocked('1.1.1.1')).toBe(true);
    
    jest.advanceTimersByTime(2100);
    expect(blocker.isBlocked('1.1.1.1')).toBe(false);
  });

  test('should cleanup old anomalies', () => {
    blocker.recordAnomaly('1.1.1.1');
    jest.advanceTimersByTime(1100);
    blocker.cleanup();
    expect(blocker.anomalies.has('1.1.1.1')).toBe(false);
  });

  test('should cleanup expired blocks', () => {
    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1');
    expect(blocker.blocks.has('1.1.1.1')).toBe(true);
    
    jest.advanceTimersByTime(2100);
    blocker.cleanup();
    expect(blocker.blocks.has('1.1.1.1')).toBe(false);
  });

  test('middleware should pass through when not blocked', () => {
    const middleware = blocker.middleware();
    const req = { ip: '1.1.1.1' };
    const res = { on: jest.fn() };
    const next = jest.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('middleware should block requests if IP is blocked', () => {
    const middleware = blocker.middleware();
    const req = { ip: '1.1.1.1' };
    const res = { 
      status: jest.fn().mockReturnThis(), 
      json: jest.fn(),
      on: jest.fn()
    };
    const next = jest.fn();

    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1');
    blocker.recordAnomaly('1.1.1.1');

    middleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.json).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  test('middleware should record anomaly on response finish if detected', () => {
    const middleware = blocker.middleware();
    const req = { 
      ip: '1.1.1.1',
      fortifyjsDetections: [{ detected: true, label: 'xss' }]
    };
    
    let finishCallback;
    const res = { 
      on: jest.fn((event, cb) => {
        if (event === 'finish') finishCallback = cb;
      })
    };
    const next = jest.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    
    finishCallback();
    
    expect(blocker.anomalies.get('1.1.1.1').length).toBe(1);
  });
});
