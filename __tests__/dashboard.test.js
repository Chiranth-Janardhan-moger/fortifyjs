const { createDashboardHandler } = require('../src/dashboard/handler');
const { Logger } = require('../src/logger');

describe('Dashboard Handler', () => {
  let req, res, next, logger, middleware;
  
  beforeEach(() => {
    logger = new Logger({ level: 'debug' });
    req = { path: '/__fortifyjs/dashboard' };
    res = { setHeader: jest.fn(), end: jest.fn() };
    next = jest.fn();
    middleware = createDashboardHandler({ auth: (req, res, next) => next() }, logger);
  });

  it('1. passes through unrelated routes', () => {
    req.path = '/api/other';
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });
  it('2. serves HTML on dashboard path', () => {
    middleware(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/html; charset=utf-8');
    expect(res.end).toHaveBeenCalledWith(expect.stringContaining('<!DOCTYPE html>'));
  });
  it('3. serves HTML on dashboard path with trailing slash', () => {
    req.path = '/__fortifyjs/dashboard/';
    middleware(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/html; charset=utf-8');
  });
  it('4. serves /api/events as JSON', () => {
    req.path = '/__fortifyjs/dashboard/api/events';
    middleware(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/json');
    expect(res.end).toHaveBeenCalledWith(expect.stringContaining('[]'));
  });
  it('5. serves /api/stats as JSON', () => {
    req.path = '/__fortifyjs/dashboard/api/stats';
    middleware(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/json');
    expect(res.end).toHaveBeenCalledWith(expect.stringContaining('"blocked":0'));
  });
  it('6. correctly computes stats from logger', () => {
    logger.warn('threat', { meta: { action: 'block', label: 'sqli' } });
    logger.warn('threat', { meta: { action: 'block', label: 'sqli' } });
    logger.warn('threat', { meta: { action: 'flag', label: 'xss' } });
    req.path = '/__fortifyjs/dashboard/api/stats';
    middleware(req, res, next);
    const result = JSON.parse(res.end.mock.calls[0][0]);
    expect(result.blocked).toBe(2);
    expect(result.allowed).toBe(1);
    expect(result.topThreat).toBe('sqli');
  });
  it('7. api/events returns warning/error logs only', () => {
    logger.info('info log');
    logger.warn('warn log');
    req.path = '/__fortifyjs/dashboard/api/events';
    middleware(req, res, next);
    const result = JSON.parse(res.end.mock.calls[0][0]);
    expect(result.length).toBe(1);
  });
  it('8. supports custom path', () => {
    const mw = createDashboardHandler({ path: '/admin/sec' }, logger);
    req.path = '/admin/sec';
    mw(req, res, next);
    expect(res.end).toHaveBeenCalled();
  });
  it('9. executes auth middleware if provided', () => {
    const auth = jest.fn((req, res, next) => next(new Error('Unauthorized')));
    const mw = createDashboardHandler({ auth }, logger);
    mw(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
  it('10. auth middleware protects api/stats', () => {
    const auth = jest.fn((req, res, next) => next(new Error('Unauthorized')));
    const mw = createDashboardHandler({ auth }, logger);
    req.path = '/__fortifyjs/dashboard/api/stats';
    mw(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});
