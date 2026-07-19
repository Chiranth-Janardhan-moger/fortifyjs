const { shield, PRESETS } = require('../src/presets');

describe('Presets & Shield Factory', () => {
  it('1. throws on unknown tier', () => {
    expect(() => shield('unknown-tier')).toThrow();
  });
  it('2. defaults to basic if tier is an object', () => {
    const mw = shield({ rateLimit: false });
    expect(typeof mw).toBe('function');
  });
  it('3. returns a middleware function for basic', () => {
    expect(typeof shield('basic')).toBe('function');
  });
  it('4. returns a middleware function for medium', () => {
    expect(typeof shield('medium')).toBe('function');
  });
  it('5. returns a middleware function for hard', () => {
    expect(typeof shield('hard')).toBe('function');
  });
  it('6. returns a middleware function for advanced', () => {
    expect(typeof shield('advanced')).toBe('function');
  });
  it('7. allows overriding properties', () => {
    const mw = shield('basic', { rateLimit: false });
    expect(typeof mw).toBe('function');
  });
  it('8. middleware stack processes requests', async () => {
    const mw = shield('basic', { rateLimit: false, botDetection: false, cors: false, headers: false, csrf: false, behavioral: false });
    const req = { path: '/' };
    const res = {};
    const next = jest.fn();
    await new Promise(resolve => {
      mw(req, res, (err) => {
        if (err) next(err);
        else next();
        resolve();
      });
    });
    expect(next).toHaveBeenCalled();
  });
  it('9. catches errors in stack', async () => {
    const mw = shield('hard', { rateLimit: false, headers: false, cors: false });
    const req = { method: 'POST', cookies: {}, headers: {}, body: {} }; // no csrf token
    const res = {};
    const next = jest.fn();
    await new Promise(resolve => {
      mw(req, res, (err) => {
        if (err) next(err);
        else next();
        resolve();
      });
    });
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
  it('10. exposes PRESETS map', () => {
    expect(PRESETS).toHaveProperty('basic');
    expect(PRESETS).toHaveProperty('advanced');
  });
});
