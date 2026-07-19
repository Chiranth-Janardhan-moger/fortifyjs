const createCorsShield = require('../src/shields/cors');

describe('CORS Shield', () => {
  let req, res, next;
  beforeEach(() => {
    req = { method: 'GET', headers: { origin: 'http://example.com' } };
    res = { setHeader: jest.fn(), end: jest.fn(), statusCode: 200 };
    next = jest.fn();
  });

  const getMiddleware = (opts) => createCorsShield(opts);

  it('1. skips if no origin', () => {
    delete req.headers.origin;
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('2. adds allow origin for *', () => {
    getMiddleware()(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', '*');
  });
  it('3. varies on origin if not *', () => {
    getMiddleware({ origin: 'http://example.com' })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Vary', 'Origin');
  });
  it('4. blocks unmatched string origin', () => {
    getMiddleware({ origin: 'http://other.com' })(req, res, next);
    expect(res.setHeader).not.toHaveBeenCalledWith('Access-Control-Allow-Origin', expect.any(String));
  });
  it('5. allows matched string origin', () => {
    getMiddleware({ origin: 'http://example.com' })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'http://example.com');
  });
  it('6. handles array of origins', () => {
    getMiddleware({ origin: ['http://example.com'] })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'http://example.com');
  });
  it('7. handles regex origins', () => {
    getMiddleware({ origin: /example\.com/ })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'http://example.com');
  });
  it('8. handles function origins', () => {
    getMiddleware({ origin: (o, cb) => cb(null, o) })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'http://example.com');
  });
  it('9. credentials=true sets header', () => {
    getMiddleware({ origin: 'http://example.com', credentials: true })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Credentials', 'true');
  });
  it('10. throws if credentials=true and origin=*', () => {
    expect(() => getMiddleware({ credentials: true })).toThrow();
  });
  it('11. sets exposed headers', () => {
    getMiddleware({ exposedHeaders: ['X-Custom'] })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Expose-Headers', 'X-Custom');
  });
  it('12. responds 204 to OPTIONS if unmatched origin', () => {
    req.method = 'OPTIONS';
    getMiddleware({ origin: 'http://other.com' })(req, res, next);
    expect(res.statusCode).toBe(204);
    expect(res.end).toHaveBeenCalled();
  });
  it('13. responds 204 to OPTIONS with headers', () => {
    req.method = 'OPTIONS';
    getMiddleware({ origin: 'http://example.com', methods: ['GET'], maxAge: 86400 })(req, res, next);
    expect(res.statusCode).toBe(204);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Methods', 'GET');
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Max-Age', '86400');
  });
  it('14. reflects access-control-request-headers', () => {
    req.method = 'OPTIONS';
    req.headers['access-control-request-headers'] = 'x-custom';
    getMiddleware({ origin: 'http://example.com' })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Headers', 'x-custom');
  });
  it('15. allows custom allowedHeaders in options', () => {
    req.method = 'OPTIONS';
    getMiddleware({ origin: 'http://example.com', allowedHeaders: 'x-allowed' })(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Headers', 'x-allowed');
  });
});
