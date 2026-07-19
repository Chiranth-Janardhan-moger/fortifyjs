const createCsrfShield = require('../src/shields/csrf');

describe('CSRF Shield', () => {
  let req, res, next;
  beforeEach(() => {
    req = { method: 'POST', cookies: {}, headers: {}, path: '/api/data', body: {} };
    res = { setHeader: jest.fn() };
    next = jest.fn();
  });

  const getMiddleware = (opts) => createCsrfShield({ secret: 'test-secret', ...opts });

  it('1. ignores safe methods GET', () => {
    req.method = 'GET';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('2. ignores safe methods HEAD', () => {
    req.method = 'HEAD';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('3. ignores safe methods OPTIONS', () => {
    req.method = 'OPTIONS';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('4. blocks mutation without token', () => {
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].code).toBe('EBADCSRFTOKEN');
  });
  it('5. allows ignoreRoutes exact match', () => {
    req.path = '/webhook';
    getMiddleware({ ignoreRoutes: ['/webhook'] })(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('6. allows ignoreRoutes wildcard match', () => {
    req.path = '/webhooks/github';
    getMiddleware({ ignoreRoutes: ['/webhooks/*'] })(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('7. generates token for safe methods if missing', () => {
    req.method = 'GET';
    getMiddleware()(req, res, next);
    expect(res.setHeader).toHaveBeenCalledWith('Set-Cookie', expect.any(String));
  });
  it('8. does not generate token for safe methods if present', () => {
    req.method = 'GET';
    req.cookies = { '_fortify_csrf': 'valid.sig' };
    getMiddleware()(req, res, next);
    expect(res.setHeader).not.toHaveBeenCalled();
  });
  it('9. blocks invalid signature format', () => {
    req.cookies = { '_fortify_csrf': 'invalid' };
    req.headers['x-csrf-token'] = 'invalid';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].code).toBe('EBADCSRFTOKEN');
  });
  it('10. blocks mismatching tokens', () => {
    req.cookies = { '_fortify_csrf': 'a.b' };
    req.headers['x-csrf-token'] = 'c.d';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].code).toBe('EBADCSRFTOKEN');
  });
  it('11. parses cookies from string if req.cookies missing', () => {
    delete req.cookies;
    req.headers.cookie = '_fortify_csrf=invalid';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].code).toBe('EBADCSRFTOKEN');
  });
  it('12. reads token from x-csrf-token header', () => {
    req.cookies = { '_fortify_csrf': 'invalid' };
    req.headers['x-csrf-token'] = 'invalid';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
  it('13. reads token from x-xsrf-token header', () => {
    req.cookies = { '_fortify_csrf': 'invalid' };
    req.headers['x-xsrf-token'] = 'invalid';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
  it('14. reads token from req.body field', () => {
    req.cookies = { '_fortify_csrf': 'invalid' };
    req.body = { _csrf: 'invalid' };
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
  it('15. allows valid token workflow', () => {
    req.method = 'GET';
    const mw = getMiddleware();
    mw(req, res, next); // generates token
    const cookieCall = res.setHeader.mock.calls[0][1];
    const token = cookieCall.match(/_fortify_csrf=([^;]+)/)[1];
    
    req.method = 'POST';
    req.cookies = { '_fortify_csrf': token };
    req.headers['x-csrf-token'] = token;
    mw(req, res, next);
    expect(next).toHaveBeenCalledWith(); // success!
  });
  it('16. uses custom cookieName', () => {
    req.method = 'GET';
    getMiddleware({ cookieName: 'my_cookie' })(req, res, next);
    expect(res.setHeader.mock.calls[0][1]).toContain('my_cookie=');
  });
  it('17. uses custom headerName', () => {
    req.cookies = { '_fortify_csrf': 'invalid' };
    req.headers['x-custom-csrf'] = 'invalid';
    getMiddleware({ headerName: 'x-custom-csrf' })(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
  it('18. uses custom bodyField', () => {
    req.cookies = { '_fortify_csrf': 'invalid' };
    req.body = { custom_csrf: 'invalid' };
    getMiddleware({ bodyField: 'custom_csrf' })(req, res, next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
  it('19. secure cookie flag when secure: true', () => {
    req.method = 'GET';
    getMiddleware({ secure: true })(req, res, next);
    expect(res.setHeader.mock.calls[0][1]).toContain('Secure');
  });
  it('20. no secure cookie flag when secure: false', () => {
    req.method = 'GET';
    getMiddleware({ secure: false })(req, res, next);
    expect(res.setHeader.mock.calls[0][1]).not.toContain('Secure');
  });
});
