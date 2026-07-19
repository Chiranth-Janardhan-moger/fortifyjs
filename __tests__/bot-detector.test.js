const createBotDetectorShield = require('../src/shields/bot-detector');

describe('Bot Detector Shield', () => {
  let req, res, next;
  beforeEach(() => {
    req = { headers: {} };
    res = {};
    next = jest.fn();
  });

  const getMiddleware = (opts) => createBotDetectorShield(opts);

  it('1. ignores if disabled', () => {
    getMiddleware({ enabled: false })(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('2. detects empty user-agent', () => {
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('empty-user-agent');
  });
  it('3. allows custom user-agent in allowList', () => {
    req.headers['user-agent'] = 'my-custom-bot';
    getMiddleware({ allowList: ['my-custom-bot'] })(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('4. allows known search engines', () => {
    req.headers['user-agent'] = 'Mozilla/5.0 Googlebot/2.1';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('5. blocks search engines if allowSearchEngines=false', () => {
    req.headers['user-agent'] = 'Mozilla/5.0 Googlebot/2.1';
    getMiddleware({ allowSearchEngines: false })(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('missing-browser-headers'); // without accept headers it falls here
  });
  it('6. blocks known bad bots', () => {
    req.headers['user-agent'] = 'python-requests/2.25.1';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('known-bad-bot');
  });
  it('7. flags instead of blocks if action=flag', () => {
    req.headers['user-agent'] = 'curl/7.68.0';
    getMiddleware({ action: 'flag' })(req, res, next);
    expect(req.isBot).toBe(true);
    expect(next).toHaveBeenCalledWith(); // no error
  });
  it('8. blocks headless browsers', () => {
    req.headers['user-agent'] = 'Mozilla/5.0 HeadlessChrome/80.0';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('headless-browser');
  });
  it('9. blocks missing browser headers on weird UA', () => {
    req.headers['user-agent'] = 'SomethingCustom';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('missing-browser-headers');
  });
  it('10. allows normal browser requests', () => {
    req.headers['user-agent'] = 'Mozilla/5.0 Chrome/100';
    req.headers['accept'] = 'text/html';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('11. respects custom blockList', () => {
    req.headers['user-agent'] = 'my-evil-bot';
    getMiddleware({ blockList: ['my-evil-bot'] })(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('known-bad-bot');
  });
  it('12. allows scrapy if removed from blockList', () => {
    req.headers['user-agent'] = 'scrapy/2.0';
    req.headers['accept'] = '*/*';
    getMiddleware({ blockList: [] })(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
  it('13. blocks phantomjs', () => {
    req.headers['user-agent'] = 'PhantomJS/2.1';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('headless-browser');
  });
  it('14. blocks puppeteer', () => {
    req.headers['user-agent'] = 'Puppeteer';
    getMiddleware()(req, res, next);
    expect(next.mock.calls[0][0].reason).toBe('headless-browser');
  });
  it('15. allows user-agent with accept-language', () => {
    req.headers['user-agent'] = 'CustomApp/1.0';
    req.headers['accept-language'] = 'en-US';
    getMiddleware()(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });
});
