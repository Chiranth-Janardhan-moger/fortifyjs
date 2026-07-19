const request = require('supertest');
const express = require('express');
const { fortifyjs } = require('../src/adapters/express');

describe('Express Adapter Edge Cases', () => {
  let app;
  let guard;

  beforeEach(() => {
    app = express();
    guard = fortifyjs({
      mode: 'block',
      maxDepth: 3,
      maxFields: 10,
      detector: {
        detect: (str) => {
          if (str.includes('malicious')) {
            return { label: 'sqli', confidence: 1, matches: [] };
          }
          if (str === 'throw') {
            throw new Error('Test Error');
          }
          return { label: 'benign', confidence: 0 };
        }
      }
    });
  });

  // 1. req.body is a Buffer (Benign)
  it('should handle req.body as a benign Buffer', async () => {
    app.use((req, res, next) => { req.body = Buffer.from('hello'); next(); });
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/');
    expect(res.status).toBe(200);
  });

  // 2. req.body is a Buffer (Malicious)
  it('should handle req.body as a malicious Buffer', async () => {
    app.use((req, res, next) => { req.body = Buffer.from('malicious payload'); next(); });
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/');
    expect(res.status).toBe(403);
  });

  // 3. req.query is nested (Benign)
  it('should handle nested req.query correctly (Benign)', async () => {
    app.use(express.urlencoded({ extended: true }));
    app.use(guard.global());
    app.get('/', (req, res) => res.send('ok'));
    const res = await request(app).get('/?a[b][c]=hello');
    expect(res.status).toBe(200);
  });

  // 4. req.query is nested (Malicious)
  it('should handle nested req.query correctly (Malicious)', async () => {
    app.use(express.urlencoded({ extended: true }));
    app.use(guard.global());
    app.get('/', (req, res) => res.send('ok'));
    const res = await request(app).get('/?a[b][c]=malicious');
    expect(res.status).toBe(403);
  });

  // 5. req.cookies is undefined
  it('should handle undefined req.cookies without crashing', async () => {
    // Note: cookie-parser is not used, so req.cookies is undefined
    app.use(guard.global());
    app.get('/', (req, res) => res.send('ok'));
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
  });

  // 6. req.cookies is defined and malicious
  it('should detect malicious cookies if defined', async () => {
    app.use((req, res, next) => { req.cookies = { session: 'malicious' }; next(); });
    app.use(guard.global());
    app.get('/', (req, res) => res.send('ok'));
    const res = await request(app).get('/');
    expect(res.status).toBe(403);
  });

  // 7. Max Depth exceeded
  it('should block if max depth is exceeded', async () => {
    app.use(express.json());
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/').send({ a: { b: { c: { d: { e: 'too deep' } } } } });
    expect(res.status).toBe(403);
    expect(res.body.details.label).toBe('dos');
  });

  // 8. Max Fields exceeded
  it('should block if max fields is exceeded', async () => {
    app.use(express.json());
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const payload = {};
    for (let i = 0; i < 15; i++) payload[`key${i}`] = 'val';
    const res = await request(app).post('/').send(payload);
    expect(res.status).toBe(403);
    expect(res.body.details.label).toBe('dos');
  });

  // 9. req.body is a primitive number
  it('should not crash if req.body is a number', async () => {
    app.use(express.json({ strict: false }));
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/').send('12345').set('Content-Type', 'application/json');
    expect(res.status).toBe(200);
  });

  // 10. req.body is an array
  it('should scan array elements in req.body', async () => {
    app.use(express.json());
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/').send(['hello', 'malicious']);
    expect(res.status).toBe(403);
  });

  // 11. Async/Await unhandled rejection test
  it('should catch errors thrown by detector and pass to next(err)', async () => {
    app.use(express.json());
    app.use(guard.global());
    app.use((err, req, res, next) => {
      res.status(500).send(err.message);
    });
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/').send({ payload: 'throw' });
    expect(res.status).toBe(500);
    expect(res.text).toBe('Test Error');
  });

  // 12. req.params are scanned
  it('should scan req.params when enabled', async () => {
    app.get('/:id', guard.global({ scanParams: true }), (req, res) => res.send('ok'));
    const res = await request(app).get('/malicious');
    expect(res.status).toBe(403);
  });

  // 13. skip function resolves asynchronously
  it('should properly await skip function', async () => {
    const asyncSkip = async (req) => {
      return new Promise(resolve => setTimeout(() => resolve(true), 10));
    };
    app.use(guard.global({ skip: asyncSkip }));
    app.get('/', (req, res) => res.send('ok'));
    const res = await request(app).get('/?q=malicious');
    expect(res.status).toBe(200); // Because it skipped
  });

  // 14. Nested Buffer in object
  it('should scan Buffer properties inside objects', async () => {
    app.use((req, res, next) => { req.body = { file: Buffer.from('malicious') }; next(); });
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/');
    expect(res.status).toBe(403);
  });

  // 15. Object enumeration failure (Dos protection)
  it('should block if object enumeration fails', async () => {
    app.use((req, res, next) => {
      const obj = {};
      Object.defineProperty(obj, 'entries', { get: () => { throw new Error('fail'); } });
      req.body = new Map(); // isMap will be true
      req.body.entries = () => { throw new Error('fail'); };
      next();
    });
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/');
    expect(res.status).toBe(403);
    expect(res.body.details.label).toBe('dos');
  });

  // 16. scanKeys scans object keys
  it('should scan object keys if scanKeys is true', async () => {
    app.use(express.json());
    app.use(guard.global({ scanKeys: true }));
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/').send({ 'malicious_key': 'value' });
    expect(res.status).toBe(403);
  });

  // 17. Null prototype object
  it('should handle Object.create(null) safely', async () => {
    app.use((req, res, next) => {
      const obj = Object.create(null);
      obj.key = 'value';
      req.body = obj;
      next();
    });
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/');
    expect(res.status).toBe(200);
  });

  // 18. WeakSet prevents circular references
  it('should prevent infinite loops on circular references', async () => {
    app.use((req, res, next) => {
      const obj = {};
      obj.self = obj; // Circular
      req.body = obj;
      next();
    });
    app.use(guard.global());
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/');
    expect(res.status).toBe(200);
  });

  // 19. Schema error does not crash
  it('should block on schema read failure', async () => {
    app.use((req, res, next) => {
      req.body = new Proxy({}, {
        ownKeys: () => { throw new Error('Proxy fail'); },
        getOwnPropertyDescriptor: () => ({ enumerable: true, configurable: true })
      });
      next();
    });
    app.use(guard.global({ schema: { body: ['allowed'] } }));
    app.post('/', (req, res) => res.send('ok'));
    const res = await request(app).post('/');
    expect(res.status).toBe(403);
    expect(res.body.details.label).toBe('schema_violation'); // Schema source read failed
  });

  // 20. logStore memory limits
  it('should limit memory usage in memory log store', async () => {
    const customGuard = fortifyjs({
      maxLogs: 2,
      storeLogs: true,
      mode: 'block',
      detector: {
        detect: (str) => ({ label: 'sqli', confidence: 1, matches: [] })
      }
    });
    app.use(customGuard.global());
    app.get('/', (req, res) => res.send('ok'));
    await request(app).get('/?q=malicious1');
    await request(app).get('/?q=malicious2');
    await request(app).get('/?q=malicious3');
    const logs = customGuard.logs();
    expect(logs.length).toBe(2);
    // Should contain the last two
    expect(logs[0].url).toContain('malicious2');
    expect(logs[1].url).toContain('malicious3');
  });

  // 21. Schema missing required field when source is undefined
  it('should block if a required schema field is missing due to undefined source', async () => {
    app.use(guard.global({ schema: { body: { required: ['userId'] } } }));
    app.post('/', (req, res) => res.send('ok'));
    // Do not use body-parser to simulate undefined req.body
    const res = await request(app).post('/');
    expect(res.status).toBe(403);
    expect(res.body.details.label).toBe('schema_violation');
  });

});
