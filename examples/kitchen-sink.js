const express = require('express');
const { shield } = require('../src');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Enable all shields explicitly with hard preset options
app.use(shield({
  preset: 'hard',
  shields: {
    headers: true,
    csrf: { cookieName: '_fortify_csrf_kitchen_sink', secret: 'supersecret_kitchen_sink' },
    cors: { origin: 'http://localhost:3000' },
    rateLimiter: { maxRequests: 50, windowMs: 60000 },
    botDetector: { allowHeadless: false }
  },
  detectors: {
    sqli: true,
    xss: true,
    nosqli: true,
    cmdi: true,
    pathTraversal: true,
    ssrf: true,
    xxe: true,
    prototypePollution: true,
    hpp: true,
    openRedirect: true
  },
  behavioral: {
    entropyThreshold: 4.0,
    maxEncodingDepth: 2,
    specialCharRatio: 0.5
  },
  action: 'block'
}));

app.post('/api/data', (req, res) => {
  res.json({ message: 'Data received securely!' });
});

app.get('/', (req, res) => {
  res.send('Kitchen Sink example running.');
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Kitchen sink server listening on port ${PORT}`);
});
