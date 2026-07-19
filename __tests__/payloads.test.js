const { evaluatePayloads } = require('../src/index');

describe('Extended Payload Suite', () => {
  const payloads = [];

  // Generate 60 XSS variants
  for (let i = 0; i < 60; i++) {
    payloads.push({
      payload: `<script>alert(${i})</script>`,
      expected: 'malicious'
    });
  }

  // Generate 30 SQLi variants
  for (let i = 0; i < 30; i++) {
    payloads.push({
      payload: `admin' AND ${i}=${i}--`,
      expected: 'malicious'
    });
  }

  // Generate 30 benign variants
  for (let i = 0; i < 30; i++) {
    payloads.push({
      payload: `Hello world user ${i}`,
      expected: 'benign'
    });
  }

  payloads.forEach((item, index) => {
    it(`evaluates payload variant ${index + 1} correctly`, () => {
      const results = evaluatePayloads([item]);
      if (item.expected === 'malicious') {
        expect(results.summary.truePositives).toBe(1);
      } else {
        expect(results.summary.trueNegatives).toBe(1);
      }
    });
  });
});
