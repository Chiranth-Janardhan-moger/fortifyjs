'use strict';

const { evaluatePayloads } = require('../src/index');

describe('NoSQL Injection Detector', () => {
  it('detects string-based operator injections', () => {
    const results = evaluatePayloads([
      { payload: '{"$gt": ""}', expected: 'malicious' },
      { payload: '{"$ne": 1}', expected: 'malicious' },
      { payload: '{"$where": "this.password == \'admin\'"}', expected: 'malicious' },
      { payload: '{"$regex": ".*"}', expected: 'malicious' },
      { payload: '{"username": {"$in": ["admin"]}}', expected: 'malicious' },
      { payload: '{"$or": [{"username": "admin"}]}', expected: 'malicious' },
      { payload: '{"$and": [{"username": "admin"}]}', expected: 'malicious' },
      // Legitimate JSON but suspicious keys
      { payload: '{"price": {"$gt": 50}}', expected: 'malicious' }, 
      // Edge cases
      { payload: '{"$where": "function() { return true; }"}', expected: 'malicious' },
      { payload: '{"$where": "() => true"}', expected: 'malicious' },
      { payload: '{"$mapReduce": "function() {}"}', expected: 'malicious' }
    ]);
    
    expect(results.summary.truePositives).toBe(11);
    expect(results.summary.trueNegatives).toBe(0);
  });

  it('detects object-based recursive operator injections', () => {
    const { DetectionEngine, Normalizer } = require('../src/index');
    const engine = new DetectionEngine();
    
    // We mock the object structure that would come from express.json()
    const maliciousObjects = [
      { $gt: '' },
      { user: { $ne: null } },
      { query: { $where: '1==1' } },
      { arr: [{ $regex: 'a' }] },
      { deep: { nested: { object: { with: { $gt: 1 } } } } }
    ];

    let detectedCount = 0;
    for (const obj of maliciousObjects) {
      // In fortifyjs, the express middleware passes the object to detect() 
      // But we can directly test the nosqli detectObject method
      const nosqli = require('../src/detectors/nosqli');
      const signals = nosqli.detectObject(obj);
      if (signals && signals.length > 0) {
        detectedCount++;
      }
    }
    
    expect(detectedCount).toBe(maliciousObjects.length);
  });

  it('allows legitimate payloads', () => {
    const results = evaluatePayloads([
      { payload: '{"price": "50"}', expected: 'benign' },
      { payload: '{"name": "where"}', expected: 'benign' },
      { payload: '{"username": "john_doe"}', expected: 'benign' },
      { payload: 'where is the park', expected: 'benign' },
      { payload: 'and so it begins', expected: 'benign' }
    ]);
    
    expect(results.summary.trueNegatives).toBe(5);
    expect(results.summary.truePositives).toBe(0);
  });
});
