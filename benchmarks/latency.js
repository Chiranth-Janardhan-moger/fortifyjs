const { DetectionEngine } = require('../src/index.js');
const engine = new DetectionEngine();

const ITERATIONS = 10000;
const payload = "SELECT * FROM users WHERE username = 'admin' AND password = 'password123' OR 1=1";
const times = [];

console.log(`Running benchmark with ${ITERATIONS} iterations...`);

for (let i = 0; i < ITERATIONS; i++) {
  const start = performance.now();
  engine.detect(payload);
  const end = performance.now();
  times.push(end - start);
}

times.sort((a, b) => a - b);

const p50 = times[Math.floor(ITERATIONS * 0.50)];
const p95 = times[Math.floor(ITERATIONS * 0.95)];
const p99 = times[Math.floor(ITERATIONS * 0.99)];

console.log(`p50: ${p50.toFixed(4)} ms`);
console.log(`p95: ${p95.toFixed(4)} ms`);
console.log(`p99: ${p99.toFixed(4)} ms`);
