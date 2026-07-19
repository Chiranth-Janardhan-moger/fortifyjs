const { DetectionEngine } = require('../src/index.js');
const engine = new DetectionEngine();

const benignPayloads = [];
for (let i = 0; i < 1000; i++) {
  benignPayloads.push(`{"user": "user${i}", "action": "login", "timestamp": ${Date.now()}}`);
}

const attackPayloads = [];
for (let i = 0; i < 1000; i++) {
  if (i % 2 === 0) {
    attackPayloads.push(`SELECT * FROM users WHERE username = 'admin' AND password = 'password${i}' OR 1=1`);
  } else {
    attackPayloads.push(`<script>alert(${i})</script>`);
  }
}

// Warmup
for (let i = 0; i < 100; i++) {
  engine.detect("test");
  engine.detect("SELECT * FROM test");
}

function measure(payloads) {
  const times = [];
  for (let i = 0; i < payloads.length; i++) {
    const start = performance.now();
    engine.detect(payloads[i]);
    const end = performance.now();
    times.push(end - start);
  }
  times.sort((a, b) => a - b);
  return {
    p50: times[Math.floor(times.length * 0.50)].toFixed(4) + ' ms',
    p95: times[Math.floor(times.length * 0.95)].toFixed(4) + ' ms',
    p99: times[Math.floor(times.length * 0.99)].toFixed(4) + ' ms',
  };
}

const benignStats = measure(benignPayloads);
const attackStats = measure(attackPayloads);

console.log("Detection Speed Benchmark (1000 payloads each)");
const results = {
  Benign: benignStats,
  Attack: attackStats,
};

console.table(results);
