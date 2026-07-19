const { DetectionEngine } = require('../src/index.js');
const engine = new DetectionEngine();

const payload = "SELECT * FROM users WHERE username = 'admin' AND password = 'password123' OR 1=1";

// Warmup
for (let i = 0; i < 5000; i++) {
  engine.detect(payload);
}

const batchSize = 10000;
const start = performance.now();
let count = 0;

for (let i = 0; i < batchSize; i++) {
  engine.detect(payload);
  count++;
}

const elapsedMs = performance.now() - start;
const callsPerSecond = (count / elapsedMs) * 1000;

console.log("Throughput Benchmark");
console.table({
  "Throughput": {
    "Detections / Second": callsPerSecond.toFixed(2),
    "Duration (ms)": elapsedMs.toFixed(2),
    "Total Detections": count
  }
});
