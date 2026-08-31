'use strict';

const express = require('express');
const path = require('path');
const {
  DetectionEngine,
  scanPrompt,
  assertSafeCommand,
  assertSafePath,
  assertSafeUrl,
  assertSafeNoSql,
  assertSafeRedirect,
  assertSafeSqlQuery,
  sanitizeObject,
  shield
} = require('../src/index');

const app = express();
const PORT = process.env.PORT || 3333;
const engine = new DetectionEngine();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// API endpoint to analyze any generic input payload
app.post('/api/scan', (req, res) => {
  const payload = req.body.payload ?? '';
  const startTime = process.hrtime.bigint();
  
  const result = engine.detect(payload, { source: req.body.source });
  const endTime = process.hrtime.bigint();
  const latencyMs = Number(endTime - startTime) / 1e6;

  res.json({
    payload,
    label: result.label,
    confidence: result.confidence,
    safe: result.label === 'benign' || result.confidence < 0.5,
    fastPath: result.fastPath || false,
    latencyMs: Number(latencyMs.toFixed(4)),
    scores: result.scores || {},
    matches: (result.matches || []).map(m => ({
      id: m.id,
      label: m.label,
      confidence: m.confidence
    }))
  });
});

// API endpoint for AI & Prompt Guard verification
app.post('/api/scan-prompt', (req, res) => {
  const prompt = req.body.prompt ?? '';
  const startTime = process.hrtime.bigint();

  const verdict = scanPrompt(prompt, { threshold: 0.6 });
  const endTime = process.hrtime.bigint();
  const latencyMs = Number(endTime - startTime) / 1e6;

  res.json({
    prompt,
    safe: verdict.safe,
    label: verdict.label,
    confidence: verdict.confidence,
    latencyMs: Number(latencyMs.toFixed(4)),
    matches: verdict.matches || [],
    scores: verdict.scores || {}
  });
});

// API endpoint for Sink Guard checks
app.post('/api/sink-check', (req, res) => {
  const { type, value } = req.body;
  const startTime = process.hrtime.bigint();

  let safe = true;
  let error = null;
  let result = null;

  try {
    switch (type) {
      case 'command':
        result = assertSafeCommand(value);
        break;
      case 'path':
        result = assertSafePath(value, { rootDir: './uploads' });
        break;
      case 'url':
        result = assertSafeUrl(value, { allowPrivate: false });
        break;
      case 'nosql':
        result = assertSafeNoSql(typeof value === 'string' ? JSON.parse(value) : value);
        break;
      case 'redirect':
        result = assertSafeRedirect(value, { allowedHosts: ['myapp.com'] });
        break;
      case 'sql':
        result = assertSafeSqlQuery(value);
        break;
      default:
        safe = false;
        error = 'Unknown sink type';
    }
  } catch (err) {
    safe = false;
    error = err.message;
  }

  const endTime = process.hrtime.bigint();
  const latencyMs = Number(endTime - startTime) / 1e6;

  res.json({
    type,
    value,
    safe,
    error,
    latencyMs: Number(latencyMs.toFixed(4))
  });
});

// API endpoint for parameter sanitization (mass assignment)
app.post('/api/sanitize', (req, res) => {
  const target = req.body.data || {};
  const { sanitized, strippedKeys, wasForbidden } = sanitizeObject(target);

  res.json({
    original: target,
    sanitized,
    strippedKeys,
    wasForbidden
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`FortifyJS Interactive Dashboard running at http://localhost:${PORT}`);
});
