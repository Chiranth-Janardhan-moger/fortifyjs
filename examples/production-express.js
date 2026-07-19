'use strict';
const express = require('express');
const { shield } = require('../src/index');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(shield('hard', {
  logRequests: true,
  exposeLogs: true,
  maxSuspiciousRequests: 2
}));

app.post('/api/data', (req, res) => res.json({ status: 'ok', received: req.body }));

if (require.main === module) {
  app.listen(3000, () => console.log('Listening on port 3000'));
}
