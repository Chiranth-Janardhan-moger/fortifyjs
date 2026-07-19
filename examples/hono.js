const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { honoMiddleware } = require('../src/index.js');

const app = new Hono();

app.use('*', honoMiddleware({ tier: 'advanced' }));

app.get('/', (c) => c.text('Hello Hono!'));

serve({ fetch: app.fetch, port: 3000 }, (info) => {
  console.log(`Listening on http://localhost:${info.port}`);
});
