const Koa = require('koa');
const { koaMiddleware } = require('../src/index.js');

const app = new Koa();

app.use(koaMiddleware({ tier: 'basic' }));

app.use(async ctx => {
  ctx.body = 'Hello World';
});

app.listen(3000, () => {
  console.log('Koa server listening on port 3000');
});
