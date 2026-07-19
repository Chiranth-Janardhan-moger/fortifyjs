const fastify = require('fastify')({ logger: true });
const { fastifyPlugin } = require('../src/index.js');

fastify.register(fastifyPlugin, { tier: 'medium' });

fastify.get('/', async (request, reply) => {
  return { hello: 'world' };
});

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();
