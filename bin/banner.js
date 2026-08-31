#!/usr/bin/env node
'use strict';

const banner = `
  ______         _   _  __       _  _____ 
 |  ____|       | | (_)/ _|     | |/ ____|
 | |__ ___  _ __| |_ _| |_ _   _| | (___  
 |  __/ _ \\| '__| __| |  _| | | | |\\___ \\ 
 | | | (_) | |  | |_| | | | |_| | |____) |
 |_|  \\___/|_|   \\__|_|_|  \\__, |_|_____/ 
                            __/ |         
                           |___/          

 Zero-Dependency Web Application Firewall & AI Security Suite
 Built by Chiranth Moger
 Version: 1.1.2
 Ready for Express, Fastify, Koa, Hono, NestJS, Next.js
`;

function showBanner() {
  if (process.env.npm_config_loglevel === 'silent') return;
  console.log(banner);
}

if (require.main === module) {
  showBanner();
}

module.exports = { banner, showBanner };
