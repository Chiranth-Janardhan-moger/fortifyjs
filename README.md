# FortifyJS

Zero-dependency WAF and security middleware for Node.js.

`Zero Dependencies` | `714+ Tests` | `14 Detectors` | `TypeScript Ready` | `MIT License`

## What It Replaces

FortifyJS consolidates multiple security dependencies into a single, cohesive solution.

| Legacy Package | FortifyJS Feature |
| :--- | :--- |
| `helmet` | FortifyJS Security Headers Shield |
| `cors` | FortifyJS CORS Shield |
| `csurf` | FortifyJS CSRF Shield |
| `express-rate-limit` | FortifyJS Rate Limiting Shield |
| `express-mongo-sanitize` | FortifyJS NoSQLi Detector |
| `xss-clean` | FortifyJS XSS Detector |

## Quick Start

Installation:
```bash
npm install fortifyjs
```

### Minimal Express Example
```javascript
const express = require('express');
const { shield } = require('fortifyjs');

const app = express();
app.use(shield('medium'));
app.listen(3000, () => console.log('Server protected by FortifyJS'));
```

### Minimal Fastify Example
```javascript
const fastify = require('fastify')();
const { fastifyPlugin } = require('fortifyjs/adapters/fastify');

fastify.register(fastifyPlugin, { tier: 'medium' });
fastify.listen({ port: 3000 });
```

## The 4 Tiers

FortifyJS provides predefined security profiles to match your application's risk profile.

| Tier | Detection Level | Headers | Rate Limit | CORS | CSRF | Bot Detection | Behavioral | File Upload | Dashboard |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **basic** | Balanced | Yes | 100/15m | Same-origin | No | Yes (Flag) | Yes (Entropy) | No | No |
| **medium** | Balanced | Yes | 200/15m | Same-origin | No | Yes (Block) | Yes | Yes | No |
| **hard** | Strict | Yes | 100/15m | Same-origin | Yes | Yes (Block) | Yes (5k reqs) | Yes | No |
| **advanced** | Strict | Yes | 100/15m | Same-origin | Yes | Yes (Block) | Yes (5k reqs) | Yes (Scan) | Yes |

## 14 Detection Engines

1. **SQLi**: Identifies SQL injection attempts across popular SQL dialects.
2. **XSS**: Blocks cross-site scripting attacks including mutations and DOM-based vectors.
3. **NoSQLi**: Detects query operator injections tailored for MongoDB, CouchDB, and Elasticsearch.
4. **CmdI**: Prevents operating system command injection across Unix and Windows platforms.
5. **Path Traversal**: Stops directory traversal attempts aiming to read arbitrary files.
6. **SSRF**: Intercepts Server-Side Request Forgery attempts against internal infrastructure.
7. **XXE**: Prevents XML External Entity processing attacks.
8. **Prototype Pollution**: Detects and stops JavaScript object prototype manipulation.
9. **HPP**: Mitigates HTTP Parameter Pollution vulnerabilities.
10. **Open Redirect**: Validates destination paths to prevent malicious redirection.
11. **CRLF**: Stops HTTP response splitting via carriage return and line feed characters.
12. **Template Injection**: Blocks server-side template injection (e.g., Jinja2, Twig, EJS).
13. **LDAP Injection**: Identifies unauthorized LDAP query manipulation.
14. **GraphQL Abuse**: Limits introspection, deep nesting, and alias batching.

## Security Shields

- **Rate Limiting**: Defends against brute-force and volumetric denial-of-service attacks.
- **CORS**: Enforces Cross-Origin Resource Sharing policies dynamically.
- **CSRF**: Protects state-changing endpoints with synchronizer tokens.
- **Security Headers**: Injects industry-standard headers to harden browser behavior.
- **Bot Detection**: Identifies automated scanners and scrapers through signature analysis.
- **File Upload Validation**: Enforces strict extension validation, null byte blocking, and MIME checks.
- **Behavioral Analysis**: Builds baseline models of traffic to detect anomalous payload structures.

## Framework Support

### Express
```javascript
const { shield } = require('fortifyjs');
app.use(shield('hard'));
```

### Fastify
```javascript
const { fastifyPlugin } = require('fortifyjs/adapters/fastify');
fastify.register(fastifyPlugin, { tier: 'hard' });
```

### Koa
```javascript
const { koaMiddleware } = require('fortifyjs/adapters/koa');
app.use(koaMiddleware({ tier: 'hard' }));
```

### Hono
```javascript
import { honoMiddleware } from 'fortifyjs/adapters/hono';
app.use('*', honoMiddleware({ tier: 'hard' }));
```

### NestJS
```typescript
import { FortifyGuard } from 'fortifyjs/adapters/nestjs';
@UseGuards(new FortifyGuard('hard'))
export class AppController {}
```

## Configuration

You can easily override tier defaults by passing a configuration object.

```javascript
const { shield } = require('fortifyjs');

app.use(shield('medium', {
  cors: {
    origin: ['https://myapp.com', 'https://admin.myapp.com']
  },
  rateLimit: {
    max: 300,
    windowMs: 10 * 60 * 1000
  }
}));
```

For a comprehensive list of all configuration options, refer to the TypeScript typings provided with the package.

## CLI

FortifyJS includes a command-line interface for testing payloads and scanning inputs offline.

Scan a specific string for malicious signatures:
```bash
fortifyjs scan "<test-input>"
```

Scan a file containing payloads and output results in CSV format:
```bash
fortifyjs scan-file payloads.txt --format csv
```

## Dashboard

The Advanced tier includes an interactive, built-in security dashboard for real-time monitoring of blocked requests and behavioral anomalies. By default, it is served securely at `/admin/security` when enabled.

## Contributing, Security, License

- Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
- Refer to [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
- FortifyJS is licensed under the MIT License.
