<div align="center">

# 🛡️ FortifyJS

**The Zero-Dependency Web Application Firewall for Node.js**

[![npm version](https://img.shields.io/npm/v/fortifyjs?color=blue&style=for-the-badge)](https://www.npmjs.com/package/fortifyjs)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![TypeScript Ready](https://img.shields.io/badge/TypeScript-Ready-blue.svg?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-success.svg?style=for-the-badge)](https://www.npmjs.com/package/fortifyjs)

*One-line protection against injection, XSS, CSRF, SSRF, and 10+ attack classes.*<br>
*Replaces `helmet`, `cors`, `csurf`, and `express-rate-limit`.*

</div>

<hr>

## 🚀 Why FortifyJS?

Building secure Node.js applications used to mean juggling half a dozen middlewares, configuring complex rulesets, and hoping you didn't miss a critical vulnerability vector. 

**Not anymore.** FortifyJS consolidates everything into a single, highly-optimized, zero-dependency engine.

### 📉 What It Replaces

| Legacy Package | FortifyJS Feature |
| :--- | :--- |
| 🐢 `helmet` | 🛡️ Security Headers Shield |
| 🐢 `cors` | 🛡️ CORS Shield |
| 🐢 `csurf` | 🛡️ CSRF Shield |
| 🐢 `express-rate-limit` | 🛡️ Rate Limiting Shield |
| 🐢 `express-mongo-sanitize` | 🛡️ NoSQLi Detector |
| 🐢 `xss-clean` | 🛡️ XSS Detector |

---

## 📦 Quick Start

```bash
npm install fortifyjs
```

### ⚡ Express
```javascript
const express = require('express');
const { shield } = require('fortifyjs');

const app = express();
app.use(shield('medium')); // That's it. You're protected.

app.listen(3000, () => console.log('Server protected by FortifyJS 🛡️'));
```

### ⚡ Fastify
```javascript
const fastify = require('fastify')();
const { fastifyPlugin } = require('fortifyjs/adapters/fastify');

fastify.register(fastifyPlugin, { tier: 'medium' });
fastify.listen({ port: 3000 });
```

---

## 🛡️ The 4 Tiers of Protection

FortifyJS provides predefined security profiles to match your application's risk profile. No complex configuration needed.

| Tier | Detection Level | Headers | Rate Limit | CORS | CSRF | Bot Detection | Behavioral | File Upload | Dashboard |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **🟢 basic** | Balanced | ✅ | 100/15m | Same-origin | ❌ | Flag | Entropy | ❌ | ❌ |
| **🟡 medium** | Balanced | ✅ | 200/15m | Same-origin | ❌ | Block | ✅ | ✅ | ❌ |
| **🟠 hard** | Strict | ✅ | 100/15m | Same-origin | ✅ | Block | 5k reqs | ✅ | ❌ |
| **🔴 advanced**| Strict | ✅ | 100/15m | Same-origin | ✅ | Block | 5k reqs | Scan | ✅ |

---

## 🔍 14 Advanced Detection Engines

Under the hood, FortifyJS acts as a complete Web Application Firewall, actively analyzing payloads against 14 distinct attack vectors:

1. 💉 **SQLi**: Identifies SQL injection attempts across popular SQL dialects.
2. 🎭 **XSS**: Blocks cross-site scripting attacks including mutations and DOM-based vectors.
3. 🍃 **NoSQLi**: Detects query operator injections tailored for MongoDB, CouchDB, and Elasticsearch.
4. 💻 **CmdI**: Prevents operating system command injection across Unix and Windows platforms.
5. 📂 **Path Traversal**: Stops directory traversal attempts aiming to read arbitrary files.
6. 🌐 **SSRF**: Intercepts Server-Side Request Forgery attempts against internal infrastructure.
7. 📄 **XXE**: Prevents XML External Entity processing attacks.
8. 🧬 **Prototype Pollution**: Detects and stops JavaScript object prototype manipulation.
9. 🔀 **HPP**: Mitigates HTTP Parameter Pollution vulnerabilities.
10. ↪️ **Open Redirect**: Validates destination paths to prevent malicious redirection.
11. ✂️ **CRLF**: Stops HTTP response splitting via carriage return and line feed characters.
12. 🧩 **Template Injection**: Blocks server-side template injection (e.g., Jinja2, Twig, EJS).
13. 📇 **LDAP Injection**: Identifies unauthorized LDAP query manipulation.
14. 🕸️ **GraphQL Abuse**: Limits introspection, deep nesting, and alias batching.

---

## 🔌 Framework Support

FortifyJS is framework-agnostic. We provide out-of-the-box adapters for the most popular Node.js web frameworks:

<details>
<summary><b>Koa</b></summary>

```javascript
const { koaMiddleware } = require('fortifyjs/adapters/koa');
app.use(koaMiddleware({ tier: 'hard' }));
```
</details>

<details>
<summary><b>Hono</b></summary>

```javascript
import { honoMiddleware } from 'fortifyjs/adapters/hono';
app.use('*', honoMiddleware({ tier: 'hard' }));
```
</details>

<details>
<summary><b>NestJS</b></summary>

```typescript
import { FortifyGuard } from 'fortifyjs/adapters/nestjs';
@UseGuards(new FortifyGuard('hard'))
export class AppController {}
```
</details>

---

## ⚙️ Advanced Configuration

Need more control? You can easily override tier defaults by passing a configuration object.

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

---

## 🛠️ Offline CLI Testing

FortifyJS includes a powerful command-line interface for testing payloads and scanning inputs offline in your CI/CD pipelines.

Scan a specific string for malicious signatures:
```bash
fortifyjs scan "<test-input>"
```

Scan a file containing payloads and output results in CSV format:
```bash
fortifyjs scan-file payloads.txt --format csv
```

---

## 📊 Security Dashboard

The **Advanced tier** includes an interactive, built-in security dashboard for real-time monitoring of blocked requests, rate limits, and behavioral anomalies. 

Served securely at `/admin/security` when enabled.

---

## 🤝 Contributing & License

- 📖 Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
- 🔒 Refer to [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
- 📜 FortifyJS is open-source software licensed under the [MIT License](LICENSE).

<div align="center">
  <i>Built with absolute security and zero bloat in mind.</i>
</div>
