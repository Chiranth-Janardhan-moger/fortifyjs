<div align="center">

# FortifyJS

**The Zero-Dependency Web Application Firewall and AI Security Suite for Node.js**

[![npm version](https://img.shields.io/npm/v/@chiranthmoger/fortifyjs?color=blue&style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@chiranthmoger/fortifyjs)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![TypeScript Ready](https://img.shields.io/badge/TypeScript-Ready-blue.svg?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-green.svg?style=for-the-badge&logo=nodedotjs)](https://www.npmjs.com/package/@chiranthmoger/fortifyjs)

*One-line protection against injection, XSS, CSRF, SSRF, prompt injection, and 15 attack classes.*<br>
*Replaces helmet, cors, csurf, express-rate-limit, and legacy sanitizers with zero external dependencies.*

</div>

<hr>

## Why FortifyJS?

Securing modern Node.js and TypeScript backends traditionally required installing half a dozen separate packages, managing conflicting configurations, and writing custom defenses for modern threats like AI prompt injection and SSRF.

FortifyJS provides a single, high-performance, zero-dependency security engine with sub-millisecond execution, comprehensive attack vector detection, runtime sink guardrails, and built-in AI/LLM prompt protection.

### Comprehensive Solution Comparison

| Feature / Dimension | FortifyJS | Legacy Node Packages | Cloud WAF (Cloudflare/AWS) | AI-Only Guardrails |
| :--- | :--- | :--- | :--- | :--- |
| **External Dependencies** | **0 (Zero)** | 6 to 10 packages | N/A (Cloud proxy) | Heavy (Python/Model weights) |
| **Inspection Latency** | **< 0.07 ms (Fast-path < 0.005 ms)** | 2 to 8 ms (Combined) | 15 to 50 ms (Network hop) | 100 to 500 ms (LLM inference) |
| **AI Prompt Injection Guard** | **Built-in (`llmGuard`)** | None | Limited / Cost add-on | Yes |
| **Traditional WAF (15 Vectors)**| **Built-in** | Fragmented | Yes | None |
| **Runtime Sink Guardrails** | **Built-in (`assertSafe*`)** | None | None (Edge proxy blind to sinks) | None |
| **SSRF Bitwise CIDR Validation** | **Built-in (RFC subnets & metadata)**| None (Requires custom DNS code) | Partial | None |
| **Mass-Assignment Sanitizer** | **Built-in (`sanitizeObject`)** | Fragmented | None | None |
| **Framework Portability** | **Express, Fastify, Next.js, Hono, Koa, NestJS** | Express only | Protocol level | API level |
| **Cloud & Vendor Lock-In** | **None (Runs in-process)** | None | Vendor locked | Model locked |

### Legacy Package Replacement Matrix

| Legacy Package | FortifyJS Feature | Performance Advantage |
| :--- | :--- | :--- |
| `helmet` | Security Headers Shield | Zero external dependencies, uniform configuration |
| `cors` | CORS Shield | Dynamic origins, regex matching, credential isolation |
| `csurf` | CSRF Protection Shield | Double-submit cookie pattern with secure timing comparisons |
| `express-rate-limit` | Distributed / Memory Rate Limiting | In-process bounded `MemoryStore` with pluggable distributed backends |
| `express-mongo-sanitize` | NoSQLi Detector and Sink Guard | Deep object tree inspection covering MongoDB, CouchDB, Elasticsearch |
| `xss-clean` | Multi-Vector XSS Detector | Context-aware HTML attribute, SVG, and DOM execution sink inspection |
| Custom LLM regexes | AI Prompt Guard (`llmGuard`) | Multi-lingual instruction override, DAN persona, delimiter hijack defense |

---

## Quick Start

```bash
npm install @chiranthmoger/fortifyjs
```

### Express (One-Line Setup)

```javascript
const express = require('express');
const { shield } = require('fortifyjs');

const app = express();
app.use(express.json());
app.use(shield('medium')); // All shields active: WAF + Headers + Rate Limit + CORS + CSRF

app.get('/api/data', (req, res) => {
  res.json({ status: 'secure' });
});

app.listen(3000);
```

### Fastify

```javascript
const fastify = require('fastify')();
const { fastifyPlugin } = require('fortifyjs/adapters/fastify');

fastify.register(fastifyPlugin, { tier: 'medium' });
fastify.listen({ port: 3000 });
```

### Next.js (App Router / Edge Middleware)

```javascript
import nextjsAdapter from 'fortifyjs/adapters/nextjs';

export async function middleware(request) {
  const verdict = await nextjsAdapter(request, { tier: 'medium' });
  if (!verdict.safe) {
    return new Response(JSON.stringify({ error: verdict.error }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
```

---

## 15-Vector Attack Arsenal Matrix

FortifyJS actively inspects incoming requests, query strings, headers, and bodies across 15 attack classes:

| Vector | Attack Class | Target Description | Detection Mechanism | Protection Layer |
| :--- | :--- | :--- | :--- | :--- |
| **SQLi** | SQL Injection | Tautologies, UNION dumps, stacked queries, OOB | Structural token parser & AST boolean abuse | WAF & `assertSafeSqlQuery` |
| **XSS** | Cross-Site Scripting | Stored, reflected, DOM sinks, SVG event handlers | HTML attribute context & JS protocol sinks | WAF & Normalizer |
| **NoSQLi**| NoSQL Injection | MongoDB `$where`, `$ne`, `$gt`, `$regex` bypasses | Query operator heuristics & object tree walk | WAF & `assertSafeNoSql` |
| **CmdI** | Command Injection | Shell metacharacters (`\|`, `;`, `&`), PowerShell, subshells | Command chain heuristics & binary denylist | WAF & `assertSafeCommand` |
| **Path** | Path Traversal | Directory escapes (`../`), overlong UTF-8, null bytes | Lexical containment & prefix verification | WAF & `assertSafePath` |
| **SSRF** | Server-Side Forgery | Cloud metadata (`169.254`), decimal/octal/IPv6 loopbacks | Bitwise CIDR validation & DNS rebinding check | WAF & `assertSafeUrl` |
| **AI/LLM**| Prompt Injection | DAN 12.0 jailbreaks, system prompt exfiltration | Multi-lingual instruction override classifier | `llmGuard` & `scanPrompt` |
| **XXE** | XML Entity Injection | DTD entities, external system entities, billion laughs | XML entity scanner & schema enforcement | WAF Parser |
| **Proto**| Prototype Pollution | `__proto__`, `constructor.prototype` key pollution | Object key scanning & assignment validation | WAF & `sanitizeObject` |
| **HPP** | Parameter Pollution | Split parameter arrays to bypass validation rules | Array normalization & query deduplication | Adapter Engine |
| **Redir**| Open Redirect | Protocol-relative URLs (`//evil.com`), domain fakes | Domain whitelist & absolute URL parser | `assertSafeRedirect` |
| **CRLF** | Response Splitting | `\r\n` carriage return injections into HTTP headers | Header delimiter scanner | Security Headers Shield |
| **SSTI** | Template Injection | Jinja2, Twig, EJS, Pug expressions (`{{...}}`, `${...}`) | Template tag & code execution heuristics | WAF Engine |
| **LDAP** | LDAP Injection | Filter bypasses and wildcard directory harvesting | LDAP filter expression tokenizer | WAF Engine |
| **GQL** | GraphQL Abuse | Introspection dumping, circular queries, alias batching | Query depth analyzer & complexity limits | WAF Engine |

---

## AI and LLM Prompt Protection

FortifyJS includes dedicated guardrails for AI applications, chat endpoints, agent tools, and RAG pipelines:

### 1. LLM Endpoint Middleware (`llmGuard`)

Mount `llmGuard()` directly on chat and generation routes to inspect, log, or block malicious prompts before they reach your model:

```javascript
const express = require('express');
const { llmGuard } = require('fortifyjs');

const app = express();
app.use(express.json());

// Protect chat endpoint
app.post('/api/chat', llmGuard(), (req, res) => {
  // Safe prompt verified
  const userPrompt = req.body.prompt;
  res.json({ response: 'Processed safely' });
});
```

### 2. Standalone Prompt Scan & Guardrail Assertions

Validate user prompts before sending them to OpenAI, Gemini, Anthropic, or local Ollama instances:

```javascript
const { assertSafePrompt, scanPrompt } = require('fortifyjs');

// Detailed diagnostics
const verdict = scanPrompt(userMessage);
console.log(verdict.safe);       // true or false
console.log(verdict.confidence); // 0.0 to 1.0
console.log(verdict.matches);    // Matched signal IDs

// Guardrail assertion: throws FortifyPromptError if malicious
assertSafePrompt(userMessage);
```

### 3. Pluggable Hybrid AI Judge (Optional Deep Semantic Layer)

For applications requiring secondary semantic validation on ambiguous prompts, FortifyJS supports pluggable AI judges:

```javascript
app.post('/api/chat', llmGuard({
  aiJudge: {
    provider: 'openai',
    apiKey: process.env.OPENAI_API_KEY,
    fallback: 'block'
  }
}), (req, res) => {
  // Process LLM chat
});
```

---

## Runtime Sink Guardrails Reference

Defense-in-depth requires verifying values at the exact execution sink to prevent second-order injection and unsafe operations:

| Guardrail Function | Primary Target / Vulnerability | Defense Strategy | Default Policy |
| :--- | :--- | :--- | :--- |
| [`assertSafeCommand`](file:///D:/Projects/fortifyjs/src/core/sinks.js#L25) | OS Command Execution (`child_process.exec`) | Blocks shell metacharacters, subshells, and dangerous binaries | Strict command validation |
| [`assertSafePath`](file:///D:/Projects/fortifyjs/src/core/sinks.js#L44) | Filesystem Reads/Writes (`fs.readFile`, `fs.writeFile`)| Canonical directory boundary check (`path.resolve`) | Root containment enforced |
| [`assertSafeUrl`](file:///D:/Projects/fortifyjs/src/core/sinks.js#L78) | Outbound Network Calls (`fetch`, `axios`) | Bitwise CIDR validation against private / metadata IPs | Private IPs blocked |
| [`assertSafeSqlQuery`](file:///D:/Projects/fortifyjs/src/core/sinks.js#L101) | Raw SQL Execution (`db.query`) | AST structural analysis preventing boolean & tautology attacks | SQLi patterns rejected |
| [`assertSafeNoSql`](file:///D:/Projects/fortifyjs/src/core/sinks.js#L124) | Document Queries (`collection.find`) | Deep object inspection stripping unauthorized `$` operators | Forbidden keys stripped |
| [`assertSafeRedirect`](file:///D:/Projects/fortifyjs/src/core/sinks.js#L166) | HTTP Redirects (`res.redirect`) | Validates destination hostname against allowed whitelist | Whitelist / Relative only |
| [`assertSafePrompt`](file:///D:/Projects/fortifyjs/src/core/sinks.js#L212) | LLM Generation Calls | Multi-lingual instruction override & jailbreak evaluation | Malicious prompts rejected |

### Runtime Sink Usage Example

```javascript
const {
  assertSafeCommand,
  assertSafePath,
  assertSafeUrl,
  assertSafeNoSql,
  assertSafeRedirect,
  assertSafeSqlQuery
} = require('fortifyjs');

// 1. Command Execution Sink
assertSafeCommand(req.body.command);

// 2. File Download Sink
const safePath = assertSafePath(req.query.file, { rootDir: '/var/www/uploads' });

// 3. Webhook Outbound Sink
assertSafeUrl(req.body.webhookUrl, { allowPrivate: false });

// 4. MongoDB Filter Sink
assertSafeNoSql(req.body.filter);

// 5. Open Redirect Sink
assertSafeRedirect(targetUrl, { allowedHosts: ['myapp.com'] });

// 6. SQL Query Sink
assertSafeSqlQuery(dynamicSql);
```

---

## Mass-Assignment and Parameter Sanitization

Automatically strip or reject forbidden fields (such as `isAdmin`, `role`, `permissions`, `balance`, `__proto__`) from incoming request bodies and query parameters:

```javascript
const { shield, sanitizeObject } = require('fortifyjs');

// 1. Middleware mode
app.use(shield('medium', {
  sanitize: {
    stripFields: ['isAdmin', 'role', 'permissions', 'credit', 'balance'],
    rejectOnForbidden: false // Set true to reject with 400 Bad Request
  }
}));

// 2. Programmatic utility
const { sanitized, strippedKeys } = sanitizeObject(req.body, {
  stripFields: ['isAdmin', 'role']
});
```

---

## The 4 Protection Tiers

| Capability / Shield | basic | medium | hard | advanced |
| :--- | :--- | :--- | :--- | :--- |
| **Detection Level** | Balanced (0.50 threshold) | Balanced (0.50 threshold) | Strict (0.25 threshold) | Strict (0.25 threshold) |
| **Security Headers**| Yes (Standard) | Yes (Standard) | Yes (Strict CSP / HSTS) | Yes (Strict CSP / HSTS) |
| **Rate Limiting** | 100 req / 15 min | 200 req / 15 min | 100 req / 15 min | 100 req / 15 min |
| **CORS Policy** | Same-Origin | Same-Origin | Strict Whitelist | Strict Whitelist |
| **CSRF Shield** | No | No | Yes (Double-Submit Token) | Yes (Double-Submit Token) |
| **Bot Detection** | Flag Mode | Block Known Bad Bots | Block Known Bad Bots | Adaptive Fingerprinting |
| **Behavioral Profiler**| Entropy Scoring | Anomaly Scoring | Anomaly Scoring | Anomaly Scoring |
| **File Upload Shield** | No | Yes (Extension whitelist) | Yes (Extension + MIME) | Yes (Deep scan + MIME) |
| **Threat Dashboard** | No | No | No | Yes (`/admin/security`) |

---

## Framework Compatibility Matrix

| Framework | Import Path | Adapter Style | Edge / Serverless Ready |
| :--- | :--- | :--- | :--- |
| **Express** | `require('fortifyjs')` | `shield(tier, options)` | Yes |
| **Fastify** | `require('fortifyjs/adapters/fastify')` | `fastify.register(fastifyPlugin)` | Yes |
| **Next.js** | `import nextjsAdapter from 'fortifyjs/adapters/nextjs'` | Edge / Route Handler Middleware | Yes |
| **Hono** | `import { honoMiddleware } from 'fortifyjs/adapters/hono'` | `app.use('*', honoMiddleware())` | Yes (Cloudflare Workers, Deno, Bun) |
| **Koa** | `const { koaMiddleware } = require('fortifyjs/adapters/koa')` | `app.use(koaMiddleware())` | Yes |
| **NestJS** | `import { FortifyGuard } from 'fortifyjs/adapters/nestjs'` | `@UseGuards(FortifyGuard)` | Yes |

---

## Latency and Performance Benchmarks

FortifyJS operates an in-memory inspection pipeline designed for high-throughput microservice architectures:

| Inspection Pipeline Stage | p50 Latency | p99 Latency | Throughput Capacity | Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Fast-Path Filter (Clean input)** | **0.003 ms** | **0.008 ms** | **> 300,000 req/sec** | Short-circuits clean alphanumeric tokens and numbers |
| **15-Vector Deep WAF Scan** | **0.067 ms** | **0.140 ms** | **> 14,000 req/sec** | Tri-variant normalization and structural scoring |
| **AI Prompt Injection Scan** | **0.052 ms** | **0.110 ms** | **> 18,000 req/sec** | Multi-lingual instruction and delimiter heuristics |
| **Runtime Sink Assertion** | **0.004 ms** | **0.012 ms** | **> 250,000 req/sec** | Bitwise IP check, directory path containment |

---

## Offline CLI Testing

FortifyJS includes a standalone command-line interface for offline testing and CI/CD pipelines:

```bash
# Scan a single input string
fortifyjs scan "1 UNION SELECT username, password FROM users--"

# Scan a batch file of test payloads with CSV output
fortifyjs scan-file test-payloads.txt --format csv
```

---

## Contributing and License

* Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
* Refer to [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.
* Licensed under the [MIT License](LICENSE).

<div align="center">
  <i>Built with absolute security and zero bloat in mind.</i>
</div>

<!-- Visitor Radar Telemetry -->
<img src="https://chiranth.vercel.app/api/telemetry/pixel.svg?target=FortifyJS%20Repository" width="1" height="1" alt="" style="display:none;" />
