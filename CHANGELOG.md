# Changelog

## [1.1.0] - 2026-07-19
### Added
- CRLF injection detector.
- Template injection detector (Jinja2, Twig, EJS, Pug).
- LDAP injection detector.
- GraphQL abuse detector (introspection, deep nesting, alias batching).
- File upload shield (extension validation, null byte blocking, MIME checks).

### Improved
- SQLi detector (error-based, OOB, time-delay signals).
- XSS detector (mXSS, CSS injection, SVG events).
- NoSQLi detector (fixed regex escaping, added CouchDB/Elasticsearch patterns).
- CmdI detector (PowerShell, Windows cmd, newline injection).
- Path traversal detector (Windows backslash, overlong UTF-8).
- SSRF detector (IPv6 mapped, DNS rebinding, URL shorteners).
- Behavioral analyzer (deep JSON nesting, content-length anomaly, scanner fingerprinting).
- Normalizer (null byte bypass fix, safe fallback decoding).
- Confidence scoring (probabilistic combination model).

### Fixed
- Express adapter schema validation bypass on missing source.
- rateLimiterFactory crash in shield() API.

## [1.0.0] - 2026-07-19
### Added
- Initial release of fortifyjs.
- `DetectionEngine` for robust WAF capabilities.
- Middleware integration for Express, Fastify, Koa, and Hono.
- Four security tiers: basic, medium, hard, advanced.
- Protection against SQLi, XSS, CSRF, SSRF, Path Traversal, and more.
- Rate limiting and bot detection modules.
- Behavioral analysis and learning mode.
