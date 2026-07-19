'use strict';

const HEADER_PATTERN = '(?:Set-Cookie|Location|Bcc|Cc|Content-Type|Content-Length|X-[A-Za-z0-9-]+|Host|Authorization)\\s*:';

module.exports = {
  name: 'crlf',
  label: 'crlf',
  
  getSignals() {
    return [
      {
        id: 'crlf-header-injection',
        confidence: 0.85,
        pattern: new RegExp(`(?:\\r\\n|\\r|\\n|%0d%0a|%0a)[ \\t]*${HEADER_PATTERN}`, 'i')
      },
      {
        id: 'crlf-encoded-header-injection',
        confidence: 0.80,
        pattern: new RegExp(`(?:\\u560a\\u560d|%E5%98%8A%E5%98%8D|\\\\u000d\\\\u000a)[ \\t]*${HEADER_PATTERN}`, 'i')
      },
      {
        id: 'crlf-log-injection',
        confidence: 0.75,
        pattern: /(?:\r\n|\r|\n|%0d%0a|%0a)[ \t]*(?:\[?(?:info|error|warn|debug|trace)\]?|\[?\d{4}-\d{2}-\d{2}|\[?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i
      },
      {
        id: 'crlf-newline-alone',
        confidence: 0.40,
        pattern: /(?:\r\n|%0d%0a)/i
      }
    ];
  }
};
