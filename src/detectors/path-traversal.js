'use strict';

module.exports = {
  name: 'path-traversal',
  label: 'path-traversal',
  getSignals() {
    return [
      {
        id: 'dot-dot-slash',
        confidence: 0.75,
        pattern: /(?:\.\.[\\\/])+/
      },
      {
        id: 'windows-backslash-traversal',
        confidence: 0.75,
        pattern: /(?:\.\.\\)+/
      },
      {
        id: 'url-encoded-traversal',
        confidence: 0.80,
        pattern: /(?:%2e%2e%2f|%252e%252e%252f|%2e%2e%5c|%252e%252e%255c)+/i
      },
      {
        id: 'overlong-utf8-traversal',
        confidence: 0.85,
        pattern: /(?:%c0%ae%c0%ae%c0%af|%e0%40%ae%e0%40%ae%e0%40%af)+/i
      },
      {
        id: 'double-dot-slash',
        confidence: 0.75,
        pattern: /(?:\.{2,}[\\\/]+)+/
      },
      {
        id: 'null-byte-injection',
        confidence: 0.85,
        pattern: /\x00|%00/i
      },
      {
        id: 'ntfs-alternate-data-stream',
        confidence: 0.85,
        pattern: /::\$DATA\b/i
      },
      {
        id: 'windows-unc-path',
        confidence: 0.80,
        pattern: /(?:^|[\\\/])\\\\\?\\/
      },
      {
        id: 'sensitive-unix-file',
        confidence: 0.80,
        pattern: /(?:\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ|\/proc\/self\/fd\/|\/var\/log\/)/i
      },
      {
        id: 'sensitive-windows-file',
        confidence: 0.80,
        pattern: /(?:\\SAM|\\boot\.ini|\\win\.ini|[\\\/]system32(?:[\\\/]|$))/i
      },
      {
        id: 'dotfile-access',
        confidence: 0.65,
        pattern: /(?:\.env|\.git\/|\.htaccess|\.DS_Store|\.ssh\/|\.aws\/credentials)/i
      }
    ];
  }
};
