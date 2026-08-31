'use strict';

const DANGEROUS_COMMANDS = 'rm|cat|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby|node|php|id|whoami|ls|uname|hostname|awk|sed|find|socat|ncat|xargs|dd|env|tee|echo|chmod|chown|kill|pkill|touch|mv|cp|tar|zip|unzip';

module.exports = {
  name: 'cmdi',
  label: 'cmdi',
  getSignals() {
    return [
      {
        id: 'destructive-command',
        confidence: 0.85,
        pattern: /\b(?:rm\s+-[rf]+|mkfs|dd\s+if=)\b/i
      },
      {
        id: 'shell-command-chain',
        confidence: 0.80,
        pattern: new RegExp(`(?:;|&&|\\|\\|)\\s*(?:${DANGEROUS_COMMANDS})\\b`, 'i')
      },
      {
        id: 'backtick-execution',
        confidence: 0.85,
        pattern: /`[^`]+`/
      },
      {
        id: 'subshell-execution',
        confidence: 0.85,
        pattern: /\$\([^\)]+\)/
      },
      {
        id: 'pipe-to-shell',
        confidence: 0.75,
        pattern: /\|\s*(?:sh|bash|cmd)\b/i
      },
      {
        id: 'shell-binary-path',
        confidence: 0.80,
        pattern: /(?:\/bin\/sh|\/bin\/bash|\/usr\/bin\/env|cmd\.exe|powershell\.exe)\b/i
      },
      {
        id: 'reverse-shell-pattern',
        confidence: 0.90,
        pattern: /(?:bash\s+-i\s+>&|nc\s+-e\s+\/bin\/sh|python\s+-c\s+['"]import\s+socket)/i
      },
      {
        id: 'curl-wget-pipe',
        confidence: 0.70,
        pattern: /(?:curl|wget).*\|\s*(?:bash|sh)\b/i
      },
      {
        id: 'windows-cmd-injection',
        confidence: 0.80,
        pattern: /(?:cmd(?:\.exe)?\s+\/c|powershell(?:\.exe)?\s+-(?:enc|e))\b/i
      },
      {
        id: 'powershell-iex',
        confidence: 0.85,
        pattern: /(?:invoke-expression|iex)\b/i
      },
      {
        id: 'windows-builtins',
        confidence: 0.70,
        pattern: /(?:^|[;&|])\s*(?:type|dir)(?:\s+[^\s]|$)/i
      },
      {
        id: 'newline-injection',
        confidence: 0.80,
        pattern: /(?:%0[ad]|\r|\n)\s*(?:rm|cat|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby|node|php)\b/i
      },
      {
        id: 'env-variable-exfil',
        confidence: 0.60,
        pattern: /(?:\$(?:PATH|HOME|USER|ENV\{)|%(?:SYSTEMROOT|APPDATA|USERPROFILE|USERNAME)%)/i
      },
      {
        id: 'process-substitution',
        confidence: 0.75,
        pattern: /[<>]\([^\)]+\)/
      },
      {
        id: 'pipe-operator-command',
        confidence: 0.80,
        pattern: /\|\s*(?:ls|cat|whoami|id|pwd|dir|type|nc|ncat|socat|tee)(?:\s|$)/i
      },
      {
        id: 'pipe-to-dangerous-binary',
        confidence: 0.75,
        pattern: new RegExp(`\\|\\s*(?:${DANGEROUS_COMMANDS})(?:\\s|$)`, 'i')
      }
    ];
  }
};
