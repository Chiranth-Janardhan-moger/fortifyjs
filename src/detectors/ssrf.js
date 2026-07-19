'use strict';

function isPrivateIP(ipString) {
  if (!ipString) return false;
  // This is a placeholder that can be fleshed out, but currently the regex handles it.
  return false;
}

module.exports = {
  name: 'ssrf',
  label: 'ssrf',
  
  isPrivateIP,

  getSignals() {
    return [
      {
        id: 'private-ip-access',
        confidence: 0.85,
        pattern: /(?:https?|ftp):\/\/(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|\[?::1\]?|\[?::ffff:127\.0\.0\.1\]?|0\.0\.0\.0)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'cloud-metadata-access',
        confidence: 0.90,
        pattern: /(?:https?|ftp):\/\/(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|192\.0\.0\.192)/i
      },
      {
        id: 'dangerous-url-scheme',
        confidence: 0.80,
        pattern: /^(?:file|gopher|dict|ldap|tftp):\/\//i
      },
      {
        id: 'decimal-ip',
        confidence: 0.70,
        pattern: /(?:https?|ftp):\/\/(?:2130706433|3232235520)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'hex-ip',
        confidence: 0.70,
        pattern: /(?:https?|ftp):\/\/(?:0x7f000001|0x7f\.0x00\.0x00\.0x01|0x7f\.0\.0\.1)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'octal-ip',
        confidence: 0.70,
        pattern: /(?:https?|ftp):\/\/(?:0177\.0000\.0000\.0001|0177\.0\.0\.1)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'dns-rebinding-localhost',
        confidence: 0.75,
        pattern: /(?:https?|ftp):\/\/(?:localhost|0\.0\.0\.0|\[0:0:0:0:0:0:0:1\])(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'dns-rebinding-service',
        confidence: 0.80,
        pattern: /(?:https?|ftp):\/\/(?:[a-zA-Z0-9.-]+\.(?:nip\.io|xip\.io|1u\.ms|sslip\.io)|spoofed\.com)/i
      },
      {
        id: 'short-url-ssrf',
        confidence: 0.50,
        pattern: /(?:https?):\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|bit\.do|mcaf\.ee|su\.pr)\//i
      }
    ];
  }
};
