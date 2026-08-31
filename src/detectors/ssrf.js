'use strict';

function parseIpv4ToNumber(ipStr) {
  if (!ipStr || typeof ipStr !== 'string') return null;
  const trimmed = ipStr.trim();
  
  // Single hex integer (e.g. 0x7f000001)
  if (/^0x[0-9a-fA-F]+$/i.test(trimmed)) {
    const num = parseInt(trimmed, 16);
    return num >= 0 && num <= 0xFFFFFFFF ? num : null;
  }

  // Single octal integer (e.g. 017700000001)
  if (/^0[0-7]+$/.test(trimmed)) {
    const num = parseInt(trimmed, 8);
    return num >= 0 && num <= 0xFFFFFFFF ? num : null;
  }

  // Single decimal integer (e.g. 2130706433)
  if (/^\d+$/.test(trimmed)) {
    const num = Number(trimmed);
    return num >= 0 && num <= 0xFFFFFFFF ? num : null;
  }

  // Dotted parts (can be 1 to 4 parts, hex/octal/decimal)
  const parts = trimmed.split('.');
  if (parts.length < 1 || parts.length > 4) return null;

  const parsedParts = [];
  for (const part of parts) {
    if (!part) return null;
    let val;
    if (/^0x[0-9a-fA-F]+$/i.test(part)) {
      val = parseInt(part, 16);
    } else if (/^0\d+$/.test(part)) {
      val = parseInt(part, 8);
    } else if (/^\d+$/.test(part)) {
      val = parseInt(part, 10);
    } else {
      return null;
    }
    if (isNaN(val) || val < 0) return null;
    parsedParts.push(val);
  }

  if (parsedParts.length === 4) {
    if (parsedParts.some(p => p > 255)) return null;
    return ((parsedParts[0] << 24) >>> 0) + ((parsedParts[1] << 16) >>> 0) + ((parsedParts[2] << 8) >>> 0) + parsedParts[3];
  } else if (parsedParts.length === 3) {
    if (parsedParts[0] > 255 || parsedParts[1] > 255 || parsedParts[2] > 0xFFFF) return null;
    return ((parsedParts[0] << 24) >>> 0) + ((parsedParts[1] << 16) >>> 0) + parsedParts[2];
  } else if (parsedParts.length === 2) {
    if (parsedParts[0] > 255 || parsedParts[1] > 0xFFFFFF) return null;
    return ((parsedParts[0] << 24) >>> 0) + parsedParts[1];
  } else if (parsedParts.length === 1) {
    if (parsedParts[0] > 0xFFFFFFFF) return null;
    return parsedParts[0] >>> 0;
  }

  return null;
}

function isPrivateIpv4Number(num) {
  if (num === null || num === undefined) return false;
  // 0.0.0.0/8
  if (((num & 0xFF000000) >>> 0) === 0x00000000) return true;
  // 10.0.0.0/8
  if (((num & 0xFF000000) >>> 0) === 0x0A000000) return true;
  // 127.0.0.0/8 Loopback
  if (((num & 0xFF000000) >>> 0) === 0x7F000000) return true;
  // 100.64.0.0/10 Carrier-grade NAT
  if (((num & 0xFFC00000) >>> 0) === 0x64400000) return true;
  // 169.254.0.0/16 Link-local / Cloud Metadata
  if (((num & 0xFFFF0000) >>> 0) === 0xA9FE0000) return true;
  // 172.16.0.0/12 Private
  if (((num & 0xFFF00000) >>> 0) === 0xAC100000) return true;
  // 192.0.0.0/24 IETF Protocol
  if (((num & 0xFFFFFF00) >>> 0) === 0xC0000000) return true;
  // 192.168.0.0/16 Private
  if (((num & 0xFFFF0000) >>> 0) === 0xC0A80000) return true;
  // 198.18.0.0/15 Benchmarking
  if (((num & 0xFFFE0000) >>> 0) === 0xC6120000) return true;
  // 224.0.0.0/4 Multicast
  if (((num & 0xF0000000) >>> 0) === 0xE0000000) return true;
  // 240.0.0.0/4 Reserved
  if (((num & 0xF0000000) >>> 0) === 0xF0000000) return true;
  // 255.255.255.255 Broadcast
  if ((num >>> 0) === 0xFFFFFFFF) return true;

  return false;
}

function isPrivateIPv6(ipStr) {
  if (!ipStr || typeof ipStr !== 'string') return false;
  let clean = ipStr.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // Canonicalize hextet leading zeros
  const parts = clean.split(':');
  const normalizedHextets = parts.map(p => {
    if (!p) return '';
    if (p.includes('.')) return p; // IPv4 dotted part
    return p.replace(/^0+/, '') || '0';
  }).join(':');

  // Loopback ::1 or 0:0:0:0:0:0:0:1
  if (clean === '::1' || normalizedHextets === '0:0:0:0:0:0:0:1' || normalizedHextets === '::1' || /^0*(?::0*)*:1$/.test(clean)) return true;
  // Unspecified :: or 0:0:0:0:0:0:0:0
  if (clean === '::' || normalizedHextets === '0:0:0:0:0:0:0:0' || normalizedHextets === '::' || /^0*(?::0*)*:0*$/.test(clean)) return true;

  // IPv4 mapped IPv6 (e.g. ::ffff:127.0.0.1, ::ffff:7f00:1, ::127.0.0.1, 0000:0000:0000:0000:0000:ffff:127.0.0.1)
  if (
    clean.startsWith('::ffff:') ||
    clean.startsWith('0:0:0:0:0:ffff:') ||
    normalizedHextets.startsWith('0:0:0:0:0:ffff:') ||
    clean.startsWith('::')
  ) {
    let v4Part = clean.replace(/^(?:::ffff:|0:0:0:0:0:ffff:|0000:0000:0000:0000:0000:ffff:|::)/, '');
    if (v4Part.includes('.')) {
      const v4Num = parseIpv4ToNumber(v4Part);
      if (v4Num !== null && isPrivateIpv4Number(v4Num)) return true;
    } else if (v4Part.includes(':')) {
      const v4SubParts = v4Part.split(':');
      if (v4SubParts.length === 2) {
        const high = parseInt(v4SubParts[0], 16);
        const low = parseInt(v4SubParts[1], 16);
        if (!isNaN(high) && !isNaN(low)) {
          const v4Num = ((high << 16) >>> 0) + low;
          if (isPrivateIpv4Number(v4Num)) return true;
        }
      }
    }
  }

  // Unique Local (fc00::/7 -> fc00 to fdff)
  if (/^f[cd][0-9a-f]{0,2}:/i.test(normalizedHextets) || /^f[cd][0-9a-f]{2}:/i.test(clean)) return true;
  // Link-Local (fe80::/10 -> fe80 to febf)
  if (/^fe[89ab][0-9a-f]{0,2}:/i.test(normalizedHextets) || /^fe[89ab][0-9a-f]:/i.test(clean)) return true;
  // AWS IMDS IPv6 (fd00:ec2::254)
  if (clean.startsWith('fd00:ec2:') || normalizedHextets.startsWith('fd00:ec2:')) return true;

  return false;
}

function isPrivateIP(ipString) {
  if (!ipString || typeof ipString !== 'string') return false;
  let clean = ipString.trim();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }
  const lower = clean.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost')) return true;

  // Try IPv4
  const v4Num = parseIpv4ToNumber(clean);
  if (v4Num !== null) {
    return isPrivateIpv4Number(v4Num);
  }

  // Try IPv6
  return isPrivateIPv6(clean);
}

function extractHostFromUrlString(urlString) {
  if (!urlString || typeof urlString !== 'string') return null;
  try {
    const match = urlString.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^@\/\?#]+@)?(\[[^\]]+\]|[^/?#:]+)/);
    if (match) {
      let host = match[1];
      if (host.startsWith('[') && host.endsWith(']')) {
        host = host.slice(1, -1);
      }
      return host;
    }
  } catch (_) {}
  return null;
}

function hasPrivateHostInUrl(payload) {
  if (!payload || typeof payload !== 'string') return false;
  const host = extractHostFromUrlString(payload);
  if (host) {
    if (isPrivateIP(host)) return true;
  }
  return false;
}

module.exports = {
  name: 'ssrf',
  label: 'ssrf',
  
  isPrivateIP,
  parseIpv4ToNumber,
  isPrivateIpv4Number,
  isPrivateIPv6,

  getSignals() {
    return [
      {
        id: 'private-ip-access',
        confidence: 0.85,
        pattern: /(?:https?|ftp):\/\/(?:[^@\/\?#]+@)?(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|\[?::1\]?|\[?::ffff:127\.0\.0\.1\]?|0\.0\.0\.0)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'bitwise-private-ip',
        confidence: 0.85,
        test: hasPrivateHostInUrl
      },
      {
        id: 'cloud-metadata-access',
        confidence: 0.90,
        pattern: /(?:https?|ftp):\/\/(?:[^@\/\?#]+@)?(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|192\.0\.0\.192|instance-data)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'dangerous-url-scheme',
        confidence: 0.80,
        pattern: /^(?:file|gopher|dict|ldap|tftp|php|data):\/\//i
      },
      {
        id: 'decimal-ip',
        confidence: 0.75,
        pattern: /(?:https?|ftp):\/\/(?:[^@\/\?#]+@)?(?:2130706433|3232235520|167772160|2886729728|2851995648|0)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'hex-ip',
        confidence: 0.75,
        pattern: /(?:https?|ftp):\/\/(?:[^@\/\?#]+@)?(?:0x7f000001|0x7f\.0x00\.0x00\.0x01|0x7f\.0\.0\.1|0x0a000001|0xc0a80001)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'octal-ip',
        confidence: 0.75,
        pattern: /(?:https?|ftp):\/\/(?:[^@\/\?#]+@)?(?:017700000001|0[0-7]{9,11}|0177\.0000\.0000\.0001|0177\.0\.0\.1|0012\.0\.0\.1|0300\.0250\.0\.1)(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'dns-rebinding-localhost',
        confidence: 0.75,
        pattern: /(?:https?|ftp):\/\/(?:[^@\/\?#]+@)?(?:localhost|[a-zA-Z0-9.-]+\.localhost|0\.0\.0\.0|\[0:0:0:0:0:0:0:1\]|\[0000:0000:0000:0000:0000:0000:0000:0001\]|\[::1\]|\[::\])(?::\d+)?(?:[\/\?#]|$)/i
      },
      {
        id: 'dns-rebinding-service',
        confidence: 0.80,
        pattern: /(?:https?|ftp):\/\/(?:[^@\/\?#]+@)?(?:[a-zA-Z0-9.-]+\.(?:nip\.io|xip\.io|1u\.ms|sslip\.io)|spoofed\.com)/i
      },
      {
        id: 'short-url-ssrf',
        confidence: 0.50,
        pattern: /(?:https?):\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|bit\.do|mcaf\.ee|su\.pr)\//i
      }
    ];
  }
};
