const ssrfDetector = require('../src/detectors/ssrf');

describe('SSRF Deep Auditor Tests', () => {
  const detect = (payload) => {
    const signals = ssrfDetector.getSignals();
    return signals.some(s => {
      if (s.pattern) return s.pattern.test(payload);
      if (s.test) return s.test(payload);
      return false;
    });
  };

  test('Standard localhost IPv4', () => {
    expect(detect('http://127.0.0.1/admin')).toBe(true);
  });

  test('Standard localhost IPv6', () => {
    expect(detect('http://[::1]/admin')).toBe(true);
  });

  test('IPv6 mapped IPv4 localhost', () => {
    expect(detect('http://[::ffff:127.0.0.1]/admin')).toBe(true);
  });

  test('Cloud metadata AWS', () => {
    expect(detect('http://169.254.169.254/latest/meta-data/')).toBe(true);
  });

  test('Cloud metadata GCP', () => {
    expect(detect('http://metadata.google.internal/computeMetadata/v1/')).toBe(true);
  });

  test('Cloud metadata Oracle', () => {
    expect(detect('http://192.0.0.192/')).toBe(true);
  });

  test('DNS rebinding xip.io', () => {
    expect(detect('http://127.0.0.1.xip.io/admin')).toBe(true);
  });

  test('DNS rebinding nip.io', () => {
    expect(detect('http://169.254.169.254.nip.io/meta-data')).toBe(true);
  });

  test('DNS rebinding spoofed.com', () => {
    expect(detect('http://spoofed.com/admin')).toBe(true);
  });

  test('URL shortener bit.ly', () => {
    expect(detect('http://bit.ly/123456')).toBe(true);
  });

  test('URL shortener bit.do', () => {
    expect(detect('https://bit.do/abcde')).toBe(true);
  });

  test('Dangerous URL scheme file://', () => {
    expect(detect('file:///etc/passwd')).toBe(true);
  });

  test('Dangerous URL scheme gopher://', () => {
    expect(detect('gopher://127.0.0.1:6379/_GET%20/')).toBe(true);
  });

  test('Decimal IP bypass', () => {
    expect(detect('http://2130706433/')).toBe(true);
  });

  test('Hex IP bypass', () => {
    expect(detect('http://0x7f000001/')).toBe(true);
  });
});
