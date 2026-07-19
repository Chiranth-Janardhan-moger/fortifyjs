const ptDetector = require('../src/detectors/path-traversal');

describe('Path Traversal Deep Auditor Tests', () => {
  const detect = (payload) => {
    const signals = ptDetector.getSignals();
    return signals.some(s => {
      if (s.pattern) return s.pattern.test(payload);
      if (s.test) return s.test(payload);
      return false;
    });
  };

  test('Standard dot-dot-slash', () => {
    expect(detect('../../../../etc/passwd')).toBe(true);
  });

  test('Windows backslash traversal', () => {
    expect(detect('..\\..\\..\\..\\Windows\\win.ini')).toBe(true);
  });

  test('Mixed slash traversal', () => {
    expect(detect('../..\\../..\\etc/passwd')).toBe(true);
  });

  test('URL-encoded dot-dot-slash', () => {
    expect(detect('%2e%2e%2f%2e%2e%2fetc%2fpasswd')).toBe(true);
  });

  test('Double URL-encoded dot-dot-slash', () => {
    expect(detect('%252e%252e%252f%252e%252e%252fetc%2fpasswd')).toBe(true);
  });

  test('URL-encoded Windows backslash', () => {
    expect(detect('%2e%2e%5c%2e%2e%5cWindows%5cwin.ini')).toBe(true);
  });

  test('Overlong UTF-8 dot-dot-slash (c0 ae)', () => {
    expect(detect('%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd')).toBe(true);
  });

  test('Overlong UTF-8 dot-dot-slash (e0 40 ae)', () => {
    expect(detect('%e0%40%ae%e0%40%ae%e0%40%af%e0%40%ae%e0%40%ae%e0%40%afetc/passwd')).toBe(true);
  });

  test('Double dot slash bypass', () => {
    expect(detect('....//....//etc/passwd')).toBe(true);
  });

  test('Null byte injection', () => {
    expect(detect('image.png\x00.php')).toBe(true);
  });

  test('Sensitive Unix file access', () => {
    expect(detect('/etc/shadow')).toBe(true);
  });

  test('Sensitive Windows file access', () => {
    expect(detect('C:\\system32\\config\\SAM')).toBe(true);
  });

  test('Dotfile access', () => {
    expect(detect('/var/www/.env')).toBe(true);
    expect(detect('.aws/credentials')).toBe(true);
  });

  test('Absolute path input (Unix)', () => {
    expect(detect('/var/www/html/config.php')).toBe(false);
  });

  test('Absolute path input (Windows)', () => {
    expect(detect('D:\\Projects\\secrets.txt')).toBe(false);
  });

  test('Benign absolute paths and URLs', () => {
    expect(detect('https://example.com/api')).toBe(false);
    expect(detect('http://localhost:8080/')).toBe(false);
    expect(detect('ftp://server.local/file')).toBe(false);
    expect(detect('/usr/local/bin/node')).toBe(false);
    expect(detect('C:\\Users\\Public\\Downloads')).toBe(false);
    expect(detect('https://google.com')).toBe(false);
    expect(detect('http://192.168.1.1')).toBe(false);
    expect(detect('/tmp/test-file.txt')).toBe(false);
    expect(detect('/opt/myapp/log.txt')).toBe(false);
    expect(detect('E:\\Data\\logs')).toBe(false);
  });
});
