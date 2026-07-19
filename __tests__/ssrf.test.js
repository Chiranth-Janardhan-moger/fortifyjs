'use strict';

const { evaluatePayloads } = require('../src/index');

describe('SSRF Detector', () => {
  it('detects private and loopback IP access', () => {
    const results = evaluatePayloads([
      { payload: 'http://127.0.0.1/admin', expected: 'malicious' },
      { payload: 'http://10.0.0.1/internal/api', expected: 'malicious' },
      { payload: 'http://192.168.1.100/router', expected: 'malicious' },
      { payload: 'http://172.16.0.5/config', expected: 'malicious' },
      { payload: 'http://0.0.0.0:8080/', expected: 'malicious' },
      { payload: 'http://[::1]/', expected: 'malicious' }
    ]);
    expect(results.summary.truePositives).toBe(6);
  });

  it('detects cloud metadata endpoints', () => {
    const results = evaluatePayloads([
      { payload: 'http://169.254.169.254/latest/meta-data/', expected: 'malicious' },
      { payload: 'http://metadata.google.internal/computeMetadata/v1/', expected: 'malicious' },
      { payload: 'http://100.100.100.200/', expected: 'malicious' }
    ]);
    expect(results.summary.truePositives).toBe(3);
  });

  it('detects dangerous URL schemes', () => {
    const results = evaluatePayloads([
      { payload: 'file:///etc/passwd', expected: 'malicious' },
      { payload: 'gopher://127.0.0.1:11211/_', expected: 'malicious' },
      { payload: 'dict://127.0.0.1:11211/', expected: 'malicious' },
      { payload: 'ldap://localhost:389/', expected: 'malicious' }
    ]);
    expect(results.summary.truePositives).toBe(4);
  });

  it('detects alternative IP encodings', () => {
    const results = evaluatePayloads([
      { payload: 'http://2130706433/', expected: 'malicious' }, // 127.0.0.1 in decimal
      { payload: 'http://0x7f000001/', expected: 'malicious' }, // 127.0.0.1 in hex
      { payload: 'http://0x7f.0.0.1/', expected: 'malicious' },
      { payload: 'http://0177.0000.0000.0001/', expected: 'malicious' } // 127.0.0.1 in octal
    ]);
    expect(results.summary.truePositives).toBe(4);
  });
});
