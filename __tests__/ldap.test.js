'use strict';

const { DetectionEngine } = require('../src/core/engine');

describe('LDAP Injection Detector', () => {
  let engine;

  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const testPayload = (payload, expectedLabel) => {
    const result = engine.detect(payload);
    expect(result.label).toBe(expectedLabel);
  };

  it('detects simple filter concatenation', () => {
    testPayload('user)(pass=1', 'ldap');
  });

  it('detects filter concatenation with spaces', () => {
    testPayload('admin)  (objectClass=user', 'ldap');
  });

  it('detects wildcard bypass', () => {
    testPayload('*)(objectClass=*)', 'ldap');
  });

  it('detects wildcard bypass with spaces and case insensitivity', () => {
    testPayload('*) ( objectclass = *', 'ldap');
  });

  it('detects OR filter injection', () => {
    testPayload('admin)(|(password=*)', 'ldap');
  });

  it('detects OR filter injection with spacing', () => {
    testPayload('*)( | (uid=admin)', 'ldap');
  });

  it('detects null byte', () => {
    testPayload('admin\\00', 'ldap');
  });

  it('detects unbalanced parentheses with uid', () => {
    testPayload('uid=admin(', 'ldap');
  });

  it('detects unbalanced parentheses with cn', () => {
    testPayload('cn=admin(', 'ldap');
  });

  it('detects unbalanced parentheses with objectClass', () => {
    testPayload('objectclass=*)(', 'ldap');
  });

  it('allows balanced parentheses with keywords', () => {
    testPayload('(cn=admin)', 'benign');
  });

  it('allows regular text without ldap syntax', () => {
    testPayload('john.doe', 'benign');
  });
});
