'use strict';

const { DetectionEngine } = require('../src/core/engine');

describe('GraphQL Injection Detector', () => {
  let engine;

  beforeEach(() => {
    engine = new DetectionEngine();
  });

  const testPayload = (payload, expectedLabel) => {
    const result = engine.detect(payload);
    expect(result.label).toBe(expectedLabel);
  };

  it('detects __schema introspection', () => {
    testPayload('{ __schema { types { name } } }', 'graphql');
  });

  it('detects __type introspection', () => {
    testPayload('{ __type(name: "User") { name } }', 'graphql');
  });

  it('detects deep nesting', () => {
    const nested = '{ a '.repeat(11) + '}' + ' }'.repeat(11);
    testPayload(nested, 'graphql');
  });

  it('allows shallow nesting', () => {
    const nested = '{ a '.repeat(5) + '}' + ' }'.repeat(5);
    testPayload(nested, 'benign');
  });

  it('detects alias batching', () => {
    let aliases = '{ ';
    for (let i = 0; i < 101; i++) {
      aliases += `a${i}: user(id: ${i}) { id } `;
    }
    aliases += '}';
    testPayload(aliases, 'graphql');
  });

  it('allows moderate alias batching', () => {
    let aliases = '{ ';
    for (let i = 0; i < 10; i++) {
      aliases += `a${i}: user(id: ${i}) { id } `;
    }
    aliases += '}';
    testPayload(aliases, 'benign');
  });

  it('detects fragment spread abuse', () => {
    let payload = '{ ';
    for (let i = 0; i < 11; i++) {
      payload += `...frag${i} `;
    }
    payload += '}';
    testPayload(payload, 'graphql');
  });

  it('allows moderate fragment spreads', () => {
    testPayload('{ ...frag1 ...frag2 ...frag3 }', 'benign');
  });

  it('detects introspection mixed with aliases', () => {
    testPayload('{ alias1: __schema { types { name } } }', 'graphql');
  });

  it('detects nested introspection', () => {
    testPayload('{ user { id ... on __Schema { types { name } } } }', 'graphql');
  });

  it('allows regular graphql queries', () => {
    testPayload('{ user(id: 1) { id name email } }', 'benign');
  });

  it('allows normal text', () => {
    testPayload('hello world', 'benign');
  });
});
