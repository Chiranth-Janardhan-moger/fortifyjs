'use strict';

const { DetectionEngine } = require('../src/core/engine');

describe('Template Injection Detector', () => {
  let engine;

  beforeEach(() => {
    engine = new DetectionEngine({ blockThreshold: 0 });
  });

  const testPayload = (payload, expectedLabel) => {
    const result = engine.detect(payload);
    expect(result.label).toBe(expectedLabel);
  };

  it('detects Jinja2 dangerous sink', () => {
    testPayload('{{ request.application.__globals__.__builtins__.__import__("os").popen("id").read() }}', 'template-injection');
  });

  it('detects JS template with process', () => {
    testPayload('${process.mainModule.require("child_process").execSync("id")}', 'template-injection');
  });

  it('detects EJS dangerous sink', () => {
    testPayload('<%= global.process.mainModule.require("child_process").execSync("id") %>', 'template-injection');
  });

  it('detects Pug dangerous sink', () => {
    testPayload('#{process.mainModule.require("child_process").execSync("id")}', 'template-injection');
  });

  it('detects constructor payload', () => {
    testPayload('{{constructor.constructor("return this")()}}', 'template-injection');
  });

  it('detects arithmetic probe with {{}}', () => {
    testPayload('{{7*7}}', 'template-injection');
  });

  it('detects arithmetic probe with ${}', () => {
    testPayload('${7 * 7}', 'template-injection');
  });

  it('detects arithmetic probe with <%= %>', () => {
    testPayload('<%= 7 * 7 %>', 'template-injection');
  });

  it('detects arithmetic probe with #{}', () => {
    testPayload('#{7 * 7}', 'template-injection');
  });

  it('detects Jinja2 import', () => {
    testPayload('{% import "os" as os %}', 'template-injection');
  });

  it('detects Jinja2 include', () => {
    testPayload('{% include "foo.txt" %}', 'template-injection');
  });

  it('detects template syntax alone', () => {
    const result = engine.detect('{{ user.name }}');
    expect(result.scores['template-injection']).toBeGreaterThan(0);
  });

  it('allows benign text', () => {
    testPayload('Hello world', 'benign');
  });

  it('allows benign math without template', () => {
    testPayload('7 * 7 = 49', 'benign');
  });

  it('detects template syntax alone with EJS', () => {
    const result = engine.detect('<%= user.name %>');
    expect(result.scores['template-injection']).toBeGreaterThan(0);
  });

  it('detects template syntax alone with Pug', () => {
    const result = engine.detect('#{ user.name }');
    expect(result.scores['template-injection']).toBeGreaterThan(0);
  });
});
