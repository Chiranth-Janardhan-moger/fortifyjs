'use strict';

const { evaluatePayloads } = require('../src/index');

describe('HTTP Parameter Pollution (HPP) Detector', () => {
  it('detects duplicate parameters in query strings', () => {
    // Note: evaluatePayloads takes single strings. For HPP, the framework integration
    // passes an object where the value is an array, e.g. { id: ['1', '2'] }.
    // We test the detectObject method.
    const hpp = require('../src/detectors/hpp');
    const signals = hpp.detectQuery({ id: ['1', '2'] });
    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].id).toBe('array-param-unexpected');
  });

  it('allows single string parameters', () => {
    const hpp = require('../src/detectors/hpp');
    const signals = hpp.detectQuery({ id: '1' });
    expect(signals.length).toBe(0);
  });
});
