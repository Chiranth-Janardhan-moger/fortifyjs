const xssDetector = require('../src/detectors/xss');

const extractSignals = (payload) => xssDetector.getSignals().filter(signal => {
  if (signal.test) return signal.test(payload);
  return signal.pattern.test(payload);
}).map(s => s.id);

describe('XSS Deep Auditor Tests', () => {
  const specificTests = [
    { name: 'mXSS math tag', payload: '<math><mtext>Test</mtext></math>', expected: 'mathml-xss-container' },
    { name: 'mXSS mglyph tag', payload: '<math><mglyph></mglyph></math>', expected: 'mathml-xss-container' },
    { name: 'mXSS annotation-xml tag', payload: '<math><annotation-xml></annotation-xml></math>', expected: 'mathml-xss-container' },
    { name: 'mXSS uppercase tags', payload: '<MATH><MTEXT>', expected: 'mathml-xss-container' },
    { name: 'mXSS mixed case math', payload: '<MaTh><mTeXt>', expected: 'mathml-xss-container' },
    { name: 'mXSS trailing spaces', payload: '<math  ><mtext  >', expected: 'mathml-xss-container' },
    { name: 'svg foreignObject', payload: '<svg><foreignObject>', expected: 'svg-xss-container' },
    { name: 'svg foreignObject upper', payload: '<SVG><FOREIGNOBJECT>', expected: 'svg-xss-container' },
    { name: 'svg foreignObject spaces', payload: '<svg>< foreignObject >', expected: 'svg-xss-container' },
    { name: 'CSS expr inline block', payload: '<style>x:expression(alert(1))</style>', expected: 'css-injection' },
    { name: 'CSS expr upper', payload: '<STYLE>x:EXPRESSION(alert(1))</STYLE>', expected: 'css-injection' },
    { name: 'CSS inline expr', payload: '<div style="color:expression(alert(1))">', expected: 'css-injection' },
    { name: 'CSS inline expr single quote', payload: '<div style=\'color:expression(alert(1))\' >', expected: 'css-injection' },
    { name: 'CSS inline expr no quotes', payload: '<div style=color:expression(alert(1))>', expected: 'css-injection' },
    { name: 'CSS url js', payload: '<style>@import url(javascript:alert(1))</style>', expected: 'css-injection' },
    { name: 'CSS url js space', payload: '<style>@import url( javascript:alert(1))</style>', expected: 'css-injection' },
    { name: 'CSS url js quote', payload: '<style>@import url("javascript:alert(1)")</style>', expected: 'css-injection' },
    { name: 'CSS inline url js', payload: '<div style="background: url(javascript:alert(1))">', expected: 'css-injection' },
    { name: 'CSS inline url js single quote', payload: '<div style=\'background: url(javascript:alert(1))\'>', expected: 'css-injection' },
    { name: 'CSS inline url js upper', payload: '<div style="background: URL(JAVASCRIPT:alert(1))">', expected: 'css-injection' },
    { name: 'autofocus order 1', payload: '<input onfocus=alert(1) autofocus>', expected: 'autofocus-event-bypass' },
    { name: 'autofocus order 2', payload: '<input autofocus onfocus=alert(1)>', expected: 'autofocus-event-bypass' },
    { name: 'autofocus upper', payload: '<INPUT AUTOFOCUS ONFOCUS=alert(1)>', expected: 'autofocus-event-bypass' },
    { name: 'autofocus spaces', payload: '<input   autofocus   onfocus=alert(1)>', expected: 'autofocus-event-bypass' },
    { name: 'autofocus newlines', payload: '<input autofocus\\n onfocus=alert(1)>', expected: 'autofocus-event-bypass' },
    { name: 'video source', payload: '<video><source onerror=alert(1)></video>', expected: 'media-error-bypass' },
    { name: 'video source uppercase', payload: '<VIDEO><SOURCE ONERROR=alert(1)></VIDEO>', expected: 'media-error-bypass' },
    { name: 'video source space', payload: '<video><source  onerror = alert(1)></video>', expected: 'media-error-bypass' },
    { name: 'audio source', payload: '<audio><source onerror=alert(1)></audio>', expected: 'media-error-bypass' },
    { name: 'audio source single quote', payload: '<audio><source onerror=\'alert(1)\'></audio>', expected: 'media-error-bypass' },
    { name: 'picture source', payload: '<picture><source onerror=alert(1)></picture>', expected: 'media-error-bypass' },
    { name: 'picture source quotes', payload: '<picture><source onerror="alert(1)"></picture>', expected: 'media-error-bypass' }
  ];

  specificTests.forEach(({ name, payload, expected }) => {
    test(`detects ${name}`, () => {
      const signals = extractSignals(payload);
      expect(signals).toContain(expected);
    });
  });
});
