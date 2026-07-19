const pkg = require('../package.json');
const { execFileSync } = require('child_process');
const path = require('path');

describe('package metadata', () => {
  it('should declare the runtime actually required by the CLI and middleware', () => {
    expect(pkg.engines.node).toBe('>=18.0.0');
  });

  it('should publish under the clean fortifyjs package name', () => {
    expect(pkg.name).toBe('fortifyjs');
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.bin.fortifyjs).toBe('bin/fortifyjs.js');
  });

  it('should point package metadata at the fortifyjs repository', () => {
    expect(pkg.repository.url).toBe('git+https://github.com/Chiranth-Janardhan-moger/fortifyjs.git');
    expect(pkg.bugs.url).toBe('https://github.com/Chiranth-Janardhan-moger/fortifyjs/issues');
    expect(pkg.homepage).toBe('https://github.com/Chiranth-Janardhan-moger/fortifyjs#readme');
  });

  it('should publish runtime files only', () => {
    expect(pkg.files).toEqual(['bin', 'src', 'examples', 'index.d.ts']);
  });

  it('should expose TypeScript definitions and optional Express peer metadata', () => {
    expect(pkg.types).toBe('index.d.ts');
    expect(pkg.peerDependencies.express).toBe('>=4.18.0 || >=5.0.0');
    expect(pkg.peerDependenciesMeta.express.optional).toBe(true);
  });

  it.each([
    'minimal-express.js',
    'production-express.js'
  ])('should keep example syntax valid: %s', fileName => {
    const examplePath = path.join(__dirname, '..', 'examples', fileName);
    expect(() => execFileSync(process.execPath, ['-c', examplePath], { encoding: 'utf8' })).not.toThrow();
  });
});




