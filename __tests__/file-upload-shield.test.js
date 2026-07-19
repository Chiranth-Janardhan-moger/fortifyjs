'use strict';

const { fileUploadShieldFactory } = require('../src/shields/file-upload');

describe('File Upload Shield', () => {
  let req, res, next;

  beforeEach(() => {
    req = {};
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    next = jest.fn();
  });

  const createShield = (options = {}) => {
    return fileUploadShieldFactory(options);
  };

  test('1. Allows request if no files are present', () => {
    const shield = createShield();
    shield(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('2. Allows valid single req.file', () => {
    const shield = createShield();
    req.file = { originalname: 'image.jpg', mimetype: 'image/jpeg' };
    shield(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('3. Blocks file with blocked extension', () => {
    const shield = createShield();
    req.file = { originalname: 'script.php', mimetype: 'text/plain' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'File extension is blocked' }));
    expect(next).not.toHaveBeenCalled();
  });

  test('4. Blocks file with extension not in allowedExtensions', () => {
    const shield = createShield(); // defaults allow .jpg, .jpeg, .png, .gif, .pdf, .docx
    req.file = { originalname: 'archive.zip', mimetype: 'application/zip' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'File extension is not allowed' }));
    expect(next).not.toHaveBeenCalled();
  });

  test('5. Blocks file with double extension', () => {
    const shield = createShield();
    req.file = { originalname: 'resume.php.pdf', mimetype: 'application/pdf' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'Double extensions are not allowed' }));
  });

  test('6. Blocks file with null byte in filename', () => {
    const shield = createShield();
    req.file = { originalname: 'image.php\0.jpg', mimetype: 'image/jpeg' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'Null byte detected in filename' }));
  });

  test('7. Blocks file with path traversal in filename', () => {
    const shield = createShield();
    req.file = { originalname: '../../etc/passwd', mimetype: 'text/plain' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'Path traversal detected in filename' }));
  });

  test('8. Blocks dot files', () => {
    const shield = createShield();
    req.file = { originalname: '.htaccess', mimetype: 'text/plain' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'Dot files are not allowed' }));
  });

  test('9. Validates MIME type mismatch', () => {
    const shield = createShield();
    req.file = { originalname: 'image.jpg', mimetype: 'application/pdf' }; // jpg but claims to be pdf
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'MIME type does not match file extension' }));
  });

  test('10. Scans filename for injection', () => {
    const shield = createShield({ scanFilenameForInjection: true, blockPathTraversal: false, blockDotFiles: false, blockDoubleExtensions: false });
    // DetectionEngine detect path-traversal in filename context
    req.file = { originalname: '../../../etc/passwd.jpg', mimetype: 'image/jpeg' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'Filename contains malicious payload' }));
  });

  test('11. Handles req.files as array', () => {
    const shield = createShield();
    req.files = [
      { originalname: 'good.jpg', mimetype: 'image/jpeg' },
      { originalname: 'bad.php', mimetype: 'text/plain' }
    ];
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('12. Handles req.files as object mapping', () => {
    const shield = createShield();
    req.files = {
      avatar: { originalname: 'good.jpg', mimetype: 'image/jpeg' },
      document: { originalname: 'bad.exe', mimetype: 'application/x-msdownload' }
    };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'File extension is blocked' }));
  });

  test('13. Handles req.files as object mapping with arrays', () => {
    const shield = createShield();
    req.files = {
      images: [
        { originalname: 'good1.jpg', mimetype: 'image/jpeg' },
        { originalname: 'good2.png', mimetype: 'image/png' }
      ]
    };
    shield(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('14. Blocks if filename exceeds maxFilenameLength', () => {
    const shield = createShield({ maxFilenameLength: 10 });
    req.file = { originalname: 'thisisaverylongfilename.jpg', mimetype: 'image/jpeg' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'Filename too long' }));
  });

  test('15. Allows when shield is disabled', () => {
    const shield = createShield({ enabled: false });
    req.file = { originalname: 'evil.php', mimetype: 'text/plain' };
    shield(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('16. Validates filename fallback properties', () => {
    const shield = createShield();
    // testing file.name instead of originalname
    req.file = { name: 'resume.php.pdf', mimetype: 'application/pdf' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('17. Allows empty allowedExtensions (fallback to block list)', () => {
    const shield = createShield({ allowedExtensions: [] });
    req.file = { originalname: 'archive.zip', mimetype: 'application/zip' };
    shield(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('18. Blocks path traversal using backslashes', () => {
    const shield = createShield();
    req.file = { originalname: '..\\..\\Windows\\System32\\cmd.exe', mimetype: 'application/x-msdownload' };
    shield(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ reason: 'Path traversal detected in filename' }));
  });

  test('19. Handles missing mimetype gracefully if validation enabled but no expected mime map', () => {
    const shield = createShield({ allowedExtensions: ['.unknown'] });
    req.file = { originalname: 'file.unknown', mimetype: 'application/unknown' };
    shield(req, res, next);
    expect(next).toHaveBeenCalled(); // Should allow because .unknown is not in mimeMap
  });

  test('20. Allows normal filename with scanFilenameForInjection: true', () => {
    const shield = createShield({ scanFilenameForInjection: true });
    req.file = { originalname: 'normal-image.jpg', mimetype: 'image/jpeg' };
    shield(req, res, next);
    expect(next).toHaveBeenCalled();
  });

});
