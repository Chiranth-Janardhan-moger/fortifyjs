'use strict';

const { DetectionEngine } = require('../core/engine');

const defaultOptions = {
  enabled: true,
  allowedExtensions: ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.docx'],
  blockedExtensions: ['.php', '.asp', '.aspx', '.jsp', '.exe', '.sh', '.bat', '.cmd'],
  maxFilenameLength: 255,
  blockDoubleExtensions: true,
  blockNullBytes: true,
  blockPathTraversal: true,
  blockDotFiles: true,
  validateMimeType: true,
  scanFilenameForInjection: true,
};

const mimeMap = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.pdf': 'application/pdf',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.doc': 'application/msword',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.txt': 'text/plain',
  '.csv': 'text/csv',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.zip': 'application/zip',
  '.tar': 'application/x-tar',
  '.gz': 'application/gzip',
  '.mp4': 'video/mp4',
  '.mp3': 'audio/mpeg'
};

function fileUploadShieldFactory(options = {}) {
  const config = Object.assign({}, defaultOptions, options);

  if (!config.enabled) {
    return (req, res, next) => next();
  }

  let engine = null;
  if (config.scanFilenameForInjection) {
    engine = new DetectionEngine();
  }

  function block(res, next, reason) {
    res.status(403).json({ error: 'File upload blocked', reason });
  }

  function validateFile(file, res, next) {
    if (!file) return true;

    // multer-style file has originalname, some others might have name or filename
    const filename = file.originalname || file.name || file.filename || (typeof file === 'string' ? file : '');

    if (!filename) return true; // Could not determine filename, skip or block? We skip if we can't tell.

    if (config.maxFilenameLength && filename.length > config.maxFilenameLength) {
      block(res, next, 'Filename too long');
      return false;
    }

    if (config.blockNullBytes && filename.indexOf('\0') !== -1) {
      block(res, next, 'Null byte detected in filename');
      return false;
    }

    if (config.blockPathTraversal && (filename.includes('../') || filename.includes('..\\') || filename.includes('/') || filename.includes('\\'))) {
      block(res, next, 'Path traversal detected in filename');
      return false;
    }

    if (config.blockDotFiles && filename.startsWith('.')) {
      block(res, next, 'Dot files are not allowed');
      return false;
    }

    if (filename.includes(':') || filename.includes('::$DATA')) {
      block(res, next, 'Alternate Data Stream syntax or forbidden character in filename');
      return false;
    }

    const parts = filename.split('.');
    const ext = parts.length > 1 ? '.' + parts[parts.length - 1].toLowerCase() : '';

    if (config.blockDoubleExtensions && parts.length > 2) {
      block(res, next, 'Double extensions are not allowed');
      return false;
    }

    if (config.blockedExtensions && config.blockedExtensions.length > 0) {
      if (config.blockedExtensions.includes(ext)) {
        block(res, next, 'File extension is blocked');
        return false;
      }
    }

    if (config.allowedExtensions && config.allowedExtensions.length > 0) {
      if (!config.allowedExtensions.includes(ext)) {
        block(res, next, 'File extension is not allowed');
        return false;
      }
    }

    if (config.validateMimeType && file.mimetype && ext) {
      const expectedMime = mimeMap[ext];
      if (expectedMime && !file.mimetype.toLowerCase().startsWith(expectedMime.split('/')[0])) {
         // Relaxed checking, e.g. application/pdf could be exact, but just compare what we have roughly
         // Or strict comparison:
         if (file.mimetype.toLowerCase() !== expectedMime) {
             block(res, next, 'MIME type does not match file extension');
             return false;
         }
      }
    }

    if (config.scanFilenameForInjection && engine) {
      const result = engine.detect(filename, { source: 'filename' });
      if (result.label && result.label !== 'benign') {
        block(res, next, 'Filename contains malicious payload');
        return false;
      }
    }

    return true;
  }

  return function fileUploadShield(req, res, next) {
    let filesToScan = [];

    if (req.file) {
      filesToScan.push(req.file);
    }

    if (req.files) {
      if (Array.isArray(req.files)) {
        filesToScan = filesToScan.concat(req.files);
      } else if (typeof req.files === 'object') {
        Object.keys(req.files).forEach(key => {
          const field = req.files[key];
          if (Array.isArray(field)) {
            filesToScan = filesToScan.concat(field);
          } else {
            filesToScan.push(field);
          }
        });
      }
    }

    for (let i = 0; i < filesToScan.length; i++) {
      if (!validateFile(filesToScan[i], res, next)) {
        return; // Response already sent
      }
    }

    next();
  };
}

module.exports = { fileUploadShieldFactory };
