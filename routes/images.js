'use strict';

const router = require('express').Router();
const multer = require('multer');
const os = require('os');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const auth = require('../middleware/auth');
const { requireAdmin } = require('../middleware/auth');
const { processImage } = require('../utils/imageProcessor');
const { detectMimeType } = require('../utils/security');

const MAX_SIZE = Math.min(50, Math.max(1, parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 5)) * 1024 * 1024;

const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/avif', 'image/gif', 'image/bmp', 'image/tiff']);
const ALLOWED_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp', '.avif', '.gif', '.bmp', '.tif', '.tiff']);

const TMP_DIR = path.resolve(os.tmpdir());

const upload = multer({
  storage: multer.diskStorage({
    destination: TMP_DIR,
    filename(_req, _file, cb) {
      cb(null, 'upload-' + crypto.randomBytes(16).toString('hex'));
    },
  }),
  limits: { fileSize: MAX_SIZE, files: 5, fields: 10, fieldSize: 1024 * 16 },
  fileFilter(_req, file, cb) {
    if (!ALLOWED_MIME.has(file.mimetype)) {
      return cb(new Error('Niedozwolony format pliku.'));
    }
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (ext && !ALLOWED_EXT.has(ext)) {
      return cb(new Error('Niedozwolone rozszerzenie pliku.'));
    }
    cb(null, true);
  },
});

async function removeTmp(filePath) {
  try {
    if (typeof filePath !== 'string' || !filePath) return;
    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(TMP_DIR + path.sep) && resolved !== TMP_DIR) return;
    await fs.unlink(resolved);
  } catch {}
}

async function validateMagicBytes(filePath) {
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(TMP_DIR + path.sep)) return false;

  const handle = await fs.open(resolved, 'r');
  try {
    const buf = Buffer.alloc(16);
    await handle.read(buf, 0, 16, 0);
    const detected = detectMimeType(buf);
    if (!detected) return false;
    return ALLOWED_MIME.has(detected);
  } finally {
    await handle.close();
  }
}

router.post('/upload', auth, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Nie przesłano pliku.' });
    }

    const validMagic = await validateMagicBytes(req.file.path);
    if (!validMagic) {
      await removeTmp(req.file.path);
      return res.status(400).json({ error: 'Plik nie jest prawidłowym obrazem.' });
    }

    const rawAlt = req.body && req.body.alt;
    const alt = typeof rawAlt === 'string' ? rawAlt.substring(0, 300) : '';
    const result = await processImage(req.file.path, req.file.originalname, alt);

    await removeTmp(req.file.path);

    res.set('Cache-Control', 'no-store');
    res.json({
      message: 'Zdjęcie przesłane.',
      image: result,
    });
  } catch (err) {
    if (req.file && req.file.path) await removeTmp(req.file.path);
    if (err && err.message && err.message.includes('Niedozwolon')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Błąd przetwarzania zdjęcia.' });
  }
});

router.post('/upload-multiple', auth, requireAdmin, upload.array('images', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'Nie przesłano plików.' });
    }

    const results = [];
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      const validMagic = await validateMagicBytes(file.path);
      if (!validMagic) {
        await removeTmp(file.path);
        continue;
      }

      const result = await processImage(file.path, file.originalname, '');
      result.order = i;
      results.push(result);

      await removeTmp(file.path);
    }

    res.set('Cache-Control', 'no-store');
    res.json({
      message: 'Przesłano ' + results.length + ' zdjęć.',
      images: results,
    });
  } catch (err) {
    if (req.files) {
      for (const f of req.files) await removeTmp(f.path);
    }
    if (err && err.message && err.message.includes('Niedozwolon')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Błąd przetwarzania zdjęć.' });
  }
});

router.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Plik jest zbyt duży.' });
    }
    return res.status(400).json({ error: 'Błąd przesyłania pliku.' });
  }
  if (err) {
    return res.status(400).json({ error: err.message || 'Błąd żądania.' });
  }
});

module.exports = router;
