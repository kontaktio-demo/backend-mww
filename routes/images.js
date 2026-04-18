'use strict';

const router = require('express').Router();
const multer = require('multer');
const os = require('os');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const auth = require('../middleware/auth');
const { processImage } = require('../utils/imageProcessor');
const { detectMimeType } = require('../utils/security');

const MAX_SIZE = (parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 5) * 1024 * 1024;

// ─── Use disk storage instead of memory to avoid holding entire files in RAM ──
const upload = multer({
  storage: multer.diskStorage({
    destination: os.tmpdir(),
    filename(_req, file, cb) {
      cb(null, `upload-${crypto.randomUUID()}${path.extname(file.originalname)}`);
    },
  }),
  limits: { fileSize: MAX_SIZE },
  fileFilter(_req, file, cb) {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/avif', 'image/gif', 'image/bmp', 'image/tiff'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Niedozwolony format pliku. Dozwolone: JPG, PNG, WebP, AVIF, GIF, BMP, TIFF.'));
    }
  },
});

/** Safely remove a temporary file. Only deletes within os.tmpdir(). */
async function removeTmp(filePath) {
  try {
    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(os.tmpdir())) return;
    await fs.unlink(resolved);
  } catch { /* ignore – file may already be gone */ }
}

/** Validate file magic bytes against declared MIME type */
async function validateMagicBytes(filePath, declaredMime) {
  const handle = await fs.open(filePath, 'r');
  try {
    const buf = Buffer.alloc(16);
    await handle.read(buf, 0, 16, 0);
    const detected = detectMimeType(buf);
    if (!detected) return false;
    // Allow the file if the detected type is a valid image type
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/avif', 'image/gif', 'image/bmp', 'image/tiff'];
    return allowed.includes(detected);
  } finally {
    await handle.close();
  }
}

/**
 * POST /api/images/upload
 * Upload single image (multipart/form-data, field: "image")
 * Auth required
 * Returns processed image object
 */
router.post('/upload', auth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Nie przesłano pliku.' });
    }

    // Validate file magic bytes to prevent spoofed MIME types
    const validMagic = await validateMagicBytes(req.file.path, req.file.mimetype);
    if (!validMagic) {
      await removeTmp(req.file.path);
      return res.status(400).json({ error: 'Plik nie jest prawidłowym obrazem (zweryfikowano nagłówki pliku).' });
    }

    const rawAlt = req.body.alt;
    const alt = typeof rawAlt === 'string' ? rawAlt.substring(0, 300) : '';
    const result = await processImage(req.file.path, req.file.originalname, alt);

    // Clean up temporary upload
    await removeTmp(req.file.path);

    res.json({
      message: 'Zdjęcie przesłane i przetworzone.',
      image: result,
    });
  } catch (err) {
    // Best-effort cleanup on error
    if (req.file && req.file.path) await removeTmp(req.file.path);

    console.error('Image upload error:', err);
    if (err.message && err.message.includes('Niedozwolony')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Błąd przetwarzania zdjęcia.' });
  }
});

/**
 * POST /api/images/upload-multiple
 * Upload up to 5 images (multipart/form-data, field: "images")
 * Auth required
 * Returns array of processed image objects
 *
 * Files are processed ONE AT A TIME and each temp file is deleted
 * immediately after processing to keep RAM & disk pressure low.
 */
router.post('/upload-multiple', auth, upload.array('images', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'Nie przesłano plików.' });
    }

    const results = [];
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      // Validate file magic bytes
      const validMagic = await validateMagicBytes(file.path, file.mimetype);
      if (!validMagic) {
        await removeTmp(file.path);
        continue; // Skip invalid files
      }

      const alt = '';
      const result = await processImage(file.path, file.originalname, alt);
      result.order = i;
      results.push(result);

      // Remove temp file immediately to free disk space for next image
      await removeTmp(file.path);
    }

    res.json({
      message: `Przesłano i przetworzono ${results.length} zdjęć.`,
      images: results,
    });
  } catch (err) {
    // Best-effort cleanup on error
    if (req.files) {
      for (const f of req.files) await removeTmp(f.path);
    }

    console.error('Multi-image upload error:', err);
    res.status(500).json({ error: 'Błąd przetwarzania zdjęć.' });
  }
});

// Error handler for multer
router.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: `Plik jest zbyt duży. Maksymalny rozmiar: ${process.env.MAX_FILE_SIZE_MB || 5} MB.` });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(400).json({ error: err.message });
  }
});

module.exports = router;
