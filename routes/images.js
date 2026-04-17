'use strict';

const router = require('express').Router();
const multer = require('multer');
const auth = require('../middleware/auth');
const { processImage } = require('../utils/imageProcessor');

const MAX_SIZE = (parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 10) * 1024 * 1024;

const upload = multer({
  storage: multer.memoryStorage(),
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

    const rawAlt = req.body.alt;
    const alt = typeof rawAlt === 'string' ? rawAlt : '';
    const result = await processImage(req.file.buffer, req.file.originalname, alt);

    res.json({
      message: 'Zdjęcie przesłane i przetworzone.',
      image: result,
    });
  } catch (err) {
    console.error('Image upload error:', err);
    if (err.message && err.message.includes('Niedozwolony')) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Błąd przetwarzania zdjęcia.' });
  }
});

/**
 * POST /api/images/upload-multiple
 * Upload multiple images (multipart/form-data, field: "images")
 * Auth required
 * Returns array of processed image objects
 */
router.post('/upload-multiple', auth, upload.array('images', 20), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'Nie przesłano plików.' });
    }

    const results = [];
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];
      const alt = '';
      const result = await processImage(file.buffer, file.originalname, alt);
      result.order = i;
      results.push(result);
    }

    res.json({
      message: `Przesłano i przetworzono ${results.length} zdjęć.`,
      images: results,
    });
  } catch (err) {
    console.error('Multi-image upload error:', err);
    res.status(500).json({ error: 'Błąd przetwarzania zdjęć.' });
  }
});

// Error handler for multer
router.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: `Plik jest zbyt duży. Maksymalny rozmiar: ${process.env.MAX_FILE_SIZE_MB || 10} MB.` });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(400).json({ error: err.message });
  }
});

module.exports = router;
