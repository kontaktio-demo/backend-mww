'use strict';

const sharp = require('sharp');
const path = require('path');
const fs = require('fs/promises');
const { v4: uuidv4 } = require('uuid');

// ─── Memory optimizations for Sharp (libvips) ───────────
// Limit internal tile cache to ~50 MB (default is much higher)
sharp.cache({ memory: 50, files: 10, items: 100 });
// Process one image at a time inside libvips to keep peak RAM low
sharp.concurrency(1);

const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');
const FORMAT = process.env.IMAGE_FORMAT || 'both';
const QUALITY = parseInt(process.env.IMAGE_QUALITY, 10) || 80;
const MAX_WIDTH = parseInt(process.env.IMAGE_MAX_WIDTH, 10) || 1920;
const THUMB_WIDTH = parseInt(process.env.THUMB_MAX_WIDTH, 10) || 400;

/**
 * Ensure uploads directory exists.
 */
async function ensureDir() {
  await fs.mkdir(UPLOADS_DIR, { recursive: true });
}

/**
 * Process an uploaded image (from a temp file on disk):
 * - Convert to WebP and/or AVIF
 * - Generate thumbnail versions
 * - Save all to disk
 *
 * Uses file→file Sharp pipelines (.toFile) instead of holding
 * full-resolution buffers in Node.js memory.
 *
 * @param {string} inputPath  – absolute path to the temp file on disk
 * @param {string} originalName – original client filename (for extension)
 * @param {string} altText
 */
async function processImage(inputPath, originalName, altText) {
  await ensureDir();

  const id = uuidv4();
  const ext = path.extname(originalName).toLowerCase();
  const baseName = `${id}`;

  const result = {
    original: '',
    webp: '',
    avif: '',
    thumb: '',
    thumbWebp: '',
    thumbAvif: '',
    alt: altText || '',
    order: 0,
  };

  // Each step reads from the temp file on disk → writes directly to final file.
  // Only one decoded image is in memory at a time (sharp.concurrency(1)).

  // Save original (resized to max width, keep original format)
  const origFilename = `${baseName}-original${ext || '.jpg'}`;
  await sharp(inputPath)
    .resize({ width: MAX_WIDTH, withoutEnlargement: true })
    .toFile(path.join(UPLOADS_DIR, origFilename));
  result.original = `/uploads/${origFilename}`;

  // Generate WebP (full + thumb)
  if (FORMAT === 'webp' || FORMAT === 'both') {
    const webpFilename = `${baseName}.webp`;
    await sharp(inputPath)
      .resize({ width: MAX_WIDTH, withoutEnlargement: true })
      .webp({ quality: QUALITY })
      .toFile(path.join(UPLOADS_DIR, webpFilename));
    result.webp = `/uploads/${webpFilename}`;

    const thumbWebpFilename = `${baseName}-thumb.webp`;
    await sharp(inputPath)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .webp({ quality: QUALITY - 10 })
      .toFile(path.join(UPLOADS_DIR, thumbWebpFilename));
    result.thumbWebp = `/uploads/${thumbWebpFilename}`;
  }

  // Generate AVIF (full + thumb)
  if (FORMAT === 'avif' || FORMAT === 'both') {
    const avifFilename = `${baseName}.avif`;
    await sharp(inputPath)
      .resize({ width: MAX_WIDTH, withoutEnlargement: true })
      .avif({ quality: QUALITY })
      .toFile(path.join(UPLOADS_DIR, avifFilename));
    result.avif = `/uploads/${avifFilename}`;

    const thumbAvifFilename = `${baseName}-thumb.avif`;
    await sharp(inputPath)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .avif({ quality: QUALITY - 10 })
      .toFile(path.join(UPLOADS_DIR, thumbAvifFilename));
    result.thumbAvif = `/uploads/${thumbAvifFilename}`;
  }

  // Thumb from original format (JPEG)
  const thumbFilename = `${baseName}-thumb.jpg`;
  await sharp(inputPath)
    .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
    .jpeg({ quality: QUALITY })
    .toFile(path.join(UPLOADS_DIR, thumbFilename));
  result.thumb = `/uploads/${thumbFilename}`;

  return result;
}

/**
 * Delete all files for an image object from disk.
 */
async function deleteImageFiles(imageObj) {
  if (!imageObj) return;
  const files = [
    imageObj.original,
    imageObj.webp,
    imageObj.avif,
    imageObj.thumb,
    imageObj.thumbWebp,
    imageObj.thumbAvif,
  ].filter(Boolean);

  for (const filePath of files) {
    try {
      const fullPath = path.join(__dirname, '..', filePath);
      await fs.unlink(fullPath);
    } catch {
      // File might not exist, ignore
    }
  }
}

module.exports = { processImage, deleteImageFiles, ensureDir };
