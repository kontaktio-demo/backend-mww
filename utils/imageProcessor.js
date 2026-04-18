'use strict';

const sharp = require('sharp');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');
const { v4: uuidv4 } = require('uuid');

// ─── Aggressive memory optimizations for 512 MB Render instances ────
// Disable libvips tile/operation cache entirely — every MB counts
sharp.cache(false);
// Single-threaded libvips processing to minimise peak resident memory
sharp.concurrency(1);

// Reject images larger than 50 megapixels (≈ 200 MB decoded RGBA).
// Prevents a single huge photo from blowing the 512 MB limit.
const MAX_INPUT_PIXELS = 50_000_000;

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
 * Helper: create a sharp instance from a file path with memory-safe defaults.
 * - sequentialRead: stream from disk instead of mmap (halves peak RAM)
 * - limitInputPixels: reject absurdly large images before decode
 */
function openImage(filePath) {
  return sharp(filePath, {
    sequentialRead: true,
    limitInputPixels: MAX_INPUT_PIXELS,
  });
}

/**
 * Process an uploaded image (from a temp file on disk).
 *
 * **Two-pass strategy** to keep RAM low on 512 MB instances:
 *   1. Decode the raw upload ONCE → save a resized JPEG intermediate to /tmp.
 *   2. Use that smaller intermediate as the source for WebP / AVIF / thumbnails.
 *
 * This avoids decoding a potentially huge raw/PNG/TIFF file multiple times.
 * Each sharp pipeline is sequential (file→file), so only ONE decoded image
 * lives in libvips memory at any moment.
 *
 * @param {string} inputPath     – absolute path to the temp upload on disk
 * @param {string} originalName  – original client filename (for extension)
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

  // ── Pass 1: decode raw upload → save resized original ──────────────
  const origFilename = `${baseName}-original${ext || '.jpg'}`;
  const origPath = path.join(UPLOADS_DIR, origFilename);
  await openImage(inputPath)
    .resize({ width: MAX_WIDTH, withoutEnlargement: true })
    .toFile(origPath);
  result.original = `/uploads/${origFilename}`;

  // ── Pass 2: use the (smaller) resized original as source ───────────
  // From here on we never touch the raw upload again, so libvips only
  // needs to decode a ≤ 1920px-wide JPEG/PNG instead of the raw input.
  const src = origPath;

  // Generate WebP (full + thumb)
  if (FORMAT === 'webp' || FORMAT === 'both') {
    const webpFilename = `${baseName}.webp`;
    await openImage(src)
      .webp({ quality: QUALITY })
      .toFile(path.join(UPLOADS_DIR, webpFilename));
    result.webp = `/uploads/${webpFilename}`;

    const thumbWebpFilename = `${baseName}-thumb.webp`;
    await openImage(src)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .webp({ quality: QUALITY - 10 })
      .toFile(path.join(UPLOADS_DIR, thumbWebpFilename));
    result.thumbWebp = `/uploads/${thumbWebpFilename}`;
  }

  // Generate AVIF (full + thumb)
  if (FORMAT === 'avif' || FORMAT === 'both') {
    const avifFilename = `${baseName}.avif`;
    await openImage(src)
      .avif({ quality: QUALITY })
      .toFile(path.join(UPLOADS_DIR, avifFilename));
    result.avif = `/uploads/${avifFilename}`;

    const thumbAvifFilename = `${baseName}-thumb.avif`;
    await openImage(src)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .avif({ quality: QUALITY - 10 })
      .toFile(path.join(UPLOADS_DIR, thumbAvifFilename));
    result.thumbAvif = `/uploads/${thumbAvifFilename}`;
  }

  // Thumb from original format (JPEG)
  const thumbFilename = `${baseName}-thumb.jpg`;
  await openImage(src)
    .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
    .jpeg({ quality: QUALITY })
    .toFile(path.join(UPLOADS_DIR, thumbFilename));
  result.thumb = `/uploads/${thumbFilename}`;

  return result;
}

/**
 * Delete all files for an image object from disk.
 * Validates paths to prevent path traversal attacks.
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
      const fullPath = path.resolve(path.join(__dirname, '..', filePath));
      // Ensure resolved path is inside the uploads directory to prevent traversal
      if (!fullPath.startsWith(UPLOADS_DIR + path.sep) && fullPath !== UPLOADS_DIR) continue;
      await fs.unlink(fullPath);
    } catch {
      // File might not exist, ignore
    }
  }
}

module.exports = { processImage, deleteImageFiles, ensureDir };
