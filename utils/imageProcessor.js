'use strict';

const sharp = require('sharp');
const path = require('path');
const fs = require('fs/promises');
const { v4: uuidv4 } = require('uuid');

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
 * Process an uploaded image buffer:
 * - Convert to WebP and/or AVIF
 * - Generate thumbnail versions
 * - Save all to disk
 *
 * Returns an image object ready to attach to an Offer.
 */
async function processImage(buffer, originalName, altText) {
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

  // Save original (as-is, just resized)
  const originalBuffer = await sharp(buffer)
    .resize({ width: MAX_WIDTH, withoutEnlargement: true })
    .toBuffer();

  const origFilename = `${baseName}-original${ext || '.jpg'}`;
  await fs.writeFile(path.join(UPLOADS_DIR, origFilename), originalBuffer);
  result.original = `/uploads/${origFilename}`;

  // Generate WebP (full + thumb)
  if (FORMAT === 'webp' || FORMAT === 'both') {
    const webpBuffer = await sharp(buffer)
      .resize({ width: MAX_WIDTH, withoutEnlargement: true })
      .webp({ quality: QUALITY })
      .toBuffer();
    const webpFilename = `${baseName}.webp`;
    await fs.writeFile(path.join(UPLOADS_DIR, webpFilename), webpBuffer);
    result.webp = `/uploads/${webpFilename}`;

    const thumbWebpBuffer = await sharp(buffer)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .webp({ quality: QUALITY - 10 })
      .toBuffer();
    const thumbWebpFilename = `${baseName}-thumb.webp`;
    await fs.writeFile(path.join(UPLOADS_DIR, thumbWebpFilename), thumbWebpBuffer);
    result.thumbWebp = `/uploads/${thumbWebpFilename}`;
  }

  // Generate AVIF (full + thumb)
  if (FORMAT === 'avif' || FORMAT === 'both') {
    const avifBuffer = await sharp(buffer)
      .resize({ width: MAX_WIDTH, withoutEnlargement: true })
      .avif({ quality: QUALITY })
      .toBuffer();
    const avifFilename = `${baseName}.avif`;
    await fs.writeFile(path.join(UPLOADS_DIR, avifFilename), avifBuffer);
    result.avif = `/uploads/${avifFilename}`;

    const thumbAvifBuffer = await sharp(buffer)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .avif({ quality: QUALITY - 10 })
      .toBuffer();
    const thumbAvifFilename = `${baseName}-thumb.avif`;
    await fs.writeFile(path.join(UPLOADS_DIR, thumbAvifFilename), thumbAvifBuffer);
    result.thumbAvif = `/uploads/${thumbAvifFilename}`;
  }

  // Thumb from original format
  const thumbBuffer = await sharp(buffer)
    .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
    .jpeg({ quality: QUALITY })
    .toBuffer();
  const thumbFilename = `${baseName}-thumb.jpg`;
  await fs.writeFile(path.join(UPLOADS_DIR, thumbFilename), thumbBuffer);
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
