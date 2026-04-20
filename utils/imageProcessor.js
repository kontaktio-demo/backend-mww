'use strict';

const sharp = require('sharp');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

sharp.cache(false);
sharp.concurrency(1);

const MAX_INPUT_PIXELS = 50000000;

const UPLOADS_DIR = path.resolve(path.join(__dirname, '..', 'uploads'));
const FORMAT = process.env.IMAGE_FORMAT || 'both';
const QUALITY = Math.min(100, Math.max(40, parseInt(process.env.IMAGE_QUALITY, 10) || 80));
const MAX_WIDTH = Math.min(8192, Math.max(320, parseInt(process.env.IMAGE_MAX_WIDTH, 10) || 1920));
const THUMB_WIDTH = Math.min(2048, Math.max(80, parseInt(process.env.THUMB_MAX_WIDTH, 10) || 400));

async function ensureDir() {
  await fs.mkdir(UPLOADS_DIR, { recursive: true, mode: 0o750 });
}

function safeOutputPath(filename) {
  if (!/^[A-Za-z0-9._-]{1,200}$/.test(filename)) {
    throw new Error('Invalid output filename.');
  }
  const full = path.resolve(path.join(UPLOADS_DIR, filename));
  if (!full.startsWith(UPLOADS_DIR + path.sep) && full !== UPLOADS_DIR) {
    throw new Error('Path traversal detected.');
  }
  return full;
}

function openImage(filePath) {
  return sharp(filePath, {
    sequentialRead: true,
    limitInputPixels: MAX_INPUT_PIXELS,
    failOn: 'error',
  }).rotate();
}

async function processImage(inputPath, _originalName, altText) {
  await ensureDir();

  const id = crypto.randomBytes(16).toString('hex');
  const baseName = id;

  const result = {
    original: '',
    webp: '',
    avif: '',
    thumb: '',
    thumbWebp: '',
    thumbAvif: '',
    alt: typeof altText === 'string' ? altText.substring(0, 300) : '',
    order: 0,
  };

  const origFilename = baseName + '-original.jpg';
  const origPath = safeOutputPath(origFilename);
  await openImage(inputPath)
    .resize({ width: MAX_WIDTH, withoutEnlargement: true })
    .jpeg({ quality: QUALITY, mozjpeg: true })
    .withMetadata({ exif: {}, icc: undefined })
    .toFile(origPath);
  result.original = '/uploads/' + origFilename;

  const src = origPath;

  if (FORMAT === 'webp' || FORMAT === 'both') {
    const webpFilename = baseName + '.webp';
    await openImage(src)
      .webp({ quality: QUALITY })
      .toFile(safeOutputPath(webpFilename));
    result.webp = '/uploads/' + webpFilename;

    const thumbWebpFilename = baseName + '-thumb.webp';
    await openImage(src)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .webp({ quality: Math.max(40, QUALITY - 10) })
      .toFile(safeOutputPath(thumbWebpFilename));
    result.thumbWebp = '/uploads/' + thumbWebpFilename;
  }

  if (FORMAT === 'avif' || FORMAT === 'both') {
    const avifFilename = baseName + '.avif';
    await openImage(src)
      .avif({ quality: QUALITY })
      .toFile(safeOutputPath(avifFilename));
    result.avif = '/uploads/' + avifFilename;

    const thumbAvifFilename = baseName + '-thumb.avif';
    await openImage(src)
      .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
      .avif({ quality: Math.max(40, QUALITY - 10) })
      .toFile(safeOutputPath(thumbAvifFilename));
    result.thumbAvif = '/uploads/' + thumbAvifFilename;
  }

  const thumbFilename = baseName + '-thumb.jpg';
  await openImage(src)
    .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
    .jpeg({ quality: QUALITY, mozjpeg: true })
    .toFile(safeOutputPath(thumbFilename));
  result.thumb = '/uploads/' + thumbFilename;

  return result;
}

async function deleteImageFiles(imageObj) {
  if (!imageObj || typeof imageObj !== 'object') return;
  const files = [
    imageObj.original,
    imageObj.webp,
    imageObj.avif,
    imageObj.thumb,
    imageObj.thumbWebp,
    imageObj.thumbAvif,
  ].filter(v => typeof v === 'string' && v.length > 0);

  for (const filePath of files) {
    try {
      if (filePath.includes('..') || filePath.includes('\0') || filePath.includes('\\')) continue;
      if (!filePath.startsWith('/uploads/')) continue;
      const rel = filePath.slice('/uploads/'.length);
      if (!/^[A-Za-z0-9._-]{1,200}$/.test(rel)) continue;
      const full = path.resolve(path.join(UPLOADS_DIR, rel));
      if (!full.startsWith(UPLOADS_DIR + path.sep) && full !== UPLOADS_DIR) continue;
      await fs.unlink(full);
    } catch {}
  }
}

module.exports = { processImage, deleteImageFiles, ensureDir };
