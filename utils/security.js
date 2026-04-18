'use strict';

/**
 * Security utility functions for input validation and sanitization.
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Check if a string is a valid UUID v4 format.
 */
function isValidUUID(str) {
  return typeof str === 'string' && UUID_RE.test(str);
}

/**
 * Validate that a URL uses a safe scheme (http/https only).
 * Returns true for empty strings (optional fields).
 */
function isSafeUrl(str) {
  if (!str || str === '') return true;
  try {
    const url = new URL(str);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    // Not a valid URL – reject
    return false;
  }
}

/**
 * Sanitise a string field: trim and enforce a maximum byte length.
 * Returns empty string for non-string input.
 */
function sanitiseString(value, maxLen = 500) {
  if (typeof value !== 'string') return '';
  return value.trim().substring(0, maxLen);
}

/**
 * Validate and sanitise a JSONB images array.
 * Ensures each element is a plain object with only allowed string keys
 * and safe URL-like values (must start with /uploads/ or be empty).
 */
const ALLOWED_IMAGE_KEYS = new Set([
  'original', 'webp', 'avif', 'thumb', 'thumbWebp', 'thumbAvif', 'alt', 'order',
]);

function sanitiseImages(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, 50).map(item => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return null;
    const clean = {};
    for (const key of Object.keys(item)) {
      if (!ALLOWED_IMAGE_KEYS.has(key)) continue;
      if (key === 'order') {
        clean.order = typeof item.order === 'number' ? Math.floor(item.order) : 0;
        continue;
      }
      if (key === 'alt') {
        clean.alt = sanitiseString(item.alt, 300);
        continue;
      }
      // Path fields must be strings that start with /uploads/ or are empty
      const val = typeof item[key] === 'string' ? item[key] : '';
      if (val !== '' && !val.startsWith('/uploads/')) continue;
      // Reject path traversal attempts
      if (val.includes('..') || val.includes('\0')) continue;
      clean[key] = val;
    }
    return clean;
  }).filter(Boolean);
}

/**
 * Validate and sanitise a features array (array of short strings).
 */
function sanitiseFeatures(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, 100).filter(item => typeof item === 'string').map(s => s.substring(0, 200));
}

/**
 * Image magic-byte detection.
 * Returns the detected MIME type or null if unrecognised.
 */
function detectMimeType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) return null;

  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';
  // PNG: 89 50 4E 47
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return 'image/png';
  // GIF: 47 49 46 38
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) return 'image/gif';
  // WebP: RIFF....WEBP
  if (buffer.length >= 12 && buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
      buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) return 'image/webp';
  // BMP: 42 4D
  if (buffer[0] === 0x42 && buffer[1] === 0x4D) return 'image/bmp';
  // TIFF: 49 49 2A 00 or 4D 4D 00 2A
  if ((buffer[0] === 0x49 && buffer[1] === 0x49 && buffer[2] === 0x2A && buffer[3] === 0x00) ||
      (buffer[0] === 0x4D && buffer[1] === 0x4D && buffer[2] === 0x00 && buffer[3] === 0x2A)) return 'image/tiff';
  // AVIF: ....ftypavif or ....ftypavis
  if (buffer.length >= 12) {
    const ftyp = buffer.toString('ascii', 4, 8);
    if (ftyp === 'ftyp') {
      const brand = buffer.toString('ascii', 8, 12);
      if (brand === 'avif' || brand === 'avis') return 'image/avif';
    }
  }

  return null;
}

module.exports = {
  isValidUUID,
  isSafeUrl,
  sanitiseString,
  sanitiseImages,
  sanitiseFeatures,
  detectMimeType,
};
