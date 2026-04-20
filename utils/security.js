'use strict';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_IMAGES_COUNT = 50;
const MAX_FEATURES_COUNT = 100;
const MAX_FEATURE_LENGTH = 200;

const isProd = process.env.NODE_ENV === 'production';

function isValidUUID(str) {
  return typeof str === 'string' && UUID_RE.test(str);
}

function isPrivateHostname(host) {
  if (!host) return true;
  const h = host.toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true;
  if (h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;
  if (/^fc[0-9a-f]{2}:/i.test(h) || /^fd[0-9a-f]{2}:/i.test(h)) return true;
  if (/^fe80:/i.test(h)) return true;
  return false;
}

function isSafeUrl(str) {
  if (!str || str === '') return true;
  if (typeof str !== 'string' || str.length > 2000) return false;
  if (/[\x00-\x1F\x7F]/.test(str)) return false;
  let url;
  try {
    url = new URL(str);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username || url.password) return false;
  if (isProd && isPrivateHostname(url.hostname)) return false;
  return true;
}

function sanitiseString(value, maxLen = 500) {
  if (typeof value !== 'string') return '';
  let v = value.replace(/\x00/g, '');
  v = v.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  return v.trim().substring(0, maxLen);
}

const ALLOWED_IMAGE_KEYS = new Set([
  'original', 'webp', 'avif', 'thumb', 'thumbWebp', 'thumbAvif', 'alt', 'order',
]);

const SAFE_PATH_RE = /^\/uploads\/[A-Za-z0-9._-]{1,200}$/;

function sanitiseImages(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, MAX_IMAGES_COUNT).map(item => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return null;
    const clean = {};
    for (const key of Object.keys(item)) {
      if (!ALLOWED_IMAGE_KEYS.has(key)) continue;
      if (key === 'order') {
        const n = Number(item.order);
        clean.order = Number.isFinite(n) ? Math.max(0, Math.min(9999, Math.floor(n))) : 0;
        continue;
      }
      if (key === 'alt') {
        clean.alt = sanitiseString(item.alt, 300);
        continue;
      }
      const val = typeof item[key] === 'string' ? item[key] : '';
      if (val === '') { clean[key] = ''; continue; }
      if (val.includes('..') || val.includes('\0') || val.includes('\\')) continue;
      if (!SAFE_PATH_RE.test(val)) continue;
      clean[key] = val;
    }
    return clean;
  }).filter(Boolean);
}

function sanitiseFeatures(arr) {
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const item of arr.slice(0, MAX_FEATURES_COUNT)) {
    if (typeof item !== 'string') continue;
    const v = sanitiseString(item, MAX_FEATURE_LENGTH);
    if (v) out.push(v);
  }
  return out;
}

function detectMimeType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) return null;

  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return 'image/png';
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) return 'image/gif';
  if (buffer.length >= 12 && buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
      buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) return 'image/webp';
  if (buffer[0] === 0x42 && buffer[1] === 0x4D) return 'image/bmp';
  if ((buffer[0] === 0x49 && buffer[1] === 0x49 && buffer[2] === 0x2A && buffer[3] === 0x00) ||
      (buffer[0] === 0x4D && buffer[1] === 0x4D && buffer[2] === 0x00 && buffer[3] === 0x2A)) return 'image/tiff';
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
