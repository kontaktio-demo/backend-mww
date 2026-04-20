'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const crypto = require('crypto');

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET must be set and at least 32 characters long.');
  process.exit(1);
}

const isProd = process.env.NODE_ENV === 'production';

const supabase = require('./db');

const authRoutes = require('./routes/auth');
const offerRoutes = require('./routes/offers');
const imageRoutes = require('./routes/images');

const app = express();

app.set('trust proxy', 1);
app.set('etag', false);
app.set('x-powered-by', false);

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  noSniff: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  dnsPrefetchControl: { allow: false },
  ieNoOpen: true,
  hidePoweredBy: true,
  xssFilter: true,
}));

app.disable('x-powered-by');
app.use(hpp());

app.use((_req, res, next) => {
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('X-Download-Options', 'noopen');
  res.setHeader('Cache-Control', 'no-store');
  res.removeHeader && res.removeHeader('Server');
  next();
});

const DEFAULT_ALLOWED_ORIGINS = [
  'https://panel-mww.vercel.app',
];

const configuredOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

const allowedOrigins = Array.from(new Set([...DEFAULT_ALLOWED_ORIGINS, ...configuredOrigins]));

app.use(cors({
  origin(origin, cb) {
    if (!origin) {
      if (isProd) return cb(null, false);
      return cb(null, true);
    }
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: [],
  maxAge: 600,
  optionsSuccessStatus: 204,
}));

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele żądań.' },
});
app.use(globalLimiter);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele żądań. Spróbuj ponownie za chwilę.' },
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'Zbyt wiele prób logowania. Spróbuj ponownie za 15 minut.' },
});
app.use('/api/auth/login', authLimiter);

const changePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele prób zmiany hasła. Spróbuj ponownie za 15 minut.' },
});
app.use('/api/auth/change-password', changePasswordLimiter);

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele plików w krótkim czasie.' },
});
app.use('/api/images/', uploadLimiter);

app.use(express.json({ limit: '512kb', strict: true, type: 'application/json' }));
app.use(express.urlencoded({ extended: false, limit: '64kb', parameterLimit: 50 }));

app.use((req, _res, next) => {
  req.id = crypto.randomUUID();
  next();
});

if (!isProd && process.env.NODE_ENV !== 'test') {
  app.use(morgan('short'));
}

app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self' data:; media-src 'self'");
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
  if (req.path.includes('..') || req.path.includes('\0')) {
    return res.status(400).end();
  }
  next();
}, express.static(path.join(__dirname, 'uploads'), {
  maxAge: '7d',
  immutable: true,
  index: false,
  dotfiles: 'deny',
  redirect: false,
  fallthrough: true,
}));

app.use('/api/auth', authRoutes);
app.use('/api/offers', offerRoutes);
app.use('/api/images', imageRoutes);

app.get('/api/health', async (_req, res) => {
  let dbOk = false;
  try {
    const { error } = await supabase.from('users').select('id').limit(1);
    dbOk = !error;
  } catch {}

  if (isProd) {
    return res.status(dbOk ? 200 : 503).json({ status: dbOk ? 'ok' : 'degraded' });
  }
  res.json({
    status: dbOk ? 'ok' : 'degraded',
    database: dbOk ? 'connected' : 'error',
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use((_req, res) => {
  res.status(404).json({ error: 'Nie znaleziono zasobu.' });
});

app.use((err, _req, res, _next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Nieprawidłowy format danych.' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Żądanie jest zbyt duże.' });
  }
  if (err && err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: 'Origin nie jest dozwolony.' });
  }
  if (!isProd) {
    console.error('[ERROR]', err && (err.stack || err.message || err));
  } else {
    console.error('[ERROR]', err && (err.code || err.name || 'error'));
  }
  res.status(err && err.status ? err.status : 500).json({
    error: isProd ? 'Wewnętrzny błąd serwera.' : (err && err.message) || 'error',
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
});

process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason && (reason.message || reason));
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err && (err.message || err));
  process.exit(1);
});

module.exports = app;
