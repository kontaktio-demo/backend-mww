'use strict';

const jwt = require('jsonwebtoken');
const supabase = require('../db');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER || 'mww-backend';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'mww-admin';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  if (typeof header !== 'string' || header.length > 4096 || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Brak tokenu autoryzacji.' });
  }
  const token = header.slice(7).trim();
  if (!token || token.length > 4096) {
    return res.status(401).json({ error: 'Brak tokenu autoryzacji.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      clockTolerance: 5,
    });

    if (!decoded || typeof decoded.id !== 'string' || !UUID_RE.test(decoded.id)) {
      return res.status(401).json({ error: 'Token nieprawidłowy.' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, role, active')
      .eq('id', decoded.id)
      .single();

    if (error || !user || !user.active) {
      return res.status(401).json({ error: 'Użytkownik nieaktywny lub nie istnieje.' });
    }

    if (decoded.role && decoded.role !== user.role) {
      return res.status(401).json({ error: 'Token nieprawidłowy.' });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł.' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Brak uprawnień.' });
  }
  next();
}

module.exports = authMiddleware;
module.exports.requireAdmin = requireAdmin;
