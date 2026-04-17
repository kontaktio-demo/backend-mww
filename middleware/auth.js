'use strict';

const jwt = require('jsonwebtoken');
const supabase = require('../db');

const JWT_SECRET = process.env.JWT_SECRET;
// JWT_SECRET is validated at startup in server.js

/**
 * Middleware: verifies JWT token from Authorization header.
 */
async function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';

  if (!token) {
    return res.status(401).json({ error: 'Brak tokenu autoryzacji.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, role, active')
      .eq('id', decoded.id)
      .single();

    if (error || !user || !user.active) {
      return res.status(401).json({ error: 'Użytkownik nieaktywny lub nie istnieje.' });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł.' });
  }
}

module.exports = authMiddleware;
