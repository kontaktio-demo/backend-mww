'use strict';

const router = require('express').Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const supabase = require('../db');
const auth = require('../middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '24h';
const JWT_ISSUER = process.env.JWT_ISSUER || 'mww-backend';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'mww-admin';

const DUMMY_HASH = '$2a$12$CwTycUXWue0Thq9StjUM0uJ8.yX8r5JQ.9zX3kqQz8lYxUq3Yp/Hu';

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

router.post('/login', async (req, res) => {
  try {
    const username = typeof req.body.username === 'string' ? req.body.username : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!username || !password) {
      return res.status(400).json({ message: 'Podaj nazwę użytkownika i hasło.' });
    }

    if (username.length > 100 || password.length > 128) {
      await bcrypt.compare('x', DUMMY_HASH);
      return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
    }

    const normalized = username.toLowerCase().trim();
    if (!/^[a-z0-9._-]{1,100}$/.test(normalized)) {
      await bcrypt.compare('x', DUMMY_HASH);
      return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, role, active, password')
      .eq('username', normalized)
      .single();

    if (error || !user) {
      await bcrypt.compare(password, DUMMY_HASH);
      return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!user.active) {
      return res.status(403).json({ message: 'Konto jest dezaktywowane.' });
    }
    if (!isMatch) {
      return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
    }

    supabase
      .from('users')
      .update({ last_login: new Date().toISOString() })
      .eq('id', user.id)
      .then(() => {}, () => {});

    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      {
        algorithm: 'HS256',
        expiresIn: JWT_EXPIRES,
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        jwtid: crypto.randomUUID(),
      }
    );

    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch {
    res.status(500).json({ message: 'Błąd serwera.' });
  }
});

router.get('/verify', auth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    valid: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
    },
  });
});

router.post('/change-password', auth, async (req, res) => {
  try {
    const currentPassword = typeof req.body.currentPassword === 'string' ? req.body.currentPassword : '';
    const newPassword = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Podaj aktualne i nowe hasło.' });
    }

    if (newPassword.length < 10) {
      return res.status(400).json({ message: 'Nowe hasło musi mieć minimum 10 znaków.' });
    }
    if (newPassword.length > 128) {
      return res.status(400).json({ message: 'Hasło nie może przekraczać 128 znaków.' });
    }
    if (currentPassword.length > 128) {
      return res.status(400).json({ message: 'Aktualne hasło jest nieprawidłowe.' });
    }
    if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return res.status(400).json({ message: 'Hasło musi zawierać małe i wielkie litery oraz cyfrę.' });
    }
    if (safeEqual(currentPassword, newPassword)) {
      return res.status(400).json({ message: 'Nowe hasło musi różnić się od aktualnego.' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, password')
      .eq('id', req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Aktualne hasło jest nieprawidłowe.' });
    }

    const hashed = await bcrypt.hash(newPassword, 12);
    const { error: upErr } = await supabase
      .from('users')
      .update({ password: hashed })
      .eq('id', user.id);

    if (upErr) {
      return res.status(500).json({ message: 'Błąd serwera.' });
    }

    res.set('Cache-Control', 'no-store');
    res.json({ message: 'Hasło zostało zmienione.' });
  } catch {
    res.status(500).json({ message: 'Błąd serwera.' });
  }
});

module.exports = router;
