'use strict';

const router = require('express').Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const supabase = require('../db');
const auth = require('../middleware/auth');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '24h';

/**
 * POST /api/auth/login
 * Body: { username, password }
 * Returns: { token, user }
 */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Podaj nazwę użytkownika i hasło.' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', String(username).toLowerCase().trim())
      .single();

    if (error || !user) {
      return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
    }

    if (!user.active) {
      return res.status(403).json({ message: 'Konto jest dezaktywowane.' });
    }

    const isMatch = await bcrypt.compare(String(password), user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
    }

    // Update last login
    await supabase
      .from('users')
      .update({ last_login: new Date().toISOString() })
      .eq('id', user.id);

    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Błąd serwera.' });
  }
});

/**
 * GET /api/auth/verify
 * Headers: Authorization: Bearer <token>
 * Returns: { valid: true, user }
 */
router.get('/verify', auth, (req, res) => {
  res.json({
    valid: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
    },
  });
});

/**
 * POST /api/auth/change-password
 * Body: { currentPassword, newPassword }
 */
router.post('/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Podaj aktualne i nowe hasło.' });
    }

    if (String(newPassword).length < 6) {
      return res.status(400).json({ message: 'Nowe hasło musi mieć minimum 6 znaków.' });
    }

    // Fetch full user with password
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });
    }

    const isMatch = await bcrypt.compare(String(currentPassword), user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Aktualne hasło jest nieprawidłowe.' });
    }

    const hashed = await bcrypt.hash(String(newPassword), 12);
    await supabase
      .from('users')
      .update({ password: hashed })
      .eq('id', user.id);

    res.json({ message: 'Hasło zostało zmienione.' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ message: 'Błąd serwera.' });
  }
});

module.exports = router;
