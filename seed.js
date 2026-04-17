'use strict';

/**
 * Seed script – creates default admin user in Supabase if none exists.
 *
 * Usage:
 *   SUPABASE_URL=... SUPABASE_SERVICE_KEY=... ADMIN_USERNAME=... ADMIN_PASSWORD=... node seed.js
 */

require('dotenv').config();
const bcrypt = require('bcryptjs');
const supabase = require('./db');

const ADMIN_USER = process.env.ADMIN_USERNAME;
const ADMIN_PASS = process.env.ADMIN_PASSWORD;

if (!ADMIN_USER || !ADMIN_PASS) {
  console.error('✗ ADMIN_USERNAME and ADMIN_PASSWORD environment variables are required.');
  process.exit(1);
}

async function seed() {
  try {
    const username = ADMIN_USER.toLowerCase().trim();

    // Check if user already exists
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('username', username)
      .single();

    if (existing) {
      console.log('✓ Admin user already exists – skipping.');
      return;
    }

    // Hash password
    const hashed = await bcrypt.hash(String(ADMIN_PASS), 12);

    const { error } = await supabase.from('users').insert({
      username,
      password: hashed,
      role: 'admin',
      active: true,
    });

    if (error) {
      console.error('✗ Seed error:', error.message);
      process.exit(1);
    }

    console.log('✓ Admin user created successfully.');
  } catch (err) {
    console.error('✗ Seed error:', err.message);
    process.exit(1);
  }
}

seed();
