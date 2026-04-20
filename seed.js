'use strict';

require('dotenv').config();
const bcrypt = require('bcryptjs');
const supabase = require('./db');

const ADMIN_USER = process.env.ADMIN_USERNAME;
const ADMIN_PASS = process.env.ADMIN_PASSWORD;

if (!ADMIN_USER || !ADMIN_PASS) {
  console.error('ADMIN_USERNAME and ADMIN_PASSWORD environment variables are required.');
  process.exit(1);
}

if (String(ADMIN_PASS).length < 12) {
  console.error('ADMIN_PASSWORD must be at least 12 characters long.');
  process.exit(1);
}

if (!/[a-z]/.test(ADMIN_PASS) || !/[A-Z]/.test(ADMIN_PASS) || !/[0-9]/.test(ADMIN_PASS)) {
  console.error('ADMIN_PASSWORD must contain lower, upper case letters and a digit.');
  process.exit(1);
}

const username = String(ADMIN_USER).toLowerCase().trim();
if (!/^[a-z0-9._-]{3,100}$/.test(username)) {
  console.error('ADMIN_USERNAME has invalid format.');
  process.exit(1);
}

async function seed() {
  try {
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('username', username)
      .single();

    if (existing) {
      console.log('Admin user already exists.');
      return;
    }

    const hashed = await bcrypt.hash(String(ADMIN_PASS), 12);

    const { error } = await supabase.from('users').insert({
      username,
      password: hashed,
      role: 'admin',
      active: true,
    });

    if (error) {
      console.error('Seed error.');
      process.exit(1);
    }

    console.log('Admin user created.');
  } catch {
    console.error('Seed error.');
    process.exit(1);
  }
}

seed();
