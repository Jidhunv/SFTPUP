'use strict';
// scrypt password hashing using only node:crypto (no native modules to build).
const crypto = require('crypto');

const N = 2 ** 15, R = 8, P = 1, KEYLEN = 64;
const MIN_LEN = 14;

function scrypt(password, salt, n) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEYLEN, { N: n, r: R, p: P, maxmem: 128 * n * R * 2 },
      (err, key) => (err ? reject(err) : resolve(key)));
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, N);
  return `scrypt$${N}$${salt.toString('base64')}$${key.toString('base64')}`;
}

async function verifyPassword(password, stored) {
  const [scheme, n, salt, key] = stored.split('$');
  if (scheme !== 'scrypt') return false;
  const expected = Buffer.from(key, 'base64');
  const actual = await scrypt(password, Buffer.from(salt, 'base64'), Number(n));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function problems(pw) {
  const out = [];
  if (pw.length < MIN_LEN) out.push(`at least ${MIN_LEN} characters`);
  if (!/[a-z]/.test(pw)) out.push('a lowercase letter');
  if (!/[A-Z]/.test(pw)) out.push('an uppercase letter');
  if (!/\d/.test(pw)) out.push('a digit');
  if (!/[^\w\s]/.test(pw)) out.push('a symbol');
  if (/(.)\1{2,}/.test(pw)) out.push('no character repeated 3+ times in a row');
  return out;
}

module.exports = { hashPassword, verifyPassword, problems };
