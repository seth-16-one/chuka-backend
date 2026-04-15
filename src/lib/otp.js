const crypto = require('crypto');

const OTP_EXPIRY_MINUTES = Number(process.env.OTP_EXPIRY_MINUTES || 10);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const OTP_REQUEST_LIMIT = Number(process.env.OTP_REQUEST_LIMIT || 3);
const OTP_REQUEST_WINDOW_MINUTES = Number(process.env.OTP_REQUEST_WINDOW_MINUTES || 15);

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function generateOtpCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashOtp({ challengeId, email, purpose, code }) {
  const secret = process.env.OTP_HASH_SECRET;
  if (!secret) {
    throw new Error('Missing OTP_HASH_SECRET.');
  }

  return crypto
    .createHmac('sha256', secret)
    .update(`${challengeId}:${normalizeEmail(email)}:${purpose}:${code}`)
    .digest('hex');
}

function expiresAtIso() {
  return new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();
}

module.exports = {
  OTP_EXPIRY_MINUTES,
  OTP_MAX_ATTEMPTS,
  OTP_REQUEST_LIMIT,
  OTP_REQUEST_WINDOW_MINUTES,
  normalizeEmail,
  generateOtpCode,
  hashOtp,
  expiresAtIso,
};
