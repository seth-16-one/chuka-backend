const crypto = require('crypto');

function getSessionSecret() {
  return (
    process.env.JWT_SECRET ||
    process.env.OTP_HASH_SECRET ||
    'chuka-dev-session-secret'
  );
}

function base64UrlEncode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function base64UrlEncodeBuffer(value) {
  return Buffer.from(value).toString('base64url');
}

function signSessionToken(payload, expiresInSeconds) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const issuedAt = Math.floor(Date.now() / 1000);
  const body = {
    ...payload,
    iat: issuedAt,
    exp: issuedAt + expiresInSeconds,
  };
  const unsignedToken = `${base64UrlEncode(header)}.${base64UrlEncode(body)}`;
  const signature = crypto
    .createHmac('sha256', getSessionSecret())
    .update(unsignedToken)
    .digest();

  return `${unsignedToken}.${base64UrlEncodeBuffer(signature)}`;
}

function verifySessionToken(token) {
  const parts = String(token || '').split('.');

  if (parts.length !== 3) {
    return null;
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = crypto
    .createHmac('sha256', getSessionSecret())
    .update(unsignedToken)
    .digest('base64url');

  if (expectedSignature !== encodedSignature) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (payload?.exp && Number(payload.exp) < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

module.exports = {
  signSessionToken,
  verifySessionToken,
};
