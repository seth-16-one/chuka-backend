const { adminClient } = require('../lib/supabase');
const { verifySessionToken } = require('../lib/session-token');

async function requireAuth(req, res, next) {
  const authHeader = String(req.headers.authorization || '');
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token.' });
  }

  const localToken = verifySessionToken(token);
  if (localToken?.sub) {
    req.user = {
      id: localToken.sub,
      email: localToken.email,
      role: localToken.role,
      source: localToken.source || 'legacy',
    };
    req.accessToken = token;
    return next();
  }

  const { data, error } = await adminClient.auth.getUser(token);

  if (error || !data.user) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }

  req.user = {
    id: data.user.id,
    email: data.user.email,
    role: data.user.user_metadata?.role,
    source: 'supabase',
  };
  req.accessToken = token;
  next();
}

module.exports = {
  requireAuth,
};
