const { adminClient } = require('../lib/supabase');

async function requireAuth(req, res, next) {
  const authHeader = String(req.headers.authorization || '');
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token.' });
  }

  const { data, error } = await adminClient.auth.getUser(token);

  if (error || !data.user) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }

  req.user = data.user;
  req.accessToken = token;
  next();
}

module.exports = {
  requireAuth,
};
