const express = require('express');
const crypto = require('crypto');

const { adminClient, publicClient } = require('../lib/supabase');
const { signSessionToken } = require('../lib/session-token');
const {
  findUserRow,
  hashLegacyPassword,
  mapLegacyAccountToProfile,
  verifyLegacyPassword,
} = require('../lib/legacy-auth');
const { sendOtpEmail } = require('../lib/mailer');
const {
  OTP_EXPIRY_MINUTES,
  OTP_MAX_ATTEMPTS,
  OTP_REQUEST_LIMIT,
  OTP_REQUEST_WINDOW_MINUTES,
  normalizeEmail,
  generateOtpCode,
  hashOtp,
  expiresAtIso,
} = require('../lib/otp');
const { buildPasswordChecklist } = require('../lib/password-rules');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const pendingLoginChallenges = new Map();

function mapProfileRow(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    role: row.role,
    regNumber: row.reg_number,
    staffNumber: row.staff_number,
    department: row.department,
    phone: row.phone,
    bio: row.bio,
    avatarUrl: row.avatar_url,
  };
}

function issueAuthTokens(profile, source) {
  const sessionPayload = {
    sub: profile.id,
    email: profile.email,
    role: profile.role,
    source,
    fullName: profile.fullName,
  };

  return {
    token: signSessionToken(sessionPayload, 60 * 60 * 24 * 7),
    refreshToken: signSessionToken({ ...sessionPayload, type: 'refresh' }, 60 * 60 * 24 * 30),
  };
}

function isMissingTableError(error) {
  const message = String(error?.message || '').toLowerCase();
  return message.includes('relation') && message.includes('does not exist');
}

async function loadLegacyProfileById(userId) {
  const sources = [
    {
      source: 'users',
      query: adminClient.from('users').select('*').eq('id', userId).maybeSingle(),
    },
    {
      source: 'registration',
      query: adminClient.from('registration').select('*').eq('id', userId).maybeSingle(),
    },
  ];

  for (const item of sources) {
    const { data, error } = await item.query;
    if (error) {
      if (isMissingTableError(error)) {
        continue;
      }
      throw error;
    }

    if (!data) {
      continue;
    }

    if (item.source === 'registration') {
      return {
        id: data.id,
        fullName: data.full_name || data.username || '',
        email: data.email,
        role: data.role || 'student',
        source: item.source,
        regNumber: data.username || undefined,
        phone: data.phone || undefined,
      };
    }

    const account = await findUserRow(data.email || data.username || data.id);
    if (!account) {
      return mapLegacyAccountToProfile({
        source: item.source,
        row: data,
        extra: {},
      });
    }

    const profile = mapLegacyAccountToProfile(account);
    return profile;
  }

  const linkedTables = [
    {
      table: 'students',
      select: 'id, user_id, full_name, admission_number, phone, address, profile_picture_url, bio',
      filter: (query, value) => query.eq('user_id', value),
      mapper: (row) => ({
        id: row.user_id || row.id,
        fullName: row.full_name,
        email: '',
        role: 'student',
        regNumber: row.admission_number,
        department: row.address,
        phone: row.phone,
        bio: row.bio,
        avatarUrl: row.profile_picture_url,
        source: 'students',
      }),
    },
    {
      table: 'teachers',
      select: 'id, user_id, full_name, teacher_number, subject, phone, profile_picture_url, bio',
      filter: (query, value) => query.eq('user_id', value),
      mapper: (row) => ({
        id: row.user_id || row.id,
        fullName: row.full_name,
        email: '',
        role: 'lecturer',
        staffNumber: row.teacher_number,
        department: row.subject,
        phone: row.phone,
        bio: row.bio,
        avatarUrl: row.profile_picture_url,
        source: 'teachers',
      }),
    },
    {
      table: 'admins',
      select: 'id, user_id, full_name, phone, profile_picture_url, bio',
      filter: (query, value) => query.eq('user_id', value),
      mapper: (row) => ({
        id: row.user_id || row.id,
        fullName: row.full_name,
        email: '',
        role: 'admin',
        phone: row.phone,
        bio: row.bio,
        avatarUrl: row.profile_picture_url,
        source: 'admins',
      }),
    },
  ];

  for (const item of linkedTables) {
    const { data, error } = await adminClient.from(item.table).select(item.select).eq('user_id', userId).maybeSingle();
    if (error) {
      if (isMissingTableError(error)) {
        continue;
      }
      throw error;
    }

    if (data) {
      return item.mapper(data);
    }
  }

  return null;
}

async function loadProfileByAuthUser(user) {
  if (user?.source === 'profiles') {
    const { data, error } = await adminClient
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .maybeSingle();

    if (error) {
      if (!isMissingTableError(error)) {
        throw error;
      }
    }

    if (data) {
      return mapProfileRow(data);
    }
  }

  const legacyProfile = await loadLegacyProfileById(user.id);
  if (legacyProfile) {
    return legacyProfile;
  }

  const { data, error } = await adminClient
    .from('profiles')
    .select('*')
    .eq('id', user.id)
    .maybeSingle();

  if (error) {
    if (!isMissingTableError(error)) {
      throw error;
    }
  }

  if (data) {
    return mapProfileRow(data);
  }

  return null;
}

async function attemptModernLogin(identifier, password) {
  const loginEmail = await resolveLoginEmail(identifier);
  const { data: signInData, error: signInError } = await publicClient.auth.signInWithPassword({
    email: loginEmail,
    password,
  });

  if (signInError || !signInData.user || !signInData.session) {
    return null;
  }

  const { data: profileRow, error: profileError } = await adminClient
    .from('profiles')
    .select('*')
    .eq('id', signInData.user.id)
    .maybeSingle();

  if (profileError) {
    if (!isMissingTableError(profileError)) {
      throw profileError;
    }
    return null;
  }

  if (!profileRow) {
    return null;
  }

  return {
    profile: mapProfileRow(profileRow),
    source: 'profiles',
  };
}

async function attemptLegacyLogin(identifier, password) {
  const account = await findUserRow(identifier);
  if (!account?.row) {
    return null;
  }

  const passwordHash = account.row.password_hash || account.row.passwordHash;
  const validPassword = await verifyLegacyPassword(password, passwordHash);
  if (!validPassword) {
    return null;
  }

  if (account.row.is_active === false || account.row.is_suspended === true) {
    const error = new Error('This account is disabled.');
    error.statusCode = 403;
    throw error;
  }

  const profile = mapLegacyAccountToProfile(account);

  return {
    profile,
    source: account.source,
  };
}

async function authenticateLogin(identifier, password) {
  let modernLogin = null;
  let modernLoginError = null;

  try {
    modernLogin = await attemptModernLogin(identifier, password);
  } catch (error) {
    modernLoginError = error;
  }

  if (modernLogin) {
    return modernLogin;
  }

  let legacyLogin = null;
  try {
    legacyLogin = await attemptLegacyLogin(identifier, password);
  } catch (error) {
    if (!modernLoginError) {
      modernLoginError = error;
    }
  }

  if (legacyLogin) {
    return legacyLogin;
  }

  if (modernLoginError && !isMissingTableError(modernLoginError)) {
    const modernMessage = String(modernLoginError?.message || '');
    if (modernMessage && !/invalid|not found|relation|does not exist/i.test(modernMessage)) {
      throw modernLoginError;
    }
  }

  return null;
}

function maskEmail(email) {
  const normalized = normalizeEmail(email);
  const atIndex = normalized.indexOf('@');
  if (atIndex <= 1) {
    return normalized;
  }

  const name = normalized.slice(0, atIndex);
  const domain = normalized.slice(atIndex);
  return `${name.slice(0, 2)}***${domain}`;
}

async function handlePasswordLogin(req, res) {
  try {
    const emailOrReg = String(req.body.email || req.body.identifier || req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!emailOrReg || !password) {
      return res.status(400).json({ error: 'Email, username, or registration number and password are required.' });
    }

    const login = await attemptDirectUserLogin(emailOrReg, password);

    if (!login) {
      return res.status(401).json({ error: 'Invalid login details.' });
    }

    const tokens = issueAuthTokens(login.profile, login.source);
    return res.status(200).json({
      ...tokens,
      user: login.profile,
    });
  } catch (error) {
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Login failed.',
    });
  }
}

async function attemptDirectUserLogin(identifier, password) {
  const normalized = String(identifier || '').trim();
  const normalizedEmail = normalizeEmail(normalized);
  const normalizedLower = normalized.toLowerCase();
  const filters = [];

  if (normalizedEmail) {
    filters.push(`email.eq.${normalizedEmail}`);
  }

  if (normalized) {
    filters.push(`username.eq.${normalized}`);
    filters.push(`reg_number.eq.${normalized}`);
    if (normalizedLower && normalizedLower !== normalized) {
      filters.push(`username.ilike.${normalized}`);
      filters.push(`reg_number.ilike.${normalized}`);
    }
  }

  const { data: userRow, error } = await adminClient
    .from('users')
    .select('*')
    .or(filters.join(','))
    .maybeSingle();

  if (error) {
    if (isMissingTableError(error)) {
      return null;
    }
    throw error;
  }

  if (!userRow) {
    return null;
  }

  const passwordHash = userRow.password_hash || userRow.passwordHash;
  const validPassword = await verifyLegacyPassword(password, passwordHash);
  if (!validPassword) {
    return null;
  }

  if (userRow.is_active === false || userRow.is_suspended === true) {
    const disabledError = new Error('This account is disabled.');
    disabledError.statusCode = 403;
    throw disabledError;
  }

  return {
    profile: mapLegacyAccountToProfile({
      source: 'users',
      row: userRow,
      extra: {
        fullName: userRow.full_name || userRow.username,
        regNumber: userRow.reg_number,
        phone: userRow.phone,
        bio: userRow.bio,
        avatarUrl: userRow.avatar_url,
      },
    }),
    source: 'users',
  };
}

function hasAtLeastTwoNames(value) {
  return String(value || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean).length >= 2;
}

function isValidRegistrationNumber(value) {
  return /^[A-Z]{2}\d\/\d{5}\/\d{2}$/i.test(String(value || '').trim());
}

function isStrongPassword(password, fullName) {
  return buildPasswordChecklist(password, [fullName], 'names').isStrong;
}

async function createOtpChallenge({ email, purpose, req }) {
  const windowStart = new Date(Date.now() - OTP_REQUEST_WINDOW_MINUTES * 60 * 1000).toISOString();
  const { data: recentChallenges, error: rateError } = await adminClient
    .from('email_otp_challenges')
    .select('id')
    .eq('email', email)
    .eq('purpose', purpose)
    .gte('created_at', windowStart);

  if (rateError) {
    throw rateError;
  }

  if ((recentChallenges || []).length >= OTP_REQUEST_LIMIT) {
    const error = new Error('Too many OTP requests. Please wait before trying again.');
    error.statusCode = 429;
    throw error;
  }

  const challengeId = crypto.randomUUID();
  const code = generateOtpCode();
  const otpHash = hashOtp({ challengeId, email, purpose, code });

  const { error: insertError } = await adminClient.from('email_otp_challenges').insert({
    id: challengeId,
    email,
    purpose,
    otp_hash: otpHash,
    request_ip: req.ip,
    user_agent: String(req.headers['user-agent'] || ''),
    attempt_count: 0,
    max_attempts: OTP_MAX_ATTEMPTS,
    expires_at: expiresAtIso(),
  });

  if (insertError) {
    throw insertError;
  }

  await sendOtpEmail({
    email,
    code,
    expiresInMinutes: OTP_EXPIRY_MINUTES,
  });

  return {
    challengeId,
    code,
    expiresInMinutes: OTP_EXPIRY_MINUTES,
  };
}

async function resolveLoginEmail(identifier) {
  const normalized = String(identifier || '').trim();
  let loginEmail = normalizeEmail(normalized);

  if (!loginEmail.includes('@')) {
    const normalizedLower = normalized.toLowerCase();

    const { data: regProfile, error: regProfileError } = await adminClient
      .from('profiles')
      .select('email')
      .eq('reg_number', normalized)
      .maybeSingle();

    if (regProfileError) {
      throw regProfileError;
    }

    if (regProfile?.email) {
      return normalizeEmail(regProfile.email);
    }

    const { data: nameProfile, error: nameProfileError } = await adminClient
      .from('profiles')
      .select('email')
      .ilike('full_name', normalized)
      .maybeSingle();

    if (nameProfileError) {
      throw nameProfileError;
    }

    if (nameProfile?.email) {
      return normalizeEmail(nameProfile.email);
    }

    const { data: aliasProfile, error: aliasProfileError } = await adminClient
      .from('profiles')
      .select('email')
      .ilike('email', `${normalizedLower}@%`)
      .maybeSingle();

    if (aliasProfileError) {
      throw aliasProfileError;
    }

    if (aliasProfile?.email) {
      return normalizeEmail(aliasProfile.email);
    }

    const error = new Error('No account found for that username, email, or registration number.');
    error.statusCode = 404;
    throw error;
  }

  return loginEmail;
}

async function verifyOtpChallenge({ email, challengeId, code, purpose }) {
  const { data: challenge, error } = await adminClient
    .from('email_otp_challenges')
    .select('*')
    .eq('id', challengeId)
    .eq('email', email)
    .eq('purpose', purpose)
    .maybeSingle();

  if (error) {
    throw error;
  }

  if (!challenge) {
    const challengeError = new Error('OTP challenge not found.');
    challengeError.statusCode = 404;
    throw challengeError;
  }

  if (challenge.consumed_at || challenge.verified_at) {
    const usedError = new Error('This OTP has already been used.');
    usedError.statusCode = 410;
    throw usedError;
  }

  if (new Date(challenge.expires_at).getTime() <= Date.now()) {
    await adminClient
      .from('email_otp_challenges')
      .update({ consumed_at: new Date().toISOString() })
      .eq('id', challengeId);

    const expiredError = new Error('OTP has expired.');
    expiredError.statusCode = 410;
    throw expiredError;
  }

  const expectedHash = hashOtp({ challengeId, email, purpose, code });
  const nextAttemptCount = Number(challenge.attempt_count || 0) + 1;

  if (expectedHash !== challenge.otp_hash) {
    const shouldLock = nextAttemptCount >= Number(challenge.max_attempts || OTP_MAX_ATTEMPTS);
    await adminClient
      .from('email_otp_challenges')
      .update({
        attempt_count: nextAttemptCount,
        last_attempt_at: new Date().toISOString(),
        consumed_at: shouldLock ? new Date().toISOString() : null,
      })
      .eq('id', challengeId);

    const invalidError = new Error(
      shouldLock ? 'Too many failed OTP attempts.' : 'Invalid OTP code.'
    );
    invalidError.statusCode = 401;
    throw invalidError;
  }

  await adminClient
    .from('email_otp_challenges')
    .update({
      attempt_count: nextAttemptCount,
      verified_at: new Date().toISOString(),
      consumed_at: new Date().toISOString(),
      last_attempt_at: new Date().toISOString(),
    })
    .eq('id', challengeId);
}

router.post('/otp/request', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const purpose = String(req.body.purpose || 'registration').trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    const { challengeId, code, expiresInMinutes } = await createOtpChallenge({ email, purpose, req });

    const response = {
      success: true,
      challengeId,
      expiresInMinutes,
      message: 'OTP sent successfully.',
    };

    if (process.env.NODE_ENV !== 'production') {
      response.otpCode = code;
    }

    return res.status(200).json(response);
  } catch (error) {
    console.error('OTP Request Error:', error);
    const statusCode = Number(error?.statusCode || 500);
    const message =
      error instanceof Error &&
      /smtp|auth|mail|greet|certificate|tls|connection/i.test(error.message)
        ? 'Failed to send OTP email. Please confirm your SMTP settings and sender email.'
        : error instanceof Error
          ? error.message
          : 'Failed to send OTP.';
    return res.status(statusCode).json({
      error: message,
    });
  }
});

router.post('/otp/verify', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const challengeId = String(req.body.challengeId || '').trim();
    const code = String(req.body.code || '').trim();
    const purpose = String(req.body.purpose || 'registration').trim().toLowerCase();

    if (!email || !challengeId || !code) {
      return res.status(400).json({ error: 'Email, challengeId, and code are required.' });
    }

    await verifyOtpChallenge({ email, challengeId, code, purpose });

    return res.status(200).json({
      success: true,
      verified: true,
    });
  } catch (error) {
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Failed to verify OTP.',
    });
  }
});

router.post('/auth/register', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const fullName = String(req.body.fullName || '').trim();
    const regNumber = String(req.body.regNumber || '').trim();
    const department = String(req.body.department || '').trim();
    const challengeId = String(req.body.challengeId || '').trim();
    const otpCode = String(req.body.otpCode || '').trim();
    const missingFields = [];

    if (!email) missingFields.push('email');
    if (!password) missingFields.push('password');
    if (!fullName) missingFields.push('fullName');
    if (!regNumber) missingFields.push('regNumber');
    if (!challengeId) missingFields.push('challengeId');
    if (!otpCode) missingFields.push('otpCode');

    if (missingFields.length > 0) {
      return res.status(400).json({
        error: `Missing required registration fields: ${missingFields.join(', ')}.`,
      });
    }

    if (!hasAtLeastTwoNames(fullName)) {
      return res.status(400).json({
        error: 'Full name must include at least two names.',
      });
    }

    if (!isValidRegistrationNumber(regNumber)) {
      return res.status(400).json({
        error: 'Registration number must follow the format AB1/12345/25.',
      });
    }

    if (!isStrongPassword(password, fullName)) {
      return res.status(400).json({
        error:
          'Password must be more than 8 characters, include an uppercase letter, a number, a special character, and must not include your names.',
      });
    }

    await verifyOtpChallenge({
      email,
      challengeId,
      code: otpCode,
      purpose: 'registration',
    });

    const { data: existingProfile, error: existingProfileError } = await adminClient
      .from('profiles')
      .select('id, email, reg_number')
      .or(`email.eq.${email},reg_number.eq.${regNumber}`)
      .maybeSingle();

    if (existingProfileError) {
      throw existingProfileError;
    }

    if (existingProfile?.email === email) {
      return res.status(409).json({
        error: 'An account with this email already exists.',
      });
    }

    if (existingProfile?.reg_number === regNumber) {
      return res.status(409).json({
        error: 'This registration number is already in the database.',
      });
    }

    const { data, error } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        full_name: fullName,
        role: 'student',
        reg_number: regNumber,
        department,
      },
    });

    if (error) {
      if (String(error.message || '').toLowerCase().includes('already')) {
        return res.status(409).json({
          error: 'Account already exists with these details.',
        });
      }
      throw error;
    }

    await adminClient
      .from('profiles')
      .update({
        full_name: fullName,
        email,
        role: 'student',
        reg_number: regNumber,
        department,
      })
      .eq('id', data.user.id);

    const { data: profileRow, error: profileError } = await adminClient
      .from('profiles')
      .select('*')
      .eq('id', data.user.id)
      .single();

    if (profileError) {
      throw profileError;
    }

    return res.status(201).json({
      success: true,
      user: mapProfileRow(profileRow),
    });
  } catch (error) {
    return res.status(500).json({
      error: error instanceof Error ? error.message : 'Registration failed.',
    });
  }
});

router.post('/login', handlePasswordLogin);
router.post('/auth/login', handlePasswordLogin);

router.post('/login-otp/request', async (req, res) => {
  try {
    const usernameOrEmail = String(req.body.usernameOrEmail || req.body.username || req.body.email || '').trim();
    const password = String(req.body.password || '');
    const expectedRole = String(req.body.expectedRole || '').trim().toLowerCase();
    const channel = String(req.body.channel || 'email').trim().toLowerCase() || 'email';

    if (!usernameOrEmail || !password) {
      return res.status(400).json({
        error: 'Username/email and password are required.',
      });
    }

    const login = await authenticateLogin(usernameOrEmail, password);
    if (!login) {
      return res.status(401).json({ error: 'Invalid login details.' });
    }

    if (expectedRole && login.profile?.role && String(login.profile.role).toLowerCase() !== expectedRole) {
      return res.status(403).json({ error: `This app accepts ${expectedRole} accounts only.` });
    }

    const email = normalizeEmail(login.profile.email);
    const { challengeId, code, expiresInMinutes } = await createOtpChallenge({ email, purpose: 'login', req });
    const tokens = issueAuthTokens(login.profile, login.source);

    pendingLoginChallenges.set(challengeId, {
      email,
      profile: login.profile,
      source: login.source,
      accessToken: tokens.token,
      refreshToken: tokens.refreshToken,
      createdAt: new Date().toISOString(),
      channel,
    });

    const response = {
      success: true,
      challengeId,
      email,
      channel,
      availableChannels: [channel],
      destinationMasked: maskEmail(email),
      expiresInMinutes,
      message: 'We sent a login verification code to your email.',
    };

    if (process.env.NODE_ENV !== 'production') {
      response.otpCode = code;
    }

    return res.status(200).json(response);
  } catch (error) {
    console.error('Login OTP Request Error:', error);
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Failed to request login OTP.',
    });
  }
});

router.post('/login-otp/verify', async (req, res) => {
  try {
    const challengeId = String(req.body.challengeId || '').trim();
    const code = String(req.body.code || '').trim();

    if (!challengeId || !code) {
      return res.status(400).json({
        error: 'challengeId and code are required.',
      });
    }

    const pendingLogin = pendingLoginChallenges.get(challengeId);
    if (!pendingLogin) {
      return res.status(410).json({
        error: 'This login request has expired. Please sign in again.',
      });
    }

    await verifyOtpChallenge({
      email: pendingLogin.email,
      challengeId,
      code,
      purpose: 'login',
    });

    pendingLoginChallenges.delete(challengeId);

    return res.status(200).json({
      token: pendingLogin.accessToken,
      refreshToken: pendingLogin.refreshToken,
      user: pendingLogin.profile,
    });
  } catch (error) {
    console.error('Login OTP Verify Error:', error);
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Failed to verify login OTP.',
    });
  }
});

router.post('/auth/login/verify', async (req, res) => {
  try {
    const challengeId = String(req.body.challengeId || '').trim();
    const otpCode = String(req.body.otpCode || req.body.code || '').trim();

    if (!challengeId || !otpCode) {
      return res.status(400).json({
        error: 'challengeId and otpCode are required.',
      });
    }

    const pendingLogin = pendingLoginChallenges.get(challengeId);
    if (!pendingLogin) {
      return res.status(410).json({
        error: 'This login request has expired. Please sign in again.',
      });
    }

    await verifyOtpChallenge({
      email: pendingLogin.email,
      challengeId,
      code: otpCode,
      purpose: 'login',
    });

    pendingLoginChallenges.delete(challengeId);

    return res.status(200).json({
      token: pendingLogin.accessToken,
      refreshToken: pendingLogin.refreshToken,
      user: pendingLogin.profile,
    });
  } catch (error) {
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Failed to verify login OTP.',
    });
  }
});

router.post('/auth/password-reset/request', async (req, res) => {
  try {
    const identifier = String(req.body.identifier || '').trim();
    if (!identifier) {
      return res.status(400).json({
        error: 'Email or registration number is required.',
      });
    }

    let email = null;
    try {
      email = await resolveLoginEmail(identifier);
    } catch {
      const legacyAccount = await findUserRow(identifier);
      email = legacyAccount?.row?.email || null;
    }

    if (!email) {
      return res.status(404).json({
        error: 'No account found for that email, username, or registration number.',
      });
    }

    const { challengeId, expiresInMinutes } = await createOtpChallenge({
      email,
      purpose: 'password_reset',
      req,
    });

    return res.status(200).json({
      success: true,
      challengeId,
      email,
      expiresInMinutes,
      message: 'We sent a password reset code to your email.',
    });
  } catch (error) {
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Failed to send password reset OTP.',
    });
  }
});

router.post('/auth/password-reset/confirm', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const challengeId = String(req.body.challengeId || '').trim();
    const otpCode = String(req.body.otpCode || '').trim();
    const newPassword = String(req.body.newPassword || '');

    if (!email || !challengeId || !otpCode || !newPassword) {
      return res.status(400).json({
        error: 'Email, challengeId, otpCode, and newPassword are required.',
      });
    }

    const { data: profile, error: profileError } = await adminClient
      .from('profiles')
      .select('id, full_name, email')
      .eq('email', email)
      .maybeSingle();

    if (profileError) {
      throw profileError;
    }

    if (!profile) {
      return res.status(404).json({
        error: 'No account found for that email address.',
      });
    }

    if (!isStrongPassword(newPassword, profile.full_name)) {
      return res.status(400).json({
        error:
          'Password must be more than 8 characters, include an uppercase letter, a number, a special character, and must not include your names.',
      });
    }

    await verifyOtpChallenge({
      email,
      challengeId,
      code: otpCode,
      purpose: 'password_reset',
    });

    const legacyAccount = await findUserRow(email);
    if (legacyAccount?.row?.password_hash !== undefined) {
      const hashedPassword = await hashLegacyPassword(newPassword);
      const legacyTable = legacyAccount.source === 'registration' ? 'registration' : 'users';

      const { error: legacyUpdateError } = await adminClient
        .from(legacyTable)
        .update({ password_hash: hashedPassword })
        .eq('id', legacyAccount.row.id);

      if (legacyUpdateError) {
        throw legacyUpdateError;
      }
    } else {
      const { error: updateError } = await adminClient.auth.admin.updateUserById(profile.id, {
        password: newPassword,
      });

      if (updateError) {
        throw updateError;
      }
    }

    return res.status(200).json({
      success: true,
      message: 'Password reset successful. You can now log in with the new password.',
    });
  } catch (error) {
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Failed to reset password.',
    });
  }
});

router.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const profile = await loadProfileByAuthUser(req.user);
    if (profile) {
      return res.status(200).json({
        user: profile,
      });
    }

    return res.status(404).json({ error: 'Profile not found.' });
  } catch (error) {
    return res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to load profile.',
    });
  }
});

router.put('/auth/profile', requireAuth, async (req, res) => {
  try {
    const updates = {
      full_name: req.body.fullName,
      department: req.body.department,
      phone: req.body.phone,
      bio: req.body.bio,
      avatar_url: req.body.avatarUrl,
    };

    Object.keys(updates).forEach((key) => {
      if (updates[key] == null || updates[key] === '') {
        delete updates[key];
      }
    });

    const { data, error } = await adminClient
      .from('profiles')
      .update(updates)
      .eq('id', req.user.id)
      .select('*')
      .single();

    if (error) {
      throw error;
    }

    return res.status(200).json({
      user: mapProfileRow(data),
    });
  } catch (error) {
    return res.status(500).json({
      error: error instanceof Error ? error.message : 'Profile update failed.',
    });
  }
});

module.exports = router;
