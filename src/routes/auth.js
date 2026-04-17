const express = require('express');
const crypto = require('crypto');

const { adminClient, publicClient } = require('../lib/supabase');
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

    const { challengeId, expiresInMinutes } = await createOtpChallenge({ email, purpose, req });

    return res.status(200).json({
      success: true,
      challengeId,
      expiresInMinutes,
      message: 'OTP sent successfully.',
    });
  } catch (error) {
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
    const missingFields = [];

    if (!email) missingFields.push('email');
    if (!password) missingFields.push('password');
    if (!fullName) missingFields.push('fullName');
    if (!regNumber) missingFields.push('regNumber');

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

router.post('/auth/login', async (req, res) => {
  try {
    const emailOrReg = String(req.body.email || req.body.identifier || req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!emailOrReg || !password) {
      return res.status(400).json({ error: 'Email or registration number and password are required.' });
    }

    const loginEmail = await resolveLoginEmail(emailOrReg);

    const { data: signInData, error: signInError } = await publicClient.auth.signInWithPassword({
      email: loginEmail,
      password,
    });

    if (signInError || !signInData.user || !signInData.session) {
      return res.status(401).json({ error: signInError?.message || 'Invalid login details.' });
    }

    const { data: profileRow, error: profileError } = await adminClient
      .from('profiles')
      .select('*')
      .eq('id', signInData.user.id)
      .single();

    if (profileError) {
      throw profileError;
    }

    return res.status(200).json({
      token: signInData.session.access_token,
      refreshToken: signInData.session.refresh_token,
      user: mapProfileRow(profileRow),
    });
  } catch (error) {
    return res.status(Number(error?.statusCode || 500)).json({
      error: error instanceof Error ? error.message : 'Login failed.',
    });
  }
});

router.post('/auth/login/verify', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const challengeId = String(req.body.challengeId || '').trim();
    const otpCode = String(req.body.otpCode || '').trim();

    if (!email || !challengeId || !otpCode) {
      return res.status(400).json({
        error: 'Email, challengeId, and otpCode are required.',
      });
    }

    const pendingLogin = pendingLoginChallenges.get(challengeId);
    if (!pendingLogin) {
      return res.status(410).json({
        error: 'This login request has expired. Please sign in again.',
      });
    }

    await verifyOtpChallenge({
      email,
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

    const email = await resolveLoginEmail(identifier);
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

    const { error: updateError } = await adminClient.auth.admin.updateUserById(profile.id, {
      password: newPassword,
    });

    if (updateError) {
      throw updateError;
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
    const { data, error } = await adminClient
      .from('profiles')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error) {
      throw error;
    }

    return res.status(200).json({
      user: mapProfileRow(data),
    });
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
