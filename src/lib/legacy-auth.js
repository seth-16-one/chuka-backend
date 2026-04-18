const bcrypt = require('bcryptjs');

const { adminClient } = require('./supabase');

function normalizeIdentifier(value) {
  return String(value || '').trim();
}

function normalizeEmailMaybe(value) {
  const normalized = normalizeIdentifier(value).toLowerCase();
  return normalized.includes('@') ? normalized : '';
}

function isOptionalSchemaError(error) {
  const message = String(error?.message || '').toLowerCase();
  return (
    (message.includes('relation') && message.includes('does not exist')) ||
    (message.includes('column') && message.includes('does not exist'))
  );
}

function mapLegacyProfile(userRow, extra = {}) {
  return {
    id: userRow.id,
    fullName: extra.fullName || userRow.full_name || userRow.username || '',
    email: userRow.email || extra.email || '',
    role: userRow.role || extra.role || 'student',
    regNumber: extra.regNumber || extra.admissionNumber || extra.teacherNumber || undefined,
    staffNumber: extra.staffNumber,
    department: extra.department,
    phone: extra.phone || userRow.phone,
    bio: extra.bio || userRow.bio,
    avatarUrl: extra.avatarUrl || extra.profilePictureUrl || userRow.profile_picture_url,
    source: extra.source || 'legacy',
  };
}

async function findUserRow(identifier) {
  const normalized = normalizeIdentifier(identifier);
  const normalizedEmail = normalizeEmailMaybe(identifier);
  const normalizedLower = normalized.toLowerCase();

  const userQueries = [
    adminClient.from('users').select('*').eq('email', normalizedEmail || normalizedLower).maybeSingle(),
    adminClient.from('users').select('*').eq('username', normalized).maybeSingle(),
    adminClient.from('users').select('*').ilike('username', normalized).maybeSingle(),
    adminClient.from('users').select('*').eq('reg_number', normalized).maybeSingle(),
  ];

  for (const query of userQueries) {
    const { data, error } = await query;
    if (error) {
      if (!isOptionalSchemaError(error)) {
        throw error;
      }
      continue;
    }

    if (data) {
      return { source: 'users', row: data };
    }
  }

  const registrationQueries = [
    adminClient.from('registration').select('*').eq('email', normalizedEmail || normalizedLower).maybeSingle(),
    adminClient.from('registration').select('*').eq('username', normalized).maybeSingle(),
    adminClient.from('registration').select('*').ilike('username', normalized).maybeSingle(),
    adminClient.from('registration').select('*').ilike('full_name', normalized).maybeSingle(),
    adminClient.from('registration').select('*').eq('reg_number', normalized).maybeSingle(),
  ];

  for (const query of registrationQueries) {
    const { data, error } = await query;
    if (error) {
      if (!isOptionalSchemaError(error)) {
        throw error;
      }
      continue;
    }

    if (data) {
      return { source: 'registration', row: data };
    }
  }

  const studentQueries = [
    adminClient
      .from('students')
      .select('id, user_id, full_name, reg_number, admission_number, phone, address, profile_picture_url, bio')
      .eq('reg_number', normalized)
      .maybeSingle(),
    adminClient
      .from('students')
      .select('id, user_id, full_name, reg_number, admission_number, phone, address, profile_picture_url, bio')
      .eq('admission_number', normalized)
      .maybeSingle(),
    adminClient
      .from('students')
      .select('id, user_id, full_name, reg_number, admission_number, phone, address, profile_picture_url, bio')
      .ilike('full_name', normalized)
      .maybeSingle(),
  ];

  for (const query of studentQueries) {
    const { data: studentRow, error } = await query;
    if (error) {
      if (!isOptionalSchemaError(error)) {
        throw error;
      }
      continue;
    }

    if (studentRow?.user_id) {
      const { data: userRow, error: userError } = await adminClient
        .from('users')
        .select('*')
        .eq('id', studentRow.user_id)
        .maybeSingle();

      if (userError) {
        throw userError;
      }

      if (userRow) {
        return {
          source: 'students',
          row: userRow,
          extra: {
            fullName: studentRow.full_name,
            regNumber: studentRow.reg_number || studentRow.admission_number,
            phone: studentRow.phone,
            department: studentRow.address,
            bio: studentRow.bio,
            avatarUrl: studentRow.profile_picture_url,
          },
        };
      }
    }
  }

  const teacherQueries = [
    adminClient
      .from('teachers')
      .select('id, user_id, full_name, reg_number, teacher_number, subject, phone, profile_picture_url, bio')
      .eq('reg_number', normalized)
      .maybeSingle(),
    adminClient
      .from('teachers')
      .select('id, user_id, full_name, reg_number, teacher_number, subject, phone, profile_picture_url, bio')
      .eq('teacher_number', normalized)
      .maybeSingle(),
    adminClient
      .from('teachers')
      .select('id, user_id, full_name, reg_number, teacher_number, subject, phone, profile_picture_url, bio')
      .ilike('full_name', normalized)
      .maybeSingle(),
  ];

  for (const query of teacherQueries) {
    const { data: teacherRow, error } = await query;
    if (error) {
      if (!isOptionalSchemaError(error)) {
        throw error;
      }
      continue;
    }

    if (teacherRow?.user_id) {
      const { data: userRow, error: userError } = await adminClient
        .from('users')
        .select('*')
        .eq('id', teacherRow.user_id)
        .maybeSingle();

      if (userError) {
        throw userError;
      }

      if (userRow) {
        return {
          source: 'teachers',
          row: userRow,
          extra: {
            fullName: teacherRow.full_name,
            staffNumber: teacherRow.reg_number || teacherRow.teacher_number,
            department: teacherRow.subject,
            phone: teacherRow.phone,
            bio: teacherRow.bio,
            avatarUrl: teacherRow.profile_picture_url,
          },
        };
      }
    }
  }

  const adminQueries = [
    adminClient.from('admins').select('id, user_id, full_name, phone, profile_picture_url, bio').ilike('full_name', normalized).maybeSingle(),
  ];

  for (const query of adminQueries) {
    const { data: adminRow, error } = await query;
    if (error) {
      if (!isOptionalSchemaError(error)) {
        throw error;
      }
      continue;
    }

    if (adminRow?.user_id) {
      const { data: userRow, error: userError } = await adminClient
        .from('users')
        .select('*')
        .eq('id', adminRow.user_id)
        .maybeSingle();

      if (userError) {
        throw userError;
      }

      if (userRow) {
        return {
          source: 'admins',
          row: userRow,
          extra: {
            fullName: adminRow.full_name,
            phone: adminRow.phone,
            bio: adminRow.bio,
            avatarUrl: adminRow.profile_picture_url,
          },
        };
      }
    }
  }

  return null;
}

async function verifyLegacyPassword(password, passwordHash) {
  const rawHash = String(passwordHash || '').trim();

  if (!rawHash) {
    return false;
  }

  if (rawHash.startsWith('$2a$') || rawHash.startsWith('$2b$') || rawHash.startsWith('$2y$')) {
    return bcrypt.compare(password, rawHash);
  }

  return false;
}

async function hashLegacyPassword(password) {
  return bcrypt.hash(password, 10);
}

function mapLegacyAccountToProfile(account) {
  const { row, extra = {}, source } = account;
  return mapLegacyProfile(row, {
    ...extra,
    role: row.role || extra.role || 'student',
    fullName: extra.fullName || row.full_name || row.username,
    email: row.email,
    regNumber: extra.regNumber,
    staffNumber: extra.staffNumber,
    department: extra.department,
    phone: extra.phone || row.phone,
    bio: extra.bio || row.bio,
    avatarUrl: extra.avatarUrl || row.profile_picture_url,
    source,
  });
}

module.exports = {
  findUserRow,
  hashLegacyPassword,
  mapLegacyAccountToProfile,
  verifyLegacyPassword,
};
