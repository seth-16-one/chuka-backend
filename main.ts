import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.49.8";
import bcrypt from "npm:bcryptjs@3.0.3";
import nodemailer from "npm:nodemailer@6.10.1";
import { createHmac, randomUUID } from "node:crypto";

type JsonObject = Record<string, unknown>;

type UserRow = {
  id: string;
  username?: string | null;
  email?: string | null;
  password_hash?: string | null;
  role?: string | null;
  reg_number?: string | null;
  full_name?: string | null;
  phone?: string | null;
  department?: string | null;
  staff_number?: string | null;
  bio?: string | null;
  avatar_url?: string | null;
  is_active?: boolean | null;
  is_suspended?: boolean | null;
  password_reset_required?: boolean | null;
};

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Vary": "Origin",
};

const OTP_EXPIRY_MINUTES = Number(Deno.env.get("OTP_EXPIRY_MINUTES") || 10);
const OTP_MAX_ATTEMPTS = Number(Deno.env.get("OTP_MAX_ATTEMPTS") || 5);
const OTP_REQUEST_LIMIT = Number(Deno.env.get("OTP_REQUEST_LIMIT") || 3);
const OTP_REQUEST_WINDOW_MINUTES = Number(Deno.env.get("OTP_REQUEST_WINDOW_MINUTES") || 15);

const pendingLoginChallenges = new Map<
  string,
  {
    email: string;
    user: Record<string, unknown>;
    token: string;
    refreshToken: string;
    createdAt: string;
  }
>();

function corsResponse(body: JsonObject, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function normalizeEmail(value: unknown) {
  return String(value || "").trim().toLowerCase();
}

function safeJsonParse(text: string) {
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? (parsed as JsonObject) : {};
  } catch {
    return {};
  }
}

async function readBodyJson(req: Request): Promise<JsonObject> {
  try {
    return safeJsonParse(await req.text());
  } catch {
    return {};
  }
}

function normalizePath(pathname: string) {
  const trimmed = pathname.replace(/\/+$/, "") || "/";
  if (trimmed.startsWith("/api")) {
    const stripped = trimmed.slice(4);
    return stripped === "" ? "/" : stripped;
  }
  return trimmed;
}

function getEnv(name: string) {
  return String(Deno.env.get(name) || "").trim();
}

function isMissingTableError(error: unknown) {
  const message = String((error as Error)?.message || "").toLowerCase();
  return message.includes("relation") && message.includes("does not exist");
}

function getSupabaseClient() {
  const url = getEnv("SUPABASE_URL");
  const key = getEnv("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.");
  }

  return createClient(url, key, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });
}

function getPublicSupabaseClient() {
  const url = getEnv("SUPABASE_URL");
  const key = getEnv("SUPABASE_ANON_KEY");
  if (!url || !key) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_ANON_KEY.");
  }

  return createClient(url, key, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });
}

let adminClientCache: SupabaseClient | null = null;
let publicClientCache: SupabaseClient | null = null;

function adminClient() {
  if (!adminClientCache) {
    adminClientCache = getSupabaseClient();
  }
  return adminClientCache;
}

function publicClient() {
  if (!publicClientCache) {
    publicClientCache = getPublicSupabaseClient();
  }
  return publicClientCache;
}

function jwtSecret() {
  return getEnv("JWT_SECRET") || getEnv("OTP_HASH_SECRET");
}

function hashOtp({ challengeId, email, purpose, code }: { challengeId: string; email: string; purpose: string; code: string }) {
  const secret = getEnv("OTP_HASH_SECRET") || jwtSecret();
  if (!secret) {
    throw new Error("Missing OTP_HASH_SECRET.");
  }

  return createHmac("sha256", secret)
    .update(`${challengeId}:${normalizeEmail(email)}:${purpose}:${code}`)
    .digest("hex");
}

function generateOtpCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function otpExpiresAtIso() {
  return new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();
}

function signToken(payload: JsonObject, expiresInSeconds: number) {
  const secret = jwtSecret();
  if (!secret) {
    throw new Error("Missing JWT_SECRET or OTP_HASH_SECRET.");
  }

  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  const now = Math.floor(Date.now() / 1000);
  const body = btoa(
    JSON.stringify({
      ...payload,
      iat: now,
      exp: now + expiresInSeconds,
    })
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  const signature = createHmac("sha256", secret)
    .update(`${header}.${body}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${header}.${body}.${signature}`;
}

function decodeBase64UrlJson(part: string) {
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return JSON.parse(atob(padded));
}

function publicUser(row: UserRow) {
  return {
    id: row.id,
    username: row.username ?? null,
    email: row.email ?? null,
    role: row.role ?? "student",
    regNumber: row.reg_number ?? null,
    fullName: row.full_name ?? null,
    phone: row.phone ?? null,
    department: row.department ?? null,
    staffNumber: row.staff_number ?? null,
    bio: row.bio ?? null,
    avatarUrl: row.avatar_url ?? null,
  };
}

function hasTwoNames(value: string) {
  return String(value || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean).length >= 2;
}

function isValidRegistrationNumber(value: string) {
  return /^[A-Z]{2}\d\/\d{5}\/\d{2}$/i.test(String(value || "").trim());
}

function strongPassword(password: string, fullName: string) {
  const value = String(password || "");
  const names = String(fullName || "")
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);

  const hasUpper = /[A-Z]/.test(value);
  const hasLower = /[a-z]/.test(value);
  const hasNumber = /\d/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const hasLength = value.length >= 8;
  const containsName = names.some((name) => name.length >= 3 && value.toLowerCase().includes(name));

  return hasLength && hasUpper && hasLower && hasNumber && hasSymbol && !containsName;
}

async function getJsonBody(req: Request) {
  const raw = await req.text().catch(() => "");
  return raw ? safeJsonParse(raw) : {};
}

async function findUserByIdentifier(identifier: string): Promise<{ table: string; row: UserRow } | null> {
  const normalized = String(identifier || "").trim();
  const normalizedEmail = normalizeEmail(normalized);
  const filters = [] as string[];

  if (normalizedEmail) {
    filters.push(`email.eq.${normalizedEmail}`);
  }

  if (normalized) {
    filters.push(`username.eq.${normalized}`);
    filters.push(`reg_number.eq.${normalized}`);
  }

  if (filters.length === 0) {
    return null;
  }

  const tables = ["users", "registration"];
  for (const table of tables) {
    try {
      const { data, error } = await adminClient().from(table).select("*").or(filters.join(",")).maybeSingle();
      if (error) {
        if (isMissingTableError(error)) continue;
        throw error;
      }
      if (data) {
        return { table, row: data as UserRow };
      }
    } catch (error) {
      if (isMissingTableError(error)) continue;
      throw error;
    }
  }

  return null;
}

async function findUserByEmail(email: string): Promise<{ table: string; row: UserRow } | null> {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;

  const tables = ["users", "registration"];
  for (const table of tables) {
    try {
      const { data, error } = await adminClient().from(table).select("*").eq("email", normalized).maybeSingle();
      if (error) {
        if (isMissingTableError(error)) continue;
        throw error;
      }
      if (data) {
        return { table, row: data as UserRow };
      }
    } catch (error) {
      if (isMissingTableError(error)) continue;
      throw error;
    }
  }

  return null;
}

function getMailerProvider() {
  return getEnv("EMAIL_PROVIDER") || "console";
}

function emailContent(code: string, expiresInMinutes: number, purpose: string) {
  const normalized = String(purpose || "registration").trim().toLowerCase();
  const label =
    normalized === "login"
      ? "login"
      : normalized === "password_reset"
        ? "password reset"
        : "registration";

  const subject =
    normalized === "login"
      ? "Your Chuka University login code"
      : normalized === "password_reset"
        ? "Your Chuka University password reset code"
        : "Your Chuka University registration code";

  return {
    subject,
    text: `Your ${label} code is ${code}. It expires in ${expiresInMinutes} minutes.`,
  };
}

async function sendOtpEmail({
  email,
  code,
  expiresInMinutes,
  purpose,
}: {
  email: string;
  code: string;
  expiresInMinutes: number;
  purpose: string;
}) {
  const provider = getMailerProvider();

  if (provider === "console") {
    console.log(`[OTP:${purpose}] ${email} -> ${code}`);
    return;
  }

  const fromName = getEnv("EMAIL_FROM_NAME") || "Chuka University App";
  const fromEmail = getEnv("EMAIL_FROM_ADDRESS") || getEnv("SMTP_USER");
  const content = emailContent(code, expiresInMinutes, purpose);

  if (provider === "resend") {
    const apiKey = getEnv("RESEND_API_KEY");
    if (!apiKey) throw new Error("Missing RESEND_API_KEY.");

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: `"${fromName}" <${fromEmail || "onboarding@resend.dev"}>`,
        to: [email],
        subject: content.subject,
        text: content.text,
      }),
    });

    if (!response.ok) {
      throw new Error(`Resend request failed: ${await response.text()}`);
    }

    return;
  }

  if (provider === "sendgrid") {
    const apiKey = getEnv("SENDGRID_API_KEY");
    if (!apiKey) throw new Error("Missing SENDGRID_API_KEY.");

    const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email }] }],
        from: { email: fromEmail, name: fromName },
        subject: content.subject,
        content: [{ type: "text/plain", value: content.text }],
      }),
    });

    if (!response.ok) {
      throw new Error(`SendGrid request failed: ${await response.text()}`);
    }

    return;
  }

  const smtpHost = getEnv("SMTP_HOST") || "smtp.gmail.com";
  const smtpPort = Number(getEnv("SMTP_PORT") || 587);
  const smtpSecure = String(getEnv("SMTP_SECURE") || "false") === "true";
  const smtpUser = getEnv("SMTP_USER");
  const smtpPass = getEnv("SMTP_PASS");

  if (!smtpHost || !smtpPort || !smtpUser || !smtpPass) {
    throw new Error("Missing SMTP configuration.");
  }

  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    requireTLS: !smtpSecure,
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
    tls: {
      minVersion: "TLSv1.2",
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000,
  });

  await transporter.sendMail({
    from: `"${fromName}" <${fromEmail || smtpUser}>`,
    replyTo: fromEmail || smtpUser,
    to: email,
    subject: content.subject,
    text: content.text,
  });
}

async function createOtpChallenge({
  email,
  purpose,
  req,
}: {
  email: string;
  purpose: string;
  req: Request;
}) {
  const challengeId = randomUUID();
  const code = generateOtpCode();
  const otpHash = hashOtp({ challengeId, email, purpose, code });
  const windowStart = new Date(Date.now() - OTP_REQUEST_WINDOW_MINUTES * 60 * 1000).toISOString();

  try {
    const { data: recent, error: recentError } = await adminClient()
      .from("email_otp_challenges")
      .select("id")
      .eq("email", email)
      .eq("purpose", purpose)
      .gte("created_at", windowStart);

    if (recentError) throw recentError;

    if ((recent || []).length >= OTP_REQUEST_LIMIT) {
      const err = new Error("Too many OTP requests. Please wait before trying again.");
      (err as Error & { statusCode?: number }).statusCode = 429;
      throw err;
    }

    const { error: insertError } = await adminClient().from("email_otp_challenges").insert({
      id: challengeId,
      email,
      purpose,
      otp_hash: otpHash,
      request_ip: req.headers.get("x-forwarded-for") || null,
      user_agent: req.headers.get("user-agent") || null,
      attempt_count: 0,
      max_attempts: OTP_MAX_ATTEMPTS,
      expires_at: otpExpiresAtIso(),
      is_used: false,
    });

    if (insertError) throw insertError;

    await sendOtpEmail({ email, code, expiresInMinutes: OTP_EXPIRY_MINUTES, purpose });
    return { challengeId, code };
  } catch (error) {
    if (isMissingTableError(error)) {
      const err = new Error("Missing email_otp_challenges table.");
      (err as Error & { statusCode?: number }).statusCode = 500;
      throw err;
    }
    throw error;
  }
}

async function verifyOtpChallenge({
  email,
  challengeId,
  code,
  purpose,
}: {
  email: string;
  challengeId: string;
  code: string;
  purpose: string;
}) {
  const { data, error } = await adminClient()
    .from("email_otp_challenges")
    .select("*")
    .eq("id", challengeId)
    .eq("email", email)
    .eq("purpose", purpose)
    .maybeSingle();

  if (error) throw error;
  if (!data) {
    const err = new Error("OTP challenge not found.");
    (err as Error & { statusCode?: number }).statusCode = 404;
    throw err;
  }

  const challenge = data as {
    otp_hash: string;
    attempt_count: number;
    max_attempts: number;
    expires_at: string;
    verified_at: string | null;
    consumed_at: string | null;
  };

  if (challenge.consumed_at || challenge.verified_at) {
    const err = new Error("This OTP has already been used.");
    (err as Error & { statusCode?: number }).statusCode = 410;
    throw err;
  }

  if (new Date(challenge.expires_at).getTime() <= Date.now()) {
    await adminClient()
      .from("email_otp_challenges")
      .update({ consumed_at: new Date().toISOString() })
      .eq("id", challengeId);

    const err = new Error("OTP has expired.");
    (err as Error & { statusCode?: number }).statusCode = 410;
    throw err;
  }

  const expectedHash = hashOtp({ challengeId, email, purpose, code });
  const nextAttemptCount = Number(challenge.attempt_count || 0) + 1;

  if (expectedHash !== challenge.otp_hash) {
    const shouldLock = nextAttemptCount >= Number(challenge.max_attempts || OTP_MAX_ATTEMPTS);
    await adminClient()
      .from("email_otp_challenges")
      .update({
        attempt_count: nextAttemptCount,
        last_attempt_at: new Date().toISOString(),
        consumed_at: shouldLock ? new Date().toISOString() : null,
      })
      .eq("id", challengeId);

    const err = new Error(shouldLock ? "Too many failed OTP attempts." : "Invalid OTP code.");
    (err as Error & { statusCode?: number }).statusCode = 401;
    throw err;
  }

  await adminClient()
    .from("email_otp_challenges")
    .update({
      attempt_count: nextAttemptCount,
      verified_at: new Date().toISOString(),
      consumed_at: new Date().toISOString(),
      last_attempt_at: new Date().toISOString(),
      is_used: true,
    })
    .eq("id", challengeId);
}

async function loginHandler(req: Request) {
  const body = await getJsonBody(req);
  const identifier = String(body.identifier || body.email || body.username || "").trim();
  const password = String(body.password || "").trim();

  if (!identifier || !password) {
    return corsResponse({ error: "Email, username, or registration number and password are required." }, 400);
  }

  try {
    const account = await findUserByIdentifier(identifier);
    if (!account) {
      return corsResponse({ error: "Invalid login details." }, 401);
    }

    const row = account.row;
    if (row.is_active === false || row.is_suspended === true) {
      return corsResponse({ error: "This account is disabled." }, 403);
    }

    if (row.password_reset_required === true) {
      return corsResponse({ error: "This account needs a password reset before login." }, 403);
    }

    const passwordHash = row.password_hash || "";
    if (!passwordHash || !bcrypt.compareSync(password, passwordHash)) {
      return corsResponse({ error: "Invalid login details." }, 401);
    }

    const user = publicUser(row);
    const token = signToken({ sub: user.id, email: user.email, role: user.role, source: account.table }, 60 * 60 * 24 * 7);
    const refreshToken = signToken(
      { sub: user.id, email: user.email, role: user.role, source: account.table, type: "refresh" },
      60 * 60 * 24 * 30
    );

    return corsResponse({
      success: true,
      token,
      refreshToken,
      user,
    });
  } catch (error) {
    console.error("login error:", error);
    return corsResponse(
      {
        error: error instanceof Error ? error.message : "Login failed.",
      },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function registerHandler(req: Request) {
  const body = await getJsonBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "").trim();
  const fullName = String(body.fullName || body.full_name || "").trim();
  const regNumber = String(body.regNumber || body.reg_number || "").trim();
  const department = String(body.department || "").trim();
  const challengeId = String(body.challengeId || "").trim();
  const otpCode = String(body.otpCode || body.code || "").trim();

  const missing: string[] = [];
  if (!email) missing.push("email");
  if (!password) missing.push("password");
  if (!fullName) missing.push("fullName");
  if (!regNumber) missing.push("regNumber");
  if (!challengeId) missing.push("challengeId");
  if (!otpCode) missing.push("otpCode");

  if (missing.length) {
    return corsResponse({ error: `Missing required registration fields: ${missing.join(", ")}.` }, 400);
  }

  if (!hasTwoNames(fullName)) {
    return corsResponse({ error: "Full name must include at least two names." }, 400);
  }

  if (!isValidRegistrationNumber(regNumber)) {
    return corsResponse({ error: "Registration number must follow the format AB1/12345/25." }, 400);
  }

  if (!strongPassword(password, fullName)) {
    return corsResponse(
      {
        error:
          "Password must be at least 8 characters and include uppercase, lowercase, a number, a symbol, and must not include your name.",
      },
      400
    );
  }

  try {
    await verifyOtpChallenge({ email, challengeId, code: otpCode, purpose: "registration" });

    const existing = await findUserByEmail(email);
    if (existing) {
      return corsResponse({ error: "An account with this email already exists." }, 409);
    }

    const existingReg = await findUserByIdentifier(regNumber);
    if (existingReg?.row?.reg_number === regNumber) {
      return corsResponse({ error: "This registration number is already in the database." }, 409);
    }

    const userId = randomUUID();
    const username = regNumber;
    const passwordHash = bcrypt.hashSync(password, 10);

    const userPayload = {
      id: userId,
      username,
      email,
      password_hash: passwordHash,
      role: "student",
      reg_number: regNumber,
      full_name: fullName,
      department: department || null,
      is_active: true,
      is_suspended: false,
      password_reset_required: false,
    };

    const profilePayload = {
      id: userId,
      full_name: fullName,
      email,
      role: "student",
      reg_number: regNumber,
      department: department || null,
    };

    const registrationPayload = {
      id: userId,
      username,
      email,
      password_hash: passwordHash,
      role: "student",
      approved: true,
      approved_at: new Date().toISOString(),
      full_name: fullName,
      reg_number: regNumber,
    };

    for (const [table, payload] of [
      ["users", userPayload],
      ["profiles", profilePayload],
      ["registration", registrationPayload],
    ] as const) {
      const { error } = await adminClient().from(table).insert(payload as never);
      if (error && !isMissingTableError(error)) {
        throw error;
      }
    }

    return corsResponse(
      {
        success: true,
        message: "Registration successful.",
        user: {
          id: userId,
          email,
          fullName,
          regNumber,
          role: "student",
        },
      },
      201
    );
  } catch (error) {
    console.error("register error:", error);
    return corsResponse(
      {
        error: error instanceof Error ? error.message : "Registration failed.",
      },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function sendOtpHandler(req: Request) {
  const body = await getJsonBody(req);
  const email = normalizeEmail(body.email || body.identifier || "");
  const purpose = String(body.purpose || "registration").trim().toLowerCase() || "registration";

  if (!email) {
    return corsResponse({ error: "Email is required." }, 400);
  }

  try {
    const { challengeId, code } = await createOtpChallenge({ email, purpose, req });
    const response: JsonObject = {
      success: true,
      challengeId,
      expiresInMinutes: OTP_EXPIRY_MINUTES,
      message:
        purpose === "login"
          ? "We sent a login verification code to your email."
          : purpose === "password_reset"
            ? "We sent a password reset code to your email."
            : "OTP sent successfully.",
    };

    if (Deno.env.get("NODE_ENV") !== "production") {
      response.otpCode = code;
    }

    return corsResponse(response, 200);
  } catch (error) {
    console.error("send-otp error:", error);
    return corsResponse(
      {
        error:
          error instanceof Error
            ? error.message
            : "Failed to send OTP.",
      },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function verifyOtpOnlyHandler(req: Request) {
  const body = await getJsonBody(req);
  const email = normalizeEmail(body.email);
  const challengeId = String(body.challengeId || "").trim();
  const code = String(body.code || body.otpCode || "").trim();
  const purpose = String(body.purpose || "registration").trim().toLowerCase() || "registration";

  if (!email || !challengeId || !code) {
    return corsResponse({ error: "Email, challengeId, and code are required." }, 400);
  }

  try {
    await verifyOtpChallenge({ email, challengeId, code, purpose });
    return corsResponse({ success: true, verified: true }, 200);
  } catch (error) {
    console.error("otp verify error:", error);
    return corsResponse(
      {
        error: error instanceof Error ? error.message : "Failed to verify OTP.",
      },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function passwordResetRequestHandler(req: Request) {
  const body = await getJsonBody(req);
  const identifier = String(body.identifier || "").trim();

  if (!identifier) {
    return corsResponse({ error: "Email or registration number is required." }, 400);
  }

  try {
    const account = await findUserByIdentifier(identifier);
    if (!account?.row?.email) {
      return corsResponse({ error: "No account found for that email, username, or registration number." }, 404);
    }

    const { challengeId } = await createOtpChallenge({
      email: normalizeEmail(account.row.email),
      purpose: "password_reset",
      req,
    });

    return corsResponse({
      success: true,
      challengeId,
      email: normalizeEmail(account.row.email),
      expiresInMinutes: OTP_EXPIRY_MINUTES,
      message: "We sent a password reset code to your email.",
    });
  } catch (error) {
    console.error("password reset request error:", error);
    return corsResponse(
      {
        error: error instanceof Error ? error.message : "Failed to send password reset OTP.",
      },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function passwordResetConfirmHandler(req: Request) {
  const body = await getJsonBody(req);
  const email = normalizeEmail(body.email);
  const challengeId = String(body.challengeId || "").trim();
  const otpCode = String(body.otpCode || body.code || "").trim();
  const newPassword = String(body.newPassword || "").trim();

  if (!email || !challengeId || !otpCode || !newPassword) {
    return corsResponse({ error: "Email, challengeId, otpCode, and newPassword are required." }, 400);
  }

  try {
    const account = await findUserByEmail(email);
    if (!account?.row) {
      return corsResponse({ error: "No account found for that email address." }, 404);
    }

    const fullName = String(account.row.full_name || account.row.username || "").trim();
    if (!strongPassword(newPassword, fullName)) {
      return corsResponse(
        {
          error:
            "Password must be at least 8 characters and include uppercase, lowercase, a number, a symbol, and must not include your name.",
        },
        400
      );
    }

    await verifyOtpChallenge({ email, challengeId, code: otpCode, purpose: "password_reset" });

    const passwordHash = bcrypt.hashSync(newPassword, 10);
    const { error: updateError } = await adminClient()
      .from(account.table)
      .update({ password_hash: passwordHash, password_reset_required: false })
      .eq("id", account.row.id);

    if (updateError && !isMissingTableError(updateError)) {
      throw updateError;
    }

    return corsResponse({
      success: true,
      message: "Password reset successful. You can now log in with the new password.",
    });
  } catch (error) {
    console.error("password reset confirm error:", error);
    return corsResponse(
      {
        error: error instanceof Error ? error.message : "Failed to reset password.",
      },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function meHandler(req: Request) {
  const authHeader = req.headers.get("authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) {
    return corsResponse({ error: "Missing bearer token." }, 401);
  }

  try {
    const payloadPart = token.split(".")[1];
    if (!payloadPart) {
      return corsResponse({ error: "Invalid token." }, 401);
    }

    const payload = decodeBase64UrlJson(payloadPart);
    const userId = String(payload.sub || "");
    if (!userId) {
      return corsResponse({ error: "Invalid token." }, 401);
    }

    const tables = ["users", "registration"];
    for (const table of tables) {
      const { data, error } = await adminClient().from(table).select("*").eq("id", userId).maybeSingle();
      if (error) {
        if (isMissingTableError(error)) continue;
        throw error;
      }

      if (data) {
        return corsResponse({ user: publicUser(data as UserRow) }, 200);
      }
    }

    return corsResponse({ error: "Profile not found." }, 404);
  } catch (error) {
    console.error("me error:", error);
    return corsResponse({ error: error instanceof Error ? error.message : "Failed to load profile." }, 500);
  }
}

async function profileUpdateHandler(req: Request) {
  const authHeader = req.headers.get("authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) {
    return corsResponse({ error: "Missing bearer token." }, 401);
  }

  const body = await getJsonBody(req);
  const updates = {
    phone: String(body.phone || "").trim() || undefined,
    bio: String(body.bio || "").trim() || undefined,
    department: String(body.department || "").trim() || undefined,
    full_name: String(body.fullName || "").trim() || undefined,
  };

  try {
    const payloadPart = token.split(".")[1];
    const payload = decodeBase64UrlJson(payloadPart);
    const userId = String(payload.sub || "");
    if (!userId) {
      return corsResponse({ error: "Invalid token." }, 401);
    }

    const { data, error } = await adminClient()
      .from("users")
      .update(
        Object.fromEntries(Object.entries(updates).filter(([, value]) => value !== undefined))
      )
      .eq("id", userId)
      .select("*")
      .single();

    if (error) throw error;

    return corsResponse({ user: publicUser(data as UserRow) }, 200);
  } catch (error) {
    console.error("profile update error:", error);
    return corsResponse({ error: error instanceof Error ? error.message : "Profile update failed." }, 500);
  }
}

async function testHandler() {
  return corsResponse({
    ok: true,
    service: "chuka-backend",
    timestamp: new Date().toISOString(),
    routes: ["/test", "/login", "/register", "/send-otp", "/login-otp/request", "/auth/password-reset/request"],
    env: {
      supabaseUrl: Boolean(getEnv("SUPABASE_URL")),
      supabaseAnonKey: Boolean(getEnv("SUPABASE_ANON_KEY")),
      supabaseServiceRoleKey: Boolean(getEnv("SUPABASE_SERVICE_ROLE_KEY")),
      jwtSecret: Boolean(getEnv("JWT_SECRET") || getEnv("OTP_HASH_SECRET")),
      emailProvider: getMailerProvider(),
    },
  });
}

Deno.serve(async (req) => {
  try {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 200, headers: CORS_HEADERS });
    }

    const path = normalizePath(new URL(req.url).pathname);

    if (path === "/test" || path === "/health") {
      return await testHandler();
    }

    if (path === "/login" || path === "/auth/login") {
      return await loginHandler(req);
    }

    if (path === "/register" || path === "/auth/register") {
      return await registerHandler(req);
    }

    if (path === "/send-otp" || path === "/otp/request" || path === "/auth/send-otp") {
      return await sendOtpHandler(req);
    }

    if (path === "/otp/verify") {
      return await verifyOtpOnlyHandler(req);
    }

    if (path === "/login-otp/request" || path === "/auth/login-otp/request") {
      const body = await getJsonBody(req);
      const usernameOrEmail = String(body.usernameOrEmail || body.username || body.email || "").trim();
      const password = String(body.password || "").trim();

      if (!usernameOrEmail || !password) {
        return corsResponse({ error: "Username/email and password are required." }, 400);
      }

      const loginResponse = await loginHandler(
        new Request(req.url, {
          method: "POST",
          headers: req.headers,
          body: JSON.stringify({ identifier: usernameOrEmail, password }),
        })
      );

      const loginJson = await loginResponse.json().catch(() => ({}));
      if (!loginResponse.ok || !loginJson.success) {
        return loginResponse;
      }

      const email = normalizeEmail((loginJson.user as { email?: string } | undefined)?.email || "");
      if (!email) {
        return corsResponse({ error: "Unable to resolve login email." }, 500);
      }

      const { challengeId, code } = await createOtpChallenge({ email, purpose: "login", req });
      const token = String((loginJson as { token?: string }).token || "");
      const refreshToken = String((loginJson as { refreshToken?: string }).refreshToken || "");

      pendingLoginChallenges.set(challengeId, {
        email,
        user: loginJson.user as Record<string, unknown>,
        token,
        refreshToken,
        createdAt: new Date().toISOString(),
      });

      const response: JsonObject = {
        success: true,
        challengeId,
        email,
        channel: "email",
        availableChannels: ["email"],
        destinationMasked: `${email.slice(0, 2)}***${email.includes("@") ? email.slice(email.indexOf("@")) : ""}`,
        expiresInMinutes: OTP_EXPIRY_MINUTES,
        message: "We sent a login verification code to your email.",
      };

      if (Deno.env.get("NODE_ENV") !== "production") {
        response.otpCode = code;
      }

      return corsResponse(response, 200);
    }

    if (path === "/login-otp/verify" || path === "/auth/login/verify") {
      const body = await getJsonBody(req);
      const challengeId = String(body.challengeId || "").trim();
      const code = String(body.code || body.otpCode || "").trim();

      if (!challengeId || !code) {
        return corsResponse({ error: "challengeId and code are required." }, 400);
      }

      const pendingLogin = pendingLoginChallenges.get(challengeId);
      if (!pendingLogin) {
        return corsResponse({ error: "This login request has expired. Please sign in again." }, 410);
      }

      await verifyOtpChallenge({
        email: pendingLogin.email,
        challengeId,
        code,
        purpose: "login",
      });

      pendingLoginChallenges.delete(challengeId);
      return corsResponse({ token: pendingLogin.token, refreshToken: pendingLogin.refreshToken, user: pendingLogin.user }, 200);
    }

    if (path === "/auth/password-reset/request") {
      return await passwordResetRequestHandler(req);
    }

    if (path === "/auth/password-reset/confirm") {
      return await passwordResetConfirmHandler(req);
    }

    if (path === "/auth/me") {
      return await meHandler(req);
    }

    if (path === "/auth/profile") {
      return await profileUpdateHandler(req);
    }

    return corsResponse({ error: "Not found." }, 404);
  } catch (error) {
    console.error("Unhandled request error:", error);
    return corsResponse(
      {
        error: error instanceof Error ? error.message : "Internal server error.",
      },
      500
    );
  }
});
