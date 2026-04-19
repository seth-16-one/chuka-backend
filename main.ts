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
  fee_balance_cents?: number | string | null;
  fees_cleared?: boolean | null;
  last_payment_at?: string | null;
};

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Vary": "Origin",
};

const OTP_EXPIRY_MINUTES = Number(Deno.env.get("OTP_EXPIRY_MINUTES") || 30);
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
    expiresAt: string;
    sessionId: string;
    requestIp: string | null;
    userAgent: string | null;
    ipLocation: JsonObject | null;
  }
>();

type SessionRow = {
  id: string;
  user_id?: string | null;
  device_name?: string | null;
  user_agent?: string | null;
  ip_address?: string | null;
  ip_location?: JsonObject | null;
  created_at?: string | null;
  last_seen_at?: string | null;
  revoked_at?: string | null;
  revoked_reason?: string | null;
  token_kind?: string | null;
};

type LoginOtpSessionRow = {
  id: string;
  email?: string | null;
  token?: string | null;
  refresh_token?: string | null;
  user_payload?: JsonObject | null;
  session_id?: string | null;
  request_ip?: string | null;
  user_agent?: string | null;
  ip_location?: JsonObject | null;
  created_at?: string | null;
  expires_at?: string | null;
  consumed_at?: string | null;
};

type LoginTicketClaims = JsonObject & {
  challenge_id?: string;
  email?: string;
  token?: string;
  refresh_token?: string;
  user_payload?: JsonObject;
  expires_at?: string;
};

type FinanceStatusRow = {
  user_id?: string | null;
  balance_cents?: number | string | null;
  paid_cents?: number | string | null;
  due_cents?: number | string | null;
  fees_cleared?: boolean | null;
  last_payment_at?: string | null;
  status_label?: string | null;
  updated_at?: string | null;
};

type StaffMaterialRow = {
  id: string;
  title?: string | null;
  course_code?: string | null;
  audience?: string | null;
  author?: string | null;
  summary?: string | null;
  file_label?: string | null;
  storage_path?: string | null;
  mime_type?: string | null;
  original_file_name?: string | null;
  file_size?: number | string | null;
  uploaded_by?: string | null;
  uploaded_at?: string | null;
  is_published?: boolean | null;
};

type StudentDocumentRow = {
  id: string;
  user_id?: string | null;
  document_type?: string | null;
  file_name?: string | null;
  mime_type?: string | null;
  storage_path?: string | null;
  file_size?: number | string | null;
  fees_cleared?: boolean | null;
  uploaded_by?: string | null;
  created_at?: string | null;
};

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

function nowIso() {
  return new Date().toISOString();
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

function signLoginTicket(payload: JsonObject) {
  return signToken(payload, 60 * 60 * 24);
}

function buildLoginTicket({
  challengeId,
  email,
  token,
  refreshToken,
  user,
  sessionId,
  expiresAt,
}: {
  challengeId: string;
  email: string;
  token: string;
  refreshToken: string;
  user: Record<string, unknown>;
  sessionId: string;
  expiresAt: string;
}) {
  return signLoginTicket({
    challenge_id: challengeId,
    email,
    token,
    refresh_token: refreshToken,
    user_payload: user,
    sid: sessionId,
    expires_at: expiresAt,
    token_kind: "login_ticket",
  });
}

function verifyLoginTicket(ticket: string): LoginTicketClaims | null {
  const claims = verifyToken(ticket);
  if (!claims) {
    return null;
  }

  if (!claims.challenge_id || !claims.email || !claims.token || !claims.refresh_token || !claims.user_payload) {
    return null;
  }

  return claims as LoginTicketClaims;
}

async function storeLoginOtpSession({
  challengeId,
  email,
  user,
  token,
  refreshToken,
  sessionId,
  requestIp,
  userAgent,
  ipLocation,
}: {
  challengeId: string;
  email: string;
  user: Record<string, unknown>;
  token: string;
  refreshToken: string;
  sessionId: string;
  requestIp: string | null;
  userAgent: string | null;
  ipLocation: JsonObject | null;
}) {
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();
  const { error } = await adminClient().from("login_otp_sessions").upsert(
    {
      id: challengeId,
      email,
      token,
      refresh_token: refreshToken,
      user_payload: user,
      session_id: sessionId,
      request_ip: requestIp,
      user_agent: userAgent,
      ip_location: ipLocation,
      created_at: nowIso(),
      expires_at: expiresAt,
      consumed_at: null,
    },
    { onConflict: "id" }
  );

  if (error) {
    if (isMissingTableError(error)) {
      return;
    }
    throw error;
  }
}

async function loadLoginOtpSession(challengeId: string): Promise<LoginOtpSessionRow | null> {
  const { data, error } = await adminClient().from("login_otp_sessions").select("*").eq("id", challengeId).maybeSingle();
  if (error) {
    if (isMissingTableError(error)) {
      return null;
    }
    throw error;
  }

  return (data as LoginOtpSessionRow | null) ?? null;
}

async function consumeLoginOtpSession(challengeId: string) {
  const { error } = await adminClient().from("login_otp_sessions").update({ consumed_at: nowIso() }).eq("id", challengeId);
  if (error && !isMissingTableError(error)) {
    throw error;
  }
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

function verifyToken(token: string) {
  const secret = jwtSecret();
  if (!secret) {
    throw new Error("Missing JWT_SECRET or OTP_HASH_SECRET.");
  }

  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    return null;
  }

  const [header, payload, signature] = parts;
  const expected = createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  if (expected !== signature) {
    return null;
  }

  try {
    const claims = decodeBase64UrlJson(payload) as JsonObject;
    if (claims?.exp && Number(claims.exp) < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return claims;
  } catch {
    return null;
  }
}

function decodeBase64UrlJson(part: string) {
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return JSON.parse(atob(padded));
}

function getRequestIp(req: Request) {
  const forwarded = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "";
  const candidate = forwarded.split(",")[0]?.trim() || "";
  return candidate || null;
}

function getRequestUserAgent(req: Request) {
  return req.headers.get("user-agent") || null;
}

function isPrivateIp(ip: string) {
  return (
    !ip ||
    /^127\./.test(ip) ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip === "::1" ||
    ip.startsWith("fc") ||
    ip.startsWith("fd")
  );
}

async function lookupIpLocation(ip: string | null): Promise<JsonObject | null> {
  if (!ip || isPrivateIp(ip)) {
    return null;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);

  try {
    const response = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      signal: controller.signal,
    });

    if (!response.ok) {
      return null;
    }

    const data = (await response.json().catch(() => ({}))) as JsonObject;
    return {
      ip,
      city: data.city || null,
      region: data.region || null,
      country: data.country_name || data.country || null,
      latitude: data.latitude || null,
      longitude: data.longitude || null,
      timezone: data.timezone || null,
      org: data.org || null,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function summarizeLocation(location: JsonObject | null) {
  if (!location) {
    return "Unknown location";
  }

  const parts = [location.city, location.region, location.country].filter(Boolean);
  return parts.length ? String(parts.join(", ")) : "Unknown location";
}

async function createSessionContext(req: Request) {
  const requestIp = getRequestIp(req);
  const userAgent = getRequestUserAgent(req);
  const ipLocation = await lookupIpLocation(requestIp);
  return {
    requestIp,
    userAgent,
    ipLocation,
  };
}

async function saveLoginSession({
  sessionId,
  userId,
  tokenKind,
  req,
}: {
  sessionId: string;
  userId: string;
  tokenKind: "access" | "refresh";
  req: Request;
}) {
  const { requestIp, userAgent, ipLocation } = await createSessionContext(req);
  const deviceName = req.headers.get("x-device-name") || userAgent || "Unknown device";
  const now = nowIso();

  const payload = {
    id: sessionId,
    user_id: userId,
    device_name: deviceName,
    user_agent: userAgent,
    ip_address: requestIp,
    ip_location: ipLocation,
    ip_city: (ipLocation?.city as string | null) || null,
    ip_region: (ipLocation?.region as string | null) || null,
    ip_country: (ipLocation?.country as string | null) || null,
    token_kind: tokenKind,
    created_at: now,
    last_seen_at: now,
    revoked_at: null,
    revoked_reason: null,
  };

  const { error } = await adminClient().from("device_sessions").upsert(payload, { onConflict: "id" });
  if (error) {
    if (isMissingTableError(error)) {
      return;
    }
    throw error;
  }
}

async function listDeviceSessions(userId: string) {
  const { data, error } = await adminClient()
    .from("device_sessions")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false });

  if (error) {
    if (isMissingTableError(error)) {
      return [];
    }
    throw error;
  }

  return (data || []) as SessionRow[];
}

async function revokeDeviceSession(userId: string, sessionId: string, reason: string) {
  const { error } = await adminClient()
    .from("device_sessions")
    .update({ revoked_at: nowIso(), revoked_reason: reason })
    .eq("id", sessionId)
    .eq("user_id", userId);

  if (error && !isMissingTableError(error)) {
    throw error;
  }
}

async function revokeOtherDeviceSessions(userId: string, currentSessionId: string) {
  const { error } = await adminClient()
    .from("device_sessions")
    .update({ revoked_at: nowIso(), revoked_reason: "revoked_by_user" })
    .eq("user_id", userId)
    .neq("id", currentSessionId);

  if (error && !isMissingTableError(error)) {
    throw error;
  }
}

async function authenticateRequest(req: Request) {
  const authHeader = req.headers.get("authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

  if (!token) {
    const err = new Error("Missing bearer token.");
    (err as Error & { statusCode?: number }).statusCode = 401;
    throw err;
  }

  const claims = verifyToken(token);
  if (!claims?.sub) {
    const err = new Error("Invalid or expired token.");
    (err as Error & { statusCode?: number }).statusCode = 401;
    throw err;
  }

  const sessionId = String(claims.sid || claims.session_id || "");
  if (sessionId) {
    const { data, error } = await adminClient()
      .from("device_sessions")
      .select("*")
      .eq("id", sessionId)
      .eq("user_id", String(claims.sub))
      .maybeSingle();

    if (error && !isMissingTableError(error)) {
      throw error;
    }

    if (data && (data as SessionRow).revoked_at) {
      const err = new Error("This session has been revoked.");
      (err as Error & { statusCode?: number }).statusCode = 401;
      throw err;
    }

    if (data) {
      await adminClient()
        .from("device_sessions")
        .update({ last_seen_at: nowIso() })
        .eq("id", sessionId)
        .eq("user_id", String(claims.sub));
    }
  }

  return {
    claims,
    token,
    sessionId: sessionId || null,
  };
}

async function requireStaffRole(req: Request) {
  const auth = await authenticateRequest(req);
  const role = String(auth.claims.role || "student").toLowerCase();
  if (role !== "lecturer" && role !== "admin") {
    const err = new Error("Staff access required.");
    (err as Error & { statusCode?: number }).statusCode = 403;
    throw err;
  }

  return auth;
}

function publicUser(row: UserRow) {
  const feeBalanceValue = Number(row.fee_balance_cents ?? 0);
  const feeBalanceCents = Number.isFinite(feeBalanceValue) ? feeBalanceValue : null;
  const feesCleared = typeof row.fees_cleared === "boolean" ? row.fees_cleared : feeBalanceCents !== null ? feeBalanceCents <= 0 : null;
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
    feeBalanceCents,
    feesCleared,
    lastPaymentAt: row.last_payment_at ?? null,
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
    const sessionId = randomUUID();
    const token = signToken(
      { sub: user.id, email: user.email, role: user.role, source: account.table, sid: sessionId, token_kind: "access" },
      60 * 60 * 24 * 7
    );
    const refreshToken = signToken(
      {
        sub: user.id,
        email: user.email,
        role: user.role,
        source: account.table,
        sid: sessionId,
        token_kind: "refresh",
      },
      60 * 60 * 24 * 30
    );

    await saveLoginSession({
      sessionId,
      userId: user.id,
      tokenKind: "access",
      req,
    });

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
  try {
    const { claims } = await authenticateRequest(req);
    const userId = String(claims.sub || "");
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
  const body = await getJsonBody(req);
  const updates = {
    phone: String(body.phone || "").trim() || undefined,
    bio: String(body.bio || "").trim() || undefined,
    department: String(body.department || "").trim() || undefined,
    full_name: String(body.fullName || "").trim() || undefined,
  };

  try {
    const { claims } = await authenticateRequest(req);
    const userId = String(claims.sub || "");
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

function normalizeCents(value: unknown) {
  if (typeof value === "number") return value;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function mapFinanceStatusRow(row: FinanceStatusRow) {
  const balanceCents = normalizeCents(row.balance_cents);
  const paidCents = normalizeCents(row.paid_cents);
  const dueCents = normalizeCents(row.due_cents);
  const feesCleared = Boolean(row.fees_cleared ?? balanceCents <= 0);

  return {
    balanceCents,
    paidCents,
    dueCents,
    feesCleared,
    lastPaymentAt: row.last_payment_at || null,
    statusLabel: row.status_label || (feesCleared ? "Cleared" : "Pending"),
    updatedAt: row.updated_at || null,
  };
}

function mapStaffMaterialRow(row: StaffMaterialRow) {
  return {
    id: row.id,
    title: row.title || "Material",
    courseCode: row.course_code || "",
    audience: row.audience || "students",
    author: row.author || "Staff",
    summary: row.summary || "",
    fileLabel: row.file_label || "Material",
    storagePath: row.storage_path || null,
    mimeType: row.mime_type || null,
    originalFileName: row.original_file_name || null,
    fileSize: typeof row.file_size === "number" ? row.file_size : Number(row.file_size || 0) || null,
    uploadedBy: row.uploaded_by || null,
    uploadedAt: row.uploaded_at || null,
    isPublished: row.is_published ?? true,
  };
}

function mapStudentDocumentRow(row: StudentDocumentRow) {
  const fileSizeValue = Number(row.file_size ?? 0);
  return {
    id: row.id,
    userId: row.user_id || null,
    documentType: row.document_type || null,
    fileName: row.file_name || null,
    mimeType: row.mime_type || null,
    storagePath: row.storage_path || null,
    fileSize: Number.isFinite(fileSizeValue) ? fileSizeValue : null,
    feesCleared: typeof row.fees_cleared === "boolean" ? row.fees_cleared : null,
    uploadedBy: row.uploaded_by || null,
    createdAt: row.created_at || null,
  };
}

function decodeBase64Payload(value: string) {
  const normalized = String(value || "").replace(/^data:.*;base64,/, "");
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function sanitizeFileName(name: string) {
  return String(name || "material.pdf")
    .trim()
    .replace(/[^\w.\-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "") || "material.pdf";
}

function buildStoragePath(scope: "students" | "teachers", userId: string, category: string, fileName: string) {
  const safeCategory = sanitizeFileName(category || "files").replace(/[.]/g, "_");
  const safeFileName = sanitizeFileName(fileName);
  return `${scope}/${userId}/${safeCategory}/${Date.now()}-${safeFileName}`;
}

async function uploadBase64File({
  bucketName,
  objectPath,
  fileBase64,
  mimeType,
}: {
  bucketName: string;
  objectPath: string;
  fileBase64: string;
  mimeType: string;
}) {
  const uploadedBytes = decodeBase64Payload(fileBase64);
  const { error } = await adminClient().storage.from(bucketName).upload(objectPath, uploadedBytes, {
    contentType: mimeType,
    upsert: true,
  });

  if (error) {
    throw error;
  }

  return uploadedBytes.length;
}

async function financeSummaryHandler(req: Request) {
  try {
    const { claims } = await authenticateRequest(req);
    const userId = String(claims.sub || "");

    const { data, error } = await adminClient()
      .from("student_finance_status")
      .select("*")
      .eq("user_id", userId)
      .maybeSingle();

    if (error && !isMissingTableError(error)) {
      throw error;
    }

    const finance = data ? mapFinanceStatusRow(data as FinanceStatusRow) : mapFinanceStatusRow({ balance_cents: 0, paid_cents: 0, due_cents: 0, fees_cleared: true });

    return corsResponse({ summary: finance }, 200);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to load finance summary." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function listStaffMaterialsHandler(req: Request) {
  try {
    await authenticateRequest(req);
    const { data, error } = await adminClient()
      .from("staff_materials")
      .select("*")
      .order("uploaded_at", { ascending: false });

    if (error) {
      if (isMissingTableError(error)) {
        return corsResponse({ materials: [] }, 200);
      }
      throw error;
    }

    return corsResponse({ materials: (data || []).map((row) => mapStaffMaterialRow(row as StaffMaterialRow)) }, 200);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to load materials." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function createStaffMaterialHandler(req: Request) {
  try {
    const { claims } = await requireStaffRole(req);
    const body = await getJsonBody(req);
    const title = String(body.title || "").trim();
    const courseCode = String(body.courseCode || body.course_code || "").trim();
    const audience = String(body.audience || "students").trim();
    const summary = String(body.summary || "").trim();
    const fileLabel = String(body.fileLabel || body.file_label || title || "Material").trim();
    const storagePath = String(body.storagePath || body.storage_path || "").trim() || null;
    const mimeType = String(body.mimeType || body.mime_type || "application/pdf").trim();
    const originalFileName = String(body.originalFileName || body.original_file_name || "").trim() || null;
    const fileSize = Number(body.fileSize || body.file_size || 0) || null;
    const fileBase64 = String(body.fileBase64 || body.file_base64 || "").trim();

    if (!title || !courseCode || !summary) {
      return corsResponse({ error: "title, courseCode, and summary are required." }, 400);
    }

    const { data: userRow } = await adminClient()
      .from("users")
      .select("full_name, email, staff_number")
      .eq("id", String(claims.sub))
      .maybeSingle();

    const author = String((userRow as { full_name?: string | null } | null)?.full_name || claims.email || "Staff");
    const bucketName = getEnv("TEACHER_FILES_BUCKET") || getEnv("STAFF_MATERIALS_BUCKET") || "campus-files";
    let nextStoragePath = storagePath;

    if (fileBase64) {
      const safeName = sanitizeFileName(originalFileName || fileLabel || `${title}.pdf`);
      const objectPath = buildStoragePath("teachers", String(claims.sub), "materials", safeName);
      await uploadBase64File({
        bucketName,
        objectPath,
        fileBase64,
        mimeType,
      });
      nextStoragePath = objectPath;
    }

    const payload = {
      title,
      course_code: courseCode,
      audience,
      author,
      summary,
      file_label: fileLabel,
      storage_path: nextStoragePath,
      mime_type: mimeType,
      original_file_name: originalFileName,
      file_size: fileSize,
      uploaded_by: String(claims.sub),
      uploaded_at: nowIso(),
      is_published: true,
    };

    const { data, error } = await adminClient().from("staff_materials").insert(payload).select("*").single();
    if (error) {
      if (isMissingTableError(error)) {
        return corsResponse({ error: "Missing staff_materials table." }, 500);
      }
      throw error;
    }

    await adminClient().from("notes").insert({
      title,
      course_code: courseCode,
      author,
      summary,
      file_label: fileLabel,
      storage_path: nextStoragePath,
      uploaded_at: nowIso(),
    });

    return corsResponse({ material: mapStaffMaterialRow(data as StaffMaterialRow) }, 201);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to upload material." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function listStudentDocumentsHandler(req: Request) {
  try {
    const { claims } = await authenticateRequest(req);
    const userId = String(claims.sub || "");
    const { data, error } = await adminClient()
      .from("student_documents")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (error) {
      if (isMissingTableError(error)) {
        return corsResponse({ documents: [] }, 200);
      }
      throw error;
    }

    return corsResponse({ documents: (data || []).map((row) => mapStudentDocumentRow(row as StudentDocumentRow)) }, 200);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to load documents." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function createStudentDocumentHandler(req: Request) {
  try {
    const { claims } = await authenticateRequest(req);
    const body = await getJsonBody(req);
    const documentType = String(body.documentType || body.document_type || "").trim().toLowerCase();
    const fileName = String(body.fileName || body.file_name || `${documentType || "document"}.pdf`).trim();
    const mimeType = String(body.mimeType || body.mime_type || "application/pdf").trim();
    const fileBase64 = String(body.fileBase64 || body.file_base64 || "").trim();
    const feesClearedValue = body.feesCleared ?? body.fees_cleared ?? null;
    const feesCleared =
      typeof feesClearedValue === "boolean"
        ? feesClearedValue
        : String(feesClearedValue || "").toLowerCase() === "true";

    if (!documentType || !fileName || !fileBase64) {
      return corsResponse({ error: "documentType, fileName, and fileBase64 are required." }, 400);
    }

    const supportedDocumentTypes = new Set(["gatepass", "exam-card", "transcript"]);
    if (!supportedDocumentTypes.has(documentType)) {
      return corsResponse({ error: "Unsupported document type." }, 400);
    }

    const bucketName = getEnv("STUDENT_FILES_BUCKET") || getEnv("DOCUMENTS_BUCKET") || "campus-files";
    const safeName = sanitizeFileName(fileName);
    const objectPath = buildStoragePath("students", String(claims.sub), documentType, safeName);
    const fileSize = await uploadBase64File({
      bucketName,
      objectPath,
      fileBase64,
      mimeType,
    });

    const payload = {
      user_id: String(claims.sub),
      document_type: documentType,
      file_name: safeName,
      mime_type: mimeType,
      storage_path: objectPath,
      file_size: fileSize,
      fees_cleared: feesCleared,
      uploaded_by: String(claims.sub),
      created_at: nowIso(),
    };

    const { data, error } = await adminClient().from("student_documents").insert(payload).select("*").single();
    if (error) {
      if (isMissingTableError(error)) {
        return corsResponse({ error: "Missing student_documents table." }, 500);
      }
      throw error;
    }

    return corsResponse({ document: mapStudentDocumentRow(data as StudentDocumentRow) }, 201);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to save document." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function createStaffAnnouncementHandler(req: Request) {
  try {
    const { claims } = await requireStaffRole(req);
    const body = await getJsonBody(req);
    const title = String(body.title || "").trim();
    const bodyText = String(body.body || body.message || "").trim();
    const audience = String(body.audience || "all students").trim();
    const priority = String(body.priority || "normal").trim();

    if (!title || !bodyText) {
      return corsResponse({ error: "title and body are required." }, 400);
    }

    const author = String(claims.email || "Staff");
    const { data, error } = await adminClient()
      .from("announcements")
      .insert({
        title,
        body: bodyText,
        audience,
        author,
        priority,
        published_at: nowIso(),
      })
      .select("*")
      .single();

    if (error) {
      if (isMissingTableError(error)) {
        return corsResponse({ error: "Missing announcements table." }, 500);
      }
      throw error;
    }

    return corsResponse({ announcement: data }, 201);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to create announcement." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function createStaffTimetableHandler(req: Request) {
  try {
    const { claims } = await requireStaffRole(req);
    const body = await getJsonBody(req);
    const audience = String(body.audience || "students").trim();
    const day = String(body.day || "").trim();
    const time = String(body.time || "").trim();
    const title = String(body.title || "").trim();
    const venue = String(body.venue || "").trim();
    const courseCode = String(body.courseCode || body.course_code || "").trim();
    const lecturer = String(body.lecturer || claims.email || "Staff").trim();
    const status = String(body.status || "upcoming").trim();
    const dayOrder = Number(body.dayOrder || body.day_order || 0);

    if (!day || !time || !title || !venue || !courseCode) {
      return corsResponse({ error: "day, time, title, venue, and courseCode are required." }, 400);
    }

    const { data, error } = await adminClient()
      .from("timetable_entries")
      .insert({
        audience,
        day,
        day_order: Number.isFinite(dayOrder) ? dayOrder : 0,
        time,
        title,
        venue,
        course_code: courseCode,
        lecturer,
        status,
        created_at: nowIso(),
      })
      .select("*")
      .single();

    if (error) {
      if (isMissingTableError(error)) {
        return corsResponse({ error: "Missing timetable_entries table." }, 500);
      }
      throw error;
    }

    return corsResponse({ timetableEntry: data }, 201);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to create timetable entry." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function sessionsListHandler(req: Request) {
  try {
    const { claims, sessionId } = await authenticateRequest(req);
    const userId = String(claims.sub || "");
    const sessions = await listDeviceSessions(userId);

    return corsResponse(
      {
        sessions: sessions.map((session) => ({
          id: session.id,
          deviceName: session.device_name || "Unknown device",
          userAgent: session.user_agent || null,
          ipAddress: session.ip_address || null,
          locationLabel: summarizeLocation(session.ip_location || null),
          city: session.ip_location?.city || session.ip_city || null,
          region: session.ip_location?.region || session.ip_region || null,
          country: session.ip_location?.country || session.ip_country || null,
          createdAt: session.created_at || null,
          lastSeenAt: session.last_seen_at || null,
          revokedAt: session.revoked_at || null,
          revokedReason: session.revoked_reason || null,
          isCurrent: sessionId ? session.id === sessionId : false,
        })),
      },
      200
    );
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to load sessions." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function revokeSessionHandler(req: Request, sessionId: string) {
  try {
    const { claims, sessionId: currentSessionId } = await authenticateRequest(req);
    const userId = String(claims.sub || "");
    if (!sessionId) {
      return corsResponse({ error: "sessionId is required." }, 400);
    }

    if (currentSessionId && sessionId === currentSessionId) {
      return corsResponse({ error: "You cannot revoke the current session from this endpoint." }, 400);
    }

    await revokeDeviceSession(userId, sessionId, "revoked_by_user");
    return corsResponse({ success: true }, 200);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to revoke session." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function revokeOtherSessionsHandler(req: Request) {
  try {
    const { claims, sessionId } = await authenticateRequest(req);
    const userId = String(claims.sub || "");
    if (!sessionId) {
      return corsResponse({ error: "Current session is unavailable." }, 400);
    }

    await revokeOtherDeviceSessions(userId, sessionId);
    return corsResponse({ success: true }, 200);
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to revoke other sessions." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
  }
}

async function refreshHandler(req: Request) {
  const body = await getJsonBody(req);
  const refreshToken = String(body.refreshToken || "").trim();
  if (!refreshToken) {
    return corsResponse({ error: "refreshToken is required." }, 400);
  }

  try {
    const claims = verifyToken(refreshToken);
    if (!claims?.sub) {
      return corsResponse({ error: "Invalid or expired refresh token." }, 401);
    }

    if (String(claims.token_kind || claims.type || "").toLowerCase() !== "refresh") {
      return corsResponse({ error: "Invalid refresh token." }, 401);
    }

    const sessionId = String(claims.sid || claims.session_id || "");
    if (!sessionId) {
      return corsResponse({ error: "Invalid refresh token." }, 401);
    }

    const { data, error } = await adminClient()
      .from("device_sessions")
      .select("*")
      .eq("id", sessionId)
      .eq("user_id", String(claims.sub))
      .maybeSingle();

    if (error && !isMissingTableError(error)) {
      throw error;
    }

    if (data && (data as SessionRow).revoked_at) {
      return corsResponse({ error: "This session has been revoked." }, 401);
    }

    const userTables = ["users", "registration"];
    let userRow: UserRow | null = null;
    for (const table of userTables) {
      const { data: row, error: rowError } = await adminClient()
        .from(table)
        .select("*")
        .eq("id", String(claims.sub))
        .maybeSingle();

      if (rowError) {
        if (isMissingTableError(rowError)) continue;
        throw rowError;
      }

      if (row) {
        userRow = row as UserRow;
        break;
      }
    }

    if (!userRow) {
      return corsResponse({ error: "Profile not found." }, 404);
    }

    const user = publicUser(userRow);
    const newAccessToken = signToken(
      { sub: user.id, email: user.email, role: user.role, source: String(claims.source || "legacy"), sid: sessionId, token_kind: "access" },
      60 * 60 * 24 * 7
    );

    return corsResponse(
      {
        success: true,
        token: newAccessToken,
        refreshToken,
        user,
      },
      200
    );
  } catch (error) {
    return corsResponse(
      { error: error instanceof Error ? error.message : "Failed to refresh session." },
      Number((error as { statusCode?: number })?.statusCode || 500)
    );
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
      const sessionId = randomUUID();
      const token = signToken(
        {
          sub: String((loginJson.user as { id?: string } | undefined)?.id || ""),
          email,
          role: String((loginJson.user as { role?: string } | undefined)?.role || "student"),
          source: "users",
          sid: sessionId,
          token_kind: "access",
        },
        60 * 60 * 24 * 7
      );
      const refreshToken = signToken(
        {
          sub: String((loginJson.user as { id?: string } | undefined)?.id || ""),
          email,
          role: String((loginJson.user as { role?: string } | undefined)?.role || "student"),
          source: "users",
          sid: sessionId,
          token_kind: "refresh",
        },
        60 * 60 * 24 * 30
      );
      const requestIp = getRequestIp(req);
      const userAgent = getRequestUserAgent(req);
      const ipLocation = await lookupIpLocation(requestIp);
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();

      pendingLoginChallenges.set(challengeId, {
        email,
        user: loginJson.user as Record<string, unknown>,
        token,
        refreshToken,
        createdAt: nowIso(),
        expiresAt,
        sessionId,
        requestIp,
        userAgent,
        ipLocation,
      });

      await storeLoginOtpSession({
        challengeId,
        email,
        user: loginJson.user as Record<string, unknown>,
        token,
        refreshToken,
        sessionId,
        requestIp,
        userAgent,
        ipLocation,
      });

      const loginTicket = buildLoginTicket({
        challengeId,
        email,
        token,
        refreshToken,
        user: loginJson.user as Record<string, unknown>,
        sessionId,
        expiresAt,
      });

      const response: JsonObject = {
        success: true,
        challengeId,
        loginTicket,
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
      const loginTicket = String(body.loginTicket || "").trim();

      if (!challengeId || !code) {
        return corsResponse({ error: "challengeId and code are required." }, 400);
      }

      const pendingLogin = pendingLoginChallenges.get(challengeId);
      const ticketClaims = loginTicket ? verifyLoginTicket(loginTicket) : null;
      const loginSession = pendingLogin
        ? {
            email: pendingLogin.email,
            token: pendingLogin.token,
            refresh_token: pendingLogin.refreshToken,
            user_payload: pendingLogin.user,
            created_at: pendingLogin.createdAt,
            expires_at: pendingLogin.expiresAt,
            consumed_at: null as string | null,
          }
        : await loadLoginOtpSession(challengeId);

      const effectiveLoginSession = loginSession || (ticketClaims
        ? {
            email: ticketClaims.email || "",
            token: ticketClaims.token || "",
            refresh_token: ticketClaims.refresh_token || "",
            user_payload: ticketClaims.user_payload || null,
            created_at: nowIso(),
            expires_at: ticketClaims.expires_at || new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString(),
            consumed_at: null as string | null,
          }
        : null);

      if (!effectiveLoginSession?.email || !effectiveLoginSession.token || !effectiveLoginSession.refresh_token || !effectiveLoginSession.user_payload) {
        return corsResponse({ error: "This login request has expired. Please sign in again." }, 410);
      }

      if (effectiveLoginSession.consumed_at) {
        return corsResponse({ error: "This login request has already been used." }, 410);
      }

      const expiresAt = effectiveLoginSession.expires_at || pendingLogin?.expiresAt || ticketClaims?.expires_at || null;
      if (expiresAt && new Date(expiresAt).getTime() <= Date.now()) {
        await consumeLoginOtpSession(challengeId);
        pendingLoginChallenges.delete(challengeId);
        return corsResponse({ error: "This login request has expired. Please sign in again." }, 410);
      }

      await verifyOtpChallenge({
        email: effectiveLoginSession.email,
        challengeId,
        code,
        purpose: "login",
      });

      pendingLoginChallenges.delete(challengeId);
      await consumeLoginOtpSession(challengeId);
      const sessionId = pendingLogin?.sessionId || String(ticketClaims?.sid || "") || "";
      if (sessionId) {
        await saveLoginSession({
          sessionId,
          userId: String((effectiveLoginSession.user_payload as JsonObject).id || pendingLogin?.user?.id || ticketClaims?.user_payload?.id || ""),
          tokenKind: "access",
          req,
        });
      }
      return corsResponse({ token: effectiveLoginSession.token, refreshToken: effectiveLoginSession.refresh_token, user: effectiveLoginSession.user_payload }, 200);
    }

    if (path === "/auth/password-reset/request") {
      return await passwordResetRequestHandler(req);
    }

    if (path === "/auth/password-reset/confirm") {
      return await passwordResetConfirmHandler(req);
    }

    if (path === "/auth/refresh") {
      return await refreshHandler(req);
    }

    if (path === "/auth/me") {
      return await meHandler(req);
    }

    if (path === "/auth/profile") {
      return await profileUpdateHandler(req);
    }

    if (path === "/finance/summary") {
      return await financeSummaryHandler(req);
    }

    if (path === "/auth/sessions") {
      return await sessionsListHandler(req);
    }

    if (path === "/auth/sessions/revoke-others") {
      return await revokeOtherSessionsHandler(req);
    }

    if (path.startsWith("/auth/sessions/") && path.endsWith("/revoke")) {
      const sessionId = path.split("/").filter(Boolean)[2] || "";
      return await revokeSessionHandler(req, sessionId);
    }

    if (path === "/student/documents") {
      if (req.method === "GET") {
        return await listStudentDocumentsHandler(req);
      }
      if (req.method === "POST") {
        return await createStudentDocumentHandler(req);
      }
    }

    if (path === "/staff/materials") {
      if (req.method === "GET") {
        return await listStaffMaterialsHandler(req);
      }

      if (req.method === "POST") {
        return await createStaffMaterialHandler(req);
      }
    }

    if (path === "/staff/announcements" && req.method === "POST") {
      return await createStaffAnnouncementHandler(req);
    }

    if (path === "/staff/timetable" && req.method === "POST") {
      return await createStaffTimetableHandler(req);
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
