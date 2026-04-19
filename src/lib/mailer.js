const nodemailer = require('nodemailer');

function getProvider() {
  return String(process.env.EMAIL_PROVIDER || 'smtp').trim().toLowerCase();
}

function hasProductionMailerConfig(provider) {
  if (provider === 'resend') {
    return Boolean(process.env.RESEND_API_KEY);
  }

  if (provider === 'sendgrid') {
    return Boolean(process.env.SENDGRID_API_KEY);
  }

  return Boolean(
    process.env.SMTP_HOST &&
    process.env.SMTP_PORT &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
  );
}

function getPurposeCopy(purpose) {
  const normalizedPurpose = String(purpose || 'registration').trim().toLowerCase();

  if (normalizedPurpose === 'login') {
    return {
      label: 'login',
      subject: 'Your Chuka University login code',
      headline: 'Login verification code',
      intro: 'Use this code to finish signing in to your Chuka University account.',
    };
  }

  if (normalizedPurpose === 'password_reset') {
    return {
      label: 'password reset',
      subject: 'Your Chuka University password reset code',
      headline: 'Password reset code',
      intro: 'Use this code to reset your Chuka University password securely.',
    };
  }

  return {
    label: 'registration',
    subject: 'Your Chuka University registration code',
    headline: 'Registration verification code',
    intro: 'Use this code to complete your Chuka University registration.',
  };
}

function getEmailContent({ code, expiresInMinutes, purpose }) {
  const copy = getPurposeCopy(purpose);

  return {
    subject: copy.subject,
    text: `Your ${copy.label} code is ${code}. It expires in ${expiresInMinutes} minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px;">
        <h2 style="margin: 0 0 8px; color: #006400;">Chuka University App</h2>
        <p style="line-height: 1.6; color: #1A1A1A;">${copy.intro}</p>
        <div style="margin: 24px 0; border-radius: 16px; padding: 18px 20px; background: #eef7ef; border: 1px solid #b7e2b7;">
          <div style="font-size: 30px; font-weight: 700; letter-spacing: 8px; color: #006400;">${code}</div>
        </div>
        <p style="line-height: 1.6; color: #4f6655;">This code expires in ${expiresInMinutes} minutes. If you did not request it, ignore this email.</p>
      </div>
    `,
  };
}

function createSmtpTransporter() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    requireTLS: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: {
      minVersion: 'TLSv1.2',
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000,
  });
}

async function sendViaSmtp({ email, code, expiresInMinutes, purpose }) {
  const transporter = createSmtpTransporter();
  const smtpUser = process.env.SMTP_USER;
  const fromName = process.env.EMAIL_FROM_NAME || 'Chuka University App';
  const fromEmail = smtpUser;
  const content = getEmailContent({ code, expiresInMinutes, purpose });

  await transporter.sendMail({
    from: `"${fromName}" <${fromEmail}>`,
    replyTo: fromEmail,
    to: email,
    subject: content.subject,
    text: content.text,
    html: content.html,
  });
}

async function sendViaResend({ email, code, expiresInMinutes, purpose }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    throw new Error('Missing RESEND_API_KEY.');
  }

  const content = getEmailContent({ code, expiresInMinutes, purpose });
  const fromName = process.env.EMAIL_FROM_NAME || 'Chuka University App';
  const fromEmail = process.env.EMAIL_FROM_ADDRESS || 'onboarding@resend.dev';

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: `"${fromName}" <${fromEmail}>`,
      to: [email],
      subject: content.subject,
      text: content.text,
      html: content.html,
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Resend request failed: ${body}`);
  }
}

async function sendViaSendGrid({ email, code, expiresInMinutes, purpose }) {
  const apiKey = process.env.SENDGRID_API_KEY;
  if (!apiKey) {
    throw new Error('Missing SENDGRID_API_KEY.');
  }

  const content = getEmailContent({ code, expiresInMinutes, purpose });
  const fromName = process.env.EMAIL_FROM_NAME || 'Chuka University App';
  const fromEmail = process.env.EMAIL_FROM_ADDRESS || process.env.SMTP_USER;

  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email }] }],
      from: { email: fromEmail, name: fromName },
      subject: content.subject,
      content: [
        { type: 'text/plain', value: content.text },
        { type: 'text/html', value: content.html },
      ],
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`SendGrid request failed: ${body}`);
  }
}

async function sendOtpEmail({ email, code, expiresInMinutes, purpose }) {
  const provider = getProvider();

  if (provider === 'console') {
    console.log(`[OTP:${expiresInMinutes}m:${purpose || 'registration'}] ${email} -> ${code}`);
    return;
  }

  if (!hasProductionMailerConfig(provider)) {
    if (String(process.env.NODE_ENV || '').trim().toLowerCase() !== 'production') {
      console.warn(
        `OTP mailer config incomplete for provider "${provider}". Falling back to console delivery in development.`
      );
      console.log(`[OTP:${expiresInMinutes}m:${purpose || 'registration'}] ${email} -> ${code}`);
      return;
    }

    throw new Error(`Missing mailer configuration for provider "${provider}".`);
  }

  if (provider === 'resend') {
    return sendViaResend({ email, code, expiresInMinutes, purpose });
  }

  if (provider === 'sendgrid') {
    return sendViaSendGrid({ email, code, expiresInMinutes, purpose });
  }

  try {
    return await sendViaSmtp({ email, code, expiresInMinutes, purpose });
  } catch (error) {
    if (String(process.env.NODE_ENV || '').trim().toLowerCase() !== 'production') {
      console.warn(`SMTP OTP send failed, falling back to console delivery: ${error.message}`);
      console.log(`[OTP:${expiresInMinutes}m:${purpose || 'registration'}] ${email} -> ${code}`);
      return;
    }

    throw error;
  }
}

module.exports = {
  sendOtpEmail,
};
