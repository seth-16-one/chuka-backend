const nodemailer = require('nodemailer');

function getProvider() {
  return String(process.env.EMAIL_PROVIDER || 'smtp').trim().toLowerCase();
}

function getEmailContent({ code, expiresInMinutes }) {
  return {
    subject: 'Your Chuka University verification code',
    text: `Your verification code is ${code}. It expires in ${expiresInMinutes} minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px;">
        <h2 style="margin: 0 0 8px; color: #006400;">Chuka University App</h2>
        <p style="line-height: 1.6; color: #1A1A1A;">Use the code below to verify your email securely.</p>
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
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || 'true') === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: {
      minVersion: 'TLSv1.2',
    },
  });
}

async function sendViaSmtp({ email, code, expiresInMinutes }) {
  const transporter = createSmtpTransporter();
  const smtpUser = process.env.SMTP_USER;
  const brandedReplyTo = process.env.EMAIL_FROM_ADDRESS || smtpUser;
  const fromName = process.env.EMAIL_FROM_NAME || 'Chuka University App';
  const content = getEmailContent({ code, expiresInMinutes });

  await transporter.sendMail({
    from: `"${fromName}" <${smtpUser}>`,
    replyTo: brandedReplyTo,
    to: email,
    subject: content.subject,
    text: content.text,
    html: content.html,
  });
}

async function sendViaResend({ email, code, expiresInMinutes }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    throw new Error('Missing RESEND_API_KEY.');
  }

  const content = getEmailContent({ code, expiresInMinutes });
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

async function sendViaSendGrid({ email, code, expiresInMinutes }) {
  const apiKey = process.env.SENDGRID_API_KEY;
  if (!apiKey) {
    throw new Error('Missing SENDGRID_API_KEY.');
  }

  const content = getEmailContent({ code, expiresInMinutes });
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

async function sendOtpEmail({ email, code, expiresInMinutes }) {
  const provider = getProvider();

  if (provider === 'resend') {
    return sendViaResend({ email, code, expiresInMinutes });
  }

  if (provider === 'sendgrid') {
    return sendViaSendGrid({ email, code, expiresInMinutes });
  }

  return sendViaSmtp({ email, code, expiresInMinutes });
}

module.exports = {
  sendOtpEmail,
};
