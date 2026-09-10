// Vercel serverless function — POST /api/contact
// Requires these set as Environment Variables in the Vercel project (never
// committed to the repo): RESEND_API_KEY, TURNSTILE_SECRET_KEY, CONTACT_TO_EMAIL.

const MAX_NAME = 120;
const MAX_EMAIL = 200;
const MAX_MESSAGE = 4000;
const RATE_LIMIT_MAX = 5;          // requests
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // ms
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Serverless instances aren't shared and aren't guaranteed to stay warm, so
// this only throttles a flood that lands on the same warm instance. Turnstile
// + the honeypot below are the real bot defenses; this is just extra friction.
const rateLimitStore = new Map();

function checkRateLimit(ip) {
  if (!ip) return true;
  const now = Date.now();
  const entry = rateLimitStore.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count += 1;
  return true;
}

async function verifyTurnstile(token, secret, ip) {
  if (!token || !secret) return false;
  const form = new URLSearchParams();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: form
  });
  const data = await res.json().catch(() => ({}));
  return data.success === true;
}

// CommonJS on purpose: there's no package.json in this repo (no build step,
// no npm install), so Vercel's Node runtime treats .js files as CommonJS by
// default — `export default` would throw at runtime without one.
module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }

  const body = req.body || {};

  const name = String(body.name || "").trim().slice(0, MAX_NAME);
  const email = String(body.email || "").trim().slice(0, MAX_EMAIL);
  const message = String(body.message || "").trim().slice(0, MAX_MESSAGE);
  const topic = String(body.topic || ""); // honeypot
  const turnstileToken = String(body.turnstileToken || "");

  // Honeypot tripped — pretend success, do nothing further.
  if (topic.trim() !== "") {
    return res.status(200).json({ ok: true });
  }

  if (!name || !email || !message || !EMAIL_RE.test(email)) {
    return res.status(400).json({ ok: false, error: "invalid_fields" });
  }

  const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ ok: false, error: "rate_limited" });
  }

  const human = await verifyTurnstile(turnstileToken, process.env.TURNSTILE_SECRET_KEY, ip);
  if (!human) {
    return res.status(403).json({ ok: false, error: "bot_check_failed" });
  }

  const toEmail = process.env.CONTACT_TO_EMAIL;
  if (!process.env.RESEND_API_KEY || !toEmail) {
    return res.status(500).json({ ok: false, error: "not_configured" });
  }

  // Resend rejects control characters in `subject` with a 422, which would
  // otherwise surface to the visitor as a generic send failure. Flatten the
  // name for the header line; the HTML body keeps it as typed, escaped.
  const subjectName = Array.from(name)
    .map((ch) => (ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) !== 127 ? ch : " "))
    .join("")
    .replace(/\s+/g, " ")
    .trim() || "someone";

  const escape = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

  const resendRes = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "Portfolio contact form <contact@resend.dev>",
      to: [toEmail],
      reply_to: email,
      subject: `Portfolio message from ${subjectName}`,
      html: `<p><strong>${escape(name)}</strong> (${escape(email)}) wrote:</p><p>${escape(message).replace(/\n/g, "<br>")}</p>`
    })
  });

  if (!resendRes.ok) {
    return res.status(502).json({ ok: false, error: "send_failed" });
  }

  return res.status(200).json({ ok: true });
};
