// Cloudflare Pages Function — POST /api/contact
// Requires these bound as encrypted environment variables in the Pages
// project (never committed to the repo): RESEND_API_KEY, TURNSTILE_SECRET_KEY,
// CONTACT_TO_EMAIL. RATE_LIMIT is an optional KV namespace binding.

const MAX_NAME = 120;
const MAX_EMAIL = 200;
const MAX_MESSAGE = 4000;
const RATE_LIMIT_MAX = 5;          // requests
const RATE_LIMIT_WINDOW = 60 * 60; // seconds
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  });
}

async function verifyTurnstile(token, secret, ip) {
  if (!token || !secret) return false;
  const form = new FormData();
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

async function checkRateLimit(env, ip) {
  if (!env.RATE_LIMIT || !ip) return true; // no KV bound → skip, fail open
  const key = `contact:${ip}`;
  const count = parseInt((await env.RATE_LIMIT.get(key)) || "0", 10);
  if (count >= RATE_LIMIT_MAX) return false;
  await env.RATE_LIMIT.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW });
  return true;
}

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "invalid_body" }, 400);
  }

  const name = String(body.name || "").trim().slice(0, MAX_NAME);
  const email = String(body.email || "").trim().slice(0, MAX_EMAIL);
  const message = String(body.message || "").trim().slice(0, MAX_MESSAGE);
  const topic = String(body.topic || ""); // honeypot
  const turnstileToken = String(body.turnstileToken || "");

  // Honeypot tripped — pretend success, do nothing further.
  if (topic.trim() !== "") {
    return json({ ok: true });
  }

  if (!name || !email || !message || !EMAIL_RE.test(email)) {
    return json({ ok: false, error: "invalid_fields" }, 400);
  }

  const ip = request.headers.get("CF-Connecting-IP");

  const allowed = await checkRateLimit(env, ip);
  if (!allowed) {
    return json({ ok: false, error: "rate_limited" }, 429);
  }

  const human = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY, ip);
  if (!human) {
    return json({ ok: false, error: "bot_check_failed" }, 403);
  }

  const toEmail = env.CONTACT_TO_EMAIL;
  if (!env.RESEND_API_KEY || !toEmail) {
    return json({ ok: false, error: "not_configured" }, 500);
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
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
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
    return json({ ok: false, error: "send_failed" }, 502);
  }

  return json({ ok: true });
}
