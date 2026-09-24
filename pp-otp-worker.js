// ═══════════════════════════════════════════════════════════════════
// PUBLIC PROJECT — SECURE OTP WORKER (Cloudflare Workers)
// ═══════════════════════════════════════════════════════════════════
// Holds the 2Factor API key privately. The website never sees it.
//
// Bindings required (Worker → Settings):
//   KV namespace binding : OTP_KV
//   Secret               : ADMIN_PASSWORD   (you choose; used on admin "SMS Key" page)
//   Secret (optional)    : TURNSTILE_SECRET (Cloudflare Turnstile bot check)
//   Variable (optional)  : DAILY_CAP        (max OTP SMS per day, default 200)
//
// Endpoints (POST, JSON):
//   /send-otp          { mobile, token }        → { ok }
//   /verify-otp        { mobile, otp }          → { ok }
//   /admin/set-key     { password, key }        → { ok, check }
//   /admin/status      { password }             → { ok, keySet, keyTail, sentToday, dailyCap, balance }
// ═══════════════════════════════════════════════════════════════════

const ALLOWED_ORIGINS = [
  'https://publicproject.in',
  'https://www.publicproject.in',
];
const TEMPLATE        = 'PublicProjectSMS';
const OTP_TTL         = 600;   // OTP valid 10 minutes
const MAX_ATTEMPTS    = 5;     // wrong tries per OTP
const PER_MOBILE      = 3;     // OTPs per mobile per 15 min
const PER_MOBILE_TTL  = 900;
const PER_IP          = 10;    // OTPs per IP per hour
const PER_IP_TTL      = 3600;
const ADMIN_FAILS     = 5;     // wrong admin passwords per IP per hour

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const allowed = ALLOWED_ORIGINS.includes(origin);
    const cors = {
      'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGINS[0],
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',
    };
    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (!allowed) return json({ ok: false, error: 'Origin not allowed' }, 403);
    if (req.method !== 'POST') return json({ ok: false, error: 'Method not allowed' }, 405);

    let body = {};
    try { body = await req.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

    const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
    const path = new URL(req.url).pathname;

    try {
      if (path === '/send-otp')     return json(await sendOtp(env, body, ip));
      if (path === '/verify-otp')   return json(await verifyOtp(env, body));
      if (path === '/admin/set-key') return json(await adminSetKey(env, body, ip));
      if (path === '/admin/status')  return json(await adminStatus(env, body, ip));
      return json({ ok: false, error: 'Not found' }, 404);
    } catch (e) {
      return json({ ok: false, error: 'Server error' }, 500);
    }
  },
};

// ── helpers ──────────────────────────────────────────────────────────
function cleanMobile(m) {
  const d = String(m || '').replace(/\D/g, '').replace(/^91(?=\d{10}$)/, '');
  return /^[6-9]\d{9}$/.test(d) ? d : null;
}
function today() { return new Date().toISOString().slice(0, 10); }
async function sha256(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function safeEqual(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function count(env, key) { return parseInt((await env.OTP_KV.get(key)) || '0', 10); }
async function bump(env, key, ttl) {
  const v = await count(env, key);
  await env.OTP_KV.put(key, String(v + 1), { expirationTtl: ttl });
}
async function getKey(env) { return (await env.OTP_KV.get('cfg:tf_key')) || env.TF_KEY || ''; }

async function turnstileOk(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return true; // not configured yet → skip
  if (!token) return false;
  const fd = new FormData();
  fd.append('secret', env.TURNSTILE_SECRET);
  fd.append('response', token);
  fd.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: fd });
  const d = await r.json();
  return !!d.success;
}

// ── send OTP ─────────────────────────────────────────────────────────
async function sendOtp(env, body, ip) {
  const mobile = cleanMobile(body.mobile);
  if (!mobile) return { ok: false, error: 'Enter a valid 10-digit mobile number.' };

  if (!(await turnstileOk(env, body.token, ip))) return { ok: false, error: 'Security check failed. Refresh and try again.' };

  const dailyCap = parseInt(env.DAILY_CAP || '200', 10);
  const dayKey = 'day:' + today();
  if ((await count(env, dayKey)) >= dailyCap) return { ok: false, error: 'OTP service is busy. Try again later.' };
  if ((await count(env, 'rm:' + mobile)) >= PER_MOBILE) return { ok: false, error: 'Too many OTP requests for this number. Try after 15 minutes.' };
  if ((await count(env, 'ri:' + ip)) >= PER_IP) return { ok: false, error: 'Too many OTP requests. Try again later.' };

  const key = await getKey(env);
  if (!key) return { ok: false, error: 'OTP service not configured.' };

  const otp = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  const r = await fetch(`https://2factor.in/API/V1/${key}/SMS/${mobile}/${otp}/${TEMPLATE}`);
  const d = await r.json().catch(() => ({}));
  if (d.Status !== 'Success') return { ok: false, error: 'SMS failed. Try again.' };

  await env.OTP_KV.put('otp:' + mobile, JSON.stringify({ h: await sha256(mobile + ':' + otp), a: 0 }), { expirationTtl: OTP_TTL });
  await bump(env, 'rm:' + mobile, PER_MOBILE_TTL);
  await bump(env, 'ri:' + ip, PER_IP_TTL);
  await bump(env, dayKey, 172800);
  return { ok: true };
}

// ── verify OTP ───────────────────────────────────────────────────────
async function verifyOtp(env, body) {
  const mobile = cleanMobile(body.mobile);
  const otp = String(body.otp || '');
  if (!mobile || !/^\d{6}$/.test(otp)) return { ok: false, error: 'Enter the 6-digit OTP.' };

  const raw = await env.OTP_KV.get('otp:' + mobile);
  if (!raw) return { ok: false, error: 'OTP expired. Request a new one.' };
  const rec = JSON.parse(raw);
  if (rec.a >= MAX_ATTEMPTS) {
    await env.OTP_KV.delete('otp:' + mobile);
    return { ok: false, error: 'Too many wrong attempts. Request a new OTP.' };
  }
  if (safeEqual(rec.h, await sha256(mobile + ':' + otp))) {
    await env.OTP_KV.delete('otp:' + mobile);
    return { ok: true };
  }
  rec.a += 1;
  await env.OTP_KV.put('otp:' + mobile, JSON.stringify(rec), { expirationTtl: OTP_TTL });
  return { ok: false, error: 'Incorrect OTP. Try again.' };
}

// ── admin ────────────────────────────────────────────────────────────
async function adminAuth(env, body, ip) {
  if (!env.ADMIN_PASSWORD) return 'Admin password not set on Worker.';
  if ((await count(env, 'af:' + ip)) >= ADMIN_FAILS) return 'Too many wrong attempts. Try after 1 hour.';
  if (!safeEqual(body.password, env.ADMIN_PASSWORD)) {
    await bump(env, 'af:' + ip, 3600);
    return 'Wrong admin password.';
  }
  return null;
}

async function checkBalance(key) {
  try {
    const r = await fetch(`https://2factor.in/API/V1/${key}/BAL/SMS`);
    const d = await r.json();
    return d.Status === 'Success' ? String(d.Details) : null;
  } catch (e) { return null; }
}

async function adminSetKey(env, body, ip) {
  const err = await adminAuth(env, body, ip);
  if (err) return { ok: false, error: err };
  const key = String(body.key || '').trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(key)) {
    return { ok: false, error: 'That does not look like a 2Factor API key.' };
  }
  await env.OTP_KV.put('cfg:tf_key', key);
  const bal = await checkBalance(key);
  return { ok: true, check: bal !== null ? 'ok' : 'unverified', balance: bal };
}

async function adminStatus(env, body, ip) {
  const err = await adminAuth(env, body, ip);
  if (err) return { ok: false, error: err };
  const key = await getKey(env);
  return {
    ok: true,
    keySet: !!key,
    keyTail: key ? key.slice(-4) : '',
    sentToday: await count(env, 'day:' + today()),
    dailyCap: parseInt(env.DAILY_CAP || '200', 10),
    balance: key ? await checkBalance(key) : null,
  };
}
