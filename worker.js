// Chore Wheel API worker.
//
// Two routes, both gated by a session cookie that proves the caller knows
// the family PIN (set as the PIN secret, never stored in this repo):
//   POST /api/login  -> checks the PIN, sets the session cookie
//   GET  /api/state  -> returns the whole app state blob from KV
//   PUT  /api/state  -> overwrites the whole app state blob in KV
//
// Everything else falls through to the static assets binding (the app's
// index.html and its friends), configured in wrangler.toml.

const STATE_KEY = 'state';
const COOKIE_NAME = 'cw_session';
const SESSION_INFO = 'chorewheel-session-v1';

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}

async function isAuthorized(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return false;
  const expected = await hmacHex(env.PIN, SESSION_INFO);
  return timingSafeEqual(token, expected);
}

function json(data, init) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init && init.headers) }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/login' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return json({ error: 'bad_request' }, { status: 400 });
      }
      const pin = typeof body.pin === 'string' ? body.pin : '';
      if (!pin || !timingSafeEqual(pin, env.PIN)) {
        return json({ error: 'invalid_pin' }, { status: 401 });
      }
      const token = await hmacHex(env.PIN, SESSION_INFO);
      const cookie = `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=15552000`;
      return json({ ok: true }, { headers: { 'Set-Cookie': cookie } });
    }

    if (url.pathname === '/api/state' && request.method === 'GET') {
      if (!(await isAuthorized(request, env))) return json({ error: 'unauthorized' }, { status: 401 });
      const raw = await env.STATE_KV.get(STATE_KEY);
      if (!raw) return json({ kids: [], chores: [], log: {} });
      return new Response(raw, { headers: { 'Content-Type': 'application/json' } });
    }

    if (url.pathname === '/api/state' && request.method === 'PUT') {
      if (!(await isAuthorized(request, env))) return json({ error: 'unauthorized' }, { status: 401 });
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return json({ error: 'bad_request' }, { status: 400 });
      }
      if (!body || !Array.isArray(body.kids) || !Array.isArray(body.chores) || typeof body.log !== 'object') {
        return json({ error: 'bad_request' }, { status: 400 });
      }
      await env.STATE_KV.put(STATE_KEY, JSON.stringify(body));
      return json({ ok: true });
    }

    if (url.pathname.startsWith('/api/')) {
      return json({ error: 'not_found' }, { status: 404 });
    }

    return env.ASSETS.fetch(request);
  }
};
