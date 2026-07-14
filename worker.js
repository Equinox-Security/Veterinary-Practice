// ─────────────────────────────────────────────────────────────────────────
// Vet Portal — Automatic Registration Worker
//
// Triggered by a Formspree webhook when a new client fills out the sign-up
// form. On each call it:
//   1. Fetches roster.json.enc from the GitHub repo and decrypts it with the
//      master roster password (a Worker secret — never the client's password).
//   2. Generates a random data key (DK) for the new client, wraps DK under
//      the password THEY chose, encrypts their pet/contact payload under DK.
//      This is the exact same scheme the engine uses — see wrapDK/encryptWithDK
//      below, ported line-for-line so a client page built here is byte-for-byte
//      compatible with one the engine builds later.
//   3. Adds the client to the roster, re-encrypts the whole roster file.
//   4. Builds a minimal, self-contained portal page for the client (login +
//      decrypt only — NOT the fully themed site page; see note below).
//   5. Adds the client to portal.html's CLIENTS directory.
//   6. Commits all three files back to the GitHub repo via the Contents API.
//
// IMPORTANT — page theming: this Worker deliberately does NOT replicate the
// engine's full page-building pipeline (nav, footer, theme CSS, etc.) — that
// would mean duplicating a large part of the engine here, doubling the
// maintenance surface for every future site-wide change. Instead this Worker
// gets the client a working, secure portal *immediately*, and the next time
// you run "Generate & Save All Files" in the engine, that client's page gets
// rebuilt with full site theming automatically — using the DK already sitting
// in the roster, so no password re-entry is ever needed for that regeneration.
//
// REQUIRED WORKER SECRETS (set via `wrangler secret put <NAME>`):
//   GITHUB_TOKEN     - a GitHub personal access token (fine-grained, with
//                      "Contents: read and write" on this one repo only)
//   ROSTER_PASSWORD  - the master password that encrypts/decrypts
//                      roster.json.enc as a whole file. This is NOT any
//                      individual client's password. Only you and this
//                      Worker should ever know it.
//
// OPTIONAL WORKER SECRET:
//   NTFY_TOPIC       - a random, hard-to-guess topic name (e.g.
//                      "vet-a8f3k2m9-signups") for a free push notification
//                      via ntfy.sh whenever someone registers. Install the
//                      ntfy app and subscribe to this same topic name to
//                      receive it. Leave unset to skip notifications
//                      entirely — nothing else depends on this.
//
// REQUIRED CONFIG (edit the constants below, or move to wrangler.toml vars):
//   GITHUB_OWNER, GITHUB_REPO, GITHUB_BRANCH
// ─────────────────────────────────────────────────────────────────────────

const GITHUB_OWNER  = 'Equinox-Security';   // TODO: fill in
const GITHUB_REPO   = 'Veterinary-Practice';         // TODO: fill in
const GITHUB_BRANCH = 'main';
const ROSTER_PATH   = 'roster.json.enc';
const PORTAL_PATH   = 'portal.html';
const PBKDF2_ITERATIONS = 200000;
const RESET_CODE_TTL_SECONDS = 1800; // 30 minutes

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    let payload;
    try {
      payload = await request.json();
    } catch (e) {
      return new Response('Bad request: invalid JSON', { status: 400 });
    }

    const action = payload.action || 'register';
    try {
      if (action === 'reset_request') return await handleResetRequest(payload, env);
      if (action === 'reset_confirm') return await handleResetConfirm(payload, env);
      return await handleRegister(payload, env);
    } catch (e) {
      console.error(e);
      return new Response('Server error: ' + e.message, { status: 500 });
    }
  }
};

async function handleRegister(payload, env) {
    const name     = (payload.name || '').trim();
    const username = (payload.username || '').trim();
    const password = (payload.password || '').trim();
    const email    = (payload.email || '').trim();
    const phone    = (payload.phone || '').trim();

    if (!name || !username || !password) {
      return new Response('Missing required fields (name, username, password)', { status: 400 });
    }
    if (!/^[a-zA-Z0-9]{8,20}$/.test(password)) {
      return new Response('Password must be 8-20 letters/numbers', { status: 400 });
    }

    {
      // ── 1. Fetch + decrypt the roster ──────────────────────────────────
      const rosterFile = await githubGetFile(env, ROSTER_PATH);
      const roster = rosterFile
        ? await decryptRoster(rosterFile.content, env.ROSTER_PASSWORD)
        : { rosterVersion: 1, clients: [] };

      if (roster.clients.some(c => c.username.toLowerCase() === username.toLowerCase())) {
        return new Response('That username is already registered. Use "Forgot password" instead.', { status: 409 });
      }

      // ── 2. Generate DK, wrap it under the client's password, encrypt payload ──
      const dkBytes = genDK();
      const wrap = await wrapDK(dkBytes, password);
      const hash = await hashStr(username.toLowerCase() + password);
      const filename = hash + '.html';
      const pay = await encryptWithDK(dkBytes, JSON.stringify({ name, email, phone, pets: [] }));

      // ── 3. Add to roster, re-encrypt ────────────────────────────────────
      roster.clients.push({
        name, username, email, phone, hash, filename, pets: [],
        dk: b64FromBytes(dkBytes), wrap
      });
      const rosterEncrypted = await encryptRoster(roster, env.ROSTER_PASSWORD);

      // ── 4. Build the client's (minimal, self-contained) portal page ────
      const clientHTML = buildMinimalClientPage({ name, wrap, pay });

      // ── 5. Add to portal.html's directory ───────────────────────────────
      const portalFile = await githubGetFile(env, PORTAL_PATH);
      if (!portalFile) throw new Error('portal.html not found in repo — cannot add client to directory.');
      const updatedPortalHTML = addClientToPortalHTML(portalFile.content, { username, hash });

      // ── 6. Commit everything ────────────────────────────────────────────
      await githubPutFile(env, ROSTER_PATH, rosterEncrypted, rosterFile ? rosterFile.sha : undefined, 'Add client: ' + username);
      await githubPutFile(env, filename, clientHTML, undefined, 'Create portal: ' + username);
      await githubPutFile(env, PORTAL_PATH, updatedPortalHTML, portalFile.sha, 'Add ' + username + ' to directory');

      // ── 7. Notify — best-effort only, never blocks or fails the registration ──
      await notify(env, name + ' (' + username + ') just registered for the pet portal. Run "Generate & Save All Files" in the engine soon to give them the fully themed page.');

      return new Response('OK', { status: 200 });
    }
}

// ── Step 1: client asks for a reset code ───────────────────────────────
// Always returns the same generic response whether or not the username
// exists, so this endpoint can't be used to check which usernames are real.
async function handleResetRequest(payload, env) {
  const username = (payload.username || '').trim();
  const generic = new Response('If that username exists, a reset code has been sent to the email on file.', { status: 200 });
  if (!username) return generic;

  const rosterFile = await githubGetFile(env, ROSTER_PATH);
  if (!rosterFile) return generic;
  const roster = await decryptRoster(rosterFile.content, env.ROSTER_PASSWORD);
  const client = roster.clients.find(c => c.username.toLowerCase() === username.toLowerCase());
  if (!client || !client.email) return generic;

  const code = genResetCode();
  // Codes live only in KV, briefly — never in the roster or the repo.
  await env.RESET_TOKENS.put('reset:' + username.toLowerCase(), code, { expirationTtl: RESET_CODE_TTL_SECONDS });

  await sendEmail(env, client.email, 'Your pet portal password reset code',
    'Your reset code is: ' + code + '\n\nThis code expires in 30 minutes. If you did not request this, you can ignore this email.');

  return generic;
}

// ── Step 2: client submits the code + their new password ────────────────
async function handleResetConfirm(payload, env) {
  const username    = (payload.username || '').trim();
  const code        = (payload.code || '').trim();
  const newPassword = (payload.newPassword || '').trim();

  if (!username || !code || !newPassword) {
    return new Response('Missing required fields (username, code, newPassword)', { status: 400 });
  }
  if (!/^[a-zA-Z0-9]{8,20}$/.test(newPassword)) {
    return new Response('Password must be 8-20 letters/numbers', { status: 400 });
  }

  const tokenKey = 'reset:' + username.toLowerCase();
  const storedCode = await env.RESET_TOKENS.get(tokenKey);
  if (!storedCode || storedCode !== code) {
    return new Response('Invalid or expired code.', { status: 400 });
  }

  const rosterFile = await githubGetFile(env, ROSTER_PATH);
  if (!rosterFile) return new Response('No account found for that username.', { status: 404 });
  const roster = await decryptRoster(rosterFile.content, env.ROSTER_PASSWORD);
  const idx = roster.clients.findIndex(c => c.username.toLowerCase() === username.toLowerCase());
  if (idx === -1) return new Response('No account found for that username.', { status: 404 });

  const client = roster.clients[idx];
  const oldFilename = client.filename;

  // Same DK as before — their pet/contact history is untouched. Only the
  // wrap (under the new password) and the hash/filename change.
  const dkBytes = bytesFromB64(client.dk);
  const newWrap = await wrapDK(dkBytes, newPassword);
  const newHash = await hashStr(username.toLowerCase() + newPassword);
  const newFilename = newHash + '.html';
  const pay = await encryptWithDK(dkBytes, JSON.stringify({
    name: client.name, email: client.email, phone: client.phone, pets: client.pets || []
  }));

  roster.clients[idx] = { ...client, hash: newHash, filename: newFilename, wrap: newWrap };
  const rosterEncrypted = await encryptRoster(roster, env.ROSTER_PASSWORD);
  const clientHTML = buildMinimalClientPage({ name: client.name, wrap: newWrap, pay });

  const portalFile = await githubGetFile(env, PORTAL_PATH);
  if (!portalFile) throw new Error('portal.html not found in repo.');
  const updatedPortalHTML = updateClientHashInPortalHTML(portalFile.content, { username, newHash });

  await githubPutFile(env, ROSTER_PATH, rosterEncrypted, rosterFile.sha, 'Password reset: ' + username);
  await githubPutFile(env, newFilename, clientHTML, undefined, 'Create portal (after reset): ' + username);
  await githubPutFile(env, PORTAL_PATH, updatedPortalHTML, portalFile.sha, 'Update directory after reset: ' + username);
  // Old page's password no longer works either way (it's not in portal.html's
  // directory anymore), but delete the file too so the old URL is fully gone.
  if (oldFilename && oldFilename !== newFilename) {
    try {
      const oldFile = await githubGetFile(env, oldFilename);
      if (oldFile) await githubDeleteFile(env, oldFilename, oldFile.sha, 'Remove old portal after reset: ' + username);
    } catch (e) { console.error('Could not delete old portal file (non-fatal):', e); }
  }

  await env.RESET_TOKENS.delete(tokenKey);
  await notify(env, client.name + ' (' + username + ') reset their password.');

  return new Response('OK', { status: 200 });
}

function genResetCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  const num = (bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]) >>> 0;
  return String(num % 1000000).padStart(6, '0');
}

// ═══════════════════════════════════════════════════════════════════════
// Crypto — same scheme as the engine (DK-wrapping, PBKDF2 + AES-GCM)
// ═══════════════════════════════════════════════════════════════════════

function b64FromBytes(u8) { return btoa(String.fromCharCode.apply(null, u8)); }
function bytesFromB64(s) { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
function genDK() { return crypto.getRandomValues(new Uint8Array(32)); }

async function hashStr(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function wrapDK(dkBytes, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const kek = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dkBytes);
  return { ct: b64FromBytes(new Uint8Array(ct)), salt: b64FromBytes(salt), iv: b64FromBytes(iv) };
}

async function encryptWithDK(dkBytes, plainStr) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const dkKey = await crypto.subtle.importKey('raw', dkBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dkKey, new TextEncoder().encode(plainStr));
  return { ct: b64FromBytes(new Uint8Array(ct)), iv: b64FromBytes(iv) };
}

// ── Whole-roster-file encryption (master password, NOT a client password) ──
async function decryptRoster(jsonStr, password) {
  const blob = JSON.parse(jsonStr); // {salt, iv, ct}
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: bytesFromB64(blob.salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMat, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesFromB64(blob.iv) }, key, bytesFromB64(blob.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

async function encryptRoster(rosterObj, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(rosterObj)));
  const blob = { salt: b64FromBytes(salt), iv: b64FromBytes(iv), ct: b64FromBytes(new Uint8Array(ct)) };
  return JSON.stringify(blob, null, 2);
}

// ═══════════════════════════════════════════════════════════════════════
// GitHub Contents API helpers
// ═══════════════════════════════════════════════════════════════════════

async function githubGetFile(env, path) {
  const url = 'https://api.github.com/repos/' + GITHUB_OWNER + '/' + GITHUB_REPO + '/contents/' + path + '?ref=' + GITHUB_BRANCH;
  const res = await fetch(url, { headers: { 'Authorization': 'token ' + env.GITHUB_TOKEN, 'User-Agent': 'vet-portal-worker', 'Accept': 'application/vnd.github+json' } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('GitHub fetch failed for ' + path + ': ' + res.status);
  const data = await res.json();
  // GitHub returns file content base64-encoded — decode once, here, so every
  // caller (decryptRoster, addClientToPortalHTML, etc.) always gets plain text.
  const decoded = decodeURIComponent(escape(atob(data.content.replace(/\n/g, ''))));
  return { content: decoded, sha: data.sha };
}

async function githubPutFile(env, path, content, sha, message) {
  const url = 'https://api.github.com/repos/' + GITHUB_OWNER + '/' + GITHUB_REPO + '/contents/' + path;
  const body = {
    message: message,
    content: btoa(unescape(encodeURIComponent(content))), // UTF-8 safe -> base64
    branch: GITHUB_BRANCH
  };
  if (sha) body.sha = sha;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { 'Authorization': 'token ' + env.GITHUB_TOKEN, 'User-Agent': 'vet-portal-worker', 'Content-Type': 'application/json', 'Accept': 'application/vnd.github+json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error('GitHub write failed for ' + path + ': ' + res.status + ' ' + await res.text());
  return await res.json();
}

// ═══════════════════════════════════════════════════════════════════════
// Client page + directory generation
// ═══════════════════════════════════════════════════════════════════════

function escapeHTML(s) {
  return (s || '').replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

// Minimal, self-contained login + decrypt page. No site theming/nav/footer —
// see the note at the top of this file for why, and how it gets upgraded.
function buildMinimalClientPage({ name, wrap, pay }) {
  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8"/>\n'
    + '<meta name="viewport" content="width=device-width, initial-scale=1.0"/>\n'
    + '<title>Pet Portal \u2014 ' + escapeHTML(name) + '</title>\n'
    + '<style>'
    + 'body{font-family:system-ui,-apple-system,sans-serif;background:#f4f6f5;margin:0;}'
    + '#login-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;}'
    + '.login-card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);padding:2.5rem;width:100%;max-width:360px;text-align:center;}'
    + '.login-card h2{margin-bottom:0.4rem;}'
    + '.login-card input{width:100%;padding:0.7rem 1rem;border:1.5px solid #dce2e8;border-radius:7px;font-size:0.95rem;margin-bottom:0.85rem;box-sizing:border-box;}'
    + '#portal-login-error{font-size:0.8rem;color:#c0392b;margin-bottom:0.75rem;display:none;}'
    + '.login-btn{width:100%;background:#2c5f4f;color:#fff;padding:0.75rem 1rem;border-radius:7px;border:none;font-size:0.9rem;font-weight:600;cursor:pointer;}'
    + '#portal-mount{max-width:640px;margin:0 auto;padding:2rem;display:none;}'
    + '</style>\n</head>\n<body>\n'
    + '<div id="login-screen"><div class="login-card">'
    + '<h2>Sign In</h2><p>Enter your password to view your pet portal.</p>'
    + '<input type="password" id="portal-password" placeholder="Password"/>'
    + '<div id="portal-login-error">Incorrect password. Please try again.</div>'
    + '<button class="login-btn" onclick="portalCheckPassword()">Sign In</button>'
    + '</div></div>\n<div id="portal-mount"></div>\n'
    + '<script>'
    + 'var WRAP_CT="' + wrap.ct + '";var WRAP_SALT="' + wrap.salt + '";var WRAP_IV="' + wrap.iv + '";'
    + 'var PAY_CT="' + pay.ct + '";var PAY_IV="' + pay.iv + '";'
    + 'function b64u(s){var b=atob(s);var u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}'
    + 'function renderPortalData(data){'
    +   'var pets=data.pets||[];'
    +   'var petHTML=pets.length?pets.map(function(p){return \'<div style="background:#fff;border-radius:10px;padding:1rem;margin-bottom:1rem;box-shadow:0 2px 8px rgba(0,0,0,0.06);"><strong>\'+p.name+\'</strong></div>\';}).join(""):\'<p style="color:#888;">No pets on file yet \u2014 your practice will add them soon.</p>\';'
    +   'return \'<h1 style="font-size:1.3rem;">Welcome, \'+data.name+\'</h1>\'+petHTML;'
    + '}'
    + 'async function portalCheckPassword(){'
    +   'var pass=document.getElementById("portal-password").value;'
    +   'var errEl=document.getElementById("portal-login-error");'
    +   'errEl.style.display="none";'
    +   'if(!pass)return;'
    +   'try{'
    +     'var km=await crypto.subtle.importKey("raw",new TextEncoder().encode(pass),{name:"PBKDF2"},false,["deriveKey"]);'
    +     'var kek=await crypto.subtle.deriveKey({name:"PBKDF2",salt:b64u(WRAP_SALT),iterations:' + PBKDF2_ITERATIONS + ',hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);'
    +     'var dkBytes=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64u(WRAP_IV)},kek,b64u(WRAP_CT));'
    +     'var dkKey=await crypto.subtle.importKey("raw",dkBytes,{name:"AES-GCM"},false,["decrypt"]);'
    +     'var plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64u(PAY_IV)},dkKey,b64u(PAY_CT));'
    +     'var data=JSON.parse(new TextDecoder().decode(plain));'
    +     'document.getElementById("portal-mount").innerHTML=renderPortalData(data);'
    +     'document.getElementById("login-screen").style.display="none";'
    +     'document.getElementById("portal-mount").style.display="block";'
    +   '}catch(e){'
    +     'errEl.style.display="block";'
    +     'document.getElementById("portal-password").value="";'
    +   '}'
    + '}'
    + '</' + 'script>\n</body>\n</html>';
}

function addClientToPortalHTML(html, { username, hash }) {
  const match = html.match(/var CLIENTS = (\[.*?\]);/s);
  if (!match) throw new Error('Could not find "var CLIENTS = [...]" in portal.html \u2014 has its format changed?');
  const clients = JSON.parse(match[1]);
  clients.push({ username, hash });
  return html.replace(/var CLIENTS = \[.*?\];/s, 'var CLIENTS = ' + JSON.stringify(clients) + ';');
}

function updateClientHashInPortalHTML(html, { username, newHash }) {
  const match = html.match(/var CLIENTS = (\[.*?\]);/s);
  if (!match) throw new Error('Could not find "var CLIENTS = [...]" in portal.html \u2014 has its format changed?');
  const clients = JSON.parse(match[1]).map(c =>
    c.username.toLowerCase() === username.toLowerCase() ? { username: c.username, hash: newHash } : c
  );
  return html.replace(/var CLIENTS = \[.*?\];/s, 'var CLIENTS = ' + JSON.stringify(clients) + ';');
}

async function githubDeleteFile(env, path, sha, message) {
  const url = 'https://api.github.com/repos/' + GITHUB_OWNER + '/' + GITHUB_REPO + '/contents/' + path;
  const res = await fetch(url, {
    method: 'DELETE',
    headers: { 'Authorization': 'token ' + env.GITHUB_TOKEN, 'User-Agent': 'vet-portal-worker', 'Content-Type': 'application/json', 'Accept': 'application/vnd.github+json' },
    body: JSON.stringify({ message, sha, branch: GITHUB_BRANCH })
  });
  if (!res.ok) throw new Error('GitHub delete failed for ' + path + ': ' + res.status + ' ' + await res.text());
  return await res.json();
}

// ═══════════════════════════════════════════════════════════════════════
// Email (Resend) — swap this one function for Mailgun/SendGrid/etc. if you
// already use a different provider; nothing else needs to change.
// Requires Worker secret: RESEND_API_KEY. Requires a "from" address on a
// domain you've verified with Resend — set RESEND_FROM below or as a secret.
// ═══════════════════════════════════════════════════════════════════════

async function sendEmail(env, to, subject, text) {
  const from = env.RESEND_FROM || 'Pet Portal <portal@yourdomain.com>';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to: [to], subject, text })
  });
  if (!res.ok) throw new Error('Email send failed: ' + res.status + ' ' + await res.text());
  return await res.json();
}

// ═══════════════════════════════════════════════════════════════════════
// Push notification (ntfy.sh) — a signup should never fail just because the
// notification did. Errors here are logged, never thrown.
// ═══════════════════════════════════════════════════════════════════════

async function notify(env, message) {
  if (!env.NTFY_TOPIC) return; // notifications are optional — skip quietly if unset
  try {
    await fetch('https://ntfy.sh/' + env.NTFY_TOPIC, {
      method: 'POST',
      headers: { 'Title': 'New pet portal signup' },
      body: message
    });
  } catch (e) {
    console.error('Notification failed (registration still succeeded):', e);
  }
}
