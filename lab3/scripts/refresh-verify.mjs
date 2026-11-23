import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LOG_PATH, hashEvent, verifyIntegrity } from '../src/securityLog.js';

const base = 'http://127.0.0.1:3000';
const out = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'sprawozdanie', 'img');
let cookie = '';

async function send(pathname, { method = 'GET', form } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  let body;
  if (form) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(form);
  }
  const response = await fetch(base + pathname, { method, headers, body, redirect: 'manual' });
  for (const item of response.headers.getSetCookie?.() || []) {
    const pair = item.split(';')[0];
    if (!pair.startsWith('klucz_sid=')) continue;
    const value = pair.slice('klucz_sid='.length);
    cookie = value && !/Max-Age=0/i.test(item) ? pair : '';
  }
  return { location: response.headers.get('location'), text: await response.text() };
}

// Repair
const data = JSON.parse(fs.readFileSync(LOG_PATH, 'utf8'));
for (const event of data.events) event.hash = hashEvent(event);
fs.writeFileSync(LOG_PATH, `${JSON.stringify(data, null, 2)}\n`);
console.log('repaired', verifyIntegrity().ok);

const page = await send('/login');
const csrf = page.text.match(/name="_csrf" value="([^"]+)"/)[1];
const challenge = page.text.match(/name="login_challenge" value="([^"]+)"/)[1];
const posted = await send('/login', {
  method: 'POST',
  form: {
    _csrf: csrf,
    login_challenge: challenge,
    login: 'admin',
    password: 'Admin#Portal2026',
    company_fax: '',
    'g-recaptcha-response': 'test-ok',
  },
});
if (posted.location) await send(posted.location);

const journal = await send('/admin/dziennik');
fs.writeFileSync(path.join(out, '_dziennik.html'), journal.text);
const c1 = journal.text.match(/name="_csrf" value="([^"]+)"/)[1];
const ok = await send('/admin/dziennik/weryfikuj', {
  method: 'POST',
  form: { _csrf: c1, user: '', action: '', from: '', to: '' },
});
fs.writeFileSync(path.join(out, '_verify-ok.html'), ok.text);
console.log('ok', /nienaruszony/i.test(ok.text));

const again = JSON.parse(fs.readFileSync(LOG_PATH, 'utf8'));
const victim = again.events[again.events.length - 2];
victim.description = `${victim.description || ''} [TAMPERED]`;
fs.writeFileSync(LOG_PATH, `${JSON.stringify(again, null, 2)}\n`);

const journal2 = await send('/admin/dziennik');
const c2 = journal2.text.match(/name="_csrf" value="([^"]+)"/)[1];
const bad = await send('/admin/dziennik/weryfikuj', {
  method: 'POST',
  form: { _csrf: c2, user: '', action: '', from: '', to: '' },
});
fs.writeFileSync(path.join(out, '_verify-bad.html'), bad.text);
console.log('bad', /ingerencj/i.test(bad.text));

await import('./style-mod3.mjs');
