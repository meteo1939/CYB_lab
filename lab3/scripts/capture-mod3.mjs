import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyIntegrity, LOG_PATH } from '../src/securityLog.js';

const base = process.env.BOT_BASE_URL || 'http://127.0.0.1:3000';
const out = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'sprawozdanie', 'img');
fs.mkdirSync(out, { recursive: true });

function jar() {
  let cookie = '';
  return {
    async send(pathname, { method = 'GET', form, json } = {}) {
      const headers = {};
      if (cookie) headers.cookie = cookie;
      let body;
      if (form) {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(form);
      }
      if (json) {
        headers['content-type'] = 'application/json';
        body = JSON.stringify(json);
      }
      const response = await fetch(base + pathname, { method, headers, body, redirect: 'manual' });
      for (const item of response.headers.getSetCookie?.() || []) {
        const pair = item.split(';')[0];
        if (!pair.startsWith('klucz_sid=')) continue;
        const value = pair.slice('klucz_sid='.length);
        cookie = value && !/Max-Age=0/i.test(item) ? pair : '';
      }
      return { status: response.status, location: response.headers.get('location'), text: await response.text(), headers: response.headers };
    },
  };
}

const http = jar();

async function loginAdmin() {
  const page = await http.send('/login');
  const csrf = page.text.match(/name="_csrf" value="([^"]+)"/)[1];
  const challenge = page.text.match(/name="login_challenge" value="([^"]+)"/)[1];
  const posted = await http.send('/login', {
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
  if (posted.location) await http.send(posted.location);
}

// Generate canary + failures for alerts
{
  const page = await http.send('/login');
  const csrf = page.text.match(/name="_csrf" value="([^"]+)"/)[1];
  const challenge = page.text.match(/name="login_challenge" value="([^"]+)"/)[1];
  await http.send('/login', {
    method: 'POST',
    form: {
      _csrf: csrf,
      login_challenge: challenge,
      login: 'svc_backup',
      password: 'x',
      company_fax: '',
      'g-recaptcha-response': 'test-ok',
    },
  });
  for (let i = 0; i < 5; i += 1) {
    const p = await http.send('/login');
    const c = p.text.match(/name="_csrf" value="([^"]+)"/)[1];
    const ch = p.text.match(/name="login_challenge" value="([^"]+)"/)[1];
    await http.send('/login', {
      method: 'POST',
      form: {
        _csrf: c,
        login_challenge: ch,
        login: 'anowak',
        password: `bad-${i}`,
        company_fax: '',
        'g-recaptcha-response': 'test-ok',
      },
    });
  }
}

await loginAdmin();
const journal = await http.send('/admin/dziennik');
fs.writeFileSync(path.join(out, '_dziennik.html'), journal.text);
console.log('dziennik', journal.status, /SHA3-256|security-log/.test(journal.text));

const filtered = await http.send('/admin/dziennik?action=login_failure');
fs.writeFileSync(path.join(out, '_filtr.html'), filtered.text);
console.log('filtr', filtered.status);

const csrf = journal.text.match(/name="_csrf" value="([^"]+)"/)[1];
const before = await http.send('/admin/dziennik/weryfikuj', {
  method: 'POST',
  form: { _csrf: csrf, user: '', action: '', from: '', to: '' },
});
fs.writeFileSync(path.join(out, '_verify-ok.html'), before.text);
console.log('verify-ok', /nienaruszony/i.test(before.text));

// Tamper
const data = JSON.parse(fs.readFileSync(LOG_PATH, 'utf8'));
const victim = data.events[data.events.length - 1];
victim.description = `${victim.description} [TAMPERED]`;
fs.writeFileSync(LOG_PATH, `${JSON.stringify(data, null, 2)}\n`);
console.log('tampered', victim.id, verifyIntegrity().ok === false);

const journal2 = await http.send('/admin/dziennik');
const csrf2 = journal2.text.match(/name="_csrf" value="([^"]+)"/)[1];
const after = await http.send('/admin/dziennik/weryfikuj', {
  method: 'POST',
  form: { _csrf: csrf2, user: '', action: '', from: '', to: '' },
});
fs.writeFileSync(path.join(out, '_verify-bad.html'), after.text);
console.log('verify-bad', /ingerencj/i.test(after.text));

const alerts = await http.send('/admin/alerty');
fs.writeFileSync(path.join(out, '_alerty.html'), alerts.text);
console.log('alerty', alerts.status, /Alert|svc_backup|nieudanych/i.test(alerts.text));

const exported = await http.send('/admin/dziennik/eksport');
fs.writeFileSync(path.join(out, 'security-log-export.json'), exported.text);
console.log('export', exported.status, exported.text.slice(0, 80));

// sample log fragment
fs.copyFileSync(LOG_PATH, path.join(out, 'security-log-sample.json'));
console.log('done');
