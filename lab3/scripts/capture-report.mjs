import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const base = process.env.BOT_BASE_URL || 'http://127.0.0.1:3000';
const out = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'sprawozdanie', 'img');
mkdirSync(out, { recursive: true });

function jar() {
  let cookie = '';
  return {
    async send(pathname, { method = 'GET', form } = {}) {
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
      return { status: response.status, location: response.headers.get('location'), text: await response.text() };
    },
  };
}

function wrap(title, bodyHtml) {
  return `<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><title>${title}</title>
  <link rel="stylesheet" href="${base}/css/app.css">
  <style>body{margin:0;background:#efe8da}</style></head><body class="auth">${bodyHtml}</body></html>`;
}

function extractCard(html) {
  const match = html.match(/<section class="auth-panel">[\s\S]*?<\/section>/);
  return match ? match[0] : html;
}

const http = jar();

// 1) Login page with CAPTCHA widget markup (for Edge live shot we also open /login)
{
  const page = await http.send('/login');
  writeFileSync(path.join(out, '_login.html'), page.text);
  console.log('login', page.status, /g-recaptcha/.test(page.text));
}

// 2) Rejected without captcha token
{
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
      'g-recaptcha-response': '',
    },
  });
  writeFileSync(path.join(out, '_no-captcha.html'), wrap('Bez CAPTCHA', extractCard(posted.text)));
  console.log('no-captcha', posted.status, /robotem|reCAPTCHA/i.test(posted.text));
}

// 3) Account lockout for elewandowska
{
  let last = null;
  for (let i = 0; i < 6; i += 1) {
    const page = await http.send('/login');
    const csrf = page.text.match(/name="_csrf" value="([^"]+)"/)[1];
    const challenge = page.text.match(/name="login_challenge" value="([^"]+)"/)[1];
    last = await http.send('/login', {
      method: 'POST',
      form: {
        _csrf: csrf,
        login_challenge: challenge,
        login: 'elewandowska',
        password: `wrong-${i}`,
        company_fax: '',
        'g-recaptcha-response': 'test-ok',
      },
    });
    if (/zablokowane|Pozostały czas/i.test(last.text)) break;
  }
  writeFileSync(path.join(out, '_lockout.html'), wrap('Blokada konta', extractCard(last.text)));
  console.log('lockout', last.status, /zablokowane|Pozostały czas/i.test(last.text));
}

// 4) Canary triggers
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
      password: 'Backup#Canary2026',
      company_fax: '',
      'g-recaptcha-response': 'test-ok',
    },
  });
  await http.send('/canary/aws-credentials.txt');

  // login as admin to open canary page
  const loginPage = await http.send('/login');
  const csrf2 = loginPage.text.match(/name="_csrf" value="([^"]+)"/)[1];
  const challenge2 = loginPage.text.match(/name="login_challenge" value="([^"]+)"/)[1];
  const admin = await http.send('/login', {
    method: 'POST',
    form: {
      _csrf: csrf2,
      login_challenge: challenge2,
      login: 'admin',
      password: 'Admin#Portal2026',
      company_fax: '',
      'g-recaptcha-response': 'test-ok',
    },
  });
  if (admin.location) await http.send(admin.location);
  const canary = await http.send('/admin/canary');
  writeFileSync(path.join(out, '_canary.html'), canary.text);
  console.log('canary', canary.status, /honeypot_account|aws_keys/.test(canary.text));

  const profile = await http.send('/profil');
  writeFileSync(path.join(out, '_profile-password.html'), profile.text);
  console.log('profile', profile.status, /g-recaptcha/.test(profile.text));
}

console.log('HTML snapshots ready in', out);
