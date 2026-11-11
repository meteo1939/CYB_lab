process.env.CAPTCHA_TEST_MODE = '1';

import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { authenticate } from '../src/auth.js';
import { openDatabase } from '../src/db.js';
import { MSG } from '../src/messages.js';
import { verifyPassword } from '../src/passwords.js';
import { resetAndSeed } from '../src/seed.js';
import { findByLogin } from '../src/users.js';

function client(base) {
  let cookie = '';
  return {
    async send(urlPath, { method = 'GET', form } = {}) {
      const headers = {};
      if (cookie) headers.cookie = cookie;
      let body;
      if (form) {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(form);
      }
      const response = await fetch(base + urlPath, { method, headers, body, redirect: 'manual' });
      const cookies = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
      for (const item of cookies) {
        const pair = item.split(';')[0];
        if (!pair.startsWith('klucz_sid=')) continue;
        const value = pair.slice('klucz_sid='.length);
        const expired = value === '' || /Max-Age=0/i.test(item) || /01 Jan 1970/i.test(item);
        cookie = expired ? '' : pair;
      }
      return {
        status: response.status,
        text: await response.text(),
        location: response.headers.get('location'),
      };
    },
  };
}

function csrfOf(html) {
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  assert.ok(match, 'brak tokenu CSRF');
  return match[1];
}

function challengeOf(html) {
  const match = html.match(/name="login_challenge" value="([^"]+)"/);
  assert.ok(match, 'brak wyzwania logowania');
  return match[1];
}

async function login(http, loginName, password) {
  const page = await http.send('/login');
  return http.send('/login', {
    method: 'POST',
    form: {
      _csrf: csrfOf(page.text),
      login_challenge: challengeOf(page.text),
      login: loginName,
      password,
      company_fax: '',
      'g-recaptcha-response': 'test-ok',
    },
  });
}

test('portal wariantu 8 + moduł 2: logowanie, role, skrót, captcha, canary', { timeout: 180000 }, async () => {
  const db = openDatabase(':memory:');
  await resetAndSeed(db);
  assert.equal(Number(db.prepare('SELECT COUNT(*) AS n FROM users').get().n), 11);

  const admin = findByLogin(db, 'admin');
  assert.match(admin.password_hash, /^\$argon2id\$/);
  assert.equal(await verifyPassword('Admin#Portal2026', admin.password_hash), true);
  assert.equal((await authenticate(db, 'nie-ma-takiego', 'Admin#Portal2026')).status, 'invalid');
  assert.equal((await authenticate(db, 'kwojcik', 'zle-haslo-test')).status, 'invalid');
  assert.equal((await authenticate(db, 'kwojcik', 'Wojcik#Zablok1')).status, 'blocked');
  assert.equal((await authenticate(db, 'pkaczmarek', '10293847')).status, 'otp_expired');
  assert.equal((await authenticate(db, 'mwisniewski', '48291573')).status, 'ok');

  const app = createApp(db);
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  const http = client(`http://127.0.0.1:${server.address().port}`);

  try {
    const page = await http.send('/login');
    const noCaptcha = await http.send('/login', {
      method: 'POST',
      form: {
        _csrf: csrfOf(page.text),
        login_challenge: challengeOf(page.text),
        login: 'admin',
        password: 'Admin#Portal2026',
        company_fax: '',
        'g-recaptcha-response': '',
      },
    });
    assert.equal(noCaptcha.status, 400);
    assert.ok(noCaptcha.text.includes(MSG.captcha));

    const missing = await login(http, 'nie-ma-takiego', 'cokolwiek123');
    const wrong = await login(http, 'admin', 'zle-haslo-test');
    assert.equal(missing.status, 200);
    assert.equal(wrong.status, 200);
    assert.ok(missing.text.includes(MSG.badLogin));
    assert.ok(wrong.text.includes(MSG.badLogin));

    const canary = await login(http, 'svc_backup', 'Backup#Canary2026');
    assert.ok(canary.text.includes(MSG.badLogin));
    assert.equal(canary.location, null);
    assert.equal(Number(db.prepare("SELECT COUNT(*) AS n FROM canary_alerts WHERE type = 'honeypot_account'").get().n) > 0, true);

    const aws = await http.send('/canary/aws-credentials.txt');
    assert.equal(aws.status, 200);
    assert.ok(aws.text.includes('AKIAIOSFODNN7CANARY'));
    assert.equal(Number(db.prepare("SELECT COUNT(*) AS n FROM canary_alerts WHERE type = 'aws_keys'").get().n) > 0, true);

    const expired = await login(http, 'pkaczmarek', '10293847');
    assert.ok(expired.text.includes(MSG.otpExpired));
    const blocked = await login(http, 'kwojcik', 'Wojcik#Zablok1');
    assert.ok(blocked.text.includes(MSG.blocked));

    const first = await login(http, 'mwisniewski', '48291573');
    assert.equal(first.status, 302);
    assert.equal(first.location, '/haslo/zmiana');
    const change = await http.send('/haslo/zmiana');
    assert.ok(change.text.includes('Zmień hasło nadane przez administratora'));
    assert.ok(change.text.includes('g-recaptcha'));
    await http.send('/wyloguj', { method: 'POST', form: { _csrf: csrfOf(change.text) } });

    const guest = await login(http, 'tzielinski', 'Zielinski.Gosc1');
    assert.equal(guest.status, 302);
    const denied = await http.send('/dokumenty');
    assert.equal(denied.status, 403);
    await http.send('/wyloguj', { method: 'POST', form: { _csrf: csrfOf(denied.text) } });

    const adminLogin = await login(http, 'admin', 'Admin#Portal2026');
    assert.equal(adminLogin.status, 302);
    const home = await http.send('/');
    assert.ok(home.text.includes('szafki laboratoryjnej'));
    const canaryPage = await http.send('/admin/canary');
    assert.equal(canaryPage.status, 200);
    assert.ok(canaryPage.text.includes('honeypot_account'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
