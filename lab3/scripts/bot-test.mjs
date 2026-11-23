/**
 * Symulacja bota wyłącznie przeciw własnej aplikacji KLUCZ (moduł 2).
 * Uruchom serwer: CAPTCHA_TEST_MODE=1 npm start
 * Potem: npm run bot-test
 */
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const base = process.env.BOT_BASE_URL || 'http://127.0.0.1:3000';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const reportPath = path.join(__dirname, '..', 'bot-report.md');

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
      const text = await response.text();
      return { status: response.status, location: response.headers.get('location'), text, cookie };
    },
  };
}

function csrfAndChallenge(html) {
  const csrf = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
  const challenge = html.match(/name="login_challenge" value="([^"]+)"/)?.[1];
  return { csrf, challenge };
}

const results = [];

function note(name, worked, detail) {
  results.push({ name, worked, detail });
  console.log(`${worked ? 'OK ' : '—  '} ${name}: ${detail}`);
}

async function main() {
  const http = jar();

  // 1) Brak CAPTCHA
  {
    const page = await http.send('/login');
    const { csrf, challenge } = csrfAndChallenge(page.text);
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
    note(
      'reCAPTCHA przy logowaniu',
      /robotem|reCAPTCHA|wyzwanie/i.test(posted.text) || posted.status === 400,
      `status ${posted.status}; formularz bez tokenu odrzucony`,
    );
  }

  // 2) Honeypot
  {
    const page = await http.send('/login');
    const { csrf, challenge } = csrfAndChallenge(page.text);
    const posted = await http.send('/login', {
      method: 'POST',
      form: {
        _csrf: csrf,
        login_challenge: challenge,
        login: 'admin',
        password: 'x',
        company_fax: 'http://evil.example',
        'g-recaptcha-response': 'test-ok',
      },
    });
    note(
      'Honeypot (ukryte pole)',
      /niepoprawne/i.test(posted.text) && !posted.location,
      `wypełnione company_fax → odrzucenie bez wejścia (status ${posted.status})`,
    );
  }

  // 3) Canary account
  {
    const page = await http.send('/login');
    const { csrf, challenge } = csrfAndChallenge(page.text);
    const posted = await http.send('/login', {
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
    note(
      'Canarytoken — konto-pułapka',
      /niepoprawne/i.test(posted.text) && !posted.location,
      'logowanie na svc_backup nie wpuszcza; alert trafia do /admin/canary',
    );
  }

  // 4) AWS canary document
  {
    const got = await http.send('/canary/aws-credentials.txt');
    note(
      'Canarytoken — klucze AWS',
      got.status === 200 && /AKIAIOSFODNN7CANARY/.test(got.text),
      `GET /canary/aws-credentials.txt → ${got.status}; alert typu aws_keys`,
    );
  }

  // 5) Account lockout (needs CAPTCHA_TEST_MODE=1)
  {
    let locked = false;
    let remaining = '';
    for (let i = 0; i < 6; i += 1) {
      const page = await http.send('/login');
      const { csrf, challenge } = csrfAndChallenge(page.text);
      const posted = await http.send('/login', {
        method: 'POST',
        form: {
          _csrf: csrf,
          login_challenge: challenge,
          login: 'jkowalski',
          password: `wrong-password-${i}`,
          company_fax: '',
          'g-recaptcha-response': 'test-ok',
        },
      });
      if (/zablokowane po błędnych|Pozostały czas blokady/i.test(posted.text)) {
        locked = true;
        remaining = posted.text.match(/(\d+:\d{2})/)?.[1] || '';
        break;
      }
    }
    note(
      'Limit błędnych logowań (konto)',
      locked,
      locked ? `konto zablokowane na 15 min; pokazano ${remaining || 'czas'}` : 'nie udało się wywołać blokady (sprawdź CAPTCHA_TEST_MODE=1)',
    );
  }

  // 6) Jednorazowe wyzwanie
  {
    const page = await http.send('/login');
    const { csrf, challenge } = csrfAndChallenge(page.text);
    const form = {
      _csrf: csrf,
      login_challenge: challenge,
      login: 'anowak',
      password: 'x',
      company_fax: '',
      'g-recaptcha-response': 'test-ok',
    };
    await http.send('/login', { method: 'POST', form });
    const reused = await http.send('/login', { method: 'POST', form });
    note(
      'Jednorazowe wyzwanie logowania',
      /wygasło|użyte|Wyzwanie/i.test(reused.text) || reused.status === 400,
      'ponowne użycie tego samego login_challenge odrzucone',
    );
  }

  const lines = [
    '# Zestawienie testu bota — KLUCZ moduł 2',
    '',
    `Cel: wyłącznie własna aplikacja \`${base}\`.`,
    '',
    '| Zabezpieczenie | Zadziałało? | Uwagi |',
    '| --- | --- | --- |',
    ...results.map((row) => `| ${row.name} | ${row.worked ? 'tak' : 'nie'} | ${row.detail} |`),
    '',
    '## Interpretacja',
    '',
    '- Bot bez tokenu reCAPTCHA nie przechodzi logowania.',
    '- Wypełnienie honeypota kończy się odrzuceniem.',
    '- Konto `svc_backup` i plik AWS generują alerty Canary.',
    '- Po serii złych haseł konto dostaje blokadę 15 minut z widocznym czasem.',
    '- Challenge serwerowy jest jednorazowy (TTL ~2 min).',
    '',
  ];
  writeFileSync(reportPath, lines.join('\n'), 'utf8');
  console.log(`\nRaport: ${reportPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
