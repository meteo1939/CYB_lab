import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {
  LOG_PATH,
  hashEvent,
  recordSecurityEvent,
  verifyIntegrity,
  listSecurityEvents,
} from '../src/securityLog.js';

test('SHA3-256 zmienia się po podmianie opisu wpisu', () => {
  if (fs.existsSync(LOG_PATH)) fs.unlinkSync(LOG_PATH);
  const first = recordSecurityEvent({
    action: 'login_failure',
    target: 'demo',
    success: false,
    detail: 'test',
    req: { ip: '127.0.0.1' },
  });
  assert.match(first.hash, /^[a-f0-9]{64}$/);
  assert.equal(verifyIntegrity().ok, true);

  const raw = JSON.parse(fs.readFileSync(LOG_PATH, 'utf8'));
  raw.events[0].description = 'zmienione';
  fs.writeFileSync(LOG_PATH, JSON.stringify(raw, null, 2));
  const check = verifyIntegrity();
  assert.equal(check.ok, false);
  assert.ok(check.issues.some((item) => item.kind === 'hash'));
  assert.notEqual(hashEvent(raw.events[0]), raw.events[0].hash);
});

test('próba na konto-pułapkę trafia do dziennika', () => {
  recordSecurityEvent({
    action: 'canary_alert',
    target: 'honeypot_account',
    success: true,
    detail: 'Próba użycia konta-pułapki svc_backup',
    req: { ip: '127.0.0.1' },
  });
  const found = listSecurityEvents({ action: 'canary_alert', limit: 20 })
    .some((event) => event.target === 'honeypot_account');
  assert.equal(found, true);
});
