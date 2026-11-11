import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluatePassword, hashPassword, passwordChangeReason } from '../src/passwords.js';
import { analyzePassword } from '../public/js/entropy.js';
import { can } from '../src/permissions.js';
import { matchesHistory } from '../src/users.js';
import { DEMO_ACCOUNTS } from '../src/seed.js';

const policyOn = { minPasswordLength: 12, entropyRequired: true, minEntropyBits: 60, passwordMaxAgeDays: 90 };
const policyOff = { ...policyOn, entropyRequired: false };

test('entropia 12 małych liter nie sięga 60 bitów', () => {
  const weak = analyzePassword('aaaaaaaaaaaa');
  assert.equal(weak.R, 26);
  assert.ok(weak.bits < 60);
  assert.equal(evaluatePassword('aaaaaaaaaaaa', policyOn).ok, false);
  assert.equal(evaluatePassword('aaaaaaaaaaaa', policyOff).ok, true);
});

test('hasło z większym alfabetem przechodzi próg 60 bitów', () => {
  const mixed = evaluatePassword('Aaaaaaaa1234', policyOn);
  assert.ok(mixed.bits >= 60);
  assert.equal(mixed.ok, true);
});

test('konta stałe spełniają politykę wariantu, a kod jednorazowy ma 8 cyfr', () => {
  assert.equal(DEMO_ACCOUNTS.filter((account) => !account.permanent).length, 9);
  for (const account of DEMO_ACCOUNTS) {
    if (account.kind === 'password' || account.kind === 'blocked') {
      assert.equal(evaluatePassword(account.password, policyOn).ok, true, account.login);
    } else {
      assert.match(account.password, /^\d{8}$/);
    }
  }
});

test('ważność hasła wymusza zmianę dopiero po terminie', () => {
  const user = { must_change_password: 0, password_changed_at: new Date('2026-01-01T00:00:00Z').toISOString() };
  assert.equal(passwordChangeReason(user, policyOn, new Date('2026-05-01T00:00:00Z').getTime()), 'expired');
  assert.equal(passwordChangeReason(user, { ...policyOn, passwordMaxAgeDays: 0 }, Date.now()), null);
  assert.equal(passwordChangeReason({ ...user, must_change_password: 1 }, policyOff), 'first');
});

test('gość nie czyta dokumentów, administrator ma pełną macierz', () => {
  assert.equal(can('gosc', 'documents.read'), false);
  assert.equal(can('gosc', 'announcements.read_public'), true);
  assert.equal(can('pracownik', 'users.read'), false);
  assert.equal(can('pracownik', 'documents.read'), true);
  assert.equal(can('administrator', 'settings.manage'), true);
  assert.equal(can('administrator', 'audit.read'), true);
});

test('to samo hasło rozpoznaje się po weryfikacji, nie po porównaniu skrótów', async () => {
  const first = await hashPassword('InneHaslo#2026x');
  const second = await hashPassword('InneHaslo#2026x');
  assert.notEqual(first, second);
  assert.match(first, /^\$argon2id\$/);
  assert.equal(await matchesHistory('InneHaslo#2026x', [first]), true);
  assert.equal(await matchesHistory('ZupelnieInne#99a', [first, second]), false);
});
