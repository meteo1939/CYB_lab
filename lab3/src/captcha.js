import { randomBytes } from 'node:crypto';

const GOOGLE_SITEVERIFY = 'https://www.google.com/recaptcha/api/siteverify';

// Oficjalne klucze testowe Google reCAPTCHA v2 — zawsze przechodzą w widżecie.
export const DEFAULT_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
export const DEFAULT_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

export function captchaConfig() {
  return {
    siteKey: process.env.RECAPTCHA_SITE_KEY || DEFAULT_SITE_KEY,
    secretKey: process.env.RECAPTCHA_SECRET_KEY || DEFAULT_SECRET_KEY,
    testMode: process.env.CAPTCHA_TEST_MODE === '1',
  };
}

export async function verifyRecaptcha(token, remoteIp) {
  const value = String(token || '').trim();
  if (!value) return { ok: false, reason: 'missing' };

  const cfg = captchaConfig();
  if (cfg.testMode && value === 'test-ok') {
    return { ok: true, reason: 'test-mode' };
  }

  const body = new URLSearchParams({
    secret: cfg.secretKey,
    response: value,
  });
  if (remoteIp) body.set('remoteip', remoteIp);

  try {
    const response = await fetch(GOOGLE_SITEVERIFY, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await response.json();
    if (!data.success) return { ok: false, reason: 'rejected', codes: data['error-codes'] || [] };
    return { ok: true, reason: 'google' };
  } catch {
    return { ok: false, reason: 'network' };
  }
}

/** Jednorazowe wyzwanie serwerowe (TTL), niezależne od tokenu Google. */
export function createLoginChallenge(db, ttlMs = 2 * 60 * 1000) {
  const id = randomBytes(24).toString('base64url');
  const expires = new Date(Date.now() + ttlMs).toISOString();
  db.prepare(`
    INSERT INTO login_challenges (id, expires_at, used, created_at)
    VALUES (?, ?, 0, ?)
  `).run(id, expires, new Date().toISOString());
  return { id, expiresAt: expires };
}

export function consumeLoginChallenge(db, id) {
  const token = String(id || '').trim();
  if (!token) return { ok: false, reason: 'missing' };
  const row = db.prepare('SELECT * FROM login_challenges WHERE id = ?').get(token);
  if (!row) return { ok: false, reason: 'unknown' };
  if (row.used) return { ok: false, reason: 'used' };
  if (new Date(row.expires_at).getTime() < Date.now()) return { ok: false, reason: 'expired' };
  db.prepare('UPDATE login_challenges SET used = 1 WHERE id = ?').run(token);
  return { ok: true };
}
