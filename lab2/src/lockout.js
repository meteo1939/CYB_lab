import { nowIso } from './db.js';

export const ACCOUNT_LOCK_MS = 15 * 60 * 1000;
export const IP_WINDOW_MS = 15 * 60 * 1000;

export function lockRemainingMs(user, now = Date.now()) {
  if (!user?.locked_until) return 0;
  const until = new Date(user.locked_until).getTime();
  return Math.max(0, until - now);
}

export function isAccountLocked(user, now = Date.now()) {
  return lockRemainingMs(user, now) > 0;
}

export function formatRemaining(ms) {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

export function registerFailedAccountLogin(db, user, maxAttempts) {
  if (!user || user.is_canary) return { locked: false, remainingMs: 0 };
  const next = Number(user.failed_login_count || 0) + 1;
  if (next >= maxAttempts) {
    const until = new Date(Date.now() + ACCOUNT_LOCK_MS).toISOString();
    db.prepare(`
      UPDATE users
      SET failed_login_count = ?, locked_until = ?, updated_at = ?
      WHERE id = ?
    `).run(0, until, nowIso(), user.id);
    return { locked: true, remainingMs: ACCOUNT_LOCK_MS };
  }
  db.prepare(`
    UPDATE users SET failed_login_count = ?, updated_at = ? WHERE id = ?
  `).run(next, nowIso(), user.id);
  return { locked: false, remainingMs: 0, failures: next };
}

export function clearFailedAccountLogin(db, userId) {
  db.prepare(`
    UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?
  `).run(nowIso(), userId);
}

export function registerFailedIp(db, ip, maxAttempts) {
  const key = String(ip || 'unknown');
  const now = Date.now();
  const row = db.prepare('SELECT * FROM ip_login_attempts WHERE ip = ?').get(key);
  if (!row || new Date(row.window_ends_at).getTime() <= now) {
    const ends = new Date(now + IP_WINDOW_MS).toISOString();
    db.prepare(`
      INSERT INTO ip_login_attempts (ip, fail_count, window_ends_at, locked_until)
      VALUES (?, 1, ?, NULL)
      ON CONFLICT(ip) DO UPDATE SET fail_count = 1, window_ends_at = excluded.window_ends_at, locked_until = NULL
    `).run(key, ends);
    return { blocked: false, failures: 1 };
  }

  const next = Number(row.fail_count) + 1;
  if (row.locked_until && new Date(row.locked_until).getTime() > now) {
    return {
      blocked: true,
      remainingMs: new Date(row.locked_until).getTime() - now,
      failures: row.fail_count,
    };
  }

  if (next >= maxAttempts) {
    const until = new Date(now + ACCOUNT_LOCK_MS).toISOString();
    db.prepare(`
      UPDATE ip_login_attempts SET fail_count = ?, locked_until = ? WHERE ip = ?
    `).run(next, until, key);
    return { blocked: true, remainingMs: ACCOUNT_LOCK_MS, failures: next };
  }

  db.prepare('UPDATE ip_login_attempts SET fail_count = ? WHERE ip = ?').run(next, key);
  return { blocked: false, failures: next };
}

export function ipLockRemainingMs(db, ip, now = Date.now()) {
  const row = db.prepare('SELECT locked_until FROM ip_login_attempts WHERE ip = ?').get(String(ip || 'unknown'));
  if (!row?.locked_until) return 0;
  return Math.max(0, new Date(row.locked_until).getTime() - now);
}

export function clearFailedIp(db, ip) {
  db.prepare('DELETE FROM ip_login_attempts WHERE ip = ?').run(String(ip || 'unknown'));
}
