import { randomBytes } from 'node:crypto';
import { nowIso } from './db.js';
import { ABSOLUTE_SESSION_MS } from './passwords.js';

export function createSession(db, { userId = null, stage = 'anon', changeReason = null, pendingTotp = null } = {}) {
  const id = randomBytes(32).toString('base64url');
  const csrf = randomBytes(32).toString('base64url');
  const ts = nowIso();
  db.prepare(`
    INSERT INTO sessions (
      id, user_id, stage, change_reason, csrf_secret, pending_totp, flash, attempt_count, created_at, last_activity_at
    ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?, ?)
  `).run(id, userId, stage, changeReason, csrf, pendingTotp, ts, ts);
  return getSession(db, id);
}

export function getSession(db, id) {
  if (!id) return null;
  return db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) || null;
}

export function deleteSession(db, id) {
  if (!id) return;
  db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

export function deleteUserSessions(db, userId, exceptId = null) {
  if (exceptId) {
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND id <> ?').run(userId, exceptId);
  } else {
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  }
}

export function touchSession(db, id) {
  db.prepare('UPDATE sessions SET last_activity_at = ? WHERE id = ?').run(nowIso(), id);
}

export function setFlash(db, id, payload) {
  db.prepare('UPDATE sessions SET flash = ? WHERE id = ?').run(JSON.stringify(payload), id);
}

export function clearFlash(db, id) {
  db.prepare('UPDATE sessions SET flash = NULL WHERE id = ?').run(id);
}

export function setPendingTotp(db, id, secret) {
  db.prepare('UPDATE sessions SET pending_totp = ? WHERE id = ?').run(secret, id);
}

export function incrementAttempts(db, id) {
  db.prepare('UPDATE sessions SET attempt_count = attempt_count + 1 WHERE id = ?').run(id);
  return getSession(db, id);
}

export function sessionExpiry(session, policy, now = Date.now()) {
  if (!session) return null;
  const created = new Date(session.created_at).getTime();
  const last = new Date(session.last_activity_at).getTime();
  if (session.user_id && now - last > policy.sessionIdleMinutes * 60 * 1000) return 'idle';
  if (now - created > ABSOLUTE_SESSION_MS) return 'absolute';
  return null;
}

export function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

export function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: ABSOLUTE_SESSION_MS,
  };
}
