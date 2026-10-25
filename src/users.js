import { nowIso } from './db.js';
import { passwordChangeReason } from './passwords.js';
import { hashPassword, generateOtp, OTP_TTL_MS, verifyPassword } from './passwords.js';
import { ROLES } from './permissions.js';
import { deleteUserSessions } from './sessions.js';

const ROLE_IDS = new Set(ROLES.map((role) => role.id));

export function isRole(value) {
  return ROLE_IDS.has(value);
}

export function findById(db, id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id) || null;
}

export function findByLogin(db, login) {
  const value = String(login ?? '').trim();
  if (!value) return null;
  return db.prepare('SELECT * FROM users WHERE login = ?').get(value) || null;
}

export function listUsers(db) {
  return db.prepare(`
    SELECT * FROM users
    ORDER BY CASE role WHEN 'administrator' THEN 0 WHEN 'pracownik' THEN 1 ELSE 2 END, login
  `).all();
}

export function accountState(user, policy, now = Date.now()) {
  if (user.is_blocked) return { key: 'blocked', label: 'Zablokowane' };
  if (user.must_change_password && user.otp_expires_at) {
    if (new Date(user.otp_expires_at).getTime() < now) {
      return { key: 'expired', label: 'Kod wygasł' };
    }
    return { key: 'otp', label: 'Jednorazowe', until: user.otp_expires_at };
  }
  if (passwordChangeReason(user, policy, now) === 'expired') {
    return { key: 'expired', label: 'Hasło wygasło' };
  }
  if (user.must_change_password) return { key: 'otp', label: 'Wymaga zmiany hasła' };
  return { key: 'active', label: 'Aktywne' };
}

function rememberHash(db, userId, passwordHash, limit) {
  const ts = nowIso();
  db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)').run(userId, passwordHash, ts);
  const rows = db.prepare('SELECT id FROM password_history WHERE user_id = ? ORDER BY id DESC').all(userId);
  const extra = rows.slice(limit).map((row) => row.id);
  if (extra.length) {
    db.prepare(`DELETE FROM password_history WHERE id IN (${extra.map(() => '?').join(',')})`).run(...extra);
  }
}

export async function matchesHistory(password, hashes) {
  for (const hash of hashes) {
    if (await verifyPassword(password, hash)) return true;
  }
  return false;
}

export function historyHashes(db, user) {
  const rows = db.prepare('SELECT password_hash FROM password_history WHERE user_id = ?').all(user.id);
  const hashes = rows.map((row) => row.password_hash);
  if (user.password_hash && !hashes.includes(user.password_hash)) hashes.push(user.password_hash);
  return hashes;
}

export async function createUserWithOtp(db, { login, firstName, lastName, role }, policy) {
  const otp = generateOtp();
  const passwordHash = await hashPassword(otp);
  const ts = nowIso();
  const expires = new Date(Date.now() + OTP_TTL_MS).toISOString();
  db.exec('BEGIN');
  try {
    const result = db.prepare(`
      INSERT INTO users (
        login, first_name, last_name, password_hash, role, is_blocked, must_change_password,
        otp_expires_at, password_changed_at, totp_enabled, is_permanent, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, 0, 0, ?, ?)
    `).run(login, firstName, lastName, passwordHash, role, expires, ts, ts, ts);
    const id = Number(result.lastInsertRowid);
    rememberHash(db, id, passwordHash, policy.passwordHistory);
    db.exec('COMMIT');
    return { id, otp, expires };
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export async function assignOneTimePassword(db, user, policy) {
  const otp = generateOtp();
  const passwordHash = await hashPassword(otp);
  const ts = nowIso();
  const expires = new Date(Date.now() + OTP_TTL_MS).toISOString();
  db.exec('BEGIN');
  try {
    db.prepare(`
      UPDATE users
      SET password_hash = ?, must_change_password = 1, otp_expires_at = ?, password_changed_at = ?, updated_at = ?
      WHERE id = ?
    `).run(passwordHash, expires, ts, ts, user.id);
    rememberHash(db, user.id, passwordHash, policy.passwordHistory);
    deleteUserSessions(db, user.id);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  return { otp, expires };
}

export async function storeChosenPassword(db, user, password, policy) {
  const passwordHash = await hashPassword(password);
  const ts = nowIso();
  db.exec('BEGIN');
  try {
    db.prepare(`
      UPDATE users
      SET password_hash = ?, must_change_password = 0, otp_expires_at = NULL, password_changed_at = ?, updated_at = ?
      WHERE id = ?
    `).run(passwordHash, ts, ts, user.id);
    rememberHash(db, user.id, passwordHash, policy.passwordHistory);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function updateUser(db, user, { firstName, lastName, role }) {
  const nextRole = user.is_permanent ? user.role : role;
  db.prepare(`
    UPDATE users SET first_name = ?, last_name = ?, role = ?, updated_at = ? WHERE id = ?
  `).run(firstName, lastName, nextRole, nowIso(), user.id);
}

export function setBlocked(db, user, blocked) {
  if (user.is_permanent && blocked) return false;
  db.prepare('UPDATE users SET is_blocked = ?, updated_at = ? WHERE id = ?').run(blocked ? 1 : 0, nowIso(), user.id);
  if (blocked) deleteUserSessions(db, user.id);
  return true;
}

export function removeUser(db, user) {
  if (user.is_permanent) return false;
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  return true;
}

export function setTotp(db, userId, secret) {
  db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1, updated_at = ? WHERE id = ?').run(secret, nowIso(), userId);
}

export function clearTotp(db, userId) {
  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ? WHERE id = ?').run(nowIso(), userId);
}
