import { nowIso } from './db.js';

export const ACTION_LABELS = {
  login_success: 'Logowanie',
  login_failure: 'Nieudane logowanie',
  logout: 'Wylogowanie',
  logout_idle: 'Wylogowanie po bezczynności',
  logout_absolute: 'Wylogowanie po czasie maksymalnym',
  password_change: 'Zmiana hasła',
  user_create: 'Utworzenie konta',
  user_update: 'Edycja konta',
  user_block: 'Blokada konta',
  user_unblock: 'Odblokowanie konta',
  user_delete: 'Usunięcie konta',
  password_reset: 'Nadanie hasła jednorazowego',
  settings_change: 'Zmiana ustawień',
  totp_enable: 'Włączenie TOTP',
  totp_disable: 'Wyłączenie TOTP',
  totp_failure: 'Nieudany kod TOTP',
  access_denied: 'Odmowa dostępu',
};

export function recordAudit(db, { req, action, target = null, success = true, detail = null, actor = null }) {
  const user = actor === undefined ? null : actor || req?.user || null;
  db.prepare(`
    INSERT INTO audit_events (created_at, actor_id, actor_login, action, target, ip, success, detail)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    nowIso(),
    user?.id ?? null,
    user?.login ?? null,
    action,
    target,
    req?.ip ?? null,
    success ? 1 : 0,
    detail,
  );
}

export function listAudit(db, limit = 200) {
  return db.prepare(`
    SELECT * FROM audit_events
    ORDER BY id DESC
    LIMIT ?
  `).all(limit);
}
