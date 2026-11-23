import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { rootDir } from './db.js';

export const LOG_PATH = path.join(rootDir, 'data', 'security-log.json');
export const MAILBOX_DIR = path.join(rootDir, 'data', 'mailbox');

export const ACTION_LABELS = {
  login_success: 'Logowanie',
  login_failure: 'Nieudane logowanie',
  logout: 'Wylogowanie',
  logout_idle: 'Wylogowanie po bezczynności',
  logout_absolute: 'Wylogowanie po czasie maksymalnym',
  password_change: 'Zmiana hasła',
  password_change_failure: 'Nieudana zmiana hasła',
  user_create: 'Utworzenie konta',
  user_update: 'Edycja konta / roli',
  user_block: 'Blokada konta',
  user_unblock: 'Odblokowanie konta',
  user_delete: 'Usunięcie konta',
  password_reset: 'Nadanie hasła jednorazowego',
  settings_change: 'Zmiana ustawień',
  totp_enable: 'Włączenie TOTP',
  totp_disable: 'Wyłączenie TOTP',
  totp_failure: 'Nieudany kod TOTP',
  access_denied: 'Odmowa dostępu',
  canary_alert: 'Alert Canarytoken',
  honeypot_hit: 'Pułapka honeypot',
  captcha_failure: 'Odrzucona CAPTCHA',
  account_lockout: 'Blokada konta po próbach',
  ip_lockout: 'Blokada adresu IP',
  security_alert: 'Alert bezpieczeństwa',
  log_export: 'Eksport dziennika',
  log_verify: 'Weryfikacja integralności dziennika',
  canary_webhook: 'Webhook Canarytokens',
};

function ensureDirs() {
  fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
  fs.mkdirSync(MAILBOX_DIR, { recursive: true });
  if (!fs.existsSync(LOG_PATH)) {
    fs.writeFileSync(LOG_PATH, `${JSON.stringify({ version: 1, algorithm: 'SHA3-256', events: [] }, null, 2)}\n`, 'utf8');
  }
}

export function sanitizeLogText(value, max = 240) {
  return String(value ?? '')
    .replace(/[\r\n\t\0]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

export function eventPayload(event) {
  return [
    event.id,
    event.created_at,
    event.actor_login || '',
    event.ip || '',
    event.action,
    event.target || '',
    event.description || '',
    event.success ? '1' : '0',
  ].join('|');
}

export function hashEvent(event) {
  return createHash('sha3-256').update(eventPayload(event), 'utf8').digest('hex');
}

function readStore() {
  ensureDirs();
  const raw = fs.readFileSync(LOG_PATH, 'utf8');
  try {
    const data = JSON.parse(raw);
    if (!Array.isArray(data.events)) data.events = [];
    return data;
  } catch {
    return { version: 1, algorithm: 'SHA3-256', events: [] };
  }
}

function writeStore(data) {
  ensureDirs();
  const tmp = `${LOG_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, LOG_PATH);
}

export function listSecurityEvents({ actor = '', action = '', from = '', to = '', limit = 500 } = {}) {
  const events = readStore().events.slice().reverse();
  return events.filter((event) => {
    if (actor && String(event.actor_login || '').toLowerCase() !== actor.toLowerCase()) return false;
    if (action && event.action !== action) return false;
    if (from && event.created_at < from) return false;
    if (to && event.created_at > to) return false;
    return true;
  }).slice(0, limit);
}

export function recordSecurityEvent({
  req = null,
  action,
  target = null,
  success = true,
  detail = null,
  actor = null,
  description = null,
}) {
  ensureDirs();
  const store = readStore();
  const user = actor === undefined ? null : actor || req?.user || null;
  const id = store.events.length ? Number(store.events[store.events.length - 1].id) + 1 : 1;
  const entry = {
    id,
    created_at: new Date().toISOString(), // UTC
    actor_login: sanitizeLogText(user?.login || null, 64) || null,
    ip: sanitizeLogText(req?.ip || null, 64) || null,
    action: sanitizeLogText(action, 64),
    target: sanitizeLogText(target, 120) || null,
    description: sanitizeLogText(description || detail || ACTION_LABELS[action] || action, 240),
    success: Boolean(success),
  };
  entry.hash = hashEvent(entry);
  store.events.push(entry);
  writeStore(store);

  // Mirror to SQLite for compatibility with older views / canary helpers that expect DB rows.
  try {
    if (req?.app?.locals?.db) {
      // no-op; routes will pass db separately when needed
    }
  } catch {
    /* ignore */
  }

  evaluateAlerts(entry, store.events);
  return entry;
}

/** Compatibility wrapper used across the app. */
export function recordAudit(db, opts) {
  const entry = recordSecurityEvent(opts);
  try {
    db?.prepare?.(`
      INSERT INTO audit_events (created_at, actor_id, actor_login, action, target, ip, success, detail)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.created_at,
      opts.actor?.id ?? opts.req?.user?.id ?? null,
      entry.actor_login,
      entry.action,
      entry.target,
      entry.ip,
      entry.success ? 1 : 0,
      entry.description,
    );
  } catch {
    /* SQLite mirror optional */
  }
  return entry;
}

export function listAudit(_db, limit = 200) {
  return listSecurityEvents({ limit }).map((event) => ({
    ...event,
    detail: event.description,
  }));
}

export function verifyIntegrity() {
  const store = readStore();
  const issues = [];
  let expectedId = 1;
  for (const event of store.events) {
    if (Number(event.id) !== expectedId) {
      issues.push({
        id: event.id,
        kind: 'sequence',
        message: `Oczekiwano id=${expectedId}, jest id=${event.id} (możliwe usunięcie wpisu).`,
      });
    }
    expectedId = Number(event.id) + 1;
    const expected = hashEvent(event);
    if (!event.hash || event.hash !== expected) {
      issues.push({
        id: event.id,
        kind: 'hash',
        message: `Niezgodny SHA3-256 wpisu #${event.id}.`,
      });
    }
  }
  return {
    ok: issues.length === 0,
    total: store.events.length,
    algorithm: 'SHA3-256',
    path: LOG_PATH,
    issues,
  };
}

export function exportEvents(filter = {}) {
  const events = listSecurityEvents({ ...filter, limit: 10000 });
  return `${JSON.stringify({ exported_at: new Date().toISOString(), algorithm: 'SHA3-256', events }, null, 2)}\n`;
}

function recentFailures(events, login, windowMs = 5 * 60 * 1000) {
  const now = Date.now();
  return events.filter((event) => (
    event.action === 'login_failure'
    && event.target === login
    && now - new Date(event.created_at).getTime() <= windowMs
  ));
}

const alertCooldown = new Map();

function shouldSend(key, cooldownMs = 60_000) {
  const last = alertCooldown.get(key) || 0;
  if (Date.now() - last < cooldownMs) return false;
  alertCooldown.set(key, Date.now());
  return true;
}

function evaluateAlerts(entry, allEvents) {
  // Reguła 1: ≥5 nieudanych logowań na jedno konto w 5 minut
  if (entry.action === 'login_failure' && entry.target) {
    const fails = recentFailures(allEvents, entry.target);
    if (fails.length >= 5 && shouldSend(`fail:${entry.target}`)) {
      emitAlert({
        rule: 'failed_logins_5_in_5min',
        subject: `[KLUCZ] Alert: 5+ nieudanych logowań (${entry.target})`,
        body: `W ciągu 5 minut odnotowano ${fails.length} nieudanych logowań na konto ${entry.target}. IP ostatniej próby: ${entry.ip || '?'}.`,
        related: entry,
      });
    }
  }

  // Reguła wariantu 8: każda próba logowania na konto-pułapkę
  if (
    (entry.action === 'canary_alert' && entry.target === 'honeypot_account')
    || (entry.action === 'login_failure' && entry.target === 'svc_backup')
    || (entry.description || '').includes('svc_backup')
  ) {
    if (shouldSend('canary:svc_backup', 10_000)) {
      emitAlert({
        rule: 'honeypot_account_login',
        subject: '[KLUCZ] Alert: próba logowania na konto-pułapkę svc_backup',
        body: `Wykryto użycie konta-pułapki. Czas UTC: ${entry.created_at}. IP: ${entry.ip || '?'}. Opis: ${entry.description}`,
        related: entry,
      });
    }
  }
}

export function emitAlert({ rule, subject, body, related = null }) {
  ensureDirs();
  const id = randomBytes(6).toString('hex');
  const created = new Date().toISOString();
  const mail = [
    `From: klucz-siem@localhost`,
    `To: admin@klucz.local`,
    `Date: ${created}`,
    `Subject: ${subject}`,
    `X-KLUCZ-Rule: ${rule}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    body,
    ``,
    related ? `Powiązany wpis dziennika: #${related.id} (${related.action})` : '',
  ].join('\r\n');
  const file = path.join(MAILBOX_DIR, `${created.replace(/[:.]/g, '-')}-${id}.eml`);
  fs.writeFileSync(file, mail, 'utf8');

  // Alert also enters the security log (without recursion on same rule spam beyond cooldown)
  const store = readStore();
  const idNum = store.events.length ? Number(store.events[store.events.length - 1].id) + 1 : 1;
  const alertEntry = {
    id: idNum,
    created_at: created,
    actor_login: 'system',
    ip: related?.ip || null,
    action: 'security_alert',
    target: rule,
    description: sanitizeLogText(`${subject} | ${body}`, 240),
    success: true,
  };
  alertEntry.hash = hashEvent(alertEntry);
  store.events.push(alertEntry);
  writeStore(store);
  return { file, entry: alertEntry };
}

export function listMailbox(limit = 50) {
  ensureDirs();
  return fs.readdirSync(MAILBOX_DIR)
    .filter((name) => name.endsWith('.eml'))
    .sort()
    .reverse()
    .slice(0, limit)
    .map((name) => {
      const full = path.join(MAILBOX_DIR, name);
      const raw = fs.readFileSync(full, 'utf8');
      const subject = raw.match(/^Subject: (.*)$/m)?.[1] || name;
      const date = raw.match(/^Date: (.*)$/m)?.[1] || '';
      return { name, subject, date, preview: raw.slice(0, 400) };
    });
}

export function getLogPath() {
  ensureDirs();
  return LOG_PATH;
}
