import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const rootDir = path.join(__dirname, '..');
export const dbPath = path.join(rootDir, 'data', 'klucz.db');

export function nowIso() {
  return new Date().toISOString();
}

export function openDatabase(file = dbPath) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA busy_timeout = 4000');
  migrate(db);
  ensureSettings(db);
  return db;
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      login TEXT NOT NULL UNIQUE COLLATE NOCASE,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('administrator', 'pracownik', 'gosc')),
      is_blocked INTEGER NOT NULL DEFAULT 0,
      must_change_password INTEGER NOT NULL DEFAULT 0,
      otp_expires_at TEXT,
      password_changed_at TEXT NOT NULL,
      totp_secret TEXT,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      is_permanent INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS password_history (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      stage TEXT NOT NULL,
      change_reason TEXT,
      csrf_secret TEXT NOT NULL,
      pending_totp TEXT,
      flash TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      last_activity_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY,
      author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      author_name TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY,
      author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      author_name TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY,
      created_at TEXT NOT NULL,
      actor_id INTEGER,
      actor_login TEXT,
      action TEXT NOT NULL,
      target TEXT,
      ip TEXT,
      success INTEGER NOT NULL,
      detail TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_history_user ON password_history(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
  `);
}

export const DEFAULT_SETTINGS = {
  min_password_length: '12',
  entropy_required: '0',
  min_entropy_bits: '60',
  password_max_age_days: '90',
  session_idle_minutes: '15',
  password_history: '5',
};

export function ensureSettings(db) {
  const insert = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING');
  for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) insert.run(key, value);
}

export function getSettings(db) {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const map = Object.fromEntries(rows.map((row) => [row.key, row.value]));
  return {
    minPasswordLength: Number(map.min_password_length ?? DEFAULT_SETTINGS.min_password_length),
    entropyRequired: map.entropy_required === '1',
    minEntropyBits: Number(map.min_entropy_bits ?? DEFAULT_SETTINGS.min_entropy_bits),
    passwordMaxAgeDays: Number(map.password_max_age_days ?? DEFAULT_SETTINGS.password_max_age_days),
    sessionIdleMinutes: Number(map.session_idle_minutes ?? DEFAULT_SETTINGS.session_idle_minutes),
    passwordHistory: Number(map.password_history ?? DEFAULT_SETTINGS.password_history),
  };
}

export function saveEditableSettings(db, { entropyRequired, passwordMaxAgeDays, sessionIdleMinutes }) {
  const update = db.prepare('UPDATE settings SET value = ? WHERE key = ?');
  update.run(entropyRequired ? '1' : '0', 'entropy_required');
  update.run(String(passwordMaxAgeDays), 'password_max_age_days');
  update.run(String(sessionIdleMinutes), 'session_idle_minutes');
}
