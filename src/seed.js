import { pathToFileURL } from 'node:url';
import { ensureSettings, getSettings, nowIso, openDatabase } from './db.js';
import { hashPassword, OTP_TTL_MS } from './passwords.js';
import { fullName } from './format.js';

export const DEMO_ACCOUNTS = [
  { login: 'admin', firstName: 'Adam', lastName: 'Majewski', role: 'administrator', password: 'Admin#Portal2026', kind: 'password', permanent: true },
  { login: 'jkowalski', firstName: 'Jan', lastName: 'Kowalski', role: 'pracownik', password: 'Kowalski#Praca19', kind: 'password' },
  { login: 'anowak', firstName: 'Anna', lastName: 'Nowak', role: 'pracownik', password: 'Nowak.Pracownik1', kind: 'password' },
  { login: 'mwisniewski', firstName: 'Michał', lastName: 'Wiśniewski', role: 'pracownik', password: '48291573', kind: 'otp' },
  { login: 'kwojcik', firstName: 'Katarzyna', lastName: 'Wójcik', role: 'pracownik', password: 'Wojcik#Zablok1', kind: 'blocked' },
  { login: 'tzielinski', firstName: 'Tomasz', lastName: 'Zieliński', role: 'gosc', password: 'Zielinski.Gosc1', kind: 'password' },
  { login: 'awojcik', firstName: 'Agnieszka', lastName: 'Wójcik', role: 'gosc', password: 'Wojcik-Gosc#2026', kind: 'password' },
  { login: 'pkaczmarek', firstName: 'Piotr', lastName: 'Kaczmarek', role: 'gosc', password: '10293847', kind: 'otp-expired' },
  { login: 'elewandowska', firstName: 'Ewa', lastName: 'Lewandowska', role: 'gosc', password: 'Ewa#Lewand2026', kind: 'password' },
  { login: 'rdabrowski', firstName: 'Rafał', lastName: 'Dąbrowski', role: 'gosc', password: '67584930', kind: 'otp' },
];

export async function resetAndSeed(db) {
  db.exec('DELETE FROM sessions');
  db.exec('DELETE FROM password_history');
  db.exec('DELETE FROM documents');
  db.exec('DELETE FROM announcements');
  db.exec('DELETE FROM audit_events');
  db.exec('DELETE FROM users');
  db.exec('DELETE FROM settings');
  ensureSettings(db);
  await seed(db);
}

export async function seed(db) {
  const existing = Number(db.prepare('SELECT COUNT(*) AS n FROM users').get().n);
  if (existing > 0) return;
  const policy = getSettings(db);
  console.log('Liczenie skrótów Argon2id dla kont startowych...');
  const ready = [];
  for (const account of DEMO_ACCOUNTS) {
    ready.push({ account, passwordHash: await hashPassword(account.password) });
  }

  const ts = nowIso();
  const insertUser = db.prepare(`
    INSERT INTO users (
      login, first_name, last_name, password_hash, role, is_blocked, must_change_password,
      otp_expires_at, password_changed_at, totp_enabled, is_permanent, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
  `);
  const insertHistory = db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)');

  db.exec('BEGIN');
  try {
    const ids = new Map();
    for (const item of ready) {
      const { account, passwordHash } = item;
      const blocked = account.kind === 'blocked' ? 1 : 0;
      const mustChange = account.kind === 'otp' || account.kind === 'otp-expired' ? 1 : 0;
      let expires = null;
      if (account.kind === 'otp') expires = new Date(Date.now() + OTP_TTL_MS).toISOString();
      if (account.kind === 'otp-expired') expires = new Date(Date.now() - OTP_TTL_MS).toISOString();
      const result = insertUser.run(
        account.login,
        account.firstName,
        account.lastName,
        passwordHash,
        account.role,
        blocked,
        mustChange,
        expires,
        ts,
        account.permanent ? 1 : 0,
        ts,
        ts,
      );
      const id = Number(result.lastInsertRowid);
      ids.set(account.login, id);
      insertHistory.run(id, passwordHash, ts);
      const extra = db.prepare('SELECT id FROM password_history WHERE user_id = ? ORDER BY id DESC').all(id).slice(policy.passwordHistory);
      if (extra.length) {
        db.prepare(`DELETE FROM password_history WHERE id IN (${extra.map(() => '?').join(',')})`).run(...extra.map((row) => row.id));
      }
    }

    const byLogin = (login) => ids.get(login);
    const addAnnouncement = db.prepare(`
      INSERT INTO announcements (author_id, author_name, title, body, visibility, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    const addDocument = db.prepare(`
      INSERT INTO documents (author_id, author_name, title, body, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const userRow = (login) => db.prepare('SELECT * FROM users WHERE id = ?').get(byLogin(login));

    const anna = userRow('anowak');
    const adam = userRow('admin');
    const jan = userRow('jkowalski');

    addAnnouncement.run(
      anna.id,
      fullName(anna),
      'Konsultacje w listopadzie',
      'Konsultacje z bezpieczeństwa systemów odbywają się we wtorki, 12:00–13:30, sala 204. Na spotkanie warto przynieść pytanie o własne hasło: jak jest liczone i gdzie leży skrót.',
      'public',
      ts,
      ts,
    );
    addAnnouncement.run(
      adam.id,
      fullName(adam),
      'Planowana przerwa techniczna',
      'W niedzielę w godzinach 2:00–4:00 portal KLUCZ będzie niedostępny. Sesje aktywne w tym czasie wygasną i trzeba będzie zalogować się ponownie.',
      'public',
      ts,
      ts,
    );
    addAnnouncement.run(
      jan.id,
      fullName(jan),
      'Zmiana zasad dostępu do laboratorium',
      'Od poniedziałku dokumenty laboratorium widzą tylko pracownicy i administratorzy. Gość zostaje przy ogłoszeniach ogólnodostępnych. Kodu do szafki laboratoryjnej nie publikujemy w portalu — przekazujemy go na zajęciach.',
      'internal',
      ts,
      ts,
    );
    addDocument.run(
      adam.id,
      fullName(adam),
      'Instrukcja pierwszego logowania',
      'Konto zakłada administrator. Hasło jednorazowe ma 8 cyfr i działa przez godzinę. Przy pierwszym wejściu portal wymaga własnego hasła, wpisanego dwa razy. Gdy polityka entropii jest włączona, próg wynosi 60 bitów.',
      ts,
      ts,
    );
    addDocument.run(
      anna.id,
      fullName(anna),
      'Zasady pracy z danymi laboratorium',
      'Wyników ćwiczeń nie wklejamy do ogłoszeń ogólnodostępnych. Ten dział czyta pracownik i administrator. Wejście gościa kończy się odpowiedzią 403, także wtedy, gdy odnośnik zniknął z menu.',
      ts,
      ts,
    );
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const db = openDatabase();
  await resetAndSeed(db);
  console.log('Baza zresetowana. Hasła jednorazowe są ważne przez godzinę od tego uruchomienia.');
}
