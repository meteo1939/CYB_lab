import { recordAudit, listAudit } from './audit.js';
import { nowIso, saveEditableSettings } from './db.js';
import { cleanText, fullName, intId } from './format.js';
import { MSG } from './messages.js';
import { can, canEditOwn, PERMISSIONS, roleLabel } from './permissions.js';
import { describeHash, evaluatePassword, passwordChangeReason, verifyPassword } from './passwords.js';
import { authenticate } from './auth.js';
import {
  createSession,
  deleteSession,
  deleteUserSessions,
  incrementAttempts,
  setFlash,
  setPendingTotp,
} from './sessions.js';
import { createTotpSecret, groupSecret, totpQrDataUrl, verifyTotp } from './totp.js';
import {
  accountState,
  assignOneTimePassword,
  clearTotp,
  createUserWithOtp,
  findById,
  historyHashes,
  isRole,
  listUsers,
  matchesHistory,
  removeUser,
  setBlocked,
  setTotp,
  storeChosenPassword,
  updateUser,
} from './users.js';

const loginAttempts = new Map();

function tooManyLogins(ip) {
  const row = loginAttempts.get(ip);
  if (!row) return false;
  if (Date.now() > row.reset) {
    loginAttempts.delete(ip);
    return false;
  }
  return row.count >= 8;
}

function markLoginFailure(ip) {
  const row = loginAttempts.get(ip);
  if (!row || Date.now() > row.reset) loginAttempts.set(ip, { count: 1, reset: Date.now() + 10 * 60 * 1000 });
  else row.count += 1;
}

function route(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function permissionLabel(id) {
  return PERMISSIONS.find((item) => item.id === id)?.label || id;
}

export function registerRoutes(app, { db, writeSid, clearSid }) {
  function forbid(req, res, permission) {
    recordAudit(db, {
      req,
      action: 'access_denied',
      success: false,
      target: req.path,
      detail: permission,
    });
    return res.status(403).render('error', {
      title: 'Brak uprawnień',
      status: 403,
      message: `Żądanie ${req.method} ${req.path} zostało odrzucone. Serwer sprawdził uprawnienie „${permissionLabel(permission)}”. Ukrycie przycisku w interfejsie nie zastępuje tej kontroli.`,
    });
  }

  function notFound(res) {
    return res.status(404).render('error', {
      title: 'Nie znaleziono',
      status: 404,
      message: 'Ten zasób nie istnieje.',
    });
  }

  function gate(req, res) {
    if (!req.user) {
      res.redirect('/login');
      return false;
    }
    if (req.session?.stage === 'totp') {
      res.redirect('/logowanie/kod');
      return false;
    }
    if (req.session?.stage === 'password_change') {
      res.redirect('/haslo/zmiana');
      return false;
    }
    if (req.session?.stage !== 'full') {
      res.redirect('/login');
      return false;
    }
    return true;
  }

  function allow(permission) {
    return (req, res, next) => {
      if (!gate(req, res)) return undefined;
      if (!can(req.user.role, permission)) return forbid(req, res, permission);
      return next();
    };
  }

  function requireFull(req, res, next) {
    if (!gate(req, res)) return undefined;
    return next();
  }

  function startSession(res, oldId, fields) {
    const session = createSession(db, fields);
    if (oldId) deleteSession(db, oldId);
    writeSid(res, session.id);
    return session;
  }

  async function applyPasswordChange(user, policy, body, requireCurrent) {
    const nextPassword = String(body.password ?? '');
    const confirmation = String(body.password_confirmation ?? '');
    const currentPassword = String(body.current_password ?? '');
    const errors = [];
    if (nextPassword !== confirmation) errors.push('Nowe hasła nie są identyczne.');
    let currentOk = true;
    if (requireCurrent) {
      currentOk = await verifyPassword(currentPassword, user.password_hash);
      if (!currentOk) errors.push('Dotychczasowe hasło jest nieprawidłowe.');
    }
    const evaluated = evaluatePassword(nextPassword, policy);
    errors.push(...evaluated.errors);
    if (currentOk && evaluated.ok && nextPassword === confirmation) {
      if (await matchesHistory(nextPassword, historyHashes(db, user))) {
        errors.push('Nowe hasło musi różnić się od poprzednich haseł.');
      }
    }
    if (errors.length) return { ok: false, errors };
    await storeChosenPassword(db, user, nextPassword, policy);
    return { ok: true };
  }

  function finishPasswordChange(req, res) {
    deleteUserSessions(db, req.user.id);
    const session = createSession(db, { userId: req.user.id, stage: 'full' });
    setFlash(db, session.id, { message: 'Hasło zostało zmienione.', tone: 'ok' });
    writeSid(res, session.id);
    recordAudit(db, { req, action: 'password_change', target: req.user.login, actor: req.user });
    res.redirect('/');
  }

  app.get('/login', (req, res) => {
    if (req.user && req.session.stage === 'full') return res.redirect('/');
    if (req.user && req.session.stage === 'totp') return res.redirect('/logowanie/kod');
    if (req.user && req.session.stage === 'password_change') return res.redirect('/haslo/zmiana');
    const notices = [];
    if (req.query.wygasla === 'bezczynnosc') notices.push(MSG.idle);
    if (req.query.wygasla === 'czas') notices.push(MSG.absolute);
    if (req.query.zablokowane === '1') notices.push(MSG.blocked);
    if (req.query.koniec === '1') notices.push(MSG.loggedOut);
    if (req.query.kod === '1') notices.push(MSG.tooManyCodes);
    res.render('login', { title: 'Logowanie', notices, error: null, login: '' });
  });

  app.post('/login', route(async (req, res) => {
    const login = String(req.body.login ?? '').trim();
    const password = String(req.body.password ?? '');
    if (tooManyLogins(req.ip)) {
      return res.status(429).render('login', { title: 'Logowanie', notices: [], error: MSG.tooMany, login });
    }
    if (!login || !password) {
      return res.status(400).render('login', { title: 'Logowanie', notices: [], error: MSG.emptyLogin, login });
    }
    const result = await authenticate(db, login, password);
    if (result.status === 'invalid') {
      markLoginFailure(req.ip);
      recordAudit(db, { req, action: 'login_failure', success: false, detail: login.slice(0, 80) });
      return res.status(200).render('login', { title: 'Logowanie', notices: [], error: MSG.badLogin, login });
    }
    if (result.status === 'otp_expired') {
      recordAudit(db, { req, action: 'login_failure', success: false, detail: 'wygasłe hasło jednorazowe', actor: result.user });
      return res.status(200).render('login', { title: 'Logowanie', notices: [], error: MSG.otpExpired, login });
    }
    if (result.status === 'blocked') {
      recordAudit(db, { req, action: 'login_failure', success: false, detail: 'konto zablokowane', actor: result.user });
      return res.status(200).render('login', { title: 'Logowanie', notices: [], error: MSG.blocked, login });
    }

    loginAttempts.delete(req.ip);
    const reason = passwordChangeReason(result.user, req.policy);
    let stage = 'full';
    let changeReason = null;
    if (result.user.totp_enabled) stage = 'totp';
    else if (reason) {
      stage = 'password_change';
      changeReason = reason;
    }
    startSession(res, req.session?.id, { userId: result.user.id, stage, changeReason });
    recordAudit(db, { req, action: 'login_success', actor: result.user, target: result.user.login });
    if (stage === 'totp') return res.redirect('/logowanie/kod');
    if (stage === 'password_change') return res.redirect('/haslo/zmiana');
    return res.redirect('/');
  }));

  app.get('/logowanie/kod', (req, res) => {
    if (!req.user || req.session.stage !== 'totp') return res.redirect('/login');
    res.render('totp', { title: 'Kod uwierzytelniający', error: null });
  });

  app.post('/logowanie/kod', route(async (req, res) => {
    if (!req.user || req.session.stage !== 'totp') return res.redirect('/login');
    if (!verifyTotp(req.user.totp_secret, req.body.code)) {
      const updated = incrementAttempts(db, req.session.id);
      recordAudit(db, { req, action: 'totp_failure', success: false, target: req.user.login });
      if (updated.attempt_count >= 5) {
        deleteSession(db, req.session.id);
        clearSid(res);
        return res.redirect('/login?kod=1');
      }
      return res.status(400).render('totp', { title: 'Kod uwierzytelniający', error: MSG.badCode });
    }
    const reason = passwordChangeReason(req.user, req.policy);
    startSession(res, req.session.id, {
      userId: req.user.id,
      stage: reason ? 'password_change' : 'full',
      changeReason: reason,
    });
    return res.redirect(reason ? '/haslo/zmiana' : '/');
  }));

  app.get('/haslo/zmiana', (req, res) => {
    if (!req.user) return res.redirect('/login');
    if (req.session.stage === 'totp') return res.redirect('/logowanie/kod');
    if (req.session.stage !== 'password_change') return res.redirect('/profil');
    res.render('password', {
      title: 'Zmiana hasła',
      reason: req.session.change_reason || 'first',
      errors: [],
    });
  });

  app.post('/haslo/zmiana', route(async (req, res) => {
    if (!req.user || req.session.stage !== 'password_change') return res.redirect('/login');
    const reason = req.session.change_reason || 'first';
    const result = await applyPasswordChange(req.user, req.policy, req.body, reason !== 'first');
    if (!result.ok) {
      return res.status(400).render('password', { title: 'Zmiana hasła', reason, errors: result.errors });
    }
    return finishPasswordChange(req, res);
  }));

  app.post('/wyloguj', (req, res) => {
    if (req.user) recordAudit(db, { req, action: 'logout', target: req.user.login });
    if (req.session?.id) deleteSession(db, req.session.id);
    clearSid(res);
    res.redirect('/login?koniec=1');
  });

  app.get('/', requireFull, (req, res) => {
    const internal = can(req.user.role, 'announcements.read_internal');
    const announcements = internal
      ? db.prepare('SELECT * FROM announcements ORDER BY id DESC').all()
      : db.prepare("SELECT * FROM announcements WHERE visibility = 'public' ORDER BY id DESC").all();
    res.render('dashboard', { title: 'Pulpit', announcements });
  });

  app.get('/uprawnienia', requireFull, (req, res) => {
    res.render('permissions', { title: 'Uprawnienia' });
  });

  app.get('/ogloszenia/nowe', allow('announcements.create'), (req, res) => {
    res.render('announcement-form', {
      title: 'Nowe ogłoszenie',
      action: '/ogloszenia',
      errors: [],
      form: { title: '', body: '', visibility: 'public' },
      heading: 'Nowe ogłoszenie',
    });
  });

  app.post('/ogloszenia', allow('announcements.create'), route(async (req, res) => {
    const form = readAnnouncement(req);
    const errors = validateAnnouncement(form);
    if (errors.length) {
      return res.status(400).render('announcement-form', {
        title: 'Nowe ogłoszenie',
        action: '/ogloszenia',
        errors,
        form,
        heading: 'Nowe ogłoszenie',
      });
    }
    const ts = nowIso();
    db.prepare(`
      INSERT INTO announcements (author_id, author_name, title, body, visibility, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(req.user.id, fullName(req.user), form.title, form.body, form.visibility, ts, ts);
    setFlash(db, req.session.id, { message: 'Ogłoszenie zostało dodane.', tone: 'ok' });
    res.redirect('/');
  }));

  app.get('/ogloszenia/:id/edytuj', requireFull, (req, res) => {
    const row = loadAnnouncement(req.params.id);
    if (!row) return notFound(res);
    const readable = row.visibility === 'internal'
      ? can(req.user.role, 'announcements.read_internal')
      : can(req.user.role, 'announcements.read_public');
    if (!readable) return forbid(req, res, 'announcements.read_internal');
    if (!canEditOwn(req.user, row, 'announcements.update_own', 'announcements.update_any')) {
      return forbid(req, res, 'announcements.update_own');
    }
    res.render('announcement-form', {
      title: 'Edycja ogłoszenia',
      action: `/ogloszenia/${row.id}`,
      errors: [],
      form: row,
      heading: 'Edycja ogłoszenia',
      remove: canEditOwn(req.user, row, 'announcements.delete_own', 'announcements.delete_any'),
    });
  });

  app.post('/ogloszenia/:id', requireFull, route(async (req, res) => {
    const row = loadAnnouncement(req.params.id);
    if (!row) return notFound(res);
    if (!canEditOwn(req.user, row, 'announcements.update_own', 'announcements.update_any')) {
      return forbid(req, res, 'announcements.update_own');
    }
    const form = readAnnouncement(req);
    const errors = validateAnnouncement(form);
    if (errors.length) {
      return res.status(400).render('announcement-form', {
        title: 'Edycja ogłoszenia',
        action: `/ogloszenia/${row.id}`,
        errors,
        form,
        heading: 'Edycja ogłoszenia',
        remove: canEditOwn(req.user, row, 'announcements.delete_own', 'announcements.delete_any'),
      });
    }
    db.prepare(`
      UPDATE announcements SET title = ?, body = ?, visibility = ?, updated_at = ? WHERE id = ?
    `).run(form.title, form.body, form.visibility, nowIso(), row.id);
    setFlash(db, req.session.id, { message: 'Ogłoszenie zostało zapisane.', tone: 'ok' });
    res.redirect('/');
  }));

  app.post('/ogloszenia/:id/usun', requireFull, (req, res) => {
    const row = loadAnnouncement(req.params.id);
    if (!row) return notFound(res);
    if (!canEditOwn(req.user, row, 'announcements.delete_own', 'announcements.delete_any')) {
      return forbid(req, res, 'announcements.delete_own');
    }
    db.prepare('DELETE FROM announcements WHERE id = ?').run(row.id);
    setFlash(db, req.session.id, { message: 'Ogłoszenie zostało usunięte.', tone: 'ok' });
    res.redirect('/');
  });

  app.get('/dokumenty', allow('documents.read'), (req, res) => {
    const documents = db.prepare('SELECT * FROM documents ORDER BY id DESC').all();
    res.render('documents', { title: 'Dokumenty', documents });
  });

  app.get('/dokumenty/nowe', allow('documents.create'), (req, res) => {
    res.render('document-form', {
      title: 'Nowy dokument',
      action: '/dokumenty',
      errors: [],
      form: { title: '', body: '' },
      heading: 'Nowy dokument',
    });
  });

  app.post('/dokumenty', allow('documents.create'), (req, res) => {
    const form = { title: cleanText(req.body.title, 120) || '', body: cleanText(req.body.body, 5000) || '' };
    const errors = validateDocument(req.body);
    if (errors.length) {
      return res.status(400).render('document-form', {
        title: 'Nowy dokument',
        action: '/dokumenty',
        errors,
        form: { title: String(req.body.title ?? ''), body: String(req.body.body ?? '') },
        heading: 'Nowy dokument',
      });
    }
    const ts = nowIso();
    db.prepare(`
      INSERT INTO documents (author_id, author_name, title, body, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(req.user.id, fullName(req.user), form.title, form.body, ts, ts);
    setFlash(db, req.session.id, { message: 'Dokument został dodany.', tone: 'ok' });
    res.redirect('/dokumenty');
  });

  app.get('/dokumenty/:id/edytuj', allow('documents.read'), (req, res) => {
    const row = loadDocument(req.params.id);
    if (!row) return notFound(res);
    if (!canEditOwn(req.user, row, 'documents.update_own', 'documents.update_any')) {
      return forbid(req, res, 'documents.update_own');
    }
    res.render('document-form', {
      title: 'Edycja dokumentu',
      action: `/dokumenty/${row.id}`,
      errors: [],
      form: row,
      heading: 'Edycja dokumentu',
      remove: canEditOwn(req.user, row, 'documents.delete_own', 'documents.delete_any'),
    });
  });

  app.post('/dokumenty/:id', allow('documents.read'), (req, res) => {
    const row = loadDocument(req.params.id);
    if (!row) return notFound(res);
    if (!canEditOwn(req.user, row, 'documents.update_own', 'documents.update_any')) {
      return forbid(req, res, 'documents.update_own');
    }
    const errors = validateDocument(req.body);
    const stored = { title: cleanText(req.body.title, 120), body: cleanText(req.body.body, 5000) };
    if (errors.length) {
      return res.status(400).render('document-form', {
        title: 'Edycja dokumentu',
        action: `/dokumenty/${row.id}`,
        errors,
        form: { title: String(req.body.title ?? ''), body: String(req.body.body ?? '') },
        heading: 'Edycja dokumentu',
        remove: canEditOwn(req.user, row, 'documents.delete_own', 'documents.delete_any'),
      });
    }
    db.prepare('UPDATE documents SET title = ?, body = ?, updated_at = ? WHERE id = ?')
      .run(stored.title, stored.body, nowIso(), row.id);
    setFlash(db, req.session.id, { message: 'Dokument został zapisany.', tone: 'ok' });
    res.redirect('/dokumenty');
  });

  app.post('/dokumenty/:id/usun', allow('documents.read'), (req, res) => {
    const row = loadDocument(req.params.id);
    if (!row) return notFound(res);
    if (!canEditOwn(req.user, row, 'documents.delete_own', 'documents.delete_any')) {
      return forbid(req, res, 'documents.delete_own');
    }
    db.prepare('DELETE FROM documents WHERE id = ?').run(row.id);
    setFlash(db, req.session.id, { message: 'Dokument został usunięty.', tone: 'ok' });
    res.redirect('/dokumenty');
  });

  app.get('/profil', requireFull, route(async (req, res) => {
    res.render('profile', await profileView(req, { errors: [], totpError: null }));
  }));

  app.post('/profil/haslo', requireFull, route(async (req, res) => {
    const result = await applyPasswordChange(req.user, req.policy, req.body, true);
    if (!result.ok) {
      return res.status(400).render('profile', await profileView(req, { errors: result.errors, totpError: null }));
    }
    return finishPasswordChange(req, res);
  }));

  app.post('/profil/totp/start', requireFull, (req, res) => {
    if (req.user.totp_enabled) return res.redirect('/profil');
    setPendingTotp(db, req.session.id, createTotpSecret());
    res.redirect('/profil');
  });

  app.post('/profil/totp/anuluj', requireFull, (req, res) => {
    setPendingTotp(db, req.session.id, null);
    res.redirect('/profil');
  });

  app.post('/profil/totp/potwierdz', requireFull, route(async (req, res) => {
    const secret = req.session.pending_totp;
    if (!secret) return res.redirect('/profil');
    if (!verifyTotp(secret, req.body.code)) {
      return res.status(400).render('profile', await profileView(req, {
        errors: [],
        totpError: MSG.badCode,
      }));
    }
    setTotp(db, req.user.id, secret);
    setPendingTotp(db, req.session.id, null);
    recordAudit(db, { req, action: 'totp_enable', target: req.user.login });
    setFlash(db, req.session.id, { message: 'Uwierzytelnianie dwuskładnikowe jest włączone.', tone: 'ok' });
    res.redirect('/profil');
  }));

  app.post('/profil/totp/wylacz', requireFull, route(async (req, res) => {
    if (!req.user.totp_enabled) return res.redirect('/profil');
    const passwordOk = await verifyPassword(String(req.body.current_password ?? ''), req.user.password_hash);
    const codeOk = verifyTotp(req.user.totp_secret, req.body.code);
    const totpError = !passwordOk
      ? 'Dotychczasowe hasło jest nieprawidłowe.'
      : !codeOk
        ? MSG.badCode
        : null;
    if (totpError) {
      return res.status(400).render('profile', await profileView(req, { errors: [], totpError }));
    }
    clearTotp(db, req.user.id);
    recordAudit(db, { req, action: 'totp_disable', target: req.user.login });
    setFlash(db, req.session.id, { message: 'Uwierzytelnianie dwuskładnikowe zostało wyłączone.', tone: 'ok' });
    res.redirect('/profil');
  }));

  app.get('/admin/uzytkownicy', allow('users.read'), (req, res) => {
    const users = listUsers(db).map((user) => ({ ...user, state: accountState(user, req.policy) }));
    res.render('users', { title: 'Użytkownicy', users });
  });

  app.get('/admin/uzytkownicy/nowy', allow('users.create'), (req, res) => {
    res.render('user-form', {
      title: 'Nowe konto',
      errors: [],
      form: { login: '', first_name: '', last_name: '', role: 'gosc' },
    });
  });

  app.post('/admin/uzytkownicy', allow('users.create'), route(async (req, res) => {
    const form = readUserForm(req);
    const errors = validateUserForm(form);
    if (errors.length) {
      return res.status(400).render('user-form', { title: 'Nowe konto', errors, form });
    }
    try {
      const created = await createUserWithOtp(db, {
        login: form.login,
        firstName: form.first_name,
        lastName: form.last_name,
        role: form.role,
      }, req.policy);
      recordAudit(db, { req, action: 'user_create', target: form.login });
      setFlash(db, req.session.id, {
        type: 'otp',
        login: form.login,
        name: `${form.first_name} ${form.last_name}`,
        otp: created.otp,
        expiresAt: created.expires,
        mode: 'create',
      });
      return res.redirect('/admin/haslo-jednorazowe');
    } catch (error) {
      if (!String(error.message).includes('UNIQUE')) throw error;
      errors.push('Login jest już zajęty.');
      return res.status(400).render('user-form', { title: 'Nowe konto', errors, form });
    }
  }));

  app.get('/admin/haslo-jednorazowe', allow('users.create'), (req, res) => {
    const otp = req.flash?.type === 'otp' ? req.flash : null;
    res.render('otp', { title: 'Hasło jednorazowe', otp });
  });

  app.get('/admin/uzytkownicy/:id', allow('users.read'), (req, res) => {
    const account = findAccount(req.params.id);
    if (!account) return notFound(res);
    res.render('user-edit', {
      title: account.login,
      account,
      errors: [],
      hashInfo: describeHash(account.password_hash),
      state: accountState(account, req.policy),
    });
  });

  app.post('/admin/uzytkownicy/:id', allow('users.update'), route(async (req, res) => {
    const account = findAccount(req.params.id);
    if (!account) return notFound(res);
    const firstName = cleanText(req.body.first_name, 60);
    const lastName = cleanText(req.body.last_name, 60);
    const role = account.is_permanent ? account.role : String(req.body.role ?? '');
    const errors = [];
    if (!firstName) errors.push('Podaj imię (do 60 znaków).');
    if (!lastName) errors.push('Podaj nazwisko (do 60 znaków).');
    if (!account.is_permanent && !isRole(role)) errors.push('Wybierz rolę.');
    if (errors.length) {
      return res.status(400).render('user-edit', {
        title: account.login,
        account: { ...account, first_name: String(req.body.first_name ?? ''), last_name: String(req.body.last_name ?? ''), role },
        errors,
        hashInfo: describeHash(account.password_hash),
        state: accountState(account, req.policy),
      });
    }
    updateUser(db, account, { firstName, lastName, role });
    recordAudit(db, { req, action: 'user_update', target: account.login, detail: roleLabel(role) });
    setFlash(db, req.session.id, { message: 'Dane konta zostały zapisane.', tone: 'ok' });
    res.redirect(`/admin/uzytkownicy/${account.id}`);
  }));

  app.post('/admin/uzytkownicy/:id/blokada', allow('users.block'), (req, res) => {
    const account = findAccount(req.params.id);
    if (!account) return notFound(res);
    if (account.id === req.user.id || account.is_permanent) {
      return res.status(400).render('error', {
        title: 'Operacja niemożliwa',
        status: 400,
        message: 'Nie można zablokować własnego konta ani stałego konta administratora.',
      });
    }
    const blocked = !account.is_blocked;
    setBlocked(db, account, blocked);
    recordAudit(db, {
      req,
      action: blocked ? 'user_block' : 'user_unblock',
      target: account.login,
    });
    setFlash(db, req.session.id, {
      message: blocked ? 'Konto zostało zablokowane.' : 'Konto zostało odblokowane.',
      tone: 'ok',
    });
    res.redirect('/admin/uzytkownicy');
  });

  app.post('/admin/uzytkownicy/:id/reset', allow('users.reset_password'), route(async (req, res) => {
    const account = findAccount(req.params.id);
    if (!account) return notFound(res);
    if (account.id === req.user.id) {
      return res.status(400).render('error', {
        title: 'Operacja niemożliwa',
        status: 400,
        message: 'Własne hasło zmienisz w profilu. Hasło jednorazowe nadaje się innemu kontu.',
      });
    }
    const created = await assignOneTimePassword(db, account, req.policy);
    recordAudit(db, { req, action: 'password_reset', target: account.login });
    setFlash(db, req.session.id, {
      type: 'otp',
      login: account.login,
      name: fullName(account),
      otp: created.otp,
      expiresAt: created.expires,
      mode: 'reset',
    });
    res.redirect('/admin/haslo-jednorazowe');
  }));

  app.get('/admin/uzytkownicy/:id/usun', allow('users.delete'), (req, res) => {
    const account = findAccount(req.params.id);
    if (!account) return notFound(res);
    if (account.id === req.user.id || account.is_permanent) {
      return res.status(400).render('error', {
        title: 'Operacja niemożliwa',
        status: 400,
        message: 'Nie można usunąć własnego konta ani stałego konta administratora.',
      });
    }
    res.render('user-delete', { title: 'Usuwanie konta', account });
  });

  app.post('/admin/uzytkownicy/:id/usun', allow('users.delete'), (req, res) => {
    const account = findAccount(req.params.id);
    if (!account) return notFound(res);
    if (account.id === req.user.id || account.is_permanent || !removeUser(db, account)) {
      return res.status(400).render('error', {
        title: 'Operacja niemożliwa',
        status: 400,
        message: 'Nie można usunąć własnego konta ani stałego konta administratora.',
      });
    }
    recordAudit(db, { req, action: 'user_delete', target: account.login });
    setFlash(db, req.session.id, { message: `Konto ${account.login} zostało usunięte.`, tone: 'ok' });
    res.redirect('/admin/uzytkownicy');
  });

  app.get('/admin/ustawienia', allow('settings.manage'), (req, res) => {
    res.render('settings', { title: 'Ustawienia', errors: [] });
  });

  app.post('/admin/ustawienia', allow('settings.manage'), (req, res) => {
    const passwordMaxAgeDays = Number(String(req.body.password_max_age_days ?? '').trim());
    const sessionIdleMinutes = Number(String(req.body.session_idle_minutes ?? '').trim());
    const errors = [];
    if (!Number.isInteger(passwordMaxAgeDays) || passwordMaxAgeDays < 0 || passwordMaxAgeDays > 3650) {
      errors.push('Ważność hasła podaj jako liczbę dni od 0 do 3650. Zero oznacza brak terminu.');
    }
    if (!Number.isInteger(sessionIdleMinutes) || sessionIdleMinutes < 1 || sessionIdleMinutes > 480) {
      errors.push('Czas bezczynności podaj w minutach, od 1 do 480.');
    }
    if (errors.length) return res.status(400).render('settings', { title: 'Ustawienia', errors });
    const entropyRequired = req.body.entropy_required === '1';
    saveEditableSettings(db, { entropyRequired, passwordMaxAgeDays, sessionIdleMinutes });
    recordAudit(db, {
      req,
      action: 'settings_change',
      detail: `entropia=${entropyRequired ? 'tak' : 'nie'}, waznosc=${passwordMaxAgeDays}, bezczynnosc=${sessionIdleMinutes}`,
    });
    setFlash(db, req.session.id, { message: 'Ustawienia zostały zapisane.', tone: 'ok' });
    res.redirect('/admin/ustawienia');
  });

  app.get('/admin/dziennik', allow('audit.read'), (req, res) => {
    res.render('audit', { title: 'Dziennik', events: listAudit(db) });
  });

  function findAccount(rawId) {
    const id = intId(rawId);
    if (!id) return null;
    return findById(db, id);
  }

  function loadAnnouncement(rawId) {
    const id = intId(rawId);
    if (!id) return null;
    return db.prepare('SELECT * FROM announcements WHERE id = ?').get(id) || null;
  }

  function loadDocument(rawId) {
    const id = intId(rawId);
    if (!id) return null;
    return db.prepare('SELECT * FROM documents WHERE id = ?').get(id) || null;
  }

  async function profileView(req, extra) {
    const pending = req.session.pending_totp;
    return {
      title: 'Profil',
      qr: pending ? await totpQrDataUrl(pending, req.user.login) : null,
      secret: pending ? groupSecret(pending) : null,
      ...extra,
    };
  }
}

function readAnnouncement(req) {
  return {
    title: String(req.body.title ?? ''),
    body: String(req.body.body ?? ''),
    visibility: req.body.visibility === 'internal' ? 'internal' : 'public',
  };
}

function validateAnnouncement(form) {
  const errors = [];
  const title = cleanText(form.title, 120);
  const body = cleanText(form.body, 5000);
  if (!title) errors.push('Tytuł jest wymagany i może mieć do 120 znaków.');
  if (!body) errors.push('Treść jest wymagana i może mieć do 5000 znaków.');
  if (title) form.title = title;
  if (body) form.body = body;
  return errors;
}

function validateDocument(body) {
  const errors = [];
  if (!cleanText(body.title, 120)) errors.push('Tytuł jest wymagany i może mieć do 120 znaków.');
  if (!cleanText(body.body, 5000)) errors.push('Treść jest wymagana i może mieć do 5000 znaków.');
  return errors;
}

function readUserForm(req) {
  return {
    login: String(req.body.login ?? '').trim(),
    first_name: String(req.body.first_name ?? '').trim(),
    last_name: String(req.body.last_name ?? '').trim(),
    role: String(req.body.role ?? ''),
  };
}

function validateUserForm(form) {
  const errors = [];
  if (!/^[A-Za-z0-9._-]{3,32}$/.test(form.login)) {
    errors.push('Login może mieć 3–32 znaki: litery, cyfry, kropkę, myślnik i podkreślenie.');
  }
  if (!cleanText(form.first_name, 60)) errors.push('Podaj imię (do 60 znaków).');
  else form.first_name = cleanText(form.first_name, 60);
  if (!cleanText(form.last_name, 60)) errors.push('Podaj nazwisko (do 60 znaków).');
  else form.last_name = cleanText(form.last_name, 60);
  if (!isRole(form.role)) errors.push('Wybierz rolę.');
  return errors;
}
