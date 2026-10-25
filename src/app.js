import path from 'node:path';
import express from 'express';
import helmet from 'helmet';
import { fileURLToPath } from 'node:url';
import { ACTION_LABELS, recordAudit } from './audit.js';
import { getSettings, rootDir } from './db.js';
import { fullName, formatDate } from './format.js';
import { MSG } from './messages.js';
import { safeEqual } from './passwords.js';
import { PERMISSIONS, ROLES, can, canEditOwn, roleLabel } from './permissions.js';
import { registerRoutes } from './routes.js';
import { findById } from './users.js';
import {
  clearFlash,
  cookieOptions,
  createSession,
  deleteSession,
  getSession,
  readCookie,
  sessionExpiry,
  touchSession,
} from './sessions.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function writeSid(res, id) {
  res.cookie('klucz_sid', id, cookieOptions());
}

function clearSid(res) {
  res.clearCookie('klucz_sid', { path: '/', sameSite: 'lax', httpOnly: true });
}

function sessionLayer(db) {
  return (req, res, next) => {
    try {
      req.policy = getSettings(db);
      const sid = readCookie(req, 'klucz_sid');
      let session = sid ? getSession(db, sid) : null;
      const expiry = sessionExpiry(session, req.policy);

      if (session && expiry) {
        if (session.user_id) {
          const actor = findById(db, session.user_id);
          recordAudit(db, {
            req,
            action: expiry === 'idle' ? 'logout_idle' : 'logout_absolute',
            success: true,
            actor,
            target: actor?.login ?? null,
          });
          deleteSession(db, session.id);
          clearSid(res);
          return res.redirect(expiry === 'idle' ? '/login?wygasla=bezczynnosc' : '/login?wygasla=czas');
        }
        deleteSession(db, session.id);
        session = null;
      }

      if (session?.user_id) {
        const user = findById(db, session.user_id);
        if (!user) {
          deleteSession(db, session.id);
          clearSid(res);
          session = null;
        } else if (user.is_blocked) {
          deleteSession(db, session.id);
          clearSid(res);
          return res.redirect('/login?zablokowane=1');
        } else {
          req.user = user;
        }
      }

      if (!session && req.method === 'GET') {
        session = createSession(db, { stage: 'anon' });
        writeSid(res, session.id);
      }

      if (session) {
        touchSession(db, session.id);
        if (session.flash) {
          try {
            req.flash = JSON.parse(session.flash);
          } catch {
            req.flash = null;
          }
          clearFlash(db, session.id);
        }
      }

      req.session = session;
      res.set('Cache-Control', 'no-store');
      res.locals.user = req.user || null;
      res.locals.sessionStage = session?.stage || null;
      res.locals.csrf = session?.csrf_secret || '';
      res.locals.flash = req.flash || null;
      res.locals.policy = req.policy;
      res.locals.path = req.path;
      res.locals.can = (permission) => (req.user ? can(req.user.role, permission) : false);
      res.locals.canEditOwn = canEditOwn;
      res.locals.granted = can;
      res.locals.roleLabel = roleLabel;
      res.locals.fullName = fullName;
      res.locals.formatDate = formatDate;
      res.locals.ROLES = ROLES;
      res.locals.PERMISSIONS = PERMISSIONS;
      res.locals.actionLabel = (id) => ACTION_LABELS[id] || id;
      next();
    } catch (error) {
      next(error);
    }
  };
}

function csrfLayer(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const token = typeof req.body?._csrf === 'string' ? req.body._csrf : '';
  const secret = req.session?.csrf_secret || '';
  if (!secret || !safeEqual(token, secret)) {
    return res.status(400).render('error', {
      title: 'Nieprawidłowy formularz',
      status: 400,
      message: 'Odśwież stronę i wyślij formularz ponownie. Token zabezpieczający wygasł albo jest niepoprawny.',
    });
  }
  next();
}

export function createApp(db) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'"],
        upgradeInsecureRequests: null,
      },
    },
    strictTransportSecurity: false,
    crossOriginEmbedderPolicy: false,
  }));
  app.use(express.static(path.join(rootDir, 'public'), { index: false }));
  app.use(express.urlencoded({ extended: false, limit: '32kb' }));
  app.use(sessionLayer(db));
  app.use(csrfLayer);
  registerRoutes(app, { db, writeSid, clearSid });
  app.use((req, res) => {
    res.status(404).render('error', {
      title: 'Nie znaleziono',
      status: 404,
      message: 'Ten adres nie istnieje.',
    });
  });
  app.use((error, req, res, next) => {
    console.error(error);
    if (res.headersSent) return next(error);
    res.status(500).send('Wystąpił błąd serwera.');
  });
  return app;
}

export { MSG };
