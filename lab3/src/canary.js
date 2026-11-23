import { nowIso } from './db.js';
import { recordAudit } from './audit.js';

export const CANARY_ACCOUNT_LOGIN = 'svc_backup';
export const CANARY_ACCOUNT_PASSWORD = 'Backup#Canary2026';

export const AWS_CANARY = {
  path: '/canary/aws-credentials.txt',
  accessKeyId: 'AKIAIOSFODNN7CANARY',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARYKEY',
};

export function raiseCanary(db, { req, type, detail = null, actorLogin = null }) {
  const ts = nowIso();
  db.prepare(`
    INSERT INTO canary_alerts (created_at, type, detail, ip, actor_login)
    VALUES (?, ?, ?, ?, ?)
  `).run(ts, type, detail, req?.ip ?? null, actorLogin);
  recordAudit(db, {
    req,
    action: 'canary_alert',
    success: true,
    target: type,
    detail: detail || actorLogin,
  });
  console.warn(`[CANARY] ${type} · ${detail || actorLogin || ''} · IP ${req?.ip || '?'}`);
}

export function listCanaryAlerts(db, limit = 100) {
  return db.prepare(`
    SELECT * FROM canary_alerts ORDER BY id DESC LIMIT ?
  `).all(limit);
}

export function awsCanaryBody() {
  return [
    '# FAKE credentials — Canarytoken (moduł 2)',
    '# Pobranie tego pliku generuje alert w portalu KLUCZ.',
    `aws_access_key_id = ${AWS_CANARY.accessKeyId}`,
    `aws_secret_access_key = ${AWS_CANARY.secretAccessKey}`,
    'region = eu-central-1',
    '',
  ].join('\n');
}
