import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode';

function totpFor(secret, login = 'KLUCZ') {
  return new OTPAuth.TOTP({
    issuer: 'KLUCZ',
    label: login,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

export function createTotpSecret() {
  return new OTPAuth.Secret({ size: 20 }).base32;
}

export function verifyTotp(secret, token) {
  const code = String(token ?? '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code) || !secret) return false;
  return totpFor(secret).validate({ token: code, window: 1 }) !== null;
}

export async function totpQrDataUrl(secret, login) {
  return QRCode.toDataURL(totpFor(secret, login).toString(), {
    margin: 1,
    width: 196,
    errorCorrectionLevel: 'M',
  });
}

export function groupSecret(secret) {
  return String(secret || '').replace(/(.{4})/g, '$1 ').trim();
}
