import { verifyPassword, warmDummyHash } from './passwords.js';
import { findByLogin } from './users.js';

export async function authenticate(db, login, password) {
  const user = findByLogin(db, login);
  const hash = user?.password_hash || (await warmDummyHash());
  const match = await verifyPassword(password, hash);
  if (!user || !match) return { status: 'invalid' };
  if (user.must_change_password && user.otp_expires_at && new Date(user.otp_expires_at).getTime() < Date.now()) {
    return { status: 'otp_expired', user };
  }
  if (user.is_blocked) return { status: 'blocked', user };
  return { status: 'ok', user };
}
