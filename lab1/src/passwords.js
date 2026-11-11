import { randomBytes, timingSafeEqual } from 'node:crypto';
import { argon2id, argon2Verify } from 'hash-wasm';
import { analyzePassword, formatBits, strengthHint } from '../public/js/entropy.js';

// OWASP Password Storage Cheat Sheet: Argon2id, min. 19 MiB, t=2, p=1.
export const ARGON2 = {
  memorySize: 19456,
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16,
};

export const OTP_TTL_MS = 60 * 60 * 1000;
export const ABSOLUTE_SESSION_MS = 12 * 60 * 60 * 1000;

let dummyHashPromise = null;

export async function hashPassword(password) {
  const salt = new Uint8Array(randomBytes(ARGON2.saltLength));
  return argon2id({
    password,
    salt,
    parallelism: ARGON2.parallelism,
    iterations: ARGON2.iterations,
    memorySize: ARGON2.memorySize,
    hashLength: ARGON2.hashLength,
    outputType: 'encoded',
  });
}

export async function verifyPassword(password, encoded) {
  if (!encoded) return false;
  try {
    return await argon2Verify({ password, hash: encoded });
  } catch {
    return false;
  }
}

export function warmDummyHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = hashPassword(randomBytes(32).toString('hex'));
  }
  return dummyHashPromise;
}

export function generateOtp() {
  return String(randomIntSafe()).padStart(8, '0');
}

function randomIntSafe() {
  const range = 100_000_000;
  const limit = 2 ** 32 - (2 ** 32 % range);
  let value = 0;
  do {
    value = randomBytes(4).readUInt32BE(0);
  } while (value >= limit);
  return value % range;
}

export function evaluatePassword(password, policy) {
  const analysis = strengthHint(password, {
    minLength: policy.minPasswordLength ?? policy.minLength,
    entropyRequired: policy.entropyRequired,
    minBits: policy.minEntropyBits ?? policy.minBits,
  });
  const minLength = policy.minPasswordLength ?? policy.minLength;
  const minBits = policy.minEntropyBits ?? policy.minBits;
  const errors = [];
  if (!password || password.length < minLength) {
    errors.push(`Hasło musi mieć co najmniej ${minLength} znaków.`);
  }
  if (password && password.length > 200) {
    errors.push('Hasło może mieć co najwyżej 200 znaków.');
  }
  if (policy.entropyRequired && analysis.bits + 1e-9 < minBits) {
    errors.push(`Hasło ma entropię ${formatBits(analysis.bits)} bitów. Wymagane jest co najmniej ${minBits} bitów.`);
  }
  return { ok: errors.length === 0, errors, ...analysis };
}

export function passwordChangeReason(user, policy, now = Date.now()) {
  if (user.must_change_password) return 'first';
  const days = Number(policy.passwordMaxAgeDays ?? 0);
  if (days > 0 && user.password_changed_at) {
    const changed = new Date(user.password_changed_at).getTime();
    if (now - changed > days * 24 * 60 * 60 * 1000) return 'expired';
  }
  return null;
}

export function describeHash(phc) {
  const parts = String(phc || '').split('$');
  if (parts.length < 5) return null;
  return {
    algorithm: parts[1],
    version: parts[2],
    params: parts[3],
  };
}

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export { analyzePassword, formatBits, strengthHint };
