import { strengthHint } from './entropy.js';

const body = document.body;
const policy = {
  minLength: Number(body.dataset.minLength || 12),
  entropyRequired: body.dataset.entropyRequired === '1',
  minBits: Number(body.dataset.minBits || 60),
};

for (const input of document.querySelectorAll('[data-strength]')) {
  const root = input.closest('form') || document;
  const hint = root.querySelector('[data-strength-hint]');
  const bar = root.querySelector('[data-strength-bar]');
  const meter = root.querySelector('[data-strength-meter]');

  const update = () => {
    const result = strengthHint(input.value, policy);
    if (!input.value) {
      if (hint) hint.textContent = '';
      if (meter) meter.hidden = true;
      return;
    }
    if (hint) hint.textContent = result.hint;
    if (meter) meter.hidden = false;
    if (bar) {
      const pct = Math.max(4, Math.min(100, (result.bits / policy.minBits) * 100));
      bar.style.width = `${pct}%`;
      bar.dataset.level = result.bits >= policy.minBits && input.value.length >= policy.minLength ? 'ok' : result.bits >= 45 ? 'mid' : 'low';
    }
  };

  input.addEventListener('input', update);
}

for (const button of document.querySelectorAll('[data-reveal]')) {
  button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.reveal);
    if (!input) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    button.textContent = show ? 'Ukryj' : 'Pokaż';
  });
}
