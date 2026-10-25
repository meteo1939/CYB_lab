export function fullName(user) {
  if (!user) return '';
  return `${user.first_name} ${user.last_name}`;
}

export function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('pl-PL', {
    dateStyle: 'short',
    timeStyle: 'short',
    timeZone: 'Europe/Warsaw',
  }).format(date);
}

export function cleanText(value, max) {
  const text = String(value ?? '').replace(/\r\n/g, '\n').trim();
  if (!text || text.length > max) return null;
  return text;
}

export function intId(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) return null;
  return n;
}
