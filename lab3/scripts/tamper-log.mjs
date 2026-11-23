/** Ręczna ingerencja w dziennik — do demonstracji weryfikacji SHA3-256. */
import fs from 'node:fs';
import { LOG_PATH } from '../src/securityLog.js';

const raw = fs.readFileSync(LOG_PATH, 'utf8');
const data = JSON.parse(raw);
if (!data.events?.length) {
  console.error('Brak wpisów — najpierw uruchom aplikację i wygeneruj zdarzenia.');
  process.exit(1);
}
const victim = data.events[Math.max(0, data.events.length - 2)];
const before = victim.description;
victim.description = `${victim.description || ''} [TAMPERED]`;
fs.writeFileSync(LOG_PATH, `${JSON.stringify(data, null, 2)}\n`);
console.log(`Zmieniono opis wpisu #${victim.id}`);
console.log(`było: ${before}`);
console.log(`jest: ${victim.description}`);
console.log('Hash w pliku NIE został przeliczony — weryfikacja w panelu powinna wykryć ingerencję.');
