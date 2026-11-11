import { createApp } from './app.js';
import { openDatabase } from './db.js';
import { warmDummyHash } from './passwords.js';
import { seed } from './seed.js';

const db = openDatabase();
if (Number(db.prepare('SELECT COUNT(*) AS n FROM users').get().n) === 0) {
  await seed(db);
  console.log('Utworzono bazę i konta startowe.');
}
await warmDummyHash();

const port = Number(process.env.PORT || 3000);
createApp(db).listen(port, () => {
  console.log(`KLUCZ nasłuchuje na http://localhost:${port}`);
  console.log('Konta i hasła: README.md. Hasła jednorazowe są ważne godzinę od utworzenia bazy.');
});
