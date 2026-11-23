# KLUCZ — lab 3 (moduł 3), wariant 8

Kontynuacja lab 1 i lab 2: dziennik zdarzeń bezpieczeństwa, integralność SHA3-256, alerty.

## Wariant 8

| Element | Wartość |
| --- | --- |
| Format zapisu | plik JSON (`data/security-log.json`) |
| Integralność | SHA3-256 każdego wpisu w polu `hash` |
| Reguła detekcji | każda próba logowania na konto-pułapkę `svc_backup` |
| Kanał alertu | e-mail (pliki `.eml` w `data/mailbox/`) |
| Reguła wspólna | ≥ 5 nieudanych logowań na jedno konto w 5 minut |

## Uruchomienie

```bash
cd lab3
npm install
npm start
```

Adres: http://localhost:3000

## Funkcje

- przeglądarka logów z filtrem (użytkownik, data, typ) i eksportem JSON
- weryfikacja integralności całego dziennika
- brak edycji/usuwania wpisów; eksport i weryfikacja też są logowane
- alerty e-mail + wpis `security_alert` w dzienniku
- webhook Canarytokens: `POST /webhooks/canary` (zadanie dodatkowe)

Demonstracja ingerencji:

```bash
npm run tamper-log
```

Potem w panelu: Dziennik → Sprawdź dziennik.

## Konta

Jak w lab 2 (w tym canary `svc_backup`). Hasła: zobacz README lab 1 / lab 2.
