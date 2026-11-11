# KLUCZ — lab 2 (moduł 2), wariant 8

Rozbudowa portalu z lab 1 o limity logowań, Google reCAPTCHA, honeypot, Canarytokeny oraz test bota.

## Uruchomienie

```bash
cd lab2
npm install
npm start
```

Adres: http://localhost:3000

Do skryptu bota (akceptuje token `test-ok` zamiast widżetu Google):

```bash
# PowerShell
$env:CAPTCHA_TEST_MODE='1'; npm start
# w drugim terminalu
npm run bot-test
```

Raport: `bot-report.md`.

## Co dodaje moduł 2

1. **Limit błędnych logowań** — administrator ustawia próg w Ustawieniach; po przekroczeniu konto jest blokowane na 15 minut; ekran pokazuje pozostały czas.
2. **CAPTCHA przy logowaniu** — Google reCAPTCHA v2 + jednorazowe wyzwanie serwerowe (`login_challenge`, TTL 2 min).
3. **reCAPTCHA przy zmianie hasła** — formularz bez poprawnego tokenu jest odrzucany.
4. **Honeypot** — ukryte pole `company_fax`; wypełnienie = bot.
5. **Canarytokens**
   - konto-pułapka `svc_backup` / `Backup#Canary2026`
   - przynęta AWS: `/canary/aws-credentials.txt`
   - alerty: `/admin/canary`
6. **Test bota** — `npm run bot-test` + zestawienie w `bot-report.md`.
7. **Dodatkowo** — limit prób z jednego IP (password spraying), też 15 minut.

## Konta

Te same co w lab 1 (patrz tabela poniżej) oraz konto-pułapka.

| Login | Hasło | Uwagi |
| --- | --- | --- |
| admin | `Admin#Portal2026` | administrator |
| jkowalski | `Kowalski#Praca19` | pracownik |
| anowak | `Nowak.Pracownik1` | pracownik |
| mwisniewski | `48291573` | OTP, 1 h |
| kwojcik | `Wojcik#Zablok1` | zablokowane |
| tzielinski | `Zielinski.Gosc1` | gość |
| awojcik | `Wojcik-Gosc#2026` | gość |
| pkaczmarek | `10293847` | OTP wygasłe |
| elewandowska | `Ewa#Lewand2026` | gość |
| rdabrowski | `67584930` | OTP, 1 h |
| svc_backup | `Backup#Canary2026` | **canary — nie używać normalnie** |

Domyślnie działają oficjalne klucze testowe Google reCAPTCHA v2. Własne:

```bash
$env:RECAPTCHA_SITE_KEY='...'
$env:RECAPTCHA_SECRET_KEY='...'
```
