# Zestawienie testu bota — KLUCZ moduł 2

Cel: wyłącznie własna aplikacja `http://127.0.0.1:3000`.

| Zabezpieczenie | Zadziałało? | Uwagi |
| --- | --- | --- |
| reCAPTCHA przy logowaniu | tak | status 400; formularz bez tokenu odrzucony |
| Honeypot (ukryte pole) | tak | wypełnione company_fax → odrzucenie bez wejścia (status 200) |
| Canarytoken — konto-pułapka | tak | logowanie na svc_backup nie wpuszcza; alert trafia do /admin/canary |
| Canarytoken — klucze AWS | tak | GET /canary/aws-credentials.txt → 200; alert typu aws_keys |
| Limit błędnych logowań (konto) | tak | konto zablokowane na 15 min; pokazano 15:00 |
| Jednorazowe wyzwanie logowania | tak | ponowne użycie tego samego login_challenge odrzucone |

## Interpretacja

- Bot bez tokenu reCAPTCHA nie przechodzi logowania.
- Wypełnienie honeypota kończy się odrzuceniem.
- Konto `svc_backup` i plik AWS generują alerty Canary.
- Po serii złych haseł konto dostaje blokadę 15 minut z widocznym czasem.
- Challenge serwerowy jest jednorazowy (TTL ~2 min).
