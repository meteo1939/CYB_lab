# KLUCZ — lab 1 (moduł 1), wariant 8

Portal zasobów wewnętrznych: identyfikacja loginem, uwierzytelnianie hasłem (oraz opcjonalnym TOTP) i autoryzacja ról Administrator, Pracownik, Gość.

Aplikacja jest lokalna i służy do zajęć. Nie wystawiaj jej do internetu.

## Uruchomienie

```bash
cd lab1
npm install
npm start
```

Adres: http://localhost:3000

Przy pierwszym starcie powstaje baza `data/klucz.db` i konta poniżej. Hasła jednorazowe są ważne **godzinę od tego startu**. Ponowne nadanie kont:

```bash
npm run seed
```

Serwer musi być wtedy wyłączony. Testy: `npm test`.

## Konta

| Login | Hasło | Rola | Uwagi |
| --- | --- | --- | --- |
| admin | `Admin#Portal2026` | Administrator | konta nie da się usunąć ani zablokować |
| jkowalski | `Kowalski#Praca19` | Pracownik | |
| anowak | `Nowak.Pracownik1` | Pracownik | |
| mwisniewski | `48291573` | Pracownik | hasło jednorazowe, ważne 1 h |
| kwojcik | `Wojcik#Zablok1` | Pracownik | konto zablokowane |
| tzielinski | `Zielinski.Gosc1` | Gość | |
| awojcik | `Wojcik-Gosc#2026` | Gość | |
| pkaczmarek | `10293847` | Gość | hasło jednorazowe już wygasło |
| elewandowska | `Ewa#Lewand2026` | Gość | |
| rdabrowski | `67584930` | Gość | hasło jednorazowe, ważne 1 h |

## Wariant 8

- minimalna długość hasła: 12 znaków
- dodatkowa reguła (admin): entropia ≥ 60 bitów, podpowiedź H = L × log₂(R)
- hasło jednorazowe: 8 cyfr, ważność 1 godzina
- role: Administrator, Pracownik, Gość

Rozszerzenia (CAPTCHA, limity, canary): katalog **`lab2`**.
