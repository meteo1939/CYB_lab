# KLUCZ — moduł 1, wariant 8

Portal zasobów wewnętrznych: identyfikacja loginem, uwierzytelnianie hasłem (oraz opcjonalnym TOTP) i autoryzacja ról Administrator, Pracownik, Gość.

Aplikacja jest lokalna i służy do zajęć. Nie wystawiaj jej do internetu.

## Uruchomienie

Wymagany jest Node.js 22 lub nowszy.

```bash
npm install
npm start
```

Adres: http://localhost:3000

Przy pierwszym starcie powstaje baza `data/klucz.db` i konta poniżej. Hasła jednorazowe są ważne **godzinę od tego startu**. Ponowne nadanie kont i świeżych kodów:

```bash
npm run seed
```

Serwer musi być wtedy wyłączony. Testy: `npm test`.

W bazie, która została po przejściu scenariuszy, reguła entropii jest włączona. `npm run seed` przywraca stan z tabeli kont: entropia wyłączona, a kody jednorazowe ważne godzinę od tego polecenia. Drugi składnik TOTP włącza się w profilu; na koncie `admin` jest wyłączony.

## Konta

Stałe konto administratora oraz 9 użytkowników testowych.

| Login | Hasło | Rola | Uwagi |
| --- | --- | --- | --- |
| admin | `Admin#Portal2026` | Administrator | konta nie da się usunąć ani zablokować |
| jkowalski | `Kowalski#Praca19` | Pracownik | |
| anowak | `Nowak.Pracownik1` | Pracownik | |
| mwisniewski | `48291573` | Pracownik | hasło jednorazowe, ważne 1 h, wymuszona zmiana |
| kwojcik | `Wojcik#Zablok1` | Pracownik | konto zablokowane |
| tzielinski | `Zielinski.Gosc1` | Gość | |
| awojcik | `Wojcik-Gosc#2026` | Gość | |
| pkaczmarek | `10293847` | Gość | hasło jednorazowe już wygasło |
| elewandowska | `Ewa#Lewand2026` | Gość | |
| rdabrowski | `67584930` | Gość | hasło jednorazowe, ważne 1 h, wymuszona zmiana |

Błędne hasło i nieistniejący login dają ten sam komunikat: „Login lub hasło niepoprawne”. Informacja o blokadzie albo o wygasłym kodzie pojawia się dopiero wtedy, gdy hasło się zgadza.

## Co sprawdza wariant 8

- minimalna długość hasła: 12 znaków
- dodatkowa reguła, włączana w ustawieniach administratora: entropia co najmniej 60 bitów, z podpowiedzią H = L × log₂(R)
- hasło jednorazowe: 8 cyfr, ważność 1 godzina
- ważność hasła w dniach i czas bezczynności sesji — ustawia administrator
- nowe hasło musi różnić się od 5 poprzednich (weryfikacja skrótów, nie porównanie napisów)

## Gdzie to jest w kodzie

- `src/passwords.js` — Argon2id i reguły hasła
- `public/js/entropy.js` — ten sam wzór entropii w przeglądarce i na serwerze
- `src/permissions.js` — macierz ról
- `src/sessions.js` i `src/app.js` — sesja, bezczynność, CSRF
- `src/auth.js` — komunikat logowania bez zdradzania, czy login istnieje
- `src/totp.js` — drugi składnik
