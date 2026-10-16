# GeoPajiști – versiune funcțională de test v0.2

Aplicație web fără GIS, structurată **Primărie → UA → Fișe de teren**. Include un import inițial **Putinței** din registrul Excel oferit.

## Funcționalități
- autentificare administrator, modificare date generale în fișe noi și salvare SQLite;
- adăugare primării și UA, creare fișe noi, istoric per UA;
- adăugare specii ierboase/lemnoase și lucrări propuse;
- fișe istorice Putintei: 46 UA, 46 fișe, 715 înregistrări de specii, 145 soluri, 172 lucrări;
- afișarea detaliilor istorice extinse și a tipurilor de sol;
- exporturi CSV (fișe/specii/lucrări), fișă pentru imprimare/salvare PDF;
- stări Ciornă, Transmisă, Verificată, Aprobată.

## Rulare pe Windows
1. Instalați Python 3.10+.
2. Dezarhivați și deschideți PowerShell în dosarul `geopajisti_cloud`.
3. Executați:
   ```powershell
   $env:ADMIN_PASSWORD='ALEGE-O-PAROLA-LUNGA-SI-UNICA'
   python start.py
   ```
4. Accesați `http://localhost:8000`, utilizator `admin`, parola stabilită.

Datele sunt stocate implicit în fișierul `geopajisti.sqlite3` din același dosar. Importul este reluabil fără duplicarea înregistrărilor deja importate. **Nu distribuiți baza SQLite după ce o populați cu date reale.**

## Cloud – Docker
- Încărcați proiectul în serviciul cloud ales, cu suport Docker și **volum persistent** la `/data`.
- Configurați `ADMIN_PASSWORD` cu o valoare secretă, URL public pe portul intern `8000`, `COOKIE_SECURE=1`, HTTPS.
- La prima lansare, baza și datele Putintei se creează automat. La restart, datele salvate pe volum sunt păstrate.
- Faceți copii de siguranță ale fișierului din `/data`.

## Atenționări
**Aceasta este o versiune de test, nu o aplicație gata pentru producție instituțională.** Autentificarea este pentru un singur administrator; sesiunile sunt în memorie; SQLite nu este alegerea recomandată pentru echipe numeroase. Nu sunt implementate încă utilizatorii separați, fotografiile, completarea offline, fișa de sol pentru înregistrări noi, nomenclatoare botanice validate, rapoarte Word formatate, jurnal complet, backup automat și control de acces pe primării. Înainte de utilizare multi-utilizator este indicată migrarea la PostgreSQL, auditul de securitate și testarea fluxurilor.

**Date istorice:** `2015-03-23` este data dedusă din numele fișierului, nu confirmarea unei vizite de teren. UA dublate au sufix `~2` în sistem, păstrând codul original în secțiunea de arhivă. Numerele de specii sunt **înregistrări, nu taxoni unici**; denumirile botanice sunt păstrate conform fișierului fără corectări taxonomice automate.
