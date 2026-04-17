# MWW Backend – API + Panel Admina

Kompletny backend API i panel administracyjny dla strony nieruchomości **MWW Mieszkanie**.

**Baza danych:** Supabase (PostgreSQL) – **[pełny opis bazy → DATABASE.md](DATABASE.md)**  
**Hosting backendu:** Render.com (Web Service, ściąga z GitHub)  
**Panel admina:** Osobne repo → Render Static Site

---

## 📁 Struktura projektu

```
backend/                  ← Backend API (Node.js + Express + Supabase)
├── server.js             ← Główny plik serwera
├── db.js                 ← Klient Supabase
├── package.json          ← Zależności
├── seed.js               ← Skrypt tworzący konto admina
├── migrate.sql           ← SQL do uruchomienia w Supabase (tworzenie tabel)
├── DATABASE.md           ← Pełny opis bazy danych (tabele, kolumny, typy, indeksy)
├── render.yaml           ← Konfiguracja Render Blueprint
├── .env.example          ← Przykładowy plik zmiennych środowiskowych
├── routes/
│   ├── auth.js           ← Logowanie, weryfikacja, zmiana hasła
│   ├── offers.js         ← CRUD ofert + filtrowanie, sortowanie
│   └── images.js         ← Upload zdjęć (AVIF/WebP konwersja)
├── middleware/
│   └── auth.js           ← Middleware JWT
├── utils/
│   └── imageProcessor.js ← Sharp – konwersja do AVIF/WebP + miniaturki
└── uploads/              ← Przesłane zdjęcia (dysk Render)

admin/                    ← Panel administracyjny (statyczny HTML/CSS/JS)
├── index.html            ← Główna strona panelu
├── admin.css             ← Style panelu
├── admin.js              ← Logika panelu (SPA)
└── admin-config.js       ← Konfiguracja (adres API)
```

---

## 🚀 Krok po kroku – pełne wdrożenie

### Krok 1: Supabase – baza danych

1. Wejdź na [supabase.com](https://supabase.com) i stwórz nowy projekt
2. Wybierz **region EU (Frankfurt)** – najbliżej Polski
3. Ustaw hasło do bazy danych i zapisz je
4. Po utworzeniu projektu, przejdź do **SQL Editor** (ikona SQL w menu)
5. Skopiuj **całą zawartość pliku `migrate.sql`** i wklej ją do edytora SQL
6. Kliknij **Run** – to stworzy tabele `users` i `offers` z indeksami i triggerami
7. Przejdź do **Settings → API** i skopiuj:
   - **Project URL** → to jest `SUPABASE_URL`
   - **service_role key** (NIE anon key!) → to jest `SUPABASE_SERVICE_KEY`

> 💡 **Pełny opis struktury bazy danych** (tabele, kolumny, typy, indeksy, JSONB) znajdziesz w pliku **[DATABASE.md](DATABASE.md)**. Możesz go wkleić do Copilota / ChatGPT z prośbą o wygenerowanie SQL, jeśli chcesz zmodyfikować bazę.

### Krok 2: Backend na Render

1. **Stwórz nowe repo na GitHub** i wrzuć zawartość folderu `backend/`
2. Na render.com kliknij **"New" → "Web Service"**
3. **Połącz repo** z backendem

4. **Konfiguracja serwisu:**

   | Pole | Wartość |
   |---|---|
   | **Name** | `mww-backend` |
   | **Region** | Frankfurt (EU) |
   | **Runtime** | Node |
   | **Build Command** | `npm install` |
   | **Start Command** | `npm start` |
   | **Plan** | Free (lub Starter $7/mies dla produkcji) |

5. **Zmienne środowiskowe** (Environment → Add Environment Variable):

   | Klucz | Wartość |
   |---|---|
   | `NODE_ENV` | `production` |
   | `SUPABASE_URL` | URL z Supabase Dashboard → Settings → API |
   | `SUPABASE_SERVICE_KEY` | service_role key z Supabase (NIGDY anon key!) |
   | `JWT_SECRET` | Kliknij "Generate" – min. 32 znaki |
   | `JWT_EXPIRES_IN` | `24h` |
   | `CORS_ORIGINS` | `https://twoja-strona.pl,https://admin.twoja-strona.pl` |
   | `ADMIN_USERNAME` | `mww` (lub inna nazwa) |
   | `ADMIN_PASSWORD` | Bezpieczne hasło – **zmień!** |
   | `MAX_FILE_SIZE_MB` | `10` |
   | `IMAGE_FORMAT` | `both` |
   | `IMAGE_QUALITY` | `80` |
   | `IMAGE_MAX_WIDTH` | `1920` |
   | `THUMB_MAX_WIDTH` | `400` |

6. **Dysk (Disk) – WAŻNE dla zdjęć:**
   - Kliknij **"Advanced" → "Add Disk"**
   - **Name:** `mww-uploads`
   - **Mount Path:** `/opt/render/project/src/uploads`
   - **Size:** 1 GB

7. **Kliknij "Create Web Service"** – Render zbuduje i uruchomi serwer.

8. **Po wdrożeniu**, uruchom seed (jednorazowo):
   - W panelu Render otwórz zakładkę **Shell** i wpisz:
   ```bash
   npm run seed
   ```
   To stworzy konto admina w bazie.

### Krok 3: Panel Admina

1. **Stwórz nowe repo** i wrzuć zawartość folderu `admin/`
2. **Zmień adres API** w pliku `admin-config.js`:
   ```js
   API_BASE_URL: 'https://mww-backend.onrender.com'
   ```
3. Na Render: **"New" → "Static Site"**
4. Konfiguracja:

   | Pole | Wartość |
   |---|---|
   | **Name** | `mww-admin` |
   | **Build Command** | (puste) |
   | **Publish Directory** | `.` |

5. Opcjonalnie dodaj **Custom Domain** np. `admin.mwwmieszkanie.pl`

### Krok 4: Frontend (strona główna)

Zaktualizuj `config.js` na stronie głównej:
```js
API_BASE_URL: 'https://mww-backend.onrender.com'
```

---

## 📡 API – Endpointy

### Publiczne (bez autoryzacji)

| Metoda | Endpoint | Opis |
|---|---|---|
| `GET` | `/api/offers` | Lista aktywnych ofert (z filtrami i sortowaniem) |
| `GET` | `/api/offers/stats` | Statystyki ofert |
| `GET` | `/api/offers/:id` | Pojedyncza oferta (po UUID lub slug) |
| `GET` | `/api/health` | Health check (z testem połączenia do Supabase) |
| `GET` | `/uploads/:filename` | Zdjęcia (statyczne pliki) |

**Query params dla `/api/offers`:**
- `type` – `sprzedaz` / `wynajem`
- `category` – `mieszkanie`, `dom`, `dzialka`, `lokal`, `biuro`, `garaz`, `magazyn`, `inne`
- `city`, `district` – szukaj po mieście/dzielnicy (ILIKE)
- `priceMin`, `priceMax` – zakres cen
- `areaMin`, `areaMax` – zakres powierzchni
- `rooms` – liczba pokoi (4 = 4+)
- `q` – wyszukiwanie tekstowe (tytuł, adres, opis, miasto, dzielnica)
- `sort` – `price-asc`, `price-desc`, `area-asc`, `area-desc`, `newest`, `oldest`, `featured`
- `page`, `limit` – paginacja
- `featured` – `true` (tylko wyróżnione)
- `meta` – `true` (zwraca z metadanymi paginacji)

### Admin (wymagana autoryzacja JWT)

| Metoda | Endpoint | Opis |
|---|---|---|
| `POST` | `/api/auth/login` | Logowanie → `{ token, user }` |
| `GET` | `/api/auth/verify` | Weryfikacja tokenu |
| `POST` | `/api/auth/change-password` | Zmiana hasła |
| `GET` | `/api/offers/all` | Wszystkie oferty (aktywne + nieaktywne) |
| `POST` | `/api/offers` | Dodaj ofertę |
| `PATCH` | `/api/offers/:id` | Edytuj ofertę |
| `PUT` | `/api/offers/:id` | Pełna aktualizacja oferty |
| `DELETE` | `/api/offers/:id` | Usuń ofertę |
| `PATCH` | `/api/offers/:id/toggle` | Zmień status aktywna/nieaktywna |
| `PATCH` | `/api/offers/:id/featured` | Zmień status wyróżniona |
| `POST` | `/api/offers/:id/images` | Dodaj zdjęcia do oferty |
| `DELETE` | `/api/offers/:id/images/:idx` | Usuń zdjęcie z oferty |
| `POST` | `/api/images/upload` | Upload pojedynczego zdjęcia → AVIF + WebP |
| `POST` | `/api/images/upload-multiple` | Upload wielu zdjęć (max 20) |

**Autoryzacja:** Header `Authorization: Bearer <token>`

---

## 🖼️ Przetwarzanie zdjęć

Każde przesłane zdjęcie jest automatycznie:

1. **Skalowane** do max 1920px szerokości
2. **Konwertowane** do:
   - **WebP** (pełny rozmiar + miniaturka 400px)
   - **AVIF** (pełny rozmiar + miniaturka 400px)
   - **JPEG** (miniaturka)
3. **Oryginał** jest zachowywany

Konfiguracja w zmiennych środowiskowych:
- `IMAGE_FORMAT` – `webp`, `avif`, lub `both` (domyślnie: `both`)
- `IMAGE_QUALITY` – jakość 1-100 (domyślnie: 80)
- `IMAGE_MAX_WIDTH` – max szerokość (domyślnie: 1920px)
- `THUMB_MAX_WIDTH` – max szerokość miniaturki (domyślnie: 400px)

---

## 📋 Pola oferty

### Wymagane
- **type** – `sprzedaz` / `wynajem`
- **category** – `mieszkanie`, `dom`, `dzialka`, `lokal`, `biuro`, `garaz`, `magazyn`, `inne`
- **title** – tytuł oferty (max 200 znaków)
- **price** – cena (liczba)
- **area** – powierzchnia w m² (liczba)
- **address** – pełny adres

### Opcjonalne
- **currency** – waluta/okres (domyślnie: PLN)
- **rooms** – liczba pokoi
- **floor**, **totalFloors** – piętro / łączna liczba pięter
- **yearBuilt** – rok budowy
- **buildingType**, **buildingMaterial**, **heatingType**, **condition**, **parking** – szczegóły budynku
- **balcony**, **terrace**, **garden**, **elevator**, **basement**, **furnished** – cechy (boolean)
- **plotArea**, **plotType**, **utilities**, **fencing** – dane działki
- **city**, **district**, **street** – lokalizacja
- **latitude**, **longitude** – GPS
- **desc**, **shortDesc** – opisy
- **images** – tablica zdjęć (JSONB, WebP/AVIF/oryginał + miniaturki)
- **img** – URL głównego zdjęcia (kompatybilność)
- **features** – dodatkowe cechy (tablica stringów w JSONB)
- **rent**, **deposit** – czynsz, kaucja
- **agentName**, **agentPhone**, **agentEmail** – dane agenta
- **refNumber** – numer referencyjny
- **source**, **sourceUrl** – źródło oferty
- **videoUrl**, **virtualTourUrl** – linki do mediów
- **availableFrom** – data dostępności
- **active** – czy oferta widoczna publicznie
- **featured** – czy wyróżniona
- **slug** – auto-generowany URL slug

---

## 🔐 Bezpieczeństwo

- **JWT** z konfigurowalnym czasem ważności (wymagany JWT_SECRET min. 32 znaki)
- **bcrypt** (12 rund) do hashowania haseł
- **Helmet** – zabezpieczenia nagłówków HTTP
- **Rate limiting** – 200 żądań/15min ogólnie, 15 prób logowania/15min
- **CORS** – konfigurowalny whitelist originów
- **Multer** – walidacja typów plików i rozmiarów
- **Supabase service_role** – backend ma pełny dostęp, klucz nigdy nie jest eksponowany
- **ILIKE escape** – ochrona przed SQL injection w filtrach tekstowych
- **Brak domyślnych haseł** – wymagane ustawienie w zmiennych środowiskowych

---

## ⚙️ Notatki do konfiguracji Render

### Ważne opcje w Render:

- **Region:** `Frankfurt` (najbliżej Polski)
- **Plan:** `Free` do testów, `Starter` ($7/mies) dla produkcji (nie usypia po 15 min)
- **Disk:** Koniecznie dodaj dysk dla zdjęć (`/opt/render/project/src/uploads`, min 1 GB)
- **Auto-Deploy:** Włączone – każdy push do main wdraża automatycznie
- **Health Check Path:** `/api/health`

### Kolejność wdrażania:

1. ✅ Stwórz projekt w Supabase i uruchom `migrate.sql`
2. ✅ Wrzuć `backend/` do repo → wdroż na Render jako Web Service
3. ✅ Ustaw zmienne środowiskowe na Render (SUPABASE_URL, SUPABASE_SERVICE_KEY, JWT_SECRET, CORS_ORIGINS, ADMIN_USERNAME, ADMIN_PASSWORD)
4. ✅ Uruchom `npm run seed` w Shell na Render
5. ✅ Skopiuj URL backendu (np. `https://mww-backend.onrender.com`)
6. ✅ Zaktualizuj `admin/admin-config.js` z URL backendu
7. ✅ Wrzuć `admin/` do repo → wdroż na Render jako Static Site
8. ✅ Zaktualizuj `config.js` na stronie głównej z URL backendu

### Testowanie:

```bash
# Health check
curl https://mww-backend.onrender.com/api/health

# Logowanie
curl -X POST https://mww-backend.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"mww","password":"TWOJE_HASLO"}'

# Lista ofert (publiczna)
curl https://mww-backend.onrender.com/api/offers
```

---

## 🎨 Panel Admina – Funkcjonalności

- **Dashboard** – statystyki ofert, kategorie, ostatnio dodane
- **Lista ofert** – wyszukiwanie, filtrowanie, sortowanie, tabela z miniaturkami
- **Dodawanie oferty** – pełny formularz ze wszystkimi polami
- **Edycja oferty** – w tym samym formularzu z prefillowanymi danymi
- **Upload zdjęć** – drag & drop, automatyczna konwersja AVIF/WebP, podgląd miniaturek
- **Podgląd ofert** – karty + widok szczegółowy (jak na stronie)
- **Toggle aktywna/nieaktywna** – jednym kliknięciem
- **Toggle wyróżniona** – jednym kliknięciem
- **Usuwanie ofert** – z potwierdzeniem
- **Zmiana hasła** – w ustawieniach
- **Health check** – status backendu i bazy
- **Responsywny design** – działa na telefonie
- **Lightbox** – powiększanie zdjęć
- **Toast notifications** – potwierdzenia akcji
- **Autentykacja JWT** – bezpieczne logowanie
# mwww
