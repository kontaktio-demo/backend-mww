# 🗄️ MWW – Opis bazy danych (Supabase / PostgreSQL)

> **Skopiuj ten opis i wklej Copilotowi / ChatGPT z prośbą:**
> *"Na podstawie tego opisu wygeneruj mi jedną komendę SQL do uruchomienia w Supabase SQL Editor, która stworzy kompletną bazę danych."*

---

## Ogólne zasady

- Baza danych: **PostgreSQL** w **Supabase**
- Wszystkie ID to **UUID** generowane automatycznie (`gen_random_uuid()`)
- Konwencja nazw: **snake_case** (np. `building_type`, `price_per_m2`)
- Każda tabela ma kolumny `created_at` i `updated_at` (TIMESTAMPTZ, auto-fill)
- Trigger `update_updated_at()` automatycznie ustawia `updated_at` przy każdym UPDATE
- RLS (Row Level Security) włączony, ale z polityką "full access" bo backend łączy się przez `service_role` key
- Nazwy tabel: **liczba mnoga** (`users`, `offers`)

---

## Tabela: `users`

Przechowuje konta administracyjne panelu admina.

| Kolumna | Typ | Wymagana | Default | Opis |
|---|---|---|---|---|
| `id` | UUID | ✅ PK | `gen_random_uuid()` | Unikalny identyfikator |
| `username` | TEXT | ✅ UNIQUE | – | Login (lowercase, 3-30 znaków) |
| `password` | TEXT | ✅ | – | Zahashowane hasło (bcrypt, 12 rund) |
| `role` | TEXT | ✅ | `'admin'` | Rola: `admin` lub `editor` (CHECK constraint) |
| `active` | BOOLEAN | ✅ | `TRUE` | Czy konto aktywne |
| `last_login` | TIMESTAMPTZ | ❌ | `NULL` | Data ostatniego logowania |
| `created_at` | TIMESTAMPTZ | ✅ | `now()` | Data utworzenia |
| `updated_at` | TIMESTAMPTZ | ✅ | `now()` | Data ostatniej modyfikacji (auto-trigger) |

**Indeksy:** `username`

---

## Tabela: `offers`

Główna tabela – przechowuje oferty nieruchomości (mieszkania, domy, działki, lokale itp.)

### Pola wymagane (NOT NULL)

| Kolumna | Typ | Opis |
|---|---|---|
| `id` | UUID PK | `gen_random_uuid()` |
| `type` | TEXT | Typ transakcji: `'sprzedaz'` lub `'wynajem'` (CHECK constraint) |
| `category` | TEXT | Kategoria: `'mieszkanie'`, `'dom'`, `'dzialka'`, `'lokal'`, `'biuro'`, `'garaz'`, `'magazyn'`, `'inne'` (CHECK) |
| `title` | TEXT | Tytuł oferty (max ~200 znaków) |
| `price` | NUMERIC(14,2) | Cena (≥ 0, CHECK) |
| `area` | NUMERIC(10,2) | Powierzchnia w m² (≥ 0, CHECK) |
| `address` | TEXT | Pełny adres nieruchomości |

### Pola opcjonalne – szczegóły nieruchomości

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `currency` | TEXT | `'PLN'` | Waluta lub okres (np. `PLN`, `PLN/mies`, `EUR`) |
| `price_per_m2` | NUMERIC(10,2) | `0` | Cena za m² (obliczana automatycznie przez backend) |
| `rooms` | INT | `0` | Liczba pokoi |
| `floor` | INT | `0` | Piętro |
| `total_floors` | INT | `0` | Łączna liczba pięter w budynku |
| `year_built` | INT | `NULL` | Rok budowy |

### Pola opcjonalne – budynek

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `building_type` | TEXT | `''` | Typ budynku: blok, kamienica, apartamentowiec, dom wolnostojący, bliźniak, szeregowiec |
| `building_material` | TEXT | `''` | Materiał: cegła, wielka płyta, beton, drewno, pustak, silikat |
| `heating_type` | TEXT | `''` | Ogrzewanie: miejskie, gazowe, elektryczne, kominkowe, podłogowe |
| `condition` | TEXT | `''` | Stan: do zamieszkania, do remontu, deweloperski, po remoncie, w budowie, surowy |
| `parking` | TEXT | `''` | Parking: garaż, miejsce podziemne, miejsce naziemne, brak |

### Pola opcjonalne – cechy (boolean)

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `balcony` | BOOLEAN | `FALSE` | Czy ma balkon |
| `terrace` | BOOLEAN | `FALSE` | Czy ma taras |
| `garden` | BOOLEAN | `FALSE` | Czy ma ogród |
| `elevator` | BOOLEAN | `FALSE` | Czy jest winda |
| `basement` | BOOLEAN | `FALSE` | Czy jest piwnica |
| `furnished` | BOOLEAN | `FALSE` | Czy umeblowane |

### Pola opcjonalne – działka

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `plot_area` | NUMERIC(10,2) | `0` | Powierzchnia działki w m² |
| `plot_type` | TEXT | `''` | Typ działki: budowlana, rolna, rekreacyjna, leśna, inwestycyjna, siedliskowa |
| `utilities` | TEXT | `''` | Media/uzbrojenie: prąd, woda, gaz, kanalizacja (tekst) |
| `fencing` | BOOLEAN | `FALSE` | Czy jest ogrodzenie |

### Pola opcjonalne – lokalizacja szczegółowa

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `city` | TEXT | `''` | Miasto |
| `district` | TEXT | `''` | Dzielnica |
| `street` | TEXT | `''` | Ulica |
| `latitude` | DOUBLE PRECISION | `NULL` | Szerokość geograficzna (GPS) |
| `longitude` | DOUBLE PRECISION | `NULL` | Długość geograficzna (GPS) |

### Pola opcjonalne – opisy i media

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `description` | TEXT | `''` | Pełny opis nieruchomości (max ~5000 znaków) |
| `short_desc` | TEXT | `''` | Krótki opis na karcie oferty (max ~300 znaków) |
| `images` | JSONB | `'[]'` | Tablica zdjęć – każde zdjęcie to obiekt: `{ original, webp, avif, thumb, thumbWebp, thumbAvif, alt, order }` |
| `img` | TEXT | `''` | URL głównego zdjęcia (kompatybilność ze starym frontendem) |
| `features` | JSONB | `'[]'` | Tablica dodatkowych cech jako stringi, np. `["klimatyzacja", "alarm", "monitoring"]` |
| `video_url` | TEXT | `''` | Link do filmu (YouTube/Vimeo) |
| `virtual_tour_url` | TEXT | `''` | Link do spaceru wirtualnego 3D |

### Pola opcjonalne – koszty

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `rent` | NUMERIC(10,2) | `0` | Czynsz administracyjny (PLN/mies) |
| `deposit` | NUMERIC(10,2) | `0` | Kaucja (PLN) |

### Pola opcjonalne – SEO

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `slug` | TEXT | `NULL` | URL-friendly slug (UNIQUE, auto-generowany przez backend) |
| `meta_title` | TEXT | `''` | Tytuł SEO |
| `meta_description` | TEXT | `''` | Opis meta SEO |

### Pola opcjonalne – statusy

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `active` | BOOLEAN | `TRUE` | Czy oferta widoczna publicznie (NOT NULL) |
| `featured` | BOOLEAN | `FALSE` | Czy oferta wyróżniona (gwiazdka) |

### Pola opcjonalne – kontakt agenta

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `agent_name` | TEXT | `''` | Imię i nazwisko agenta |
| `agent_phone` | TEXT | `''` | Telefon agenta |
| `agent_email` | TEXT | `''` | Email agenta |

### Pola opcjonalne – referencje i źródło

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `ref_number` | TEXT | `''` | Numer referencyjny oferty (np. MWW-001) |
| `source` | TEXT | `''` | Źródło oferty (np. otodom, olx, własne) |
| `source_url` | TEXT | `''` | URL źródłowy oferty |

### Pola opcjonalne – daty i statystyki

| Kolumna | Typ | Default | Opis |
|---|---|---|---|
| `available_from` | DATE | `NULL` | Data dostępności nieruchomości |
| `created_at` | TIMESTAMPTZ | `now()` | Data utworzenia oferty (NOT NULL) |
| `updated_at` | TIMESTAMPTZ | `now()` | Data ostatniej modyfikacji (NOT NULL, auto-trigger) |
| `views` | INT | `0` | Liczba wyświetleń (inkrementowana przez backend) |

---

## Indeksy na tabeli `offers`

| Nazwa indeksu | Kolumna(y) | Po co |
|---|---|---|
| `idx_offers_active` | `active` | Szybkie filtrowanie aktywnych ofert |
| `idx_offers_type` | `type` | Filtrowanie sprzedaż/wynajem |
| `idx_offers_category` | `category` | Filtrowanie po kategorii |
| `idx_offers_price` | `price` | Sortowanie i filtrowanie po cenie |
| `idx_offers_area` | `area` | Sortowanie i filtrowanie po powierzchni |
| `idx_offers_city` | `city` | Filtrowanie po mieście |
| `idx_offers_featured` | `featured DESC, created_at DESC` | Wyróżnione oferty na górze |
| `idx_offers_created` | `created_at DESC` | Sortowanie od najnowszych |
| `idx_offers_slug` | `slug` | Szybkie wyszukiwanie po slug (URL) |

---

## Trigger

Funkcja `update_updated_at()` – automatycznie ustawia kolumnę `updated_at` na `now()` przy każdym UPDATE na obu tabelach (`users` i `offers`).

---

## Row Level Security (RLS)

- RLS **włączony** na obu tabelach
- Polityka "full access" (`USING (true) WITH CHECK (true)`) – ponieważ backend łączy się kluczem `service_role` który omija RLS
- Dzięki temu nikt z kluczem `anon` nie ma dostępu do danych bezpośrednio przez Supabase API

---

## Struktura JSONB kolumny `images`

Każdy element tablicy `images` to obiekt o strukturze:

```json
{
  "original": "/uploads/abc123-original.jpg",
  "webp": "/uploads/abc123.webp",
  "avif": "/uploads/abc123.avif",
  "thumb": "/uploads/abc123-thumb.jpg",
  "thumbWebp": "/uploads/abc123-thumb.webp",
  "thumbAvif": "/uploads/abc123-thumb.avif",
  "alt": "Zdjęcie salonu",
  "order": 0
}
```

Zdjęcia są przesyłane przez backend (endpoint `/api/images/upload`) i automatycznie konwertowane do WebP + AVIF + miniaturek przez bibliotekę Sharp.

---

## Struktura JSONB kolumny `features`

Prosta tablica stringów:

```json
["klimatyzacja", "alarm", "monitoring", "wideo-domofon", "pralka", "zmywarka"]
```
