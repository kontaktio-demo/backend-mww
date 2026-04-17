-- ============================================================
--  MWW Backend – Supabase / PostgreSQL Migration
-- ============================================================
--  Uruchom ten SQL w Supabase Dashboard → SQL Editor → New Query
--  Lub przez CLI: supabase db push
-- ============================================================

-- ─── Tabela: users ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password      TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'editor')),
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  last_login    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- ─── Tabela: offers ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS offers (
  id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,

  -- Podstawowe (wymagane)
  type            TEXT NOT NULL CHECK (type IN ('sprzedaz', 'wynajem')),
  category        TEXT NOT NULL CHECK (category IN ('mieszkanie','dom','dzialka','lokal','biuro','garaz','magazyn','inne')),
  title           TEXT NOT NULL,
  price           NUMERIC(14,2) NOT NULL CHECK (price >= 0),
  area            NUMERIC(10,2) NOT NULL CHECK (area >= 0),
  address         TEXT NOT NULL,

  -- Rozszerzone (opcjonalne)
  currency        TEXT DEFAULT 'PLN',
  price_per_m2    NUMERIC(10,2) DEFAULT 0,
  rooms           INT DEFAULT 0,
  floor           INT DEFAULT 0,
  total_floors    INT DEFAULT 0,
  year_built      INT,

  -- Budynek
  building_type     TEXT DEFAULT '',
  building_material TEXT DEFAULT '',
  heating_type      TEXT DEFAULT '',
  condition         TEXT DEFAULT '',
  parking           TEXT DEFAULT '',
  balcony           BOOLEAN DEFAULT FALSE,
  terrace           BOOLEAN DEFAULT FALSE,
  garden            BOOLEAN DEFAULT FALSE,
  elevator          BOOLEAN DEFAULT FALSE,
  basement          BOOLEAN DEFAULT FALSE,
  furnished         BOOLEAN DEFAULT FALSE,

  -- Działka
  plot_area         NUMERIC(10,2) DEFAULT 0,
  plot_type         TEXT DEFAULT '',
  utilities         TEXT DEFAULT '',
  fencing           BOOLEAN DEFAULT FALSE,

  -- Lokalizacja
  city              TEXT DEFAULT '',
  district          TEXT DEFAULT '',
  street            TEXT DEFAULT '',
  latitude          DOUBLE PRECISION,
  longitude         DOUBLE PRECISION,

  -- Opisy
  description       TEXT DEFAULT '',
  short_desc        TEXT DEFAULT '',

  -- Zdjęcia (JSONB array)
  images            JSONB DEFAULT '[]'::jsonb,
  img               TEXT DEFAULT '',

  -- Cechy dodatkowe (JSONB array of strings)
  features          JSONB DEFAULT '[]'::jsonb,

  -- Koszty
  rent              NUMERIC(10,2) DEFAULT 0,
  deposit           NUMERIC(10,2) DEFAULT 0,

  -- SEO
  slug              TEXT UNIQUE,
  meta_title        TEXT DEFAULT '',
  meta_description  TEXT DEFAULT '',

  -- Statusy
  active            BOOLEAN NOT NULL DEFAULT TRUE,
  featured          BOOLEAN DEFAULT FALSE,

  -- Kontakt agenta
  agent_name        TEXT DEFAULT '',
  agent_phone       TEXT DEFAULT '',
  agent_email       TEXT DEFAULT '',

  -- Referencje
  ref_number        TEXT DEFAULT '',
  source            TEXT DEFAULT '',
  source_url        TEXT DEFAULT '',

  -- Media
  video_url           TEXT DEFAULT '',
  virtual_tour_url    TEXT DEFAULT '',

  -- Daty
  available_from    DATE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Statystyki
  views             INT DEFAULT 0
);

-- Indeksy
CREATE INDEX IF NOT EXISTS idx_offers_active       ON offers (active);
CREATE INDEX IF NOT EXISTS idx_offers_type         ON offers (type);
CREATE INDEX IF NOT EXISTS idx_offers_category     ON offers (category);
CREATE INDEX IF NOT EXISTS idx_offers_price        ON offers (price);
CREATE INDEX IF NOT EXISTS idx_offers_area         ON offers (area);
CREATE INDEX IF NOT EXISTS idx_offers_city         ON offers (city);
CREATE INDEX IF NOT EXISTS idx_offers_featured     ON offers (featured DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_offers_created      ON offers (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_offers_slug         ON offers (slug);

-- ─── Trigger: auto-update updated_at ─────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_offers_updated ON offers;
CREATE TRIGGER trg_offers_updated
  BEFORE UPDATE ON offers
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS trg_users_updated ON users;
CREATE TRIGGER trg_users_updated
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Wyłącz RLS (backend używa service_role key) ────────
ALTER TABLE users  ENABLE ROW LEVEL SECURITY;
ALTER TABLE offers ENABLE ROW LEVEL SECURITY;

-- Polityka: service_role ma pełny dostęp (domyślnie),
-- ale dodajmy jawną politykę dla jasności
CREATE POLICY "Service role full access on users"
  ON users FOR ALL
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role full access on offers"
  ON offers FOR ALL
  USING (true)
  WITH CHECK (true);
