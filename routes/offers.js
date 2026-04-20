'use strict';

const router = require('express').Router();
const crypto = require('crypto');
const supabase = require('../db');
const auth = require('../middleware/auth');
const { requireAdmin } = require('../middleware/auth');
const { deleteImageFiles } = require('../utils/imageProcessor');
const { isValidUUID, isSafeUrl, sanitiseString, sanitiseImages, sanitiseFeatures } = require('../utils/security');

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,200}$/;

const ALLOWED_TYPES = new Set(['sprzedaz', 'wynajem']);
const ALLOWED_SORT = new Set(['price-asc', 'price-desc', 'area-asc', 'area-desc', 'oldest', 'featured', 'newest']);

function escapeILike(str) {
  return String(str).replace(/[%_\\]/g, c => '\\' + c);
}

function safeNumber(v, fallback = 0, min = -1e15, max = 1e15) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function safeInt(v, fallback = 0, min = -2147483648, max = 2147483647) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function generateSlug(title) {
  const base = String(title)
    .toLowerCase()
    .replace(/ą/g, 'a').replace(/à/g, 'a')
    .replace(/ć/g, 'c').replace(/ç/g, 'c')
    .replace(/ę/g, 'e').replace(/è/g, 'e')
    .replace(/ł/g, 'l')
    .replace(/ń/g, 'n').replace(/ñ/g, 'n')
    .replace(/ó/g, 'o').replace(/ò/g, 'o')
    .replace(/ś/g, 's').replace(/š/g, 's')
    .replace(/[źżž]/g, 'z')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 100);
  const suffix = crypto.randomBytes(6).toString('hex');
  const slug = (base || 'oferta') + '-' + suffix;
  return slug.substring(0, 200);
}

function buildOfferRow(body) {
  const row = {};
  if (!body || typeof body !== 'object' || Array.isArray(body)) return row;

  if (body.type !== undefined) {
    const t = sanitiseString(body.type, 20).toLowerCase();
    row.type = ALLOWED_TYPES.has(t) ? t : '';
  }
  if (body.category !== undefined) row.category = sanitiseString(body.category, 30);
  if (body.title !== undefined) row.title = sanitiseString(body.title, 200);
  if (body.price !== undefined) row.price = Math.max(0, safeNumber(body.price, 0, 0, 1e12));
  if (body.area !== undefined) row.area = Math.max(0, safeNumber(body.area, 0, 0, 1e9));
  if (body.address !== undefined) row.address = sanitiseString(body.address, 500);

  if (body.currency !== undefined) row.currency = sanitiseString(body.currency || 'PLN', 10);
  if (body.rooms !== undefined) row.rooms = Math.max(0, safeInt(body.rooms, 0, 0, 1000));
  if (body.floor !== undefined) row.floor = safeInt(body.floor, 0, -10, 1000);
  if (body.totalFloors !== undefined) row.total_floors = Math.max(0, safeInt(body.totalFloors, 0, 0, 1000));
  if (body.yearBuilt !== undefined) row.year_built = body.yearBuilt ? safeInt(body.yearBuilt, null, 1500, 2200) : null;

  if (body.buildingType !== undefined) row.building_type = sanitiseString(body.buildingType, 100);
  if (body.buildingMaterial !== undefined) row.building_material = sanitiseString(body.buildingMaterial, 100);
  if (body.heatingType !== undefined) row.heating_type = sanitiseString(body.heatingType, 100);
  if (body.condition !== undefined) row.condition = sanitiseString(body.condition, 100);
  if (body.parking !== undefined) row.parking = sanitiseString(body.parking, 100);

  const bools = ['balcony', 'terrace', 'garden', 'elevator', 'basement', 'furnished', 'fencing', 'active', 'featured'];
  for (const k of bools) {
    if (body[k] !== undefined) row[k] = Boolean(body[k]);
  }

  if (body.plotArea !== undefined) row.plot_area = Math.max(0, safeNumber(body.plotArea, 0, 0, 1e9));
  if (body.plotType !== undefined) row.plot_type = sanitiseString(body.plotType, 100);
  if (body.utilities !== undefined) row.utilities = sanitiseString(body.utilities, 300);

  if (body.city !== undefined) row.city = sanitiseString(body.city, 100);
  if (body.district !== undefined) row.district = sanitiseString(body.district, 100);
  if (body.street !== undefined) row.street = sanitiseString(body.street, 200);
  if (body.latitude !== undefined) {
    if (body.latitude === null || body.latitude === '') row.latitude = null;
    else { const n = safeNumber(body.latitude, NaN, -90, 90); row.latitude = Number.isFinite(n) ? n : null; }
  }
  if (body.longitude !== undefined) {
    if (body.longitude === null || body.longitude === '') row.longitude = null;
    else { const n = safeNumber(body.longitude, NaN, -180, 180); row.longitude = Number.isFinite(n) ? n : null; }
  }

  if (body.desc !== undefined) row.description = sanitiseString(body.desc, 5000);
  if (body.shortDesc !== undefined) row.short_desc = sanitiseString(body.shortDesc, 300);

  if (body.images !== undefined) row.images = sanitiseImages(body.images);
  if (body.img !== undefined) {
    const v = sanitiseString(body.img, 500);
    row.img = (v === '' || /^\/uploads\/[A-Za-z0-9._-]{1,200}$/.test(v)) ? v : '';
  }

  if (body.features !== undefined) row.features = sanitiseFeatures(body.features);

  if (body.rent !== undefined) row.rent = Math.max(0, safeNumber(body.rent, 0, 0, 1e9));
  if (body.deposit !== undefined) row.deposit = Math.max(0, safeNumber(body.deposit, 0, 0, 1e9));

  if (body.metaTitle !== undefined) row.meta_title = sanitiseString(body.metaTitle, 200);
  if (body.metaDescription !== undefined) row.meta_description = sanitiseString(body.metaDescription, 500);

  if (body.agentName !== undefined) row.agent_name = sanitiseString(body.agentName, 100);
  if (body.agentPhone !== undefined) row.agent_phone = sanitiseString(body.agentPhone, 30);
  if (body.agentEmail !== undefined) row.agent_email = sanitiseString(body.agentEmail, 200);

  if (body.refNumber !== undefined) row.ref_number = sanitiseString(body.refNumber, 50);
  if (body.source !== undefined) row.source = sanitiseString(body.source, 100);
  if (body.sourceUrl !== undefined) {
    const url = sanitiseString(body.sourceUrl, 2000);
    row.source_url = isSafeUrl(url) ? url : '';
  }

  if (body.videoUrl !== undefined) {
    const url = sanitiseString(body.videoUrl, 2000);
    row.video_url = isSafeUrl(url) ? url : '';
  }
  if (body.virtualTourUrl !== undefined) {
    const url = sanitiseString(body.virtualTourUrl, 2000);
    row.virtual_tour_url = isSafeUrl(url) ? url : '';
  }

  if (body.availableFrom !== undefined) {
    if (!body.availableFrom) row.available_from = null;
    else {
      const s = sanitiseString(body.availableFrom, 30);
      row.available_from = /^\d{4}-\d{2}-\d{2}/.test(s) ? s : null;
    }
  }

  const price = row.price ?? safeNumber(body.price, 0);
  const area = row.area ?? safeNumber(body.area, 0);
  if (price && area && area > 0) {
    row.price_per_m2 = Math.round(price / area);
  }

  if (row.images && row.images.length > 0 && !row.img) {
    const first = row.images[0];
    row.img = first.webp || first.avif || first.original || '';
  }

  return row;
}

function rowToApi(r) {
  if (!r) return null;
  return {
    id: r.id,
    type: r.type,
    category: r.category,
    title: r.title,
    price: Number(r.price),
    area: Number(r.area),
    address: r.address,
    currency: r.currency,
    pricePerM2: Number(r.price_per_m2) || 0,
    rooms: r.rooms,
    floor: r.floor,
    totalFloors: r.total_floors,
    yearBuilt: r.year_built,
    buildingType: r.building_type,
    buildingMaterial: r.building_material,
    heatingType: r.heating_type,
    condition: r.condition,
    parking: r.parking,
    balcony: r.balcony,
    terrace: r.terrace,
    garden: r.garden,
    elevator: r.elevator,
    basement: r.basement,
    furnished: r.furnished,
    plotArea: Number(r.plot_area) || 0,
    plotType: r.plot_type,
    utilities: r.utilities,
    fencing: r.fencing,
    city: r.city,
    district: r.district,
    street: r.street,
    latitude: r.latitude,
    longitude: r.longitude,
    desc: r.description,
    shortDesc: r.short_desc,
    images: r.images || [],
    img: r.img,
    features: r.features || [],
    rent: Number(r.rent) || 0,
    deposit: Number(r.deposit) || 0,
    slug: r.slug,
    metaTitle: r.meta_title,
    metaDescription: r.meta_description,
    active: r.active,
    featured: r.featured,
    agentName: r.agent_name,
    agentPhone: r.agent_phone,
    agentEmail: r.agent_email,
    refNumber: r.ref_number,
    source: r.source,
    sourceUrl: r.source_url,
    videoUrl: r.video_url,
    virtualTourUrl: r.virtual_tour_url,
    availableFrom: r.available_from,
    views: r.views,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

router.get('/', async (req, res) => {
  try {
    let query = supabase.from('offers').select('*', { count: 'exact' });
    query = query.eq('active', true);

    if (req.query.type) {
      const t = String(req.query.type).toLowerCase();
      if (ALLOWED_TYPES.has(t)) query = query.eq('type', t);
    }
    if (req.query.category) {
      const c = sanitiseString(String(req.query.category), 30);
      if (c) query = query.eq('category', c);
    }
    if (req.query.featured === 'true') query = query.eq('featured', true);

    if (req.query.city) {
      const c = sanitiseString(String(req.query.city), 100);
      if (c) query = query.ilike('city', '%' + escapeILike(c) + '%');
    }
    if (req.query.district) {
      const d = sanitiseString(String(req.query.district), 100);
      if (d) query = query.ilike('district', '%' + escapeILike(d) + '%');
    }
    if (req.query.priceMin) query = query.gte('price', safeNumber(req.query.priceMin, 0, 0, 1e12));
    if (req.query.priceMax) query = query.lte('price', safeNumber(req.query.priceMax, 0, 0, 1e12));
    if (req.query.areaMin) query = query.gte('area', safeNumber(req.query.areaMin, 0, 0, 1e9));
    if (req.query.areaMax) query = query.lte('area', safeNumber(req.query.areaMax, 0, 0, 1e9));

    if (req.query.rooms) {
      const r = safeInt(req.query.rooms, 0, 0, 100);
      if (r >= 4) query = query.gte('rooms', 4);
      else if (r > 0) query = query.eq('rooms', r);
    }

    if (req.query.q) {
      const raw = String(req.query.q).slice(0, 100);
      const cleaned = sanitiseString(raw, 100);
      if (cleaned) {
        const pattern = '%' + escapeILike(cleaned) + '%';
        query = query.or(
          'title.ilike.' + pattern + ',address.ilike.' + pattern + ',description.ilike.' + pattern + ',city.ilike.' + pattern + ',district.ilike.' + pattern
        );
      }
    }

    const sort = ALLOWED_SORT.has(String(req.query.sort)) ? String(req.query.sort) : 'newest';
    switch (sort) {
      case 'price-asc':  query = query.order('price', { ascending: true }); break;
      case 'price-desc': query = query.order('price', { ascending: false }); break;
      case 'area-desc':  query = query.order('area', { ascending: false }); break;
      case 'area-asc':   query = query.order('area', { ascending: true }); break;
      case 'oldest':     query = query.order('created_at', { ascending: true }); break;
      case 'featured':
        query = query.order('featured', { ascending: false }).order('created_at', { ascending: false });
        break;
      default:
        query = query.order('created_at', { ascending: false });
    }

    const page = Math.max(1, Math.min(10000, safeInt(req.query.page, 1, 1, 10000)));
    const limit = Math.min(100, Math.max(1, safeInt(req.query.limit, 50, 1, 100)));
    const from = (page - 1) * limit;
    query = query.range(from, from + limit - 1);

    const { data: rows, error, count } = await query;
    if (error) throw error;

    const result = (rows || []).map(rowToApi);

    if (req.query.meta === 'true') {
      return res.json({
        data: result,
        meta: { total: count || 0, page, limit, pages: Math.ceil((count || 0) / limit) },
      });
    }

    res.json(result);
  } catch {
    res.status(500).json({ error: 'Błąd pobierania ofert.' });
  }
});

router.get('/stats', async (_req, res) => {
  try {
    const [totalR, activeR, sprzedazR, wynajemR, catsR] = await Promise.all([
      supabase.from('offers').select('id', { count: 'exact', head: true }),
      supabase.from('offers').select('id', { count: 'exact', head: true }).eq('active', true),
      supabase.from('offers').select('id', { count: 'exact', head: true }).eq('active', true).eq('type', 'sprzedaz'),
      supabase.from('offers').select('id', { count: 'exact', head: true }).eq('active', true).eq('type', 'wynajem'),
      supabase.from('offers').select('category').eq('active', true),
    ]);

    const total = totalR.count || 0;
    const active = activeR.count || 0;
    const sprzedaz = sprzedazR.count || 0;
    const wynajem = wynajemR.count || 0;

    const categories = {};
    for (const row of (catsR.data || [])) {
      categories[row.category] = (categories[row.category] || 0) + 1;
    }

    res.json({ total, active, inactive: total - active, sprzedaz, wynajem, categories });
  } catch {
    res.status(500).json({ error: 'Błąd pobierania statystyk.' });
  }
});

router.get('/all', auth, requireAdmin, async (_req, res) => {
  try {
    const { data, error } = await supabase
      .from('offers')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.set('Cache-Control', 'no-store');
    res.json((data || []).map(rowToApi));
  } catch {
    res.status(500).json({ error: 'Błąd pobierania ofert.' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').slice(0, 250);
    let row = null;

    if (isValidUUID(id)) {
      const { data } = await supabase.from('offers').select('*').eq('id', id).single();
      row = data;
    } else if (SLUG_RE.test(id)) {
      const { data } = await supabase.from('offers').select('*').eq('slug', id).single();
      row = data;
    }

    if (!row) {
      return res.status(404).json({ error: 'Oferta nie została znaleziona.' });
    }

    if (!row.active) {
      return res.status(404).json({ error: 'Oferta nie została znaleziona.' });
    }

    supabase.from('offers').update({ views: (row.views || 0) + 1 }).eq('id', row.id).then(() => {}, () => {});

    res.json(rowToApi(row));
  } catch {
    res.status(500).json({ error: 'Błąd pobierania oferty.' });
  }
});

router.post('/', auth, requireAdmin, async (req, res) => {
  try {
    const row = buildOfferRow(req.body);

    if (!row.title || !row.price || !row.area || !row.address || !row.type || !row.category) {
      return res.status(400).json({ error: 'Wymagane pola: type, category, title, price, area, address.' });
    }

    row.slug = generateSlug(row.title);

    const { data, error } = await supabase
      .from('offers')
      .insert(row)
      .select('*')
      .single();

    if (error) throw error;
    res.status(201).json(rowToApi(data));
  } catch {
    res.status(500).json({ error: 'Błąd tworzenia oferty.' });
  }
});

router.patch('/:id', auth, requireAdmin, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator oferty.' });
    }
    const row = buildOfferRow(req.body);
    delete row.id;
    delete row.created_at;
    delete row.views;

    const { data, error } = await supabase
      .from('offers')
      .update(row)
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    res.json(rowToApi(data));
  } catch {
    res.status(500).json({ error: 'Błąd aktualizacji oferty.' });
  }
});

router.put('/:id', auth, requireAdmin, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator oferty.' });
    }
    const row = buildOfferRow(req.body);
    delete row.id;
    delete row.created_at;
    delete row.views;

    const { data, error } = await supabase
      .from('offers')
      .update(row)
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    res.json(rowToApi(data));
  } catch {
    res.status(500).json({ error: 'Błąd aktualizacji oferty.' });
  }
});

router.patch('/:id/toggle', auth, requireAdmin, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator oferty.' });
    }
    const { data: current, error: fetchErr } = await supabase
      .from('offers')
      .select('id, active')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !current) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const { data, error } = await supabase
      .from('offers')
      .update({ active: !current.active })
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    res.json(rowToApi(data));
  } catch {
    res.status(500).json({ error: 'Błąd zmiany statusu oferty.' });
  }
});

router.patch('/:id/featured', auth, requireAdmin, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator oferty.' });
    }
    const { data: current, error: fetchErr } = await supabase
      .from('offers')
      .select('id, featured')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !current) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const { data, error } = await supabase
      .from('offers')
      .update({ featured: !current.featured })
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    res.json(rowToApi(data));
  } catch {
    res.status(500).json({ error: 'Błąd zmiany statusu wyróżnienia.' });
  }
});

router.delete('/:id', auth, requireAdmin, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator oferty.' });
    }
    const { data: offer, error: fetchErr } = await supabase
      .from('offers')
      .select('id, images')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !offer) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const imgs = Array.isArray(offer.images) ? offer.images : [];
    for (const img of imgs) {
      await deleteImageFiles(img);
    }

    const { error } = await supabase
      .from('offers')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ message: 'Oferta została usunięta.' });
  } catch {
    res.status(500).json({ error: 'Błąd usuwania oferty.' });
  }
});

router.post('/:id/images', auth, requireAdmin, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator oferty.' });
    }
    const { data: offer, error: fetchErr } = await supabase
      .from('offers')
      .select('id, images, img')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !offer) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const newImages = sanitiseImages(req.body && req.body.images);
    if (!Array.isArray(newImages) || newImages.length === 0) {
      return res.status(400).json({ error: 'Brak zdjęć do dodania.' });
    }

    const existing = Array.isArray(offer.images) ? offer.images : [];
    const allImages = [...existing, ...newImages].slice(0, 50);

    let img = offer.img;
    if (allImages.length > 0) {
      const first = allImages[0];
      img = first.webp || first.avif || first.original || img;
    }

    const { data, error } = await supabase
      .from('offers')
      .update({ images: allImages, img })
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    res.json(rowToApi(data));
  } catch {
    res.status(500).json({ error: 'Błąd dodawania zdjęć.' });
  }
});

router.delete('/:id/images/:imageIndex', auth, requireAdmin, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) {
      return res.status(400).json({ error: 'Nieprawidłowy identyfikator oferty.' });
    }
    const { data: offer, error: fetchErr } = await supabase
      .from('offers')
      .select('id, images')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !offer) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const idx = parseInt(req.params.imageIndex, 10);
    const imgs = Array.isArray(offer.images) ? offer.images.slice() : [];
    if (!Number.isInteger(idx) || idx < 0 || idx >= imgs.length) {
      return res.status(400).json({ error: 'Nieprawidłowy indeks zdjęcia.' });
    }

    await deleteImageFiles(imgs[idx]);
    imgs.splice(idx, 1);

    let img = '';
    if (imgs.length > 0) {
      const first = imgs[0];
      img = first.webp || first.avif || first.original || '';
    }

    const { data, error } = await supabase
      .from('offers')
      .update({ images: imgs, img })
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    res.json(rowToApi(data));
  } catch {
    res.status(500).json({ error: 'Błąd usuwania zdjęcia.' });
  }
});

module.exports = router;
