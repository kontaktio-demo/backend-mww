'use strict';

const router = require('express').Router();
const supabase = require('../db');
const auth = require('../middleware/auth');
const { deleteImageFiles } = require('../utils/imageProcessor');

// ─── Helpers ─────────────────────────────────────────────

/** Escape special characters for Postgres ILIKE pattern */
function escapeILike(str) {
  return String(str).replace(/[%_\\]/g, c => '\\' + c);
}

/** Generate a URL-friendly slug from title */
function generateSlug(title) {
  return String(title)
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
    .substring(0, 120)
    + '-' + Date.now().toString(36);
}

/** Build an offer row from request body (maps camelCase → snake_case) */
function buildOfferRow(body) {
  const row = {};

  // Required
  if (body.type !== undefined) row.type = String(body.type);
  if (body.category !== undefined) row.category = String(body.category);
  if (body.title !== undefined) row.title = String(body.title).substring(0, 200);
  if (body.price !== undefined) row.price = Number(body.price) || 0;
  if (body.area !== undefined) row.area = Number(body.area) || 0;
  if (body.address !== undefined) row.address = String(body.address).substring(0, 500);

  // Optional scalars
  if (body.currency !== undefined) row.currency = String(body.currency || 'PLN');
  if (body.rooms !== undefined) row.rooms = parseInt(body.rooms, 10) || 0;
  if (body.floor !== undefined) row.floor = parseInt(body.floor, 10) || 0;
  if (body.totalFloors !== undefined) row.total_floors = parseInt(body.totalFloors, 10) || 0;
  if (body.yearBuilt !== undefined) row.year_built = parseInt(body.yearBuilt, 10) || null;

  // Building
  if (body.buildingType !== undefined) row.building_type = String(body.buildingType || '');
  if (body.buildingMaterial !== undefined) row.building_material = String(body.buildingMaterial || '');
  if (body.heatingType !== undefined) row.heating_type = String(body.heatingType || '');
  if (body.condition !== undefined) row.condition = String(body.condition || '');
  if (body.parking !== undefined) row.parking = String(body.parking || '');

  // Booleans
  const bools = ['balcony','terrace','garden','elevator','basement','furnished','fencing','active','featured'];
  for (const k of bools) {
    if (body[k] !== undefined) row[k] = Boolean(body[k]);
  }

  // Plot
  if (body.plotArea !== undefined) row.plot_area = Number(body.plotArea) || 0;
  if (body.plotType !== undefined) row.plot_type = String(body.plotType || '');
  if (body.utilities !== undefined) row.utilities = String(body.utilities || '');

  // Location
  if (body.city !== undefined) row.city = String(body.city || '');
  if (body.district !== undefined) row.district = String(body.district || '');
  if (body.street !== undefined) row.street = String(body.street || '');
  if (body.latitude !== undefined) row.latitude = body.latitude ? Number(body.latitude) : null;
  if (body.longitude !== undefined) row.longitude = body.longitude ? Number(body.longitude) : null;

  // Descriptions
  if (body.desc !== undefined) row.description = String(body.desc || '').substring(0, 5000);
  if (body.shortDesc !== undefined) row.short_desc = String(body.shortDesc || '').substring(0, 300);

  // Images
  if (body.images !== undefined) row.images = Array.isArray(body.images) ? body.images : [];
  if (body.img !== undefined) row.img = String(body.img || '');

  // Features
  if (body.features !== undefined) row.features = Array.isArray(body.features) ? body.features : [];

  // Costs
  if (body.rent !== undefined) row.rent = Number(body.rent) || 0;
  if (body.deposit !== undefined) row.deposit = Number(body.deposit) || 0;

  // SEO
  if (body.metaTitle !== undefined) row.meta_title = String(body.metaTitle || '');
  if (body.metaDescription !== undefined) row.meta_description = String(body.metaDescription || '');

  // Agent
  if (body.agentName !== undefined) row.agent_name = String(body.agentName || '');
  if (body.agentPhone !== undefined) row.agent_phone = String(body.agentPhone || '');
  if (body.agentEmail !== undefined) row.agent_email = String(body.agentEmail || '');

  // Refs & source
  if (body.refNumber !== undefined) row.ref_number = String(body.refNumber || '');
  if (body.source !== undefined) row.source = String(body.source || '');
  if (body.sourceUrl !== undefined) row.source_url = String(body.sourceUrl || '');

  // Media
  if (body.videoUrl !== undefined) row.video_url = String(body.videoUrl || '');
  if (body.virtualTourUrl !== undefined) row.virtual_tour_url = String(body.virtualTourUrl || '');

  // Dates
  if (body.availableFrom !== undefined) row.available_from = body.availableFrom || null;

  // Auto-calculate price per m²
  const price = row.price ?? body.price;
  const area = row.area ?? body.area;
  if (price && area && area > 0) {
    row.price_per_m2 = Math.round(price / area);
  }

  // Set main img from first image if needed
  if (row.images && row.images.length > 0 && !row.img) {
    const first = row.images[0];
    row.img = first.webp || first.avif || first.original || '';
  }

  return row;
}

/** Convert a DB row (snake_case) back to camelCase for API response */
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

// ─────────────────────────────────────────────────────────
// PUBLIC ROUTES
// ─────────────────────────────────────────────────────────

/**
 * GET /api/offers
 * Public – active offers with filters, sorting, pagination
 */
router.get('/', async (req, res) => {
  try {
    let query = supabase.from('offers').select('*', { count: 'exact' });

    // Always filter active for public
    query = query.eq('active', true);

    // Filters
    if (req.query.type) query = query.eq('type', String(req.query.type));
    if (req.query.category) query = query.eq('category', String(req.query.category));
    if (req.query.featured === 'true') query = query.eq('featured', true);

    if (req.query.city) {
      query = query.ilike('city', '%' + escapeILike(req.query.city) + '%');
    }
    if (req.query.district) {
      query = query.ilike('district', '%' + escapeILike(req.query.district) + '%');
    }
    if (req.query.priceMin) query = query.gte('price', Number(req.query.priceMin));
    if (req.query.priceMax) query = query.lte('price', Number(req.query.priceMax));
    if (req.query.areaMin) query = query.gte('area', Number(req.query.areaMin));
    if (req.query.areaMax) query = query.lte('area', Number(req.query.areaMax));

    if (req.query.rooms) {
      const r = Number(req.query.rooms);
      if (r >= 4) {
        query = query.gte('rooms', 4);
      } else {
        query = query.eq('rooms', r);
      }
    }

    // Text search (ILIKE on title, address, description)
    if (req.query.q) {
      const pattern = '%' + escapeILike(req.query.q) + '%';
      query = query.or(
        'title.ilike.' + pattern + ',address.ilike.' + pattern + ',description.ilike.' + pattern + ',city.ilike.' + pattern + ',district.ilike.' + pattern
      );
    }

    // Sorting
    switch (req.query.sort) {
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

    // Pagination
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
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
  } catch (err) {
    console.error('GET /api/offers error:', err);
    res.status(500).json({ error: 'Błąd pobierania ofert.' });
  }
});

/**
 * GET /api/offers/stats
 * Public – offer statistics
 */
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
  } catch (err) {
    console.error('GET /api/offers/stats error:', err);
    res.status(500).json({ error: 'Błąd pobierania statystyk.' });
  }
});

// ─────────────────────────────────────────────────────────
// ADMIN – GET ALL (before /:id to avoid conflict)
// ─────────────────────────────────────────────────────────

router.get('/all', auth, async (_req, res) => {
  try {
    const { data, error } = await supabase
      .from('offers')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json((data || []).map(rowToApi));
  } catch (err) {
    console.error('GET /api/offers/all error:', err);
    res.status(500).json({ error: 'Błąd pobierania ofert.' });
  }
});

// ─────────────────────────────────────────────────────────
// PUBLIC – single offer (after /all and /stats)
// ─────────────────────────────────────────────────────────

router.get('/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    let row = null;

    // UUID pattern
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      const { data } = await supabase.from('offers').select('*').eq('id', id).single();
      row = data;
    }

    // Try slug
    if (!row) {
      const { data } = await supabase.from('offers').select('*').eq('slug', id).single();
      row = data;
    }

    if (!row) {
      return res.status(404).json({ error: 'Oferta nie została znaleziona.' });
    }

    // Increment views
    await supabase.from('offers').update({ views: (row.views || 0) + 1 }).eq('id', row.id);

    res.json(rowToApi(row));
  } catch (err) {
    console.error('GET /api/offers/:id error:', err);
    res.status(500).json({ error: 'Błąd pobierania oferty.' });
  }
});

// ─────────────────────────────────────────────────────────
// ADMIN – CRUD
// ─────────────────────────────────────────────────────────

router.post('/', auth, async (req, res) => {
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
  } catch (err) {
    console.error('POST /api/offers error:', err);
    res.status(500).json({ error: 'Błąd tworzenia oferty.' });
  }
});

router.patch('/:id', auth, async (req, res) => {
  try {
    const row = buildOfferRow(req.body);

    const { data, error } = await supabase
      .from('offers')
      .update(row)
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    res.json(rowToApi(data));
  } catch (err) {
    console.error('PATCH /api/offers/:id error:', err);
    res.status(500).json({ error: 'Błąd aktualizacji oferty.' });
  }
});

router.put('/:id', auth, async (req, res) => {
  try {
    const row = buildOfferRow(req.body);

    const { data, error } = await supabase
      .from('offers')
      .update(row)
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    res.json(rowToApi(data));
  } catch (err) {
    console.error('PUT /api/offers/:id error:', err);
    res.status(500).json({ error: 'Błąd aktualizacji oferty.' });
  }
});

router.patch('/:id/toggle', auth, async (req, res) => {
  try {
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
  } catch (err) {
    console.error('PATCH /api/offers/:id/toggle error:', err);
    res.status(500).json({ error: 'Błąd zmiany statusu oferty.' });
  }
});

router.patch('/:id/featured', auth, async (req, res) => {
  try {
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
  } catch (err) {
    console.error('PATCH /api/offers/:id/featured error:', err);
    res.status(500).json({ error: 'Błąd zmiany statusu wyróżnienia.' });
  }
});

router.delete('/:id', auth, async (req, res) => {
  try {
    const { data: offer, error: fetchErr } = await supabase
      .from('offers')
      .select('id, images')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !offer) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const imgs = offer.images || [];
    for (const img of imgs) {
      await deleteImageFiles(img);
    }

    const { error } = await supabase
      .from('offers')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ message: 'Oferta została usunięta.' });
  } catch (err) {
    console.error('DELETE /api/offers/:id error:', err);
    res.status(500).json({ error: 'Błąd usuwania oferty.' });
  }
});

router.post('/:id/images', auth, async (req, res) => {
  try {
    const { data: offer, error: fetchErr } = await supabase
      .from('offers')
      .select('id, images, img')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !offer) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const newImages = req.body.images || [];
    if (!Array.isArray(newImages) || newImages.length === 0) {
      return res.status(400).json({ error: 'Brak zdjęć do dodania.' });
    }

    const allImages = [...(offer.images || []), ...newImages];

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
  } catch (err) {
    console.error('POST /api/offers/:id/images error:', err);
    res.status(500).json({ error: 'Błąd dodawania zdjęć.' });
  }
});

router.delete('/:id/images/:imageIndex', auth, async (req, res) => {
  try {
    const { data: offer, error: fetchErr } = await supabase
      .from('offers')
      .select('id, images')
      .eq('id', req.params.id)
      .single();

    if (fetchErr || !offer) return res.status(404).json({ error: 'Oferta nie została znaleziona.' });

    const idx = parseInt(req.params.imageIndex, 10);
    const imgs = offer.images || [];
    if (isNaN(idx) || idx < 0 || idx >= imgs.length) {
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
  } catch (err) {
    console.error('DELETE /api/offers/:id/images/:idx error:', err);
    res.status(500).json({ error: 'Błąd usuwania zdjęcia.' });
  }
});

module.exports = router;
