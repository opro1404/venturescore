require('dotenv').config();
const express      = require('express');
const fetch        = require('node-fetch');
const path         = require('path');
const Stripe       = require('stripe');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// ── Validate required env vars on startup ─────────────────────
const REQUIRED_ENV = [
  'ANTHROPIC_API_KEY',
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'STRIPE_SECRET_KEY',
];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error('❌ Missing required environment variables:', missing.join(', '));
  process.exit(1);
}

const app     = express();
const PORT    = process.env.PORT || 3456;
const API_KEY = process.env.ANTHROPIC_API_KEY;
const IS_PROD = process.env.NODE_ENV === 'production';

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ── Security headers ──────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // disabled — inline scripts in HTML files
  crossOriginEmbedderPolicy: false,
}));

// ── Trust proxy (needed for rate limiter behind Railway/Render) ─
app.set('trust proxy', 1);

// ── Rate limiters ─────────────────────────────────────────────

// Global — 200 requests per 15 mins per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many requests. Please slow down.' } },
});

// AI endpoints — 10 per hour per IP (expensive)
const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Hourly analysis limit reached. Try again later.' } },
  // Combine IP + user ID; suppress IPv6 helper warning — we strip ::ffff: prefix manually
  keyGenerator: (req) => {
    const ip = (req.ip || '').replace(/^::ffff:/, '');
    const uid = req.user?.id || 'anon';
    return `${ip}:${uid}`;
  },
  validate: { keyGeneratorIpFallback: false },
});

// Checkout — 20 per hour per IP (prevent spam sessions)
const checkoutLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many checkout attempts. Try again later.' } },
});

app.use(globalLimiter);

// ── Raw body for Stripe webhook (must be before express.json) ──
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));

// ── Body parsing with size limits ────────────────────────────
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// ── Static files ──────────────────────────────────────────────
app.use(express.static(__dirname, {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.env') || filePath.includes('node_modules')) {
      res.status(403).end();
    }
  }
}));

// ── Input sanitiser ───────────────────────────────────────────
function sanitise(str, maxLen = 3000) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen);
}

// ── Static page routes ────────────────────────────────────────
app.get('/',         (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/analysis', (req, res) => res.sendFile(path.join(__dirname, 'venturescore.html')));
app.get('/success',  (req, res) => res.sendFile(path.join(__dirname, 'success.html')));

// ── Auth middleware ───────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: { message: 'Not authenticated.' } });

  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: { message: 'Session expired. Please sign in again.' } });

  req.user = user;
  next();
}

// ── Plan check middleware ─────────────────────────────────────
async function requirePlan(req, res, next) {
  const { data: profile, error } = await supabase
    .from('profiles')
    .select('plan, analyses_used, plan_expires_at')
    .eq('id', req.user.id)
    .single();

  if (error || !profile) return res.status(500).json({ error: { message: 'Could not load your profile.' } });

  const plan = profile.plan;

  if (plan === 'free')
    return res.status(403).json({ error: { message: 'UPGRADE_REQUIRED' } });

  if (plan === 'one_time' && profile.analyses_used >= 1)
    return res.status(403).json({ error: { message: 'UPGRADE_REQUIRED' } });

  if (plan === 'monthly') {
    const expires = profile.plan_expires_at ? new Date(profile.plan_expires_at) : null;
    if (!expires || expires < new Date())
      return res.status(403).json({ error: { message: 'PLAN_EXPIRED' } });
  }

  req.profile = profile;
  next();
}

// ── GET /api/me ───────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req, res) => {
  const { data: profile } = await supabase
    .from('profiles')
    .select('plan, analyses_used, plan_expires_at, email')
    .eq('id', req.user.id)
    .single();
  res.json({ user: { id: req.user.id, email: req.user.email }, profile });
});

// ── POST /api/analyse ─────────────────────────────────────────
app.post('/api/analyse', requireAuth, requirePlan, aiLimiter, async (req, res) => {
  const { messages, model, max_tokens, system } = req.body;

  // Validate shape
  if (!messages || !Array.isArray(messages) || !model) {
    return res.status(400).json({ error: { message: 'Invalid request shape.' } });
  }

  // Sanitise user content
  if (messages[0]?.content) {
    messages[0].content = sanitise(messages[0].content, 5000);
  }

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({ messages, model, max_tokens, system }),
    });

    const data = await upstream.json();

    if (upstream.status === 200) {
      await supabase
        .from('profiles')
        .update({ analyses_used: (req.profile.analyses_used || 0) + 1 })
        .eq('id', req.user.id);
    }

    res.status(upstream.status).json(data);
  } catch (err) {
    console.error('Analyse error:', err.message);
    res.status(500).json({ error: { message: 'Analysis failed. Please try again.' } });
  }
});

// ── POST /api/pivot ───────────────────────────────────────────
app.post('/api/pivot', requireAuth, aiLimiter, async (req, res) => {
  const { data: profile } = await supabase
    .from('profiles')
    .select('plan, pivots_used')
    .eq('id', req.user.id)
    .single();

  if (!profile) return res.status(500).json({ error: { message: 'Could not load profile.' } });
  if (profile.plan === 'free') return res.status(403).json({ error: { message: 'UPGRADE_REQUIRED' } });
  if (profile.plan === 'one_time' && (profile.pivots_used || 0) >= 1)
    return res.status(403).json({ error: { message: 'PIVOT_LIMIT_REACHED' } });

  const idea       = sanitise(req.body.idea, 2000);
  const background = sanitise(req.body.background, 500);
  const report     = req.body.report || {};
  const count      = profile.plan === 'one_time' ? 1 : 3;

  const prompt = `You are a startup pivot specialist. A founder submitted a business idea that received a VentureScore analysis.

Original idea: ${idea}
${background ? `Founder background: ${background}` : ''}

Original scores — Survival: ${report.survival_score}/100, Originality: ${report.originality_score}/100, Futureproof: ${report.futureproof_score}/100, Verdict: ${report.verdict?.decision}
Main weaknesses: ${(report.whats_bad || []).join('; ')}
Biggest threats: ${(report.biggest_threats || []).map(t => t.title).join('; ')}

Generate exactly ${count} meaningfully different pivot(s) that fix the core weaknesses while keeping the founder's core insight.

Return ONLY a JSON array of exactly ${count} objects:
[{"name":"","concept":"","key_change":"","why_better":"","survival_score":0,"originality_score":0,"futureproof_score":0,"verdict":"BUILD THIS NOW"}]

verdict must be "BUILD THIS NOW", "NEEDS WORK", or "KILL THIS IDEA". Return raw JSON only.`;

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-5',
        max_tokens: 2048,
        system:     'You are a startup pivot specialist. Return only valid JSON arrays. No markdown.',
        messages:   [{ role: 'user', content: prompt }],
      }),
    });

    const data = await upstream.json();
    if (!upstream.ok) throw new Error(data?.error?.message || 'AI error');

    const raw = data.content[0].text.trim();
    let pivots;
    try { pivots = JSON.parse(raw); }
    catch { const m = raw.match(/\[[\s\S]*\]/); pivots = JSON.parse(m[0]); }

    await supabase
      .from('profiles')
      .update({ pivots_used: (profile.pivots_used || 0) + count })
      .eq('id', req.user.id);

    res.json({ pivots, plan: profile.plan, pivots_used: (profile.pivots_used || 0) + count });
  } catch (err) {
    console.error('Pivot error:', err.message);
    res.status(500).json({ error: { message: 'Pivot generation failed. Please try again.' } });
  }
});

// ── POST /api/marketing ───────────────────────────────────────
app.post('/api/marketing', requireAuth, aiLimiter, async (req, res) => {
  const { data: profile } = await supabase
    .from('profiles').select('plan').eq('id', req.user.id).single();

  if (!profile || profile.plan === 'free')
    return res.status(403).json({ error: { message: 'UPGRADE_REQUIRED' } });

  const idea     = sanitise(req.body.idea, 2000);
  const channels = (req.body.channels || []).slice(0, 5);
  const icp      = req.body.icp || {};
  const usps     = (req.body.usps || []).slice(0, 5);

  if (!channels.length) return res.status(400).json({ error: { message: 'No channels provided.' } });

  const prompt = `You are an expert CMO. Build a 90-day marketing plan for this startup.

Business: ${idea}
ICP: ${JSON.stringify(icp)}
USPs: ${usps.join(', ')}

Channels:
${channels.map((c, i) => `${i + 1}. ${c.channel} — ${c.why_it_works}`).join('\n')}

Return ONLY a JSON array of exactly ${channels.length} objects:
[{
  "channel": "channel name",
  "monthly_budget": "$X–$Y/mo",
  "day_30": "30-day focus (max 50 words)",
  "day_60": "60-day focus (max 50 words)",
  "day_90": "90-day focus (max 50 words)",
  "weekly_actions": ["action 1","action 2","action 3","action 4"],
  "kpis": ["KPI 1","KPI 2","KPI 3","KPI 4"],
  "content_ideas": ["idea 1","idea 2","idea 3","idea 4"]
}]

Be specific to this business. Each action/KPI/idea under 15 words. Return raw JSON array only.`;

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-5',
        max_tokens: 8192,
        system:     'You are an expert CMO. Return only valid JSON arrays. No markdown. Keep all strings concise.',
        messages:   [{ role: 'user', content: prompt }],
      }),
    });

    const data = await upstream.json();
    if (!upstream.ok) throw new Error(data?.error?.message || 'AI error');

    const raw = data.content[0].text.trim();
    let plans;
    try { plans = JSON.parse(raw); }
    catch {
      const start = raw.indexOf('['), end = raw.lastIndexOf(']');
      if (start === -1 || end === -1) throw new Error('Could not parse marketing plan JSON.');
      plans = JSON.parse(raw.slice(start, end + 1));
    }

    res.json({ plans });
  } catch (err) {
    console.error('Marketing error:', err.message);
    res.status(500).json({ error: { message: 'Marketing plan generation failed. Please try again.' } });
  }
});

// ── POST /api/checkout ────────────────────────────────────────
app.post('/api/checkout', requireAuth, checkoutLimiter, async (req, res) => {
  const plan = req.body.plan;
  const priceMap = {
    one_time: process.env.STRIPE_PRICE_ONE_TIME,
    monthly:  process.env.STRIPE_PRICE_MONTHLY,
    lifetime: process.env.STRIPE_PRICE_LIFETIME,
  };

  if (!priceMap[plan]) return res.status(400).json({ error: 'Invalid plan.' });

  const baseUrl = process.env.APP_URL || `http://localhost:${PORT}`;

  try {
    const session = await stripe.checkout.sessions.create({
      mode:                 plan === 'monthly' ? 'subscription' : 'payment',
      payment_method_types: ['card'],
      line_items:           [{ price: priceMap[plan], quantity: 1 }],
      customer_email:       req.user.email,
      client_reference_id:  req.user.id,
      metadata:             { supabase_user_id: req.user.id, plan },
      success_url:          `${baseUrl}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:           `${baseUrl}/#pricing`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /webhook/stripe ──────────────────────────────────────
app.post('/webhook/stripe', async (req, res) => {
  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!secret) {
    console.warn('⚠️  STRIPE_WEBHOOK_SECRET not set — skipping verification');
    return res.json({ received: true });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch (err) {
    console.error('Webhook signature failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId  = session.metadata?.supabase_user_id;
    const plan    = session.metadata?.plan;
    if (!userId || !plan) return res.json({ received: true });

    const update = { plan, analyses_used: 0 };
    if (plan === 'monthly') {
      update.plan_expires_at = new Date(Date.now() + 31 * 24 * 60 * 60 * 1000).toISOString();
    }

    const { error } = await supabase.from('profiles').update(update).eq('id', userId);
    if (error) console.error('Supabase update error:', error.message);
    else console.log(`✓ Plan "${plan}" activated for ${userId}`);
  }

  if (event.type === 'customer.subscription.deleted') {
    const email = event.data.object?.customer_email;
    if (email) {
      const { data: profile } = await supabase
        .from('profiles').select('id').eq('email', email).single();
      if (profile) {
        await supabase.from('profiles')
          .update({ plan: 'free', plan_expires_at: null })
          .eq('id', profile.id);
        console.log(`✓ Plan reverted to free for ${email}`);
      }
    }
  }

  res.json({ received: true });
});

// ── Health check (useful for deployment platforms) ────────────
app.get('/health',       (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));
app.get('/privacy',      (req, res) => res.sendFile(path.join(__dirname, 'privacy.html')));
app.get('/terms',        (req, res) => res.sendFile(path.join(__dirname, 'terms.html')));
app.get('/favicon.png',  (req, res) => res.sendFile(path.join(__dirname, 'favicon.png')));
app.get('/favicon.ico',  (req, res) => res.sendFile(path.join(__dirname, 'favicon.png')));

// ── 404 fallback ──────────────────────────────────────────────
app.get('/{*path}', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Global error handler ──────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: { message: 'Something went wrong. Please try again.' } });
});

// Start server locally; export for Vercel serverless
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`✅ VentureScore running at http://localhost:${PORT}`);
    console.log(`   Environment: ${IS_PROD ? 'production' : 'development'}`);
  });
}

module.exports = app;
