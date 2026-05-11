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

// ── Blog (Supabase-backed, serverless-safe) ───────────────────

// List all blog posts (sorted newest first)
app.get('/blog', async (req, res) => {
  try {
    const { data: posts, error } = await supabase
      .from('blog_posts')
      .select('slug, title, meta_description, created_at')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.send(buildBlogIndex(posts || []));
  } catch (err) {
    console.error('Blog index error:', err.message);
    res.send(buildBlogIndex([]));
  }
});

app.get('/blog/:slug', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('blog_posts')
      .select('content_html')
      .eq('slug', req.params.slug)
      .single();

    if (error || !data) return res.status(404).sendFile(path.join(__dirname, 'index.html'));
    res.send(data.content_html);
  } catch (err) {
    res.status(404).sendFile(path.join(__dirname, 'index.html'));
  }
});

// Internal: generate a blog post (called by scheduled task with a secret)
app.post('/api/generate-blog', async (req, res) => {
  const secret = req.headers['x-blog-secret'];
  if (!secret || secret !== process.env.BLOG_SECRET) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const post = await generateBlogPost();
    res.json({ ok: true, slug: post.slug, title: post.title });
  } catch (err) {
    console.error('Blog generation error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

async function generateBlogPost() {
  // Pick a rotating topic based on week number so it's different every week
  const weekNum = Math.floor(Date.now() / (7 * 24 * 60 * 60 * 1000));
  const topics = [
    'how to validate a business idea before building anything',
    'the startup ideas most likely to succeed in 2025',
    'why most business ideas fail and how to avoid it',
    'how to find your unfair advantage as a first-time founder',
    'the best niches to start a profitable business in right now',
    'how to identify a gap in the market and exploit it',
    'building a business with no money: what actually works',
    'how to stress-test your startup idea like a VC investor',
    '10 questions every founder should ask before starting a business',
    'the difference between a good idea and a fundable business',
    'market sizing 101: how to know if your idea is big enough',
    'how competition analysis can save your startup before launch',
    'pivot or persist: how to know when to change your business idea',
    'the one metric that predicts whether your startup will survive',
    'how to write a business plan that actually helps you execute',
    'go-to-market strategies for founders with zero budget',
    'side hustle ideas that could become real businesses in 2025',
    'how to find product-market fit as early as possible',
    'why your business idea needs a moat — and how to build one',
    'solopreneur vs startup: which model is right for your idea',
    'how AI is changing what makes a good business idea in 2025',
    'the biggest mistakes first-time entrepreneurs make (and how to avoid them)',
    'how to validate demand for your product without spending a dollar',
    'what investors look for in early-stage startups',
    'turning your expertise into a profitable business idea',
  ];
  const topic = topics[weekNum % topics.length];
  const dateStr = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const slug = dateStr + '-' + topic.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50);

  const prompt = `You are an expert startup content writer. Write a high-quality, SEO-optimised blog article for the VentureScore blog. VentureScore (venturescore.app) is an AI-powered tool that analyses business ideas and gives founders a detailed score, market analysis, pivot suggestions, and marketing plan.

Topic: "${topic}"

Requirements:
- Title: catchy, SEO-friendly (include the main keyword naturally)
- Meta description: 150-160 characters, compelling, includes keyword
- Word count: 900-1100 words
- Structure: intro, 4-6 clear H2 sections, conclusion with a CTA to try VentureScore
- Tone: practical, direct, knowledgeable — like a smart founder writing for other founders
- Naturally mention VentureScore once or twice in the article body as a useful tool, with a link to https://venturescore.app
- Include specific, actionable advice — not fluffy generalities
- End with a short CTA paragraph mentioning VentureScore with a link

Return ONLY valid JSON in this exact shape (no markdown, no code block):
{
  "title": "...",
  "meta_description": "...",
  "intro": "...",
  "sections": [
    { "heading": "...", "body": "..." },
    ...
  ],
  "conclusion": "..."
}`;

  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-5',
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!aiRes.ok) throw new Error('AI request failed: ' + aiRes.status);
  const aiData = await aiRes.json();
  const raw = aiData.content?.[0]?.text || '';

  let article;
  try {
    const jsonStr = raw.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/i, '').trim();
    article = JSON.parse(jsonStr);
  } catch {
    throw new Error('Failed to parse AI blog JSON');
  }

  const html = buildBlogPostHTML(article, slug, dateStr);
  const { error } = await supabase.from('blog_posts').upsert({
    slug,
    title: article.title,
    meta_description: article.meta_description || '',
    content_html: html,
  });
  if (error) throw new Error('Supabase insert failed: ' + error.message);

  return { slug, title: article.title };
}

function buildBlogPostHTML(article, slug, dateStr) {
  const esc = s => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const formattedDate = new Date(dateStr).toLocaleDateString('en-AU', { day: 'numeric', month: 'long', year: 'numeric' });
  // Convert markdown-style links to <a> tags
  const linkify = s => (s||'').replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" style="color:#b8ff57;text-decoration:none;">$1</a>');
  const paragraphize = s => linkify(s||'').split(/\n\n+/).map(p => `<p>${p.replace(/\n/g,'<br>')}</p>`).join('\n');

  const sectionsHTML = (article.sections||[]).map(s => `
    <h2>${esc(s.heading)}</h2>
    ${paragraphize(s.body)}`).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(article.title)} — VentureScore Blog</title>
<meta name="description" content="${esc(article.meta_description)}">
<meta property="og:title" content="${esc(article.title)}">
<meta property="og:description" content="${esc(article.meta_description)}">
<meta property="og:url" content="https://venturescore.app/blog/${esc(slug)}">
<meta property="og:type" content="article">
<link rel="icon" type="image/png" href="/favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  :root{--bg:#0a0a0f;--surface:#111118;--border:#1e1e28;--text:#f0f0f0;--muted:#8888a0;--accent:#b8ff57;}
  body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;line-height:1.75;}
  nav{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:20px 40px;background:rgba(10,10,15,0.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);}
  nav a{font-family:'Syne',sans-serif;font-size:18px;font-weight:800;color:var(--text);text-decoration:none;}
  nav a em{color:var(--accent);font-style:normal;}
  nav .back{font-size:13px;color:var(--muted);text-decoration:none;font-family:'DM Sans',sans-serif;font-weight:400;}
  nav .back:hover{color:var(--text);}
  .hero{background:linear-gradient(135deg,rgba(184,255,87,0.04) 0%,transparent 60%);border-bottom:1px solid var(--border);padding:60px 24px 48px;text-align:center;}
  .tag{display:inline-block;background:rgba(184,255,87,0.1);border:1px solid rgba(184,255,87,0.25);border-radius:100px;padding:5px 16px;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:20px;}
  h1{font-family:'Syne',sans-serif;font-size:clamp(26px,4vw,44px);font-weight:800;max-width:700px;margin:0 auto 16px;line-height:1.2;}
  .meta{font-size:13px;color:var(--muted);}
  .container{max-width:740px;margin:0 auto;padding:60px 24px 100px;}
  p{color:#c0c0d0;margin-bottom:18px;font-size:16px;}
  h2{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;margin:40px 0 14px;color:var(--text);}
  a{color:var(--accent);}a:hover{text-decoration:underline;}
  .cta-box{background:var(--surface);border:1px solid rgba(184,255,87,0.25);border-radius:16px;padding:32px;text-align:center;margin-top:56px;}
  .cta-box h3{font-family:'Syne',sans-serif;font-size:20px;font-weight:800;color:var(--text);margin-bottom:10px;}
  .cta-box p{color:var(--muted);margin-bottom:20px;font-size:15px;}
  .cta-btn{display:inline-block;background:var(--accent);color:#0a0a0f;font-family:'Syne',sans-serif;font-size:15px;font-weight:700;padding:14px 36px;border-radius:10px;text-decoration:none;}
  .cta-btn:hover{opacity:0.9;}
  footer{border-top:1px solid var(--border);padding:32px 40px;text-align:center;font-size:13px;color:var(--muted);}
  footer a{color:var(--accent);}
</style>
</head>
<body data-date="${dateStr}">
<nav>
  <a href="/">Venture<em>Score</em></a>
  <a href="/blog" class="back">← All Articles</a>
</nav>
<div class="hero">
  <div class="tag">VentureScore Blog</div>
  <h1>${esc(article.title)}</h1>
  <div class="meta">${formattedDate} · 5 min read</div>
</div>
<div class="container">
  ${paragraphize(article.intro)}
  ${sectionsHTML}
  ${paragraphize(article.conclusion)}

  <div class="cta-box">
    <h3>Ready to test your business idea?</h3>
    <p>Stop guessing. Get an AI-powered analysis that scores your idea, identifies threats, suggests pivots, and builds your marketing plan — in under 60 seconds.</p>
    <a href="https://venturescore.app" class="cta-btn">Analyse My Idea →</a>
  </div>
</div>
<footer>© 2026 VentureScore · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <a href="/blog">Blog</a></footer>
</body>
</html>`;
}

function buildBlogIndex(posts) {
  const esc = s => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const cards = posts.length === 0
    ? '<p style="color:#8888a0;text-align:center;padding:60px 0;">No articles yet — check back soon.</p>'
    : posts.map(p => {
        const formattedDate = (p.created_at || p.date) ? new Date(p.created_at || p.date).toLocaleDateString('en-AU', { day:'numeric', month:'long', year:'numeric' }) : '';
        return `
        <a href="/blog/${esc(p.slug)}" class="card">
          <div class="card-tag">Article</div>
          <h2>${esc(p.title)}</h2>
          <p>${esc(p.meta_description || p.description || '')}</p>
          <div class="card-meta">${formattedDate} · 5 min read →</div>
        </a>`;
      }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Blog — VentureScore</title>
<meta name="description" content="Founder insights, startup ideas, and business analysis tips from the VentureScore team.">
<link rel="icon" type="image/png" href="/favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  :root{--bg:#0a0a0f;--surface:#111118;--border:#1e1e28;--text:#f0f0f0;--muted:#8888a0;--accent:#b8ff57;}
  body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;min-height:100vh;}
  nav{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:20px 40px;background:rgba(10,10,15,0.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);}
  nav a{font-family:'Syne',sans-serif;font-size:18px;font-weight:800;color:var(--text);text-decoration:none;}
  nav a em{color:var(--accent);font-style:normal;}
  nav .back{font-size:13px;color:var(--muted);text-decoration:none;font-family:'DM Sans',sans-serif;font-weight:400;}
  nav .back:hover{color:var(--text);}
  .hero{padding:80px 24px 56px;text-align:center;}
  h1{font-family:'Syne',sans-serif;font-size:clamp(32px,5vw,54px);font-weight:800;margin-bottom:14px;}
  h1 em{color:var(--accent);font-style:normal;}
  .subtitle{color:var(--muted);font-size:17px;max-width:480px;margin:0 auto;}
  .grid{max-width:880px;margin:0 auto;padding:0 24px 100px;display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:24px;}
  .card{display:block;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:32px;text-decoration:none;transition:border-color 0.2s,transform 0.2s;}
  .card:hover{border-color:rgba(184,255,87,0.3);transform:translateY(-2px);}
  .card-tag{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:12px;}
  .card h2{font-family:'Syne',sans-serif;font-size:20px;font-weight:800;color:var(--text);margin-bottom:10px;line-height:1.3;}
  .card p{font-size:14px;color:var(--muted);margin-bottom:20px;line-height:1.6;}
  .card-meta{font-size:12px;color:var(--accent);font-weight:600;}
  footer{border-top:1px solid var(--border);padding:32px 40px;text-align:center;font-size:13px;color:var(--muted);}
  footer a{color:var(--accent);}
</style>
</head>
<body>
<nav>
  <a href="/">Venture<em>Score</em></a>
  <a href="/" class="back">← Home</a>
</nav>
<div class="hero">
  <h1>The <em>Venture</em>Score Blog</h1>
  <p class="subtitle">Startup insights, idea validation frameworks, and founder resources — updated weekly.</p>
</div>
<div class="grid">
  ${cards}
</div>
<footer>© 2026 VentureScore · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a></footer>
</body>
</html>`;
}

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
