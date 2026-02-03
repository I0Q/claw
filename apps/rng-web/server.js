import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json({ limit: '64kb' }));

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'rng-web' });
});

// Simple UI
app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>RNG</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:720px}
    label{display:block;margin:12px 0 6px}
    input{padding:10px;font-size:16px;width:220px}
    button{padding:10px 14px;font-size:16px;cursor:pointer}
    .row{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-end}
    .card{border:1px solid #ddd;border-radius:10px;padding:18px}
    code{background:#f6f6f6;padding:2px 6px;border-radius:6px}
    #out{font-size:28px;font-weight:700;margin-top:10px}
  </style>
</head>
<body>
  <h1>Random Number Generator</h1>
  <p>Backend uses <code>random.org</code> via their JSON-RPC API.</p>

  <div class="card">
    <div class="row">
      <div>
        <label for="min">Min (inclusive)</label>
        <input id="min" type="number" value="1" />
      </div>
      <div>
        <label for="max">Max (inclusive)</label>
        <input id="max" type="number" value="100" />
      </div>
      <div>
        <button id="go">Generate</button>
      </div>
    </div>
    <div id="out"></div>
    <div id="err" style="color:#b00020;margin-top:8px"></div>
  </div>

<script>
  const $ = (id) => document.getElementById(id);
  $('go').addEventListener('click', async () => {
    $('err').textContent = '';
    $('out').textContent = '';
    const min = Number($('min').value);
    const max = Number($('max').value);
    try {
      const r = await fetch('/api/rng?min=' + encodeURIComponent(min) + '&max=' + encodeURIComponent(max));
      const j = await r.json();
      if (!r.ok) throw new Error(j?.error || 'Request failed');
      $('out').textContent = String(j.value);
    } catch (e) {
      $('err').textContent = e.message || String(e);
    }
  });
</script>
</body>
</html>`);
});

app.get('/api/rng', async (req, res) => {
  const min = Number(req.query.min);
  const max = Number(req.query.max);

  if (!Number.isFinite(min) || !Number.isFinite(max)) {
    return res.status(400).json({ ok: false, error: 'min and max must be numbers' });
  }
  if (!Number.isInteger(min) || !Number.isInteger(max)) {
    return res.status(400).json({ ok: false, error: 'min and max must be integers' });
  }
  if (max < min) {
    return res.status(400).json({ ok: false, error: 'max must be >= min' });
  }

  try {
    const payload = {
      jsonrpc: '2.0',
      method: 'generateIntegers',
      params: {
        apiKey: process.env.RANDOM_ORG_API_KEY,
        n: 1,
        min,
        max,
        replacement: true,
        base: 10
      },
      id: Date.now()
    };

    const r = await fetch('https://api.random.org/json-rpc/4/invoke', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const j = await r.json().catch(() => null);
    if (!r.ok) {
      return res.status(502).json({ ok: false, error: 'random.org request failed', status: r.status, detail: j });
    }

    if (!j || j.error) {
      return res.status(502).json({ ok: false, error: 'random.org error', detail: j && (j.error || j) });
    }

    const value = j?.result?.random?.data?.[0];
    if (!Number.isInteger(value)) {
      return res.status(502).json({ ok: false, error: 'random.org returned unexpected payload', detail: j });
    }

    res.json({ ok: true, value, min, max, source: 'random.org' });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'random.org call failed', message: String(e?.message || e) });
  }
});

const port = Number(process.env.PORT || 8080);
app.listen(port, '0.0.0.0', () => {
  console.log(`rng-web listening on :${port}`);
});
