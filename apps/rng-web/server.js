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
    <div id="verify" style="margin-top:10px"></div>
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
      if (j.verifyUrl) {
        $('verify').innerHTML = '<a href="' + j.verifyUrl + '">Verify on random.org</a>';
      } else {
        $('verify').textContent = '';
      }
    } catch (e) {
      $('err').textContent = e.message || String(e);
    }
  });
</script>
</body>
</html>`);
});

// In-memory store of signed results for verification links.
// Not durable; intended for short-lived “verify” UX.
const signedStore = new Map();
const SIGNED_TTL_MS = 6 * 60 * 60 * 1000; // 6h

function storeSignedResult(obj) {
  const id = crypto.randomUUID();
  signedStore.set(id, { ...obj, storedAt: Date.now() });
  return id;
}

function getSignedResult(id) {
  const v = signedStore.get(id);
  if (!v) return null;
  if (Date.now() - v.storedAt > SIGNED_TTL_MS) {
    signedStore.delete(id);
    return null;
  }
  return v;
}

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
      method: 'generateSignedIntegers',
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
    const random = j?.result?.random;
    const signature = j?.result?.signature;

    if (!Number.isInteger(value) || !random || typeof signature !== 'string') {
      return res.status(502).json({ ok: false, error: 'random.org returned unexpected payload', detail: j });
    }

    const storeId = storeSignedResult({ random, signature });
    const verifyUrl = `/verify/${encodeURIComponent(storeId)}`;

    res.json({
      ok: true,
      value,
      min,
      max,
      source: 'random.org',
      completionTime: random?.completionTime,
      serialNumber: random?.serialNumber,
      verifyUrl
    });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'random.org call failed', message: String(e?.message || e) });
  }
});

app.get('/api/verify/:id', async (req, res) => {
  const id = String(req.params.id || '');
  const stored = getSignedResult(id);
  if (!stored) {
    return res.status(404).json({ ok: false, error: 'unknown_or_expired' });
  }

  try {
    const payload = {
      jsonrpc: '2.0',
      method: 'verifySignature',
      params: {
        random: stored.random,
        signature: stored.signature
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
      return res.status(502).json({ ok: false, error: 'random.org verify failed', status: r.status, detail: j });
    }
    if (!j || j.error) {
      return res.status(502).json({ ok: false, error: 'random.org verify error', detail: j && (j.error || j) });
    }

    // random.org typically returns { result: { authenticity: true/false } }
    const authenticity = j?.result?.authenticity;
    res.json({ ok: true, authenticity: Boolean(authenticity), raw: j?.result });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'verifySignature call failed', message: String(e?.message || e) });
  }
});

app.get('/verify/:id', (req, res) => {
  const id = String(req.params.id || '');
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Verify RNG (random.org)</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:720px}
    .card{border:1px solid #ddd;border-radius:10px;padding:18px}
    .ok{color:#0b7a0b;font-weight:700}
    .bad{color:#b00020;font-weight:700}
    code{background:#f6f6f6;padding:2px 6px;border-radius:6px}
  </style>
</head>
<body>
  <h1>Verification</h1>
  <p>This checks the <code>random</code> object + <code>signature</code> using random.org’s <code>verifySignature</code>.</p>
  <div class="card" id="card">Checking…</div>
  <p style="margin-top:18px"><a href="/">Back</a></p>

<script>
(async () => {
  const el = document.getElementById('card');
  try {
    const r = await fetch('/api/verify/${id}');
    const j = await r.json();
    if (!r.ok) throw new Error(j?.error || 'verify failed');
    if (j.authenticity) {
      el.innerHTML = '<div class="ok">VALID</div><div>random.org verified this result.</div>';
    } else {
      el.innerHTML = '<div class="bad">INVALID</div><div>random.org did not verify this result.</div>';
    }
  } catch (e) {
    el.innerHTML = '<div class="bad">ERROR</div><div>' + (e.message || String(e)) + '</div>';
  }
})();
</script>
</body>
</html>`);
});

const port = Number(process.env.PORT || 8080);
app.listen(port, '0.0.0.0', () => {
  console.log(`rng-web listening on :${port}`);
});
