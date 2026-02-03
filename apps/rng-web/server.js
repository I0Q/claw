import express from 'express';
import crypto from 'crypto';
import QRCode from 'qrcode';

const app = express();
app.set('trust proxy', 1);
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

app.get('/verify/:id', async (req, res) => {
  const id = String(req.params.id || '');
  const stored = getSignedResult(id);
  if (!stored) {
    return res.status(404).type('html').send('<h1>Expired</h1><p>This verification link is unknown or has expired.</p>');
  }

  const verifyPageUrl = `${req.protocol}://${req.get('host')}/verify/${encodeURIComponent(id)}`;
  const qr = await QRCode.toDataURL(verifyPageUrl, { margin: 1, width: 240 });

  // Keep the payload copy/paste friendly.
  const randomJson = JSON.stringify(stored.random, null, 2);
  const signature = String(stored.signature);

  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Verify RNG (random.org)</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:860px}
    .card{border:1px solid #ddd;border-radius:10px;padding:18px}
    .ok{color:#0b7a0b;font-weight:700}
    .bad{color:#b00020;font-weight:700}
    code{background:#f6f6f6;padding:2px 6px;border-radius:6px}
    textarea{width:100%;min-height:160px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;padding:10px;border-radius:8px;border:1px solid #ddd}
    .row{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}
    .qr{border:1px solid #ddd;border-radius:10px;padding:10px;display:inline-block;background:#fff}
    button{padding:8px 12px;font-size:14px;cursor:pointer}
    a{word-break:break-word}
  </style>
</head>
<body>
  <h1>Verification</h1>

  <div class="row">
    <div class="qr">
      <div style="font-weight:700;margin-bottom:8px">Scan to view this proof</div>
      <img alt="QR" src="${qr}" width="240" height="240" />
      <div style="margin-top:8px;font-size:12px">${verifyPageUrl}</div>
    </div>

    <div style="flex:1;min-width:280px">
      <p>This page checks the <code>random</code> object + <code>signature</code> using random.org’s <code>verifySignature</code> API.</p>
      <div class="card" id="card">Checking…</div>
      <p style="margin-top:12px">
        Also verify yourself on random.org (public form):
        <a href="https://api.random.org/signatures/form" target="_blank" rel="noreferrer">https://api.random.org/signatures/form</a>
      </p>
    </div>
  </div>

  <h2 style="margin-top:26px">Verify on random.org (manual)</h2>
  <ol>
    <li>Open the random.org verification form link above.</li>
    <li>Paste the <b>random</b> JSON and the <b>signature</b> from below.</li>
    <li>Submit — it should say the signature is valid.</li>
  </ol>

  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
      <div style="font-weight:700">random (JSON)</div>
      <button type="button" onclick="copyText('random')">Copy random</button>
    </div>
    <textarea id="random" readonly>${randomJson.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</textarea>
  </div>

  <div class="card" style="margin-top:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
      <div style="font-weight:700">signature</div>
      <button type="button" onclick="copyText('signature')">Copy signature</button>
    </div>
    <textarea id="signature" readonly>${signature.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</textarea>
  </div>

  <p style="margin-top:18px"><a href="/">Back</a></p>

<script>
  async function copyText(id) {
    const el = document.getElementById(id);
    try {
      await navigator.clipboard.writeText(el.value);
    } catch {
      el.select();
      document.execCommand('copy');
      window.getSelection().removeAllRanges();
    }
  }

  (async () => {
    const el = document.getElementById('card');
    try {
      const r = await fetch('/api/verify/${id}');
      const j = await r.json();
      if (!r.ok) throw new Error(j?.error || 'verify failed');
      if (j.authenticity) {
        el.innerHTML = '<div class="ok">VALID</div><div>random.org verified this result (via verifySignature).</div>';
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
