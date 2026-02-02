import express from "express";

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true, service: "whatsapp-flows-endpoint" });
});

// Minimal WhatsApp Flows data_exchange endpoint placeholder.
// We'll refine the exact request/response contract once we capture a real payload from Meta.
app.post("/wa/flows", (req, res) => {
  // For now, just echo back a safe response so the endpoint is reachable.
  res.status(200).json({
    ok: true,
    note: "endpoint reachable",
    receivedKeys: Object.keys(req.body || {}),
  });
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`listening on :${port}`);
});
