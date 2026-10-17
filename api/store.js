import { put, list } from "@vercel/blob";
import { createHash, timingSafeEqual } from "node:crypto";

const FILE = "shop.json";
const hash = (p) => createHash("sha256").update("qf|" + p).digest("hex");
const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const pw = process.env.ADMIN_PASSWORD;

  if (req.method === "GET") {
    const { blobs } = await list({ prefix: FILE, limit: 1 });
    return res.status(200).json({ url: blobs[0] ? blobs[0].url : null, hasPw: !!pw });
  }
  if (req.method !== "POST") return res.status(405).json({ error: "method" });
  if (!pw) return res.status(500).json({ error: "ADMIN_PASSWORD is not set" });

  const b = req.body || {};
  if (!b.ph || !same(b.ph, hash(pw))) return res.status(401).json({ error: "auth" });
  if (b.action === "login") return res.status(200).json({ ok: true });

  if (b.action === "save") {
    const st = b.state;
    if (!st || !Array.isArray(st.products)) return res.status(400).json({ error: "bad state" });
    if (st.cfg) delete st.cfg.ph;
    await put(FILE, JSON.stringify(st), {
      access: "public",
      addRandomSuffix: false,
      allowOverwrite: true,
      contentType: "application/json",
      cacheControlMaxAge: 60,
    });
    return res.status(200).json({ ok: true });
