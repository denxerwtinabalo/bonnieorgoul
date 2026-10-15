import { getStore } from "@netlify/blobs";
import { createHash } from "node:crypto";

const KEYS = ["bonnie", "goul"];
const SALT = process.env.VOTE_SALT || "bonnie-or-goul-v1";
// Βάλε USE_FP=0 στο Netlify αν θες να απενεργοποιήσεις τον έλεγχο "δακτυλικού αποτυπώματος" συσκευής
const USE_FP = process.env.USE_FP !== "0";

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extra },
  });

const h = (s) => createHash("sha256").update(SALT + s).digest("hex");
const getCookie = (req, name) => {
  const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : "";
};
const clean = (v) => (typeof v === "string" && /^[A-Za-z0-9-]{8,128}$/.test(v) ? v : "");

export default async (req, context) => {
  // Μόνο Ελλάδα
  const country = (context?.geo?.country?.code || "").toUpperCase();
  if (country !== "GR") return json({ error: "geo", message: "Επιτρέπεται μόνο από την Ελλάδα" }, 403);

  const ip =
    context?.ip ||
    req.headers.get("x-nf-client-connection-ip") ||
    (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
  if (!ip) return json({ error: "no ip" }, 400);

  const dev = clean(req.headers.get("x-device-id")) || clean(getCookie(req, "bg_dev"));
  const fp = clean(req.headers.get("x-fp"));

  // Κάθε "ταυτότητα" της συσκευής: IP, device id (localStorage/cookie), αποτύπωμα συσκευής
  const ids = ["ip:" + h(ip)];
  if (dev) ids.push("dev:" + h(dev));
  if (USE_FP && fp) ids.push("fp:" + h(fp));

  const countStore = getStore("bonnie-or-goul");
  const voterStore = getStore("bonnie-or-goul-voters");

  const stored = (await countStore.get("counts", { type: "json" })) || {};
  const c = { bonnie: Math.max(0, +stored.bonnie || 0), goul: Math.max(0, +stored.goul || 0) };

  let mine = null;
  for (const id of ids) {
    const v = await voterStore.get(id);
    if (KEYS.includes(v)) { mine = v; break; }
  }

  const cookie = dev ? { "set-cookie": `bg_dev=${dev}; Path=/; Max-Age=63072000; Secure; SameSite=Lax` } : {};

  if (req.method === "POST") {
    let next;
    try { ({ next } = await req.json()); } catch { return json({ error: "bad request" }, 400); }
    if (!KEYS.includes(next) || !dev) return json({ error: "bad request" }, 400);

    if (mine) return json({ ...c, mine, error: "already" }, 409, cookie);

    c[next] += 1;
    await Promise.all(ids.map((id) => voterStore.set(id, next)));
    await countStore.setJSON("counts", c);
    mine = next;
  } else if (mine) {
    // Αν η συσκευή έχει ήδη ψηφίσει, "δέσε" και τις νέες ταυτότητές της (π.χ. νέα IP από δεδομένα)
    await Promise.all(ids.map((id) => voterStore.set(id, mine)));
  }
  return json({ ...c, mine }, 200, cookie);
};

export const config = { path: "/api/votes" };
