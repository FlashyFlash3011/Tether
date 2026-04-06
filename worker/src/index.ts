/**
 * Tether coordination Worker.
 *
 * Routes:
 *   GET  /health          — unauthenticated liveness check
 *   POST /register        — register this node's public key + endpoint
 *   GET  /peers           — return all peers except the caller
 *   GET  /relay/:session  — WebSocket relay fallback (upgrades to WS)
 *
 * Auth: every protected route requires `Authorization: Bearer <jwt>` where
 * the JWT is HMAC-HS256 signed with the per-node secret (TOKEN_PC / TOKEN_MAC).
 *
 * Endpoint discovery (no STUN):
 *   The Worker reads CF-Connecting-IP (the client's real external IP as seen
 *   by Cloudflare) and pairs it with the listen_port field from the JSON body.
 *   For port-preserving NAT (all home routers) this equals the WireGuard UDP
 *   external endpoint. Falls back to relay if direct handshake fails.
 */

export interface Env {
  PEERS: KVNamespace;
  TOKEN_PC: string;
  TOKEN_MAC: string;
}

// ── JWT helpers ──────────────────────────────────────────────────────────────

const ALLOWED_NODES: readonly string[] = ["pc", "mac"];
const TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getSecret(nodeId: string, env: Env): string | null {
  if (nodeId === "pc") return env.TOKEN_PC;
  if (nodeId === "mac") return env.TOKEN_MAC;
  return null;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(secret), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/** Validate a HS256 JWT. Returns the node_id claim or throws. */
async function validateJWT(token: string, env: Env): Promise<string> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");

  const [headerB64, payloadB64, sigB64] = parts;

  // Decode header to verify algorithm.
  const header = JSON.parse(atob(headerB64.replace(/-/g, "+").replace(/_/g, "/")));
  if (header.alg !== "HS256") throw new Error("unexpected algorithm");

  // Decode payload.
  const payload = JSON.parse(
    atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"))
  );
  const nodeId: string = payload.node_id ?? "";
  if (!ALLOWED_NODES.includes(nodeId)) throw new Error(`unknown node_id: ${nodeId}`);

  // Check expiry.
  const expMs = (payload.exp ?? 0) * 1000;
  if (Date.now() > expMs + TOKEN_TTL_MS) throw new Error("token expired");

  // Verify signature using the node-specific secret.
  const secret = getSecret(nodeId, env);
  if (!secret) throw new Error("no secret for node");

  const key = await hmacKey(secret);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = Uint8Array.from(
    atob(sigB64.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );
  const valid = await crypto.subtle.verify("HMAC", key, sig, signingInput);
  if (!valid) throw new Error("invalid signature");

  return nodeId;
}

/** Extract and validate the Bearer JWT. Returns nodeId or a 401 Response. */
async function auth(req: Request, env: Env): Promise<string | Response> {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return new Response("Unauthorized", { status: 401 });
  }
  const token = authHeader.slice(7);
  try {
    return await validateJWT(token, env);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "auth error";
    return new Response(`Unauthorized: ${msg}`, { status: 401 });
  }
}

// ── KV helpers ───────────────────────────────────────────────────────────────

interface PeerRecord {
  nodeId: string;
  pubkey: string;
  vpnAddr: string;
  endpoint: string;   // "ip:port" (CF-Connecting-IP + listen_port)
  relayUrl: string;   // cloudflared tunnel URL for relay fallback (empty if none)
  lastSeen: number;   // Unix ms
}

async function upsertPeer(kv: KVNamespace, record: PeerRecord): Promise<void> {
  await kv.put(`peer:${record.nodeId}`, JSON.stringify(record), {
    expirationTtl: 300, // auto-expire after 5 min if node stops re-registering
  });
}

async function getAllPeers(kv: KVNamespace): Promise<PeerRecord[]> {
  const list = await kv.list({ prefix: "peer:" });
  const records: PeerRecord[] = [];
  for (const key of list.keys) {
    const val = await kv.get(key.name);
    if (val) records.push(JSON.parse(val) as PeerRecord);
  }
  return records;
}

// ── Static peer config (vpn_addr per node) ───────────────────────────────────

const VPN_ADDR: Record<string, string> = {
  pc:  "100.64.0.1/32",
  mac: "100.64.0.2/32",
};

// ── Handlers ─────────────────────────────────────────────────────────────────

function handleHealth(): Response {
  return Response.json({ ok: true });
}

async function handleRegister(req: Request, env: Env): Promise<Response> {
  const nodeId = await auth(req, env);
  if (nodeId instanceof Response) return nodeId;

  interface RegisterBody { pubkey: string; listen_port: number; relay_url?: string }
  let body: RegisterBody;
  try {
    body = await req.json() as RegisterBody;
  } catch {
    return new Response("Bad Request: invalid JSON", { status: 400 });
  }
  if (!body.pubkey || !body.listen_port) {
    return new Response("Bad Request: pubkey and listen_port required", { status: 400 });
  }

  // Derive endpoint: CF's view of the client IP + the self-reported WG port.
  const clientIP = req.headers.get("CF-Connecting-IP") ?? "";
  if (!clientIP) {
    return new Response("Internal Error: cannot determine client IP", { status: 500 });
  }
  // Handle IPv6: wrap in brackets for the "host:port" format.
  const endpoint = clientIP.includes(":")
    ? `[${clientIP}]:${body.listen_port}`
    : `${clientIP}:${body.listen_port}`;

  await upsertPeer(env.PEERS, {
    nodeId,
    pubkey: body.pubkey,
    vpnAddr: VPN_ADDR[nodeId] ?? "",
    endpoint,
    relayUrl: body.relay_url ?? "",
    lastSeen: Date.now(),
  });

  return Response.json({ ok: true, vpn_addr: VPN_ADDR[nodeId] });
}

async function handleGetPeers(req: Request, env: Env): Promise<Response> {
  const nodeId = await auth(req, env);
  if (nodeId instanceof Response) return nodeId;

  const all = await getAllPeers(env.PEERS);
  // Return all peers except the caller.
  const peers = all
    .filter((p) => p.nodeId !== nodeId)
    .map((p) => ({
      node_id:   p.nodeId,
      pubkey:    p.pubkey,
      vpn_addr:  p.vpnAddr,
      endpoint:  p.endpoint,
      relay_url: p.relayUrl ?? "",
    }));

  return Response.json({ peers });
}

// ── WebSocket relay ───────────────────────────────────────────────────────────
//
// Each relay session is identified by a random session ID. Two peers connect
// to the same session; the Worker pairs them and forwards WireGuard-encrypted
// frames between them. All traffic is E2E encrypted — the relay only sees
// ciphertext.
//
// Protocol (binary WebSocket frames):
//   Each frame = one WireGuard UDP packet, forwarded verbatim.
//
// Limitation: Cloudflare Workers free plan closes WebSocket connections after
// 100 seconds of inactivity. Mitigate with WireGuard PersistentKeepalive = 25.

// In-memory session map. Note: Workers are stateless across requests, so
// sessions only work if both peers connect to the same Worker isolate.
// For a personal 2-node setup this is fine; for production use Durable Objects.
const relaySessions = new Map<string, WebSocket>();

async function handleRelay(req: Request, env: Env, sessionId: string): Promise<Response> {
  const nodeId = await auth(req, env);
  if (nodeId instanceof Response) return nodeId;

  if (req.headers.get("Upgrade") !== "websocket") {
    return new Response("Expected WebSocket upgrade", { status: 426 });
  }

  const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
  server.accept();

  const existing = relaySessions.get(sessionId);
  if (existing) {
    // Second peer: wire them together.
    relaySessions.delete(sessionId);

    server.addEventListener("message", (e) => {
      if (existing.readyState === WebSocket.OPEN) {
        existing.send(e.data);
      }
    });
    existing.addEventListener("message", (e) => {
      if (server.readyState === WebSocket.OPEN) {
        server.send(e.data);
      }
    });
    server.addEventListener("close", () => existing.close());
    existing.addEventListener("close", () => server.close());
  } else {
    // First peer: park and wait.
    relaySessions.set(sessionId, server);
    // Clean up if the first peer disconnects before the second arrives.
    server.addEventListener("close", () => {
      if (relaySessions.get(sessionId) === server) {
        relaySessions.delete(sessionId);
      }
    });
  }

  return new Response(null, { status: 101, webSocket: client });
}

// ── Router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    // Security headers on every response.
    const wrap = (r: Response): Response => {
      r.headers.set("Cache-Control", "no-store");
      r.headers.set("X-Content-Type-Options", "nosniff");
      return r;
    };

    try {
      if (path === "/health" && req.method === "GET") {
        return wrap(handleHealth());
      }
      if (path === "/register" && req.method === "POST") {
        return wrap(await handleRegister(req, env));
      }
      if (path === "/peers" && req.method === "GET") {
        return wrap(await handleGetPeers(req, env));
      }
      const relayMatch = path.match(/^\/relay\/([a-zA-Z0-9_-]{8,64})$/);
      if (relayMatch && req.method === "GET") {
        return wrap(await handleRelay(req, env, relayMatch[1]));
      }
      return wrap(new Response("Not Found", { status: 404 }));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "internal error";
      return wrap(new Response(`Internal Server Error: ${msg}`, { status: 500 }));
    }
  },
};
