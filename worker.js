// zkVerify Agent Games — Proof Gatekeeper agent (Cloudflare Worker).
//
// Protocol (source of truth: https://agentgames.zkverify.io/build,
// https://agentgames.zkverify.io/events/proof-gatekeeper,
// https://agentgames.zkverify.io/rules):
// - Platform POSTs signed JSON tasks to this public HTTPS endpoint.
// - Inbound: verify HMAC-SHA256 over the RAW request body against the
//   `x-agent-games-signature` header (secret = AGENT_GAMES_HMAC_SECRET,
//   32-byte value issued once at registration via dashboard "Rotate Secret").
// - Preflight:  {"type":"agent-games.preflight.v1","agent_id":"agt_...","issued_at":"...","nonce":"..."}
//   -> respond {"ok":true,"protocolVersion":"v1"} (signed).
// - Task: {"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_24_9d1","mode":"competition",
//   "issued_at":"...","deadline_at":"...","input":{registered_vk, proof_vk, minimum,
//   public_balance, expiry_block, current_block, recipient, condition_recipient,
//   amount, max_transfer, proof_tx}}
// - Response: {"decision":"APPROVE"|"REJECT","reason_code":"...","proof_tx":"..."}
//   signed with x-agent-games-signature over the raw response body.
// - 60s hard deadline. Fail closed: REJECT on timeout/uncertainty.
// - task_id is the idempotency key: a retried delivery must get the same response.
//   The response is stored durably in KV ("task:<task_id>") as well as in the
//   per-isolate cache, so a retry on another isolate replays the original.
// - Only APPROVEd proof_tx values go into the seen-set (PROOF_REUSED = "already
//   accepted in a previous task").
//
// FIX 2026-11-15 (GPT-6 Astra review): durable task records in KV; strict
// numeric/string field types in decide(); null-envelope guard; base64
// signatures checked against the original-case header; unsigned DEV MODE
// fallback removed (no secret = 500, never accept unsigned); KV calls bounded
// at 5s so a stalled store cannot eat the 60s budget. Residuals the review
// flagged but this change does not fix: proof acceptance is check-then-act
// (KV has no atomic claim; a Durable Object would be needed for strict
// correctness) and an empty proof_tx can still APPROVE (no fitting reason
// code exists for it in the protocol).
//
// PHASE 2 (not yet wired): Groth16 decision proof (proof + public_signals in the
// response). The circuit artifacts are in ./circuits/ and the 13 circuit inputs
// were recovered by probing the wasm (see circuits/PROOF_NOTES.md). What is still
// missing is the platform's exact field-element encoding of taskId / vk hashes /
// addresses — that must come from a practice-task observation (dashboard) or
// platform docs. Without the proof, each provable task costs -2 and earns no
// reliability bonus, but correct decisions still score +12.

const REASON = {
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  REUSED: "PROOF_REUSED",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  OVERFLOW: "AMOUNT_OVERFLOW",
};

// ---- HMAC helpers (Web Crypto, constant-time compare) ----
async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function normalizeSignature(header) {
  if (!header) return null;
  let s = header.trim().toLowerCase();
  if (s.startsWith("sha256=")) s = s.slice(7);
  return s;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function verifySignature(secret, rawBody, header) {
  if (!header) return false;
  const trimmed = header.trim();
  const provided = normalizeSignature(trimmed);
  if (!provided) return false;
  const expectedHex = await hmacHex(secret, rawBody);
  if (timingSafeEqual(provided, expectedHex)) return true;
  // Base64 form is case-sensitive, so use the original header (not lowercased).
  let b64 = trimmed;
  if (/^sha256=/i.test(b64)) b64 = b64.slice(7);
  if (b64 === provided) return false; // already tried as hex above
  try {
    const asBytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const expectedBytes = hexToBytes(expectedHex);
    if (asBytes.length === expectedBytes.length) {
      let diff = 0;
      for (let i = 0; i < asBytes.length; i++) diff |= asBytes[i] ^ expectedBytes[i];
      if (diff === 0) return true;
    }
  } catch { /* not base64 — ignore */ }
  return false;
}

function signResponse(secret, rawBody) {
  return hmacHex(secret, rawBody);
}

// Bound a KV call so a stalled store can never eat the 60s task budget.
// On timeout the caller treats it exactly like a KV error (proceed / ignore).
async function withTimeout(promise, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), ms); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// ---- decision logic: the 7 checks, first failure wins ----
function decide(input, isReused) {
  const norm = (v) => (typeof v === "string" ? v.toLowerCase() : v);
  // Strict numbers only: strings (non-empty) or JSON numbers. Booleans, null,
  // arrays and objects must never coerce to 0/1 (BigInt(null) === 0n).
  const bi = (v) => {
    if (typeof v === "bigint") return v;
    if (typeof v === "number") {
      try { return BigInt(v); } catch { return null; }
    }
    if (typeof v === "string") {
      const s = v.trim();
      if (!s) return null;
      try { return BigInt(s); } catch { return null; }
    }
    return null;
  };

  // 1. Proof reused (only proofs APPROVEd before count as seen).
  if (isReused) return { decision: "REJECT", reason_code: REASON.REUSED };

  // 2. VK substitution — proof verifies but under a different key.
  // VKs must be strings; a truthy non-string (e.g. true) must never pass.
  if (!input.registered_vk || !input.proof_vk ||
      typeof input.registered_vk !== "string" || typeof input.proof_vk !== "string" ||
      norm(input.registered_vk) !== norm(input.proof_vk)) {
    return { decision: "REJECT", reason_code: REASON.VK };
  }

  // 3. Expired condition — current block at/after expiry.
  const expiry = bi(input.expiry_block);
  const current = bi(input.current_block);
  if (expiry === null || current === null || current >= expiry) {
    return { decision: "REJECT", reason_code: REASON.EXPIRED };
  }

  // 4. Recipient mismatch.
  if (!input.recipient || !input.condition_recipient ||
      typeof input.recipient !== "string" || typeof input.condition_recipient !== "string" ||
      norm(input.recipient) !== norm(input.condition_recipient)) {
    return { decision: "REJECT", reason_code: REASON.RECIPIENT };
  }

  // 5. Threshold mismatch — public balance below required minimum.
  const balance = bi(input.public_balance);
  const minimum = bi(input.minimum);
  if (balance === null || minimum === null || balance < minimum) {
    return { decision: "REJECT", reason_code: REASON.THRESHOLD };
  }

  // 6. Amount overflow — amount above single-transfer cap.
  const amount = bi(input.amount);
  const maxTransfer = bi(input.max_transfer);
  if (amount === null || maxTransfer === null || amount > maxTransfer) {
    return { decision: "REJECT", reason_code: REASON.OVERFLOW };
  }

  return { decision: "APPROVE", reason_code: REASON.VALID };
}

const jsonResponse = (obj, status, secret) => {
  const body = JSON.stringify(obj);
  if (!secret) {
    return Promise.resolve(new Response(body, {
      status, headers: { "content-type": "application/json" },
    }));
  }
  return signResponse(secret, body).then((sig) =>
    new Response(body, {
      status,
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sig,
      },
    }));
};

export default {
  async fetch(request, env) {
    const secret = env.AGENT_GAMES_HMAC_SECRET || "";
    const secretIsPlaceholder = !secret || secret === "PLACEHOLDER_SET_VIA_DASHBOARD_ROTATE_SECRET";
    const url = new URL(request.url);

    // Liveness probe (GET /).
    if (request.method === "GET") {
      return new Response(JSON.stringify({
        ok: true, service: "zkverify-gatekeeper", protocolVersion: "v1",
        hmac_configured: !secretIsPlaceholder,
      }), { headers: { "content-type": "application/json" } });
    }
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "method not allowed" }), {
        status: 405, headers: { "content-type": "application/json" },
      });
    }

    const rawBody = await request.text();

    // No secret configured: refuse to process. An unsigned answer would be
    // rejected by the platform anyway, so the old DEV MODE fallback only
    // opened the endpoint to forged tasks and proof-history poisoning.
    if (secretIsPlaceholder) {
      return new Response(JSON.stringify({ error: "hmac not configured" }), {
        status: 500, headers: { "content-type": "application/json" },
      });
    }

    // HMAC verification on the RAW body, before parsing.
    const ok = await verifySignature(secret, rawBody, request.headers.get("x-agent-games-signature"));
    if (!ok) {
      return new Response(JSON.stringify({ error: "bad signature" }), {
        status: 401, headers: { "content-type": "application/json" },
      });
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody);
    } catch {
      return new Response(JSON.stringify({ error: "invalid json" }), {
        status: 400, headers: { "content-type": "application/json" },
      });
    }
    // JSON "null" parses fine but has no .type — fail closed instead of throwing.
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
      return new Response(JSON.stringify({ error: "invalid envelope" }), {
        status: 400, headers: { "content-type": "application/json" },
      });
    }

    // Preflight handshake.
    if (envelope.type === "agent-games.preflight.v1") {
      return jsonResponse({ ok: true, protocolVersion: "v1" }, 200, secret);
    }

    if (envelope.type !== "agent-games.proof-gatekeeper.v1") {
      return new Response(JSON.stringify({ error: "unknown envelope type" }), {
        status: 400, headers: { "content-type": "application/json" },
      });
    }

    const taskId = envelope.task_id || "";
    const input = envelope.input || {};
    const proofTx = typeof input.proof_tx === "string" ? input.proof_tx : "";

    // Idempotency: task_id is the key. A platform retry gets the identical response.
    const cache = globalThis.__taskCache || (globalThis.__taskCache = new Map());
    if (taskId && cache.has(taskId)) {
      const prev = cache.get(taskId);
      return jsonResponse(prev, 200, secret);
    }
    // Durable idempotency: the in-memory cache lives in one isolate only. A
    // retry landing on another isolate would otherwise re-decide — and an
    // APPROVEd proof already in the seen-set would come back REJECT.
    // Check the stored response in KV first, before the reuse check.
    if (taskId && env.SEEN_PROOFS) {
      try {
        const stored = await withTimeout(env.SEEN_PROOFS.get("task:" + taskId), 5000);
        if (stored) {
          const prev = JSON.parse(stored);
          cache.set(taskId, prev);
          return jsonResponse(prev, 200, secret);
        }
      } catch { /* KV unavailable — fall through and decide normally */ }
    }
    const seen = globalThis.__seenProofs || (globalThis.__seenProofs = new Set());
    // Optional durable KV binding (SEEN_PROOFS) — created at deploy time.
    let isReused = proofTx ? seen.has(proofTx.toLowerCase()) : false;
    if (!isReused && proofTx && env.SEEN_PROOFS) {
      try {
        const hit = await withTimeout(env.SEEN_PROOFS.get("proof:" + proofTx.toLowerCase()), 5000);
        if (hit) isReused = true;
      } catch { /* KV unavailable — fall back to in-memory set */ }
    }

    // Deadline already passed? Fail closed.
    let result;
    if (envelope.deadline_at) {
      const deadline = Date.parse(envelope.deadline_at);
      if (!Number.isNaN(deadline) && Date.now() > deadline) {
        result = { decision: "REJECT", reason_code: REASON.EXPIRED };
      }
    }
    if (!result) result = decide(input, isReused);
    const response = { decision: result.decision, reason_code: result.reason_code, proof_tx: proofTx };

    // Record outcome for idempotency + reuse detection (only APPROVEd proofs are "seen").
    // Store the response durably too, so a retry on any isolate replays it.
    if (taskId) cache.set(taskId, response);
    if (taskId && env.SEEN_PROOFS) {
      try { await withTimeout(env.SEEN_PROOFS.put("task:" + taskId, JSON.stringify(response)), 5000); } catch { /* ignore */ }
    }
    if (result.decision === "APPROVE" && proofTx) {
      seen.add(proofTx.toLowerCase());
      if (env.SEEN_PROOFS) {
        try { await withTimeout(env.SEEN_PROOFS.put("proof:" + proofTx.toLowerCase(), taskId || "1"), 5000); } catch { /* ignore */ }
      }
    }

    return jsonResponse(response, 200, secret);
  },
};
