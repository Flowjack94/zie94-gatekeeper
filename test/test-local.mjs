// Local test harness for the Gatekeeper worker — runs the Worker entrypoint in
// Node (Web Crypto + Request/Response are available in Node 24) with NO deploy.
// Usage: node test/test-local.mjs
import { createHmac } from "node:crypto";
import worker from "../worker.js";

const SECRET = "test-secret-32-bytes-long-0123456789";
const env = { AGENT_GAMES_HMAC_SECRET: SECRET };
const BASE = "https://gatekeeper.test";

function sign(body) {
  return createHmac("sha256", SECRET).update(body, "utf8").digest("hex");
}

async function post(bodyObj, { sig = true, rawBody = null } = {}) {
  const body = rawBody ?? JSON.stringify(bodyObj);
  const headers = { "content-type": "application/json" };
  if (sig) headers["x-agent-games-signature"] = sign(body);
  const t0 = Date.now();
  const res = await worker.fetch(new Request(BASE + "/agent", { method: "POST", headers, body }), env);
  const ms = Date.now() - t0;
  const text = await res.text();
  return { status: res.status, ms, body: text, sigHeader: res.headers.get("x-agent-games-signature") };
}

function checkRespSig(r) {
  if (!r.sigHeader) return "MISSING-SIG";
  const expected = createHmac("sha256", SECRET).update(r.body, "utf8").digest("hex");
  return r.sigHeader === expected ? "SIG-OK" : "SIG-BAD";
}

const BASE_INPUT = {
  registered_vk: "0x7d3a11111111111111111111111111111111111111111111111111111111f291",
  proof_vk: "0x7d3a11111111111111111111111111111111111111111111111111111111f291",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: "0xDe4200000000000000000000000000000000009f01",
  condition_recipient: "0xDe4200000000000000000000000000000000009f01",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
};

function task(id, input, proofTx) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: id,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: { ...BASE_INPUT, ...input, ...(proofTx ? { proof_tx: proofTx } : {}) },
  };
}

let pass = 0, fail = 0;
function expect(name, cond, extra = "") {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
}

console.log("== preflight ==");
{
  const r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  const j = JSON.parse(r.body);
  expect("status 200", r.status === 200, `got ${r.status}`);
  expect("ok:true + protocolVersion v1", j.ok === true && j.protocolVersion === "v1", r.body);
  expect("response signed", checkRespSig(r) === "SIG-OK", checkRespSig(r));
  expect("fast (<1000ms)", r.ms < 1000, `${r.ms}ms`);
}

console.log("== unsigned request rejected ==");
{
  const r = await post(task("gk_t_unsigned", {}), { sig: false });
  expect("status 401", r.status === 401, `got ${r.status}`);
}

console.log("== decisions: 7 trap types + valid ==");
const cases = [
  ["valid approve", "gk_t_valid", {}, "APPROVE", "VALID_CONDITION", "0xaaa1000000000000000000000000000000000000000000000000000000000001"],
  ["vk substitution", "gk_t_vk", { proof_vk: "0xa4c10000000000000000000000000000000000000000000000000000000000b8ff" }, "REJECT", "VK_SUBSTITUTION", "0xaaa2000000000000000000000000000000000000000000000000000000000002"],
  ["threshold mismatch", "gk_t_thr", { public_balance: "999" }, "REJECT", "THRESHOLD_MISMATCH", "0xaaa3000000000000000000000000000000000000000000000000000000000003"],
  ["expired", "gk_t_exp", { current_block: 19842201 }, "REJECT", "EXPIRED_CONDITION", "0xaaa4000000000000000000000000000000000000000000000000000000000004"],
  ["recipient mismatch", "gk_t_rcp", { recipient: "0xDe4200000000000000000000000000000000009f02" }, "REJECT", "RECIPIENT_MISMATCH", "0xaaa5000000000000000000000000000000000000000000000000000000000005"],
  ["amount overflow", "gk_t_amt", { amount: "1001" }, "REJECT", "AMOUNT_OVERFLOW", "0xaaa6000000000000000000000000000000000000000000000000000000000006"],
];
for (const [name, id, patch, wantDecision, wantReason, tx] of cases) {
  const r = await post(task(id, patch, tx));
  let j = {};
  try { j = JSON.parse(r.body); } catch { /* ignore */ }
  expect(`${name}: ${wantDecision}/${wantReason}`, r.status === 200 && j.decision === wantDecision && j.reason_code === wantReason && j.proof_tx === tx, `got ${r.status} ${r.body}`);
  expect(`${name}: signed`, checkRespSig(r) === "SIG-OK", checkRespSig(r));
  expect(`${name}: fast`, r.ms < 1000, `${r.ms}ms`);
}

console.log("== proof reuse ==");
{
  // The valid case above APPROVEd tx ...0001. Same proof_tx, new task_id -> REJECT PROOF_REUSED.
  const r = await post(task("gk_t_reuse", {}, "0xaaa1000000000000000000000000000000000000000000000000000000000001"));
  const j = JSON.parse(r.body);
  expect("reused proof rejected", j.decision === "REJECT" && j.reason_code === "PROOF_REUSED", r.body);
  // Same task_id retried -> identical cached response (still the APPROVE).
  const r2 = await post(task("gk_t_valid", {}, "0xaaa1000000000000000000000000000000000000000000000000000000000001"));
  const j2 = JSON.parse(r2.body);
  expect("same task_id returns cached APPROVE", j2.decision === "APPROVE" && j2.reason_code === "VALID_CONDITION", r2.body);
}

console.log("== deadline passed fails closed ==");
{
  const t = task("gk_t_late", {}, "0xaaa7000000000000000000000000000000000000000000000000000000000007");
  t.deadline_at = new Date(Date.now() - 1000).toISOString();
  const r = await post(t);
  const j = JSON.parse(r.body);
  expect("late task rejected", j.decision === "REJECT", r.body);
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
