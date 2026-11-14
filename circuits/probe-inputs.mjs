import fs from "node:fs";
function fnvHash(str) {
  const bytes = Buffer.from(str, "utf8");
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (const b of bytes) { h ^= BigInt(b); h = (h * prime) & 0xffffffffffffffffn; }
  return h.toString(16).padStart(16, "0");
}
const wasm = fs.readFileSync("circuits/gatekeeper.wasm");
const { instance } = await WebAssembly.instantiate(wasm, {});
const ex = instance.exports;
console.log("exports:", Object.keys(ex).filter(k=>/input|signal|version|witness/i.test(k)));
console.log("inputSize total:", ex.getInputSize());
const candidates = [
  "decision","approve","approved","isApproved","valid","isValid","result","outcome",
  "reasonCode","reason_code","reason","reasonCodeHash",
  "taskId","task_id","taskHash","task_hash","nonce","issuedAt","issued_at","deadlineAt","deadline_at","mode","type",
  "vkHash","vk_hash","vk","registeredVk","registered_vk","registeredVkHash","proofVk","proof_vk","proofVkHash",
  "publicBalance","public_balance","balance","minimum","threshold","amount","maxTransfer","max_transfer",
  "recipient","conditionRecipient","condition_recipient","recipientHash",
  "expiryBlock","expiry_block","currentBlock","current_block","expiry","blockNumber",
  "proofTx","proof_tx","proofRef","proofReference","proof_reference","proofHash","txHash",
  "agentId","agent_id","agent","secret","salt","commitment","nullifier","publicSignals","vkRegistered",
  "checkPassed","checksPassed","allChecks","passed",
  // single letters / generic circom names
  "a","b","c","x","in","input","out","signal",
  // hashed variants
  "taskIdHash","decisionHash","proofTxHash","recipientHash2",
];
const found = [];
for (const name of candidates) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  try {
    const size = ex.getInputSignalSize(hMSB, hLSB);
    if (size >= 0) found.push([name, size]);
  } catch (e) { /* absent */ }
}
console.log("FOUND:", JSON.stringify(found));
