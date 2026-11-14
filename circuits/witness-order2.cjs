const fs = require("node:fs");
const snarkjs = require("snarkjs");
(async () => {
  const approve = {
    decision: 1, taskId: 2, registeredVkHash: 3, proofVkHash: 3,
    publicBalance: 1460, minimum: 1000, amount: 500, maxTransfer: 1000,
    recipient: 9, conditionRecipient: 9, expiryBlock: 19842201, currentBlock: 19832000, salt: 13,
  };
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      approve, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
    console.log("APPROVE-case publicSignals:", JSON.stringify(publicSignals));
    const vk = JSON.parse(fs.readFileSync("circuits/vk.json", "utf8"));
    console.log("APPROVE-case local verify:", await snarkjs.groth16.verify(vk, publicSignals, proof));
  } catch (e) { console.log("APPROVE-case FAILED:", String(e).split("\n")[0]); }
  const reject = { ...approve, decision: 0, proofVkHash: 4 };
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      reject, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
    console.log("REJECT-case publicSignals:", JSON.stringify(publicSignals));
    const vk = JSON.parse(fs.readFileSync("circuits/vk.json", "utf8"));
    console.log("REJECT-case local verify:", await snarkjs.groth16.verify(vk, publicSignals, proof));
  } catch (e) { console.log("REJECT-case FAILED:", String(e).split("\n")[0]); }
})();
