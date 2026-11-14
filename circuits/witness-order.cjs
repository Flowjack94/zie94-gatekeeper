const fs = require("node:fs");
const snarkjs = require("snarkjs");
(async () => {
  // distinct small values per input to map witness public-signal order
  const input = {
    decision: 1, taskId: 2, registeredVkHash: 3, proofVkHash: 4,
    publicBalance: 5, minimum: 6, amount: 7, maxTransfer: 8,
    recipient: 9, conditionRecipient: 10, expiryBlock: 11, currentBlock: 12, salt: 13,
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
  console.log("publicSignals:", JSON.stringify(publicSignals));
  console.log("proof pi_a:", proof.pi_a.slice(0,2));
  // verify locally against the exported vk
  const vk = JSON.parse(fs.readFileSync("circuits/vk.json", "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log("local verify:", ok);
})();
