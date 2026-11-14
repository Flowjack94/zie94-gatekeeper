# Gatekeeper Groth16 decision proof — findings (2026-11-14)

Circuit: `gatekeeper.wasm` + `gatekeeper_final.zkey` (Groth16 / BN128, Circom 2.x).
Template `GatekeeperEvaluation_79`. Witness size 647. vkHash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

## Inputs (13, all size 1, probed via `getInputSignalSize`)

| input | meaning |
|---|---|
| `decision` | 1 = APPROVE, 0 = REJECT |
| `taskId` | task id as a field element |
| `registeredVkHash` | registered condition VK hash as a field element |
| `proofVkHash` | proof's VK hash as a field element |
| `publicBalance` | on-chain balance (integer) |
| `minimum` | threshold (integer) |
| `amount` | transfer amount (integer) |
| `maxTransfer` | max transfer (integer) |
| `recipient` | recipient address (integer) |
| `conditionRecipient` | condition recipient address (integer) |
| `expiryBlock` | expiry block (integer) |
| `currentBlock` | current block (integer) |
| `salt` | private salt (random per proof) |

## Public signals (13, order proven by a real proof)

```
[0]  Poseidon(salt, taskId)     <- binding commitment; VERIFIED by experiment
[1]  registeredVkHash
[2]  proofVkHash
[3]  minimum
[4]  publicBalance
[5]  expiryBlock
[6]  currentBlock
[7]  recipient
[8]  conditionRecipient
[9]  amount
[10] maxTransfer
[11] decision
[12] taskId
```

Experiment: input `{decision:1, taskId:2, registeredVkHash:3, proofVkHash:3,
publicBalance:1460, minimum:1000, amount:500, maxTransfer:1000, recipient:9,
conditionRecipient:9, expiryBlock:19842201, currentBlock:19832000, salt:13}`
produced public signals
`[15867685234644183079204889623347310915484708841379972547850205349761700032732,
3, 3, 1000, 1460, 19842201, 19832000, 9, 9, 500, 1000, 1, 2]`.
`Poseidon([13, 2])` (circomlibjs) equals signal [0] exactly.
keccak256 / sha256 / Poseidon([salt]) / Poseidon(all 12) / Poseidon(salt+12)
all tested and REJECTED.

## Circuit semantics (proven by witness experiments)

- `decision = 1` + all checks consistent → witness OK, proof generates.
- `decision = 0` + a check failing (e.g. VK mismatch) → witness OK.
- `decision = 0` + ALL checks passing → witness ASSERTION FAILS (line 102).
- `decision = 1` + any check failing → witness ASSERTION FAILS (line 102).

So the circuit enforces **decision == (all 7 checks pass)**. A proof attests the
decision is correct — you cannot prove a wrong decision. The agent's decision
logic must match the circuit's checks exactly (it does — see worker.js).

## Performance (local, snarkjs 0.7.5)

- Witness calculation: ~0.5 s.
- Groth16 prove: **~1.3 s** (total fullProve ≈ 2 s, well inside 60 s).
- Verify: instant.
- Artifacts: wasm 1,755,820 bytes, zkey 309,750 bytes.

## OPEN — string → field-element encoding (not documented publicly)

To submit a proof the platform accepts, the agent must encode the task's
string fields exactly the way the platform expects:

- `taskId` is a string like `"gk_24_9d1"`. Candidate encodings:
  keccak256(taskId) mod p, Poseidon of ASCII bytes, ASCII packing.
  **Not verified — no public material states it.**
- `registeredVkHash` / `proofVkHash` are 32-byte hashes. The gatekeeper vkHash
  `0x6b79c601...` EXCEEDS the BN128 prime p, so the raw integer cannot be a
  circuit input — the platform MUST reduce it somehow; **BigInt(hex) mod p is
  the most likely scheme, unconfirmed**.
- Numbers and 20-byte addresses are unambiguous (raw integer, always < p).
- `salt`: the platform cannot recompute Poseidon(salt, taskId) without the salt,
  and the response format has no salt field — so signal [0] is most likely
  NOT re-derived by the platform; it just binds the proof to the task. The
  platform most likely checks: (a) proof verifies against the registered vk
  with the supplied public signals, (b) public signals [1..12] match the task
  under ITS encoding, (c) decision matches its own scoring.

## How to unlock phase 2

1. Run a practice task from Alza's dashboard (practice mode, behind his login).
2. Submit a proof generated locally with the candidate encoding
   (taskId → keccak256 mod p; vkHash → BigInt mod p; salt random) and see
   whether the platform accepts it (reliability bonus / no −2).
3. If rejected, try the next candidate encoding (Poseidon of ASCII bytes for
   taskId; Poseidon(vkHash bytes) for the VKs).
4. Alternatively, ask the platform docs/support for the exact encoding.

## Worker feasibility

Proving inside the Cloudflare Worker is possible in principle (fetch wasm+zkey
from the public circuit URLs at cold start, cache in memory, snarkjs in the
bundle) but NOT attempted: the wasm (1.75 MB) + zkey (310 KB) exceed the 1 MB
free script limit if bundled, and snarkjs's Node-isms need wrangler bundling
verification. The decision-only agent ships first; proving can be added once
the encoding is confirmed (or proving can run in a tiny side service).

## Files in this folder

- `gatekeeper.wasm`, `gatekeeper_final.zkey`, `vk.json` — circuit artifacts.
- `input-approve.json`, `witness-approve.wtns`, `proof-approve.json`,
  `public-approve.json` — the proven APPROVE experiment (taskId 2, salt 13).
- `input-reject.json`, `input-reject-valid.json` — reject witness experiments.
- `probe-inputs.cjs/.mjs`, `witness-order.cjs`, `witness-order2.cjs` — probing scripts.
