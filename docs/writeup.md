# pq-evm-account — Technical Writeup v2

**Hybrid post-quantum signature verification for ERC-4337 smart accounts**
Date: 2026-08-24 · Status: experimental, unaudited · License: MIT

---

## 1. Summary

This project demonstrates that Ethereum smart accounts can gain **post-quantum
signature protection today** — without a hard fork, precompile, or protocol
change — by verifying SPHINCS- C13 signatures (hash-based, keccak256-instantiated)
inside ERC-4337 `validateUserOp`.

We ship and validate:

1. **An independent Solidity verifier** for SPHINCS- C13 (3,704-byte signatures,
   2²² per-key budget), optimized to **98,118 gas** on live chain state — within
   5% of the reference assembly implementation and consistent across five EVM chains.
2. **Two account designs** built on it:
   - `HybridPQAccount` — every operation requires both ECDSA and PQ signatures
     (maximum security, maximum cost).
   - `ThresholdHybridAccount` — risk-based protection: everyday operations use
     cheap ECDSA-only authentication; large transfers, untrusted callees, and
     administration automatically demand the quantum-safe co-signature.

Both were executed live on Sepolia through the canonical EntryPoint v0.8
(`0x4337084D9E255Ff0702461CF8895CE9E3b5FF108`).

## 2. Claims and evidence

| # | Claim | Evidence |
|---|---|---|
| C1 | Verifier accepts all valid reference-signer signatures | `test_ReferenceVectors_Accept`, vectors in `test/vectors/c13.json` |
| C2 | Any single-bit mutation of a valid signature is rejected | fuzz tests, 256+ runs per suite |
| C3 | Wrong message/hash/keys rejected; malformed input reverts cleanly | `SphincsVerifierTest`, account test suites |
| C4 | Verify costs **98,118 gas** (execution only) | `benchmarks/gas-report.md`, `script/BenchmarkChains.s.sol` |
| C5 | Identical cost on Sepolia, Arbitrum-Sepolia, Base-Sepolia, OP-Sepolia, Polygon-Amoy | same, forked-state simulation |
| C6 | Hybrid UserOp executed live via EntryPoint v0.8 on Sepolia | tx [`0xb987b7f3…ae291`](https://sepolia.etherscan.io/tx/0xb987b7f3a10ae26326439af36292d62ca7c4cd654250547a7212cbefb26ae291) |
| C7 | Either signature failing alone fails validation | hybrid + threshold test matrices |
| C8 | Cheap-path ops authenticate with a 65-byte ECDSA signature at normal cost, with zero PQ involvement | tx [`0xb18a0a82…d2c6b37`](https://sepolia.etherscan.io/tx/0xb18a0a82c088a1bb8e68343eee3b7666214ca3d75ed3519f637050523d2c6b37), 91,772 gas total |
| C9 | Policy/PQ-key configuration cannot be weakened by the ECDSA key alone once provisioned | `ThresholdAccountTest::test_bootstrapThenLock`, `test_setPolicy_lockedAfterProvisioning` |

## 3. Design

### 3.1 SPHINCS- C13

Parameters per the June 2026 ethresear.ch proposal (nconsigny): n=16, h=22,
d=2, FORS k=7/a=19, w=8/l=43, WOTS+C target-sum grinding (208), forced-zero
FORS tree, keccak256 substituted for SHAKE256, FIPS 205 §4.2 ADRS layout.
Our implementation is an independent codebase validated against the upstream
reference signer's outputs.

### 3.2 Two implementations, differential testing

`verify()` (optimized assembly) must agree bit-for-bit with
`verifyReadable()` (plain-Solidity oracle) across mutated inputs. This caught
two real defects during development. The readable version costs ~600K gas and
exists purely as a test oracle.

### 3.3 Signature layouts

```
HybridPQAccount / risky path:
  userOp.signature = SPHINCS- sig [3688 B] ‖ ECDSA r,s,v [65 B]   (3753 B)

ThresholdHybridAccount cheap path:
  userOp.signature = ECDSA r,s,v [65 B]
```

Both signatures cover the same `userOpHash` (recomputed by EntryPoint v0.8).

### 3.4 Risk classification (`ThresholdHybridAccount`)

An operation requires the PQ co-signature if any of:

- global switch `requireHybridForAll`
- transfer value ≥ `valueThreshold`
- callee not in the trusted-target allowlist (**fail-closed default**)
- self-targeted call (administration surface)
- callData does not decode to a known execute selector

Configuration (`setPolicy`, `setTrustedTarget`) is reachable only through
self-execution inside a hybrid-validated UserOp once PQ keys are live;
before that, an explicit bootstrap window allows the ECDSA owner to configure
and provision. Consequence: a quantum adversary holding only the ECDSA key
can spend small amounts to already-trusted targets — nothing more — and can
never disable or weaken the PQ layer.

## 4. Measurements

See [`benchmarks/gas-report.md`](../benchmarks/gas-report.md) for full detail.

| Measurement | Result |
|---|---|
| verify() execution gas (live-chain forks, ×5 chains) | **98,118**, deterministic |
| verify() on Anvil defaults | 105,707 |
| Reference assembly verifier | 100,251 |
| Full hybrid UserOp, live Sepolia | 272,212 gas (tx-level) |
| Cheap-path UserOp, live Sepolia | 91,772 gas (tx-level) |

Methodology notes: inputs decoded before timing (an early benchmark
accidentally measured ~250K of storage reads); `via_ir = false` pinned
(IR adds ~260K around the assembly block); cross-chain numbers come from
forked-state simulation, which isolates EVM execution pricing from L1
data-availability fees.

## 5. What we do NOT claim

1. **Not audited.** Our code is validated by vector tests, differential fuzzing,
   and live execution — not formal verification or security review.
2. **No EOA protection.** EOAs cannot intercept native `ecrecover`.
3. **No token-level protection.** ERC-20 transfers don't consult wallet signatures.
4. **L2 end-to-end fees unmeasured.** On rollups, posting the 3.7 KB signature
   to L1 will dominate UserOp cost; real receipts pending.
5. **Demo-grade signer.** The committed signer derives keys from each message
   (no persistent secret). Production needs real secret management, which is
   out of scope here. The *verifier* side is what this repo validates.
6. **Third-party bundlers blocked (provider-side).** Live submission used
   self-bundling. Alchemy free-tier blanket-rejects sends; Pimlico's simulator
   reverts empty even on corrupted-signature controls while identical inputs
   succeed on canonical state. Reproduction in repo history.
7. **Single parameter set** (C13). Hardware-wallet-friendly variants future work.
8. **Per-key budget:** ~4.2M signatures before FORS degradation requires rotation.

## 6. Security considerations

- **Why hybrid:** the PQ implementation is new; ECDSA co-signature means a bug
  in either primitive alone cannot move funds.
- **Threshold model residual risk:** small transfers to trusted targets are
  ECDSA-only. Users should set thresholds according to what they can afford to
  lose to a classical (non-quantum) key compromise.
- **Bootstrap window:** before provisioning, the account has no PQ protection;
  provision promptly after deployment.
- **Canonical keys enforced** (zero lower halves) to prevent silent mismatch.

## 7. Reproduction

```shell
git clone https://github.com/lvingsarcophagus/pq-evm-account && cd pq-evm-account
forge test                                          # 33 tests
forge test --match-test test_GasBenchmark -vv       # gas
forge script script/BenchmarkChains.s.sol \
  --fork-url https://ethereum-sepolia-rpc.publicnode.com -vvv
```

Requires Foundry; `ffi = true` (already in foundry.toml); tests use the
committed Linux x86_64 signer at `tools/signer-c13`.

## 8. Future work

Live L2 receipts incl. L1-data fees; third-party bundler demonstration;
session keys amortizing one hybrid signature across many cheap ops; Naysayer
optimistic verification; audited release; leanSPHINCS tracking.
