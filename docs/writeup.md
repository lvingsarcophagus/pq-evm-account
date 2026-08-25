# Hybrid Post-Quantum Signature Verification for ERC-4337 Smart Accounts

**pq-evm-account — technical writeup, v1**
Date: 2026-08-24 · Status: experimental, unaudited

---

## 1. Summary

We implemented and validated an independent Solidity verifier for **SPHINCS- C13**
— a stateless hash-based post-quantum signature scheme derived from SLH-DSA
(FIPS 205), instantiated with keccak256 and parameterized for wallet-scale
signature budgets — and integrated it into an ERC-4337 smart account that
requires **both** a classical ECDSA signature and the PQ signature over every
UserOperation.

Every claim in this document is backed by an artifact in this repository
(committed test vectors, runnable tests, benchmark scripts, or an on-chain
transaction). Section 6 lists exactly what we do *not* claim.

## 2. Claims and their evidence

| # | Claim | Evidence |
|---|---|---|
| C1 | Our verifier accepts all valid reference-signer signatures | `test/SphincsVerifier.t.sol::test_ReferenceVectors_Accept`, vectors in `test/vectors/c13.json` |
| C2 | Any single-bit mutation of a valid signature is rejected | `testFuzz_SigBitFlip_Reject` (256 runs), `DifferentialTest` fuzzing |
| C3 | Wrong message / wrong hash / swapped keys are rejected; malformed inputs revert cleanly | `SphincsVerifierTest`, `HybridAccountTest` |
| C4 | Verification costs **98,118 gas** (execution only) | `benchmarks/gas-report.md`, `script/BenchmarkChains.s.sol` |
| C5 | That cost is **identical across Ethereum-Sepolia, Arbitrum-Sepolia, Base-Sepolia, OP-Sepolia, Polygon-Amoy** | same, forked-state simulation at live blocks |
| C6 | A UserOp carrying both signatures executes through the real EntryPoint v0.8 on Sepolia | tx [`0xb987b7f3…ae291`](https://sepolia.etherscan.io/tx/0xb987b7f3a10ae26326439af36292d62ca7c4cd654250547a7212cbefb26ae291), account `0x7CD2f0C3…a38A9`, nonce consumed, deposit debited |
| C7 | Either signature failing alone fails validation; both layers must pass | `HybridAccountTest` matrix + `test_handleOps_rejectsWhenOnlyECDSAValid` |

## 3. Design

### 3.1 Parameter set (C13)

n=16, h=22 (2²² ≈ 4.2M signatures/key), d=2, FORS k=7/a=19, Winternitz w=8
(l=43 chains), WOTS+C target digit-sum grinding (208), forced-zero FORS tree,
keccak256 substituted for SHAKE256. Signature size 3,704 bytes. Parameters per
the June 2026 ethresear.ch proposal by nconsigny; our implementation is an
independent codebase following FIPS 205 §4.2 ADRS layout.

### 3.2 Two implementations, one contract

- `verify()` — optimized single-pass assembly hot path: fixed scratch slots,
  branchless Merkle swaps, no allocation. **105,707 gas** on Anvil defaults,
  **98,118** on live-chain forks.
- `verifyReadable()` — plain-Solidity oracle (~600K gas), kept solely as a
  differential-fuzz counterpart: the two must agree bit-for-bit on acceptance
  across mutated inputs (`test/Differential.t.sol`).

The optimization was gated by differential testing, which caught two real
defects during development (static-array packing offsets; a lost FORS-commitment
initialization during helper extraction).

### 3.3 Hybrid account (`src/account/HybridPQAccount.sol`)

`userOp.signature = SPHINCS- sig (3688 B) ‖ ECDSA (r,s,v) (65 B)`, both over
`userOpHash`. Validation returns ERC-4337 `SIG_VALIDATION_FAILED` (not a revert)
when either layer fails, preserving mempool simulation semantics. The ECDSA
owner may rotate PQ keys (`setPQKeys`); rotation changes only which PQ key must
co-sign future spends — per-operation dual control is unchanged.

## 4. Measurement notes (methodology honesty)

- **Storage-read pitfall:** an early benchmark measured ~250K gas of cold
  SLOADs alongside verification because the 3.7 KB signature was decoded from
  storage inside the timed region. All published numbers decode inputs first;
  pure verify is what's reported.
- **via-ir penalty:** IR codegen adds ~260K gas around the assembly block vs
  the legacy pipeline; the project pins `via_ir = false`.
- **Cross-chain method:** identical bytecode deployed against forked live state
  via public RPC, deterministic across repeated runs. This isolates EVM
  execution pricing; it does *not* capture L1 data-availability fees (§5).
- The published ~127K figure for C13 reconciles with our 100–106K execution
  measurement once transaction-level calldata cost (~59K for a mostly-nonzero
  3.7 KB signature) is included.

## 5. What we explicitly do NOT claim

Per the project's scope discipline:

1. **Not audited.** No formal verification of our Solidity (upstream provides a
   Lean/Verity proof for *their* verifiers; ours is validated by differential +
   vector testing only). Treat all contracts as research-stage.
2. **No EOA protection.** Nothing here helps externally owned accounts; native
   `ecrecover` interception requires protocol change.
3. **No token-level protection.** ERC-20 transfers don't consult wallet
   signatures; this doesn't make any token quantum-resistant.
4. **L2 end-to-end cost unmeasured.** On Arbitrum/Base/OP the dominant UserOp
   cost will be L1 data posting of the 3.7 KB signature, not the 98K execution
   gas. We have not yet captured real receipts there.
5. **Signer-side key management is out of scope for this repo.** The committed
   `tools/signer-c13` is the upstream *demo* signer: it derives keys
   deterministically from each message (no persistent secret). Our work
   validates the verifier and account integration; production deployment needs
   a real signer with protected secret state and a migration story.
6. **Third-party bundler path partially blocked.** Live submission used
   self-bundling (direct `handleOps`); Alchemy free-tier rejected
   `eth_sendUserOperation` outright. Third-party bundler compatibility remains
   to be demonstrated with Pimlico/Stackup or an Alchemy AA-enabled key.
7. **Single parameter set.** Only C13 is implemented; hardware-wallet-friendly
   variants (C11/C12) are future work.

## 6. Security considerations

- **Why hybrid:** the PQ code is new. Requiring ECDSA co-signature means an
  undiscovered bug in either primitive alone cannot move funds. The residual
  risk concentrates in implementation bugs common to both paths (e.g., hash
  computation of `userOpHash`) and in the account logic itself.
- **FORS few-time reuse:** C13's security degrades with per-key signature count
  per the upstream analysis (2²² budget, k·a=133-bit FORS margin at low
  counts). Keys should be rotated well before budget exhaustion.
- **Key rotation trust:** `setPQKeys` is owner-only by design. An attacker with
  only the PQ key material cannot rotate; an attacker with the ECDSA key can,
  but then still cannot spend without a valid PQ signature under the new keys…
  unless they also control the new PQ key. Rotation therefore assumes the
  rotating party generates honest new PQ keys — acceptable for the reference
  design, worth revisiting for production.
- **Canonical-key check:** public keys must have zero lower halves; the
  verifier reverts otherwise, preventing silent address-mismatch bricking.

## 7. Reproduction

```shell
git clone https://github.com/lvingsarcophagus/pq-evm-account && cd pq-evm-account
forge install   # deps are vendored; forge build directly also works
forge test                                            # 21 tests
forge test --match-test test_GasBenchmark -vv         # gas numbers
forge script script/BenchmarkChains.s.sol \
  --fork-url https://ethereum-sepolia-rpc.publicnode.com -vvv
```

Requires Foundry with `ffi = true` (set in foundry.toml); tests use the
committed Linux x86_64 signer binary at `tools/signer-c13`.

## 8. Future work

Live deployments + receipts across L2 testnets (incl. L1-data fee capture);
third-party bundler demonstration; audited/reviewed release; Naysayer
optimistic-verification mode (opt-in, different trust assumptions); leanSPHINCS
ZK-friendly variant tracking.
