# pq-evm-account

Hybrid post-quantum signature verification for ERC-4337 smart accounts.
Adds a quantum-safe backup signature requirement to any smart wallet today —
no hard fork required.

**Status: Phase 1b complete — experimental, unaudited.**

## Results at a glance

`src/verifiers/SphincsMinusVerifier.sol` verifies **SPHINCS- C13** signatures
(hash-based post-quantum, keccak256-instantiated, n=16 h=22 d=2 k=7 a=19 w=8
l=43, 3,704-byte signatures) per the June 2026 ethresear.ch proposal by
nconsigny.

| Verifier | Gas |
|---|---|
| Reference assembly contract | 100,251 |
| **Ours (optimized `verify`)** | **105,707** (+5.4%) |
| Ours (readable `verifyReadable`) | ~600K (kept as test oracle) |

The published ~127K figure includes the calldata floor for a 3.7 KB signature;
we reproduce it end-to-end. Full numbers and methodology:
[benchmarks/gas-report.md](benchmarks/gas-report.md).

## Correctness gate

- Accepts all reference-signer vectors (`test/vectors/c13.json`, committed).
- Rejects any single-bit signature mutation — fuzz-tested.
- Rejects wrong messages, swapped keys, malformed inputs; reverts on
  non-canonical public keys and bad lengths.
- **Differential testing**: the optimized assembly path and the readable
  implementation must agree on every input (fuzzed mutations, random messages).

## Scope & non-goals (read before citing)

- ERC-4337 smart accounts only — **not** EOAs, not token-level protection.
- Not audited. Research-stage; the planned hybrid ECDSA+PQ mode exists
  precisely because this code is unproven.

## Layout

```
src/verifiers/   SPHINCS- verifier (optimized + readable oracle)
src/account/     (Phase 2) ERC-4337 hybrid account
test/vectors/    reference-signer test vectors
benchmarks/      per-phase gas reports
docs/            technical writeup (Phase 4)
```

## Reproduce

```shell
forge test --match-contract SphincsVerifierTest -vv   # correctness + gas
forge test --match-contract DifferentialTest -vv      # impl agreement fuzzing
```

## Roadmap

- [x] Phase 1 — independent verifier validated against reference vectors
- [x] Phase 1b — optimized hot path within ~5% of reference assembly
- [ ] Phase 2 — ERC-4337 `HybridPQAccount` (`validateUserOp`: ECDSA + PQ)
- [ ] Phase 3 — multi-testnet gas consistency (Sepolia / Arbitrum / Base)
- [ ] Phase 4 — writeup + community review
