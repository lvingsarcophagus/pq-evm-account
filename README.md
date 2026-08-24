# pq-evm-account

Hybrid post-quantum signature verification for ERC-4337 smart accounts.
Adds a quantum-safe backup signature requirement to any smart wallet today —
no hard fork required.

**Status: Phase 1 (verifier correctness) — experimental, unaudited.**

## What works today

`src/verifiers/SphincsMinusVerifier.sol` verifies **SPHINCS- C13**
signatures (hash-based post-quantum, keccak256-instantiated, n=16 h=22 d=2
k=7 a=19 w=8 l=43, 3,704-byte signatures) against the reference scheme
described in the June 2026 ethresear.ch post by nconsigny.

- Correctness gate: accepts all reference-signer vectors; rejects any
  single-bit mutation (fuzz-tested), wrong messages, and malformed inputs.
- Gas: see `benchmarks/gas-report.md`. The readable v0 costs ~604K gas;
  the reference assembly implementation measures ~100K on identical inputs
  (independently reproduced; published ~127K figure includes calldata).

## Scope & non-goals (read before citing)

- ERC-4337 smart accounts only — **not** EOAs, not token-level protection.
- Not audited. Treat as research-stage; hybrid ECDSA+PQ mode is planned
  precisely because this code is unproven.

## Layout

```
src/verifiers/   SPHINCS- verifier library
src/account/     (Phase 2) ERC-4337 hybrid account
test/vectors/    reference-signer test vectors
benchmarks/      per-phase gas reports
docs/            technical writeup (Phase 4)
```

## Reproduce

```shell
forge test --match-contract SphincsVerifierTest -vv   # correctness + gas
```

Vectors in `test/vectors/c13.json` were generated with the reference Rust
signer (`nconsigny/SPHINCs-`, `signer-c13 c13 <msg-hex>`) and are committed
for reproducibility.
