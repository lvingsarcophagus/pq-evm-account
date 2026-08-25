# pq-evm-account

Hybrid post-quantum signature verification for ERC-4337 smart accounts.
Adds a quantum-safe backup signature requirement to any smart wallet today —
no hard fork required.

**Status: Phase 2 complete — experimental, unaudited.**

> **Requires `ffi = true`** (set in foundry.toml): the hybrid-signature tests
> invoke the committed reference signer binary at `tools/signer-c13` (Linux
> x86_64, MIT-licensed reference implementation from nconsigny/SPHINCs-).

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

## Testnet / live bundler

Deploy (any EVM chain with EntryPoint v0.8 at the canonical address):

```shell
export PRIVATE_KEY=<funded key>            # also becomes the ECDSA owner
export ENTRYPOINT=0x4337084D9E255Ff0702461CF8895CE9E3b5FF108
forge script script/DeployTestnet.s.sol --rpc-url <RPC> --broadcast
```

Send a hybrid-signed UserOp through a bundler:

```shell
export ACCOUNT=<deployed address>
export BUNDLER_RPC=<alchemy/stackup/pimlico node URL>
./scripts/send_userop.sh
```

The script computes `getUserOpHash`, PQ-signs it with the reference signer,
rotates the on-chain PQ keys if needed, ECDSA-signs, and submits via
`eth_sendUserOperation`. Verified end-to-end locally against a real
`EntryPoint.handleOps` (nonce consumed, gas paid from the account deposit).

## Reproduce

```shell
forge test --match-contract SphincsVerifierTest -vv   # correctness + gas
forge test --match-contract DifferentialTest -vv      # impl agreement fuzzing
```

## Roadmap

- [x] Phase 1 — independent verifier validated against reference vectors
- [x] Phase 1b — optimized hot path within ~5% of reference assembly
- [x] Phase 2 — ERC-4337 `HybridPQAccount` (`validateUserOp`: ECDSA + PQ),
      executed end-to-end through the real v0.8 `EntryPoint.handleOps`
- [x] Phase 3 — gas consistency verified via forked-state simulation:
      **98,118 gas identically** on Ethereum-Sepolia, Arbitrum-Sepolia,
      Base-Sepolia, OP-Sepolia, Polygon-Amoy (`benchmarks/gas-report.md`).
      Live deployments deferred.
- [ ] Phase 4 — writeup + community review
