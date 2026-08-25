# pq-evm-account

**Quantum-safe Ethereum wallets you can deploy today.**

A hybrid post-quantum signature layer for ERC-4337 smart accounts. When
quantum computers eventually break ECDSA — the cryptography securing every
Ethereum account today — accounts protected by this project stay safe.

No hard fork. No precompile. Just a smart contract you deploy.

[![tests](https://img.shields.io/badge/tests-33%20passing-brightgreen)]() [![gas](https://img.shields.io/badge/verify-98%2C118%20gas-blue)]() [![live](https://img.shields.io/badge/live-Sepolia%20v0.8-success)]()

---

## Why this exists

Every Ethereum account's security rests on ECDSA (secp256k1), which a sufficiently
powerful quantum computer breaks with Shor's algorithm. Attackers can already
record public keys today and decrypt them years from now ("harvest now,
decrypt later").

This project lets a smart account require a **post-quantum signature alongside
(or instead of, for risky operations) ECDSA**, so funds remain protected even
after ECDSA falls.

## The two account designs

| | `HybridPQAccount` | `ThresholdHybridAccount` |
|---|---|---|
| Everyday transfers | ECDSA **+ PQ** every time | ECDSA only |
| Large transfers (≥ your threshold) | ECDSA + PQ | ECDSA + PQ |
| Transfers to untrusted addresses | ECDSA + PQ | ECDSA + PQ |
| Changing keys / policy | ECDSA + PQ | ECDSA + PQ |
| Everyday cost | ~4–6× normal tx | **normal tx cost** |
| Best for | vaults, max paranoia | real users |

Both use SPHINCS- C13: hash-based post-quantum signatures (the most
conservative PQC assumption — just hash functions), 3,704-byte signatures,
~4 million signatures per key pair.

**Measured on-chain:** PQ verification costs **98,118 gas, identical across
Ethereum, Arbitrum, Base, OP, and Polygon testnets** ([full benchmarks](benchmarks/gas-report.md)).

## Proven live

Both designs executed real UserOperations through the canonical EntryPoint v0.8
on Sepolia:

| Demo | Link |
|---|---|
| Full-hybrid UserOp (ECDSA + PQ, 3753-byte signature) | [tx 0xb987b7f3…](https://sepolia.etherscan.io/tx/0xb987b7f3a10ae26326439af36292d62ca7c4cd654250547a7212cbefb26ae291) |
| Cheap-path UserOp (65-byte ECDSA only, zero PQ cost) | [tx 0xb18a0a82…](https://sepolia.etherscan.io/tx/0xb18a0a82c088a1bb8e68343eee3b7666214ca3d75ed3519f637050523d2c6b37) |

Accounts: [`0x7CD2f0C3…`](https://sepolia.etherscan.io/address/0x7CD2f0C30D5e0218e7Eaac535dd19108436a38A9) (hybrid) · [`0x99e100cF…`](https://sepolia.etherscan.io/address/0x99e100cFFe4e211687c3F7D08644E2363E5F9F10) (threshold)

---

## How anyone can use this

### What you need

- [Foundry](https://book.getfoundry.sh/) (`curl -L https://foundryup.sh | bash`)
- A wallet key with testnet ETH (Sepolia faucet: [Google Cloud Web3](https://cloud.google.com/application/web3/faucet/ethereum/sepolia))
- That's it. Everything else is in this repo, including the PQ signing tool.

### 1. Clone and build

```bash
git clone https://github.com/lvingsarcophagus/pq-evm-account && cd pq-evm-account
forge build
forge test          # optional: run all 33 tests
```

### 2. Deploy your quantum-safe account

```bash
export PRIVATE_KEY=0x<your-key>        # becomes the account's owner
export ENTRYPOINT=0x4337084D9E255Ff0702461CF8895CE9E3b5FF108  # v0.8 canonical
export TRUSTED_TARGET=0x<address-you-transfer-to-often>
export VALUE_THRESHOLD=1000000000000000000   # 1 ETH: transfers ≥ this need PQ

forge script script/DeployThreshold.s.sol \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com --broadcast
```

This deploys the account, sets your risk policy, and deposits gas money into
the EntryPoint. Print the address:

```bash
cast call <ACCOUNT> "pqSeed()(bytes32)" --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# returns 0x000...0 → PQ keys not yet provisioned; do step 3
```

### 3. Provision your post-quantum keys

```bash
tools/signer-c13 keygen <any-32-byte-hex-seed-material>
# → {"seed":"0x...","sk_seed":"0x...","root":"0x..."}

cast send <ACCOUNT> "setPQKeys(bytes32,bytes32)" 0x<seed> 0x<root> \
  --private-key $PRIVATE_KEY --rpc-url <RPC>
```

⚠️ **Do this right after deploying.** Until keys are provisioned the account
runs without PQ protection, and this one-time window is when configuration is
directly editable. After provisioning, the policy locks: changing it requires
a hybrid-signed operation through the account itself.

> In production you would keep `sk_seed` in a real secret store. The committed
> tooling is a demo signer — see [limitations](docs/writeup.md).

### 4. Send transactions

Use any ERC-4337 stack (Pimlico/Alchemy/Stackup SDKs, or our script). Every
UserOp carries a signature:

```text
small transfer to trusted address  →  65-byte ECDSA sig (cheap, normal UX)
big transfer / untrusted address   →  PQ sig + ECDSA sig (quantum-safe)
```

The account decides automatically based on your policy — users don't choose.

Try it end-to-end:

```bash
export ACCOUNT=<your-account-address>
export BUNDLER_RPC=<pimlico/alchemy/stackup node url>
./scripts/send_userop.sh
```

(Or self-bundle like we did for the demo txs: sign the UserOp, then submit
`EntryPoint.handleOps` yourself — see `script/SimulateOp.s.sol` /
`script/SubmitLive.s.sol`.)

### 5. Manage your risk policy later

Policy changes are themselves quantum-protected operations: submit a UserOp
whose `callData` calls `execute(<account>, 0, setPolicy(...))`. The validator
detects self-administration and demands both signatures automatically.
There is no way to weaken the policy with the ECDSA key alone.

---

## For developers: how it works

```text
UserOp ──▶ EntryPoint v0.8 ──▶ validateUserOp()
                                   │
                                   ▼
                          classify calldata risk
                     (value? trusted target? self-call?)
                                   │
                 ┌────── non-risky ┴────── risky ──────┐
                 ▼                                     ▼
           ECDSA check                    ECDSA check + SPHINCS- C13 verify
          (~3K gas)                              (98K gas)
                 └──────── both must pass ────────────┘
```

- `src/verifiers/SphincsMinusVerifier.sol` — optimized verifier + readable oracle
- `src/account/HybridPQAccount.sol` — always-hybrid design
- `src/account/ThresholdHybridAccount.sol` — risk-based design
- `test/vectors/c13.json` — reference-signer test vectors (committed)
- `benchmarks/gas-report.md` — full methodology and per-chain numbers
- `docs/writeup.md` — technical writeup with claims scoped to evidence

Signature layout for hybrid ops: `[3688 B SPHINCS- ‖ 65 B ECDSA]`, both over
the same `userOpHash`.

## Honest limitations

Read [`docs/writeup.md §5`](docs/writeup.md) before building on this:

- **Not audited.** Research-grade code validated by testing, not review.
- **Demo signer**: committed tool derives keys per-message; production needs
  real secret management.
- **No EOA / token-level protection** — smart accounts only.
- **Rollup data fees** for the 3.7 KB signature are unmeasured.
- **~4M signatures per PQ key**, then rotate.

## Reproduce everything

```bash
forge test                                          # correctness suites
forge test --match-test test_GasBenchmark -vv       # gas benchmark
forge script script/BenchmarkChains.s.sol \
  --fork-url https://ethereum-sepolia-rpc.publicnode.com -vvv   # cross-chain
```

## Credits, attribution & licensing

This project **builds on** published research — it is an independent
implementation and extension, not a re-publication:

- **SPHINCS- / C13 scheme**: nconsigny ([ethresear.ch, June 2026](https://ethresear.ch/t/sphincs-minus-efficient-stateless-post-quantum-signature-verification-on-the-evm/25165)) — we implement their *algorithm* in our own independent Solidity codebase and validate against their reference signer's outputs (committed binary, MIT).
- **SLH-DSA / FIPS 205**: NIST · **WOTS+C / FORS+C compression**: Drake et al. (ePrint 2025/055), Kudinov & Nick (ePrint 2025/2203) · **poqeth** (2025) established hash-based PQ verification viability on the EVM.
- **ERC-4337 contracts**: eth-infinitism v0.8.0 (vendored).

Original contributions of this repo: the independent Solidity verifier,
differential-testing methodology, the risk-gated `ThresholdHybridAccount`
design, cross-chain benchmarks, and live deployments.

## License

MIT for original code — see [LICENSE](LICENSE) and
[LICENSE-NOTICES.md](LICENSE-NOTICES.md). Note: vendored ERC-4337 contracts
are GPL-3.0; deployed bytecode inheriting them carries those terms.
