# License Notices

This repository contains code under multiple licenses:

## Original project code (src/, test/, script/, scripts/, benchmarks/, docs/)

MIT License — see LICENSE.

## Vendored third-party libraries (lib/, tools/)

| Path | Source | License | Purpose |
|---|---|---|---|
| `lib/account-abstraction` | [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction) v0.8.0 | **GPL-3.0** | ERC-4337 EntryPoint, BaseAccount, SimpleAccount |
| `lib/openzeppelin-contracts` | OpenZeppelin Contracts v5.1.0 | MIT | dependency of account-abstraction |
| `lib/forge-std` | foundry-rs/forge-std | Apache-2.0/MIT | test harness |
| `tools/signer-c13` | compiled from [nconsigny/SPHINCs-](https://github.com/nconsigny/SPHINCs-) (`signer-wasm`, MIT) | MIT | reference PQ signing oracle for tests |

**Important:** because the vendored ERC-4337 contracts are GPL-3.0, any
distribution of this repository's compiled artifacts that links them
(e.g., deployed bytecode of accounts inheriting `BaseAccount`) is subject to
GPL-3.0 for those portions. The original verifier and account logic in
`src/` is offered under MIT; combine per your compliance needs. When in
doubt, treat the whole as GPL-3.0-compatible usage.
