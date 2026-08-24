#!/usr/bin/env bash
# Send a hybrid-signed (ECDSA + SPHINCS- C13) UserOp through a live bundler.
#
# Required env:
#   PRIVATE_KEY        funded ECDSA owner key (must equal the account's ecdsaOwner)
#   ACCOUNT            deployed HybridPQAccount address (from script/DeployTestnet.s.sol)
#   BUNDLER_RPC        bundler node URL supporting erc-4337 RPC methods
#
# Optional env:
#   PUBLIC_RPC         plain JSON-RPC for reads (default: public Sepolia)
#   ENTRYPOINT         default 0x4337084D9E255Ff0702461CF8895CE9E3b5FF108 (v0.8 canonical)
#   TO / VALUE         transfer target and wei value (defaults: self, 1e12 wei)
#
# Flow: build op -> getUserOpHash -> PQ-sign via tools/signer-c13 -> rotate
#       on-chain PQ keys if needed -> ECDSA-sign -> eth_sendUserOperation.
set -euo pipefail

: "${PRIVATE_KEY:?set PRIVATE_KEY}"
: "${ACCOUNT:?set ACCOUNT}"
: "${BUNDLER_RPC:?set BUNDLER_RPC}"

ENTRYPOINT="${ENTRYPOINT:-0x4337084D9E255Ff0702461CF8895CE9E3b5FF108}"
TO="${TO:-$ACCOUNT}"
VALUE="${VALUE:-1000000000000}" # 1e12 wei
PUBLIC_RPC="${PUBLIC_RPC:-https://ethereum-sepolia-rpc.publicnode.com}"
SIGNER="tools/signer-c13"

hex() { printf '0x%x' "$1"; }

echo "== chain =="
echo "chainId: $(cast chain-id --rpc-url "$PUBLIC_RPC")"
ep_code=$(cast code "$ENTRYPOINT" --rpc-url "$PUBLIC_RPC")
[ "${#ep_code}" -gt 2 ] || { echo "EntryPoint $ENTRYPOINT has no code"; exit 1; }

echo "== build UserOp =="
nonce_dec=$(cast call "$ENTRYPOINT" \
  "getNonce(address,uint192)(uint256)" "$ACCOUNT" 0 --rpc-url "$PUBLIC_RPC")
nonce=$(hex "$nonce_dec")
call_data=$(cast calldata "execute(address,uint256,bytes)" "$TO" "$VALUE" 0x)
verification_gas=800000
call_gas=20000
pre_verification_gas=200000
account_gas_limits="0x$(printf '%032x%032x' "$verification_gas" "$call_gas")"
gas_fees="0x$(printf '%032x%032x' 2000000000 2000000000)"

unsigned="($ACCOUNT,$nonce,0x,$call_data,$account_gas_limits,$pre_verification_gas,$gas_fees,0x,0x)"

echo "== getUserOpHash =="
hash_raw=$(cast call "$ENTRYPOINT" \
  "getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes))" \
  "$unsigned" --rpc-url "$PUBLIC_RPC")
hash=$(cast to-bytes32 "$hash_raw")
echo "userOpHash: $hash"

echo "== SPHINCS- C13 sign =="
"$SIGNER" c13 "$hash" | python3 -c "
import sys
raw = bytes.fromhex(sys.stdin.read().strip().removeprefix('0x'))
print('0x' + raw[0:32].hex())
print('0x' + raw[32:64].hex())
sig_len = int.from_bytes(raw[96:128], 'big')
print('0x' + raw[128:128 + sig_len].hex())
" > /tmp/opencode/pq_out.txt || { echo "signer failed"; exit 1; }
{ read -r seed; read -r root; read -r pq_sig; } < /tmp/opencode/pq_out.txt
echo "pqSeed: $seed"
echo "pqRoot: $root"

echo "== ensure on-chain PQ keys match =="
current_seed=$(cast call "$ACCOUNT" "pqSeed()(bytes32)" --rpc-url "$PUBLIC_RPC")
if [ "${current_seed,,}" != "${seed,,}" ]; then
  echo "rotating PQ keys on-chain..."
  cast send "$ACCOUNT" "setPQKeys(bytes32,bytes32)" "$seed" "$root" \
    --private-key "$PRIVATE_KEY" --rpc-url "$PUBLIC_RPC" > /dev/null
fi

echo "== ECDSA sign =="
ecdsa_sig=$(cast wallet sign --no-hash "$hash" --private-key "$PRIVATE_KEY")

full_sig="${pq_sig#0x}${ecdsa_sig#0x}"
echo "hybrid signature: $(( ${#full_sig} / 2 )) bytes"

echo "== eth_sendUserOperation via bundler =="
user_op_json="[{\"sender\":\"$ACCOUNT\",\"nonce\":\"$nonce\",\"initCode\":\"0x\",\"callData\":\"$call_data\",\"accountGasLimits\":\"$account_gas_limits\",\"preVerificationGas\":\"$(hex "$pre_verification_gas")\",\"gasFees\":\"$gas_fees\",\"paymasterAndData\":\"0x\",\"signature\":\"0x$full_sig\"}]"
op_hash=$(cast rpc --rpc-url "$BUNDLER_RPC" eth_sendUserOperation "$user_op_json" "$ENTRYPOINT")
echo "userOpHash (bundler): $op_hash"

echo "== polling for receipt (max ~90s) =="
for i in $(seq 1 30); do
  sleep 3
  receipt=$(cast rpc --rpc-url "$BUNDLER_RPC" eth_getUserOperationReceipt "$op_hash" 2>/dev/null || true)
  if [ -n "$receipt" ] && [ "$receipt" != "null" ]; then
    echo "$receipt" | python3 -m json.tool | head -40
    echo "SUCCESS"
    exit 0
  fi
done
echo "no receipt yet; check later with: cast rpc --rpc-url \$BUNDLER_RPC eth_getUserOperationReceipt $op_hash"
exit 1
