// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsMinusVerifier — SPHINCS- C13 signature verification (independent implementation)
/// @notice Verifies SPHINCS- "C13" signatures: a stateless hash-based post-quantum
///         scheme derived from SPHINCS+/SLH-DSA (FIPS 205), instantiated with
///         keccak256 instead of SHAKE256 and sized for wallet-scale signature budgets.
///
///         Parameter set C13 (see ethresear.ch post, June 2026, nconsigny):
///           n=16, h=22, d=2, subtree_h=11, k=7, a=19, w=8, l=43, target_sum=208
///           signature size: 3688 bytes
///
///         This implementation prioritizes auditability over gas. It follows the
///         FIPS 205 §4.2 uncompressed 32-byte ADRS layout with keccak256 substituted
///         for SHAKE256. Correctness gate: must accept signatures produced by the
///         reference signer and reject mutated ones.
contract SphincsMinusVerifier {
    // ------------------------------------------------------------------
    // Parameters (C13)
    // ------------------------------------------------------------------
    uint256 internal constant N_BYTES = 16; // hash output size
    uint256 internal constant H = 22; // hypertree height (signature budget 2^22)
    uint256 internal constant D = 2; // hypertree layers
    uint256 internal constant SUBTREE_H = 11; // h / d
    uint256 internal constant K = 7; // FORS trees
    uint256 internal constant A = 19; // FORS tree height
    uint256 internal constant LOG_W = 3;
    uint256 internal constant W = 8; // Winternitz base
    uint256 internal constant L = 43; // WOTS chains
    uint256 internal constant TARGET_SUM = 208; // WOTS+C ground digit sum
    uint256 internal constant SIG_LEN = 3688;

    uint256 internal constant MAX_CHAIN_STEPS = W - 1; // 7
    uint256 internal constant W_MASK = W - 1;

    // ------------------------------------------------------------------
    // Signature layout (byte offsets)
    // ------------------------------------------------------------------
    // [0   ..16 ) randomizer R                      (n bytes)
    // [16  ..128) FORS: K secrets                   (K*n = 112)
    // [128 ..1952) FORS: K auth paths               ((K-1)*a*n = 1824; last tree forced-zero)
    // [1952..     ) hypertree, d layers, per layer:
    //                 WOTS sig  l*n        = 688
    //                 grind count (4 B BE) = 4
    //                 Merkle auth (h/d)*n  = 176
    //               layer stride = 868
    uint256 internal constant OFF_R = 0;
    uint256 internal constant OFF_FORS_SECRET = 16;
    uint256 internal constant OFF_FORS_AUTH = 128;
    uint256 internal constant OFF_HYPERTREE = 1952;
    uint256 internal constant HT_LAYER_STRIDE = 868;
    uint256 internal constant WOTS_SIG_BYTES = L * N_BYTES; // 688
    uint256 internal constant MERKLE_AUTH_NODES = SUBTREE_H; // 11
    uint256 internal constant MERKLE_AUTH_BYTES = SUBTREE_H * N_BYTES; // 176

    uint256 internal constant N_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    // ADRS types (FIPS 205 §4.2)
    uint256 internal constant ADRS_WOTS_HASH = 0;
    uint256 internal constant ADRS_WOTS_PK = 1;
    uint256 internal constant ADRS_TREE = 2;
    uint256 internal constant ADRS_FORS_TREE = 3;
    uint256 internal constant ADRS_FORS_ROOTS = 4;

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------
    error InvalidSignatureLength();
    error InvalidPublicKey();

    /// @notice Verify a C13 signature over `message` against (pkSeed, pkRoot).
    /// @return valid true iff the signature is well-formed AND authentic.
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool valid)
    {
        if (sig.length != SIG_LEN) revert InvalidSignatureLength();
        // Public keys are canonical: low 128 bits must be zero (n = 16 bytes).
        if (!_isCanonical(pkSeed) || !_isCanonical(pkRoot)) revert InvalidPublicKey();

        bytes32 seed = pkSeed;

        // --- H_msg: derive randomizer-bound digest -------------------------
        // H_msg = keccak256(pkSeed || pkRoot || R || message || M_MASK)
        bytes32 r = _loadN(sig, OFF_R);
        bytes32 digest = keccak256(
            abi.encodePacked(
                seed,
                pkRoot,
                r,
                message,
                bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            )
        );

        // Hypertree index: top K*A = 7*19 = 133 bits used; take h=22 bits below them.
        uint256 htIdx = uint256(digest >> (K * A)) & ((1 << H) - 1);

        // --- FORS+C ---------------------------------------------------------
        // Forced-zero grinding: the last FORS index must be zero.
        if (_forsIndex(digest, K - 1) != 0) return false;

        uint256 idxLeaf0 = htIdx & ((1 << SUBTREE_H) - 1);
        uint256 idxTree0 = htIdx >> SUBTREE_H;

        bytes32[K] memory forsRoots;
        for (uint256 i = 0; i < K - 1; ++i) {
            uint256 forsTreeIdx = _forsIndex(digest, i);
            bytes32 secret = _loadN(sig, OFF_FORS_SECRET + i * N_BYTES);

            // Leaf hash: ADRS(tree=idxTree0, type=FORS_TREE, kp=idxLeaf0,
            //                height=0, index=(i << A) | forsTreeIdx)
            bytes32 node = _tweakN(seed, _forsAdrs(idxTree0, idxLeaf0, 0, (i << A) | forsTreeIdx), secret);

            // Walk the a-node authentication path.
            uint256 pathIdx = forsTreeIdx;
            uint256 authOff = OFF_FORS_AUTH + i * (A * N_BYTES);
            for (uint256 level = 0; level < A; ++level) {
                bytes32 sibling = _loadN(sig, authOff + level * N_BYTES);
                uint256 parentIdx = pathIdx >> 1;
                node = _tweakPackedN(
                    seed,
                    _forsAdrs(
                        idxTree0,
                        idxLeaf0,
                        level + 1,
                        (i << (A - 1 - level)) | parentIdx
                    ),
                    _merklePair(node, sibling, pathIdx)
                );
                pathIdx = parentIdx;
            }
            forsRoots[i] = node;
        }

        // Last FORS tree (forced-zero): the revealed "secret" IS the leaf node.
        {
            bytes32 leaf = _loadN(sig, OFF_FORS_SECRET + (K - 1) * N_BYTES);
            forsRoots[K - 1] =
                _tweakN(
                seed,
                _forsAdrs(idxTree0, idxLeaf0, 0, (K - 1) << A),
                leaf
            );
        }

        // Compress FORS public key.
        bytes32 forsPk = _tweakPackedN(
            seed,
            bytes32((idxTree0 << 128) | (ADRS_FORS_ROOTS << 96) | (idxLeaf0 << 64)),
            _packK(forsRoots)
        );

        // --- Hypertree: d layers of WOTS+C + Merkle --------------------------
        bytes32 currentNode = forsPk;
        uint256 idxTree = htIdx;
        uint256 off = OFF_HYPERTREE;

        for (uint256 layer = 0; layer < D; ++layer) {
            uint256 idxLeaf = idxTree & ((1 << SUBTREE_H) - 1);
            idxTree = idxTree >> SUBTREE_H;

            // WOTS message: keccak(seed || WOTS_HASH adrs || node || grind_count)
            bytes32 wotsBase = bytes32((layer << 224) | (idxTree << 128) | (idxLeaf << 64));
            uint256 grindCount;
            assembly ("memory-safe") {
                grindCount := shr(224, calldataload(add(sig.offset, add(off, 688))))
            }
            bytes32 wotsMsg = keccak256(
                abi.encodePacked(seed, wotsBase, currentNode, bytes32(grindCount))
            );

            // WOTS+C: digit sum over l base-w digits must equal TARGET_SUM.
            {
                uint256 digitSum = 0;
                for (uint256 i = 0; i < L; ++i) {
                    digitSum += (uint256(wotsMsg) >> (i * LOG_W)) & W_MASK;
                }
                if (digitSum != TARGET_SUM) return false;
            }

            // Hash chains: reveal chain tails, walk (w-1-digit) remaining steps.
            bytes32[L] memory chainEnds;
            for (uint256 i = 0; i < L; ++i) {
                uint256 digit = (uint256(wotsMsg) >> (i * LOG_W)) & W_MASK;
                bytes32 val = _loadN(sig, off + i * N_BYTES);
                // WOTS_HASH adrs with word2 = chain address i.
                bytes32 chainAdrs =
                    bytes32((layer << 224) | (idxTree << 128) | (idxLeaf << 64) | (i << 32));
                for (uint256 j = 0; j < MAX_CHAIN_STEPS - digit; ++j) {
                    val = _tweakN(seed, bytes32(uint256(chainAdrs) | (digit + j)), val);
                }
                chainEnds[i] = val;
            }

            // Compress WOTS public key.
            bytes32 wotsPk = _tweakPackedN(
                seed,
                bytes32((layer << 224) | (idxTree << 128) | (ADRS_WOTS_PK << 96) | (idxLeaf << 64)),
                _packL(chainEnds)
            );

            // Merkle authentication path up this subtree.
            bytes32 node = wotsPk;
            uint256 mIdx = idxLeaf;
            uint256 authOff = off + WOTS_SIG_BYTES + 4;
            bytes32 treeBase = bytes32((layer << 224) | (idxTree << 128) | (ADRS_TREE << 96));
            for (uint256 level = 0; level < MERKLE_AUTH_NODES; ++level) {
                bytes32 sibling = _loadN(sig, authOff + level * N_BYTES);
                uint256 parentIdx = mIdx >> 1;
                node = _tweakPackedN(
                    seed,
                    bytes32(uint256(treeBase) | ((level + 1) << 32) | parentIdx),
                    _merklePair(node, sibling, mIdx)
                );
                mIdx = parentIdx;
            }

            currentNode = node;
            off += HT_LAYER_STRIDE;
        }

        valid = (currentNode == pkRoot);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    function _isCanonical(bytes32 x) internal pure returns (bool) {
        return x == bytes32(uint256(x) & N_MASK);
    }

    /// Load an n-byte (16 B) value from calldata, left-aligned in a bytes32.
    function _loadN(bytes calldata sig, uint256 off) internal pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := and(calldataload(add(sig.offset, off)), N_MASK)
        }
    }

    /// i-th a-bit FORS index from the message digest.
    function _forsIndex(bytes32 digest, uint256 i) internal pure returns (uint256) {
        return (uint256(digest) >> (i * A)) & ((1 << A) - 1);
    }

    /// Tweakable hash: keccak256(seed || adrs || payload), truncated to n bytes.
    function _tweakN(bytes32 seed, bytes32 adrs, bytes32 payload) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encodePacked(seed, adrs, payload))) & N_MASK);
    }

    /// Truncated hash of a pre-packed payload (used for PK compressions).
    function _tweakPackedN(bytes32 seed, bytes32 adrs, bytes memory payload)
        internal
        pure
        returns (bytes32)
    {
        return bytes32(uint256(keccak256(abi.encodePacked(seed, adrs, payload))) & N_MASK);
    }

    /// Order (node, sibling) by leaf parity before hashing a Merkle parent.
    function _merklePair(bytes32 node, bytes32 sibling, uint256 pathIdx)
        internal
        pure
        returns (bytes memory)
    {
        if (pathIdx & 1 == 0) {
            return abi.encodePacked(node, sibling);
        } else {
            return abi.encodePacked(sibling, node);
        }
    }

    // PK compressions hash each n-byte value as a full 32-byte word
    // (low 16 bytes zero-padded), matching the SPHINCS- reference layout.
    function _packWords(uint256 count, bytes32[] memory vals) internal pure returns (bytes memory) {
        bytes memory out = new bytes(count * 32);
        for (uint256 i = 0; i < count; ++i) {
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(i, 0x20)), mload(add(vals, add(0x20, mul(i, 0x20)))))
            }
        }
        return out;
    }

    // NOTE: static arrays carry no length header — element i lives at base + i*0x20.
    function _packK(bytes32[K] memory roots) internal pure returns (bytes memory) {
        bytes memory out = new bytes(K * 32);
        for (uint256 i = 0; i < K; ++i) {
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(i, 0x20)), mload(add(roots, mul(i, 0x20))))
            }
        }
        return out;
    }

    function _packL(bytes32[L] memory vals) internal pure returns (bytes memory) {
        bytes memory out = new bytes(L * 32);
        for (uint256 i = 0; i < L; ++i) {
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(i, 0x20)), mload(add(vals, mul(i, 0x20))))
            }
        }
        return out;
    }

    // --- ADRS layout reference (FIPS 205 §4.2, 32-byte uncompressed form) --

    /// FORS_TREE address: type=3, kp=key pair, word2=height, word3=tree index.
    function _forsAdrs(uint256 tree, uint256 kp, uint256 height, uint256 treeIndex)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((tree << 128) | (ADRS_FORS_TREE << 96) | (kp << 64) | (height << 32) | treeIndex);
    }

    // bytes  0.. 4   layer address
    // bytes  4..16   tree address (96-bit)
    // bytes 16..20   type
    // bytes 20..24   word1 (key pair address)
    // bytes 24..28   word2 (tree height / chain address)
    // bytes 28..32   word3 (tree index / hash address)
}
