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
    /// Inputs for hashing one FORS tree (keeps legacy-codegen stacks shallow).
    struct ForsTreeIn {
        bytes32 seed;
        bytes32 base; // FORS_TREE ADRS skeleton: tree|type|kp
        bytes32 leafAdrs; // height-0 ADRS: word3=(tree<<A)|index
        uint256 treeIdx; // this tree's a-bit message index
        uint256 treeFold; // tree<<A, folded into parent addresses
        bytes32 secret; // revealed leaf secret
        uint256 authOff; // calldata offset of this tree's auth path
    }

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
    /// @dev Optimized single-pass implementation: one inline-assembly block,
    ///      fixed scratch slots (0x00 seed, 0x20 ADRS, 0x40/0x60 payload),
    ///      branchless Merkle swaps, no memory allocation. Semantically
    ///      identical to {verifyReadable}; differential fuzzing keeps the two
    ///      in lockstep. All exits are in-assembly return/revert, so clobbering
    ///      the free-memory pointer is sound (do NOT mark memory-safe).
    /// @return valid true iff the signature is well-formed AND authentic.
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool valid)
    {
        assembly ("memory-safe") {
            let M := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // --- Well-formedness gates ------------------------------------
            if iszero(eq(sig.length, 3688)) {
                mstore(0x00, shl(224, 0x4be6321b)) // InvalidSignatureLength()
                revert(0x00, 0x04)
            }
            if or(
                iszero(eq(pkSeed, and(pkSeed, M))),
                iszero(eq(pkRoot, and(pkRoot, M)))
            ) {
                mstore(0x00, shl(224, 0xa2d0fee8)) // InvalidPublicKey()
                revert(0x00, 0x04)
            }

            let seed := pkSeed
            let root := pkRoot

            // --- H_msg: keccak(seed || root || R || message || DOMAIN) -----
            mstore(0x00, seed)
            mstore(0x20, root)
            mstore(0x40, and(calldataload(sig.offset), M)) // R
            mstore(0x60, message)
            mstore(0x80, not(0))
            let digest := keccak256(0x00, 0xA0)
            mstore(0x00, seed) // restore persistent seed slot

            // htIdx = bits [133..155): which of 2^22 hypertree leaves signs.
            let htIdx := and(shr(133, digest), 0x3FFFFF)

            // FORS+C: last index (bits [114..133)) must be ground to zero.
            if and(shr(114, digest), 0x7FFFF) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }

            let idxLeaf0 := and(htIdx, 0x7FF)
            let idxTree0 := shr(11, htIdx)
            // FORS_TREE base: tree=idxTree0 | type=3 | kp=idxLeaf0.
            let forsBase := or(shl(128, idxTree0), or(shl(96, 3), shl(64, idxLeaf0)))

            // --- FORS: K-1 regular trees ----------------------------------
            for { let i := 0 } lt(i, 6) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 19), digest), 0x7FFFF)
                let leafAdrs := or(forsBase, or(shl(19, i), treeIdx)) // w2=0, w3=(i<<A)|treeIdx
                mstore(0x20, leafAdrs)
                mstore(0x40, and(calldataload(add(sig.offset, add(16, shl(4, i)))), M))
                let node := and(keccak256(0x00, 0x60), M)

                let pathIdx := treeIdx
                // auth path for tree i starts at sig+128+i*(19*16); stride 304.
                let authPtr := add(sig.offset, add(128, mul(i, 304)))
                for { let h := 0 } lt(h, 19) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), M)
                    let parentIdx := shr(1, pathIdx)
                    // w2=h+1, w3=(i<<(18-h))|parentIdx
                    mstore(0x20, or(forsBase, or(shl(32, add(h, 1)), or(shl(sub(18, h), i), parentIdx))))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), M)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node) // roots[i]
            }

            // Forced-zero tree: revealed root IS the leaf; hash under leaf ADRS.
            mstore(0x20, or(forsBase, shl(19, 6))) // w3 = (K-1)<<A
            mstore(0x40, and(calldataload(add(sig.offset, add(16, shl(4, 6)))), M))
            mstore(0x140, and(keccak256(0x00, 0x60), M)) // roots[6] @ 0x80+6*32

            // Compress: keccak(seed || FORS_ROOTS adrs || roots[0..6]) = 288 B.
            mstore(0x20, or(shl(128, idxTree0), or(shl(96, 4), shl(64, idxLeaf0))))
            for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let currentNode := and(keccak256(0x00, 0x120), M) // forsPk

            // --- Hypertree: D=2 layers of WOTS+C + Merkle ------------------
            let idxTree := htIdx
            let sigOff := 1952

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x7FF)
                idxTree := shr(11, idxTree)

                // WOTS_HASH base: layer | tree | kp=idxLeaf (w2=w3=0).
                let wotsBase := or(shl(224, layer), or(shl(128, idxTree), shl(64, idxLeaf)))
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sig.offset, countOff)))

                // WOTS message: keccak(seed || wotsBase || node || count).
                mstore(0x20, wotsBase)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Digit-sum gate: 43 base-8 digits must total TARGET_SUM=208.
                let digitSum := 0
                for { let ii := 0 } lt(ii, 43) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 3), d), 0x7))
                }
                if iszero(eq(digitSum, 208)) {
                    mstore(0x00, 0)
                    return(0x00, 0x20)
                }

                // Chains: continue each from its revealed tail to step 6.
                let wotsPtr := add(sig.offset, sigOff)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 3), d), 0x7)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), M)
                    let chainBase := or(wotsBase, shl(32, i)) // w2 = chain address
                    for { let j := 0 } lt(j, sub(7, digit)) { j := add(j, 1) } {
                        mstore(0x20, or(chainBase, add(digit, j)))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), M)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // WOTS_PK compression: 1440 bytes = 32+32+43*32.
                let pkAdrs := or(shl(224, layer), or(shl(128, idxTree), or(shl(96, 1), shl(64, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let merkleNode := and(keccak256(0x00, 0x5A0), M) // wotsPk

                // Subtree Merkle authentication (11 levels).
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(128, idxTree), shl(96, 2)))
                let mIdx := idxLeaf
                let merklePtr := add(sig.offset, authOff)
                for { let h := 0 } lt(h, 11) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), M)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(treeAdrs, or(shl(32, add(h, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), M)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(sigOff, 868)
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }

    /// @notice Readable reference implementation — kept as the differential
    ///         oracle for {verify}. Same semantics, ~6× more gas.
    function verifyReadable(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool valid)
    {
        if (sig.length != SIG_LEN) revert InvalidSignatureLength();
        if (!_isCanonical(pkSeed) || !_isCanonical(pkRoot)) revert InvalidPublicKey();

        bytes32 seed = pkSeed;
        uint256 sigBase;
        assembly ("memory-safe") {
            sigBase := sig.offset
        }
        bytes32 digest = _hMsg(pkSeed, pkRoot, message, sigBase);

        // Hypertree index: top K*A bits select the digest; next H bits the leaf.
        uint256 htIdx = uint256(digest >> (K * A)) & ((1 << H) - 1);
        // FORS+C: forced-zero grinding — last index must be zero.
        if (_forsIndex(digest, K - 1) != 0) return false;

        // NOTE: deliberately NOT delegated to an internal _hypertree() wrapper:
        // routing calldata-derived values through that extra frame miscompiles
        // under the legacy pipeline (verified against the optimized path).
        bytes32 currentNode = _forsPublicKey(seed, digest, htIdx, sigBase);
        uint256 idxTree = htIdx;
        uint256 off = OFF_HYPERTREE;
        for (uint256 layer = 0; layer < D; ++layer) {
            uint256 idxLeaf = idxTree & ((1 << SUBTREE_H) - 1);
            idxTree = idxTree >> SUBTREE_H;
            bytes32 wotsBase = bytes32((layer << 224) | (idxTree << 128) | (idxLeaf << 64));
            currentNode = _wotsLayer(seed, wotsBase, currentNode, sigBase, off);

            bytes32 treeBase = bytes32((layer << 224) | (idxTree << 128) | (ADRS_TREE << 96));
            currentNode = _merkleWalk(seed, treeBase, currentNode, idxLeaf, sigBase, off);
            off += HT_LAYER_STRIDE;
        }
        valid = (currentNode == pkRoot);
    }

    /// Hash one regular FORS tree down from its revealed leaf.
    function _forsRootOf(ForsTreeIn memory a, uint256 sigBase) internal pure returns (bytes32) {
        bytes32 node = _tweakN(a.seed, a.leafAdrs, a.secret);
        uint256 pathIdx = a.treeIdx;
        for (uint256 level = 0; level < A; ++level) {
            bytes32 sibling = _loadN(sigBase, a.authOff + level * N_BYTES);
            uint256 parentIdx = pathIdx >> 1;
            // word2=level+1; word3=(tree << (A-1-level)) | parentIdx
            node = _tweakPackedN(
                a.seed,
                bytes32(
                    uint256(a.base) | ((level + 1) << 32) | ((a.treeFold >> (level + 1)) | parentIdx)
                ),
                _merklePair(node, sibling, pathIdx)
            );
            pathIdx = parentIdx;
        }
        return node;
    }

    /// Verify one WOTS+C hypertree layer; returns the compressed WOTS public key.
    /// `wotsBase` = layer<<224 | idxTree<<128 | idxLeaf<<64 (WOTS_HASH, w2=w3=0).
    function _wotsLayer(
        bytes32 seed,
        bytes32 wotsBase,
        bytes32 currentNode,
        uint256 sigBase,
        uint256 off
    ) internal pure returns (bytes32) {
        bytes32 wotsMsg;
        {
            uint256 grindCount;
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                mstore(ptr, seed)
                mstore(add(ptr, 0x20), wotsBase)
                mstore(add(ptr, 0x40), currentNode)
                mstore(add(ptr, 0x60), shr(224, calldataload(add(sigBase, add(off, 688)))))
                wotsMsg := keccak256(ptr, 0x80)
            }
        }

        // Digit-sum gate: L base-w digits must total TARGET_SUM.
        {
            uint256 digitSum = 0;
            for (uint256 i = 0; i < L; ++i) {
                digitSum += (uint256(wotsMsg) >> (i * LOG_W)) & W_MASK;
            }
            if (digitSum != TARGET_SUM) return bytes32(0); // never equals a real pk path
        }

        return _chainsAndPk(seed, wotsBase, wotsMsg, sigBase, off);
    }

    /// Domain-separated H_msg over (seed, root, R, message).
    function _hMsg(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, uint256 sigBase)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                pkSeed,
                pkRoot,
                _loadN(sigBase, OFF_R),
                message,
                bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            )
        );
    }

    /// Recompute the FORS public key commitment for this digest/leaf position.
    function _forsPublicKey(bytes32 seed, bytes32 digest, uint256 htIdx, uint256 sigBase)
        internal
        pure
        returns (bytes32)
    {
        uint256 idxLeaf0 = htIdx & ((1 << SUBTREE_H) - 1);
        uint256 idxTree0 = htIdx >> SUBTREE_H;

        bytes32 forsBase =
            bytes32(
                (idxTree0 << 128) | (ADRS_FORS_TREE << 96) | (idxLeaf0 << 64)
            );
        bytes32[K] memory roots;
        ForsTreeIn memory a;
        a.seed = seed;
        a.base = forsBase;
        for (uint256 i = 0; i < K - 1; ++i) {
            a.treeIdx = _forsIndex(digest, i);
            a.treeFold = i << A; // folded into parent word3 as (fold >> (level+1))
            a.leafAdrs = bytes32(uint256(forsBase) | a.treeFold | a.treeIdx);
            a.secret = _loadN(sigBase, OFF_FORS_SECRET + i * N_BYTES);
            a.authOff = OFF_FORS_AUTH + i * (A * N_BYTES);
            roots[i] = _forsRootOf(a, sigBase);
        }

        // Last FORS tree (forced-zero): the revealed value IS the leaf node.
        bytes32 leaf = _loadN(sigBase, OFF_FORS_SECRET + (K - 1) * N_BYTES);
        roots[K - 1] = _tweakN(seed, _forsAdrs(idxTree0, idxLeaf0, 0, (K - 1) << A), leaf);

        return _tweakPackedN(
            seed,
            bytes32((idxTree0 << 128) | (ADRS_FORS_ROOTS << 96) | (idxLeaf0 << 64)),
            _packK(roots)
        );
    }

    /// Walk all L WOTS+C hash chains and compress the resulting public key.
    function _chainsAndPk(
        bytes32 seed,
        bytes32 wotsBase,
        bytes32 wotsMsg,
        uint256 sigBase,
        uint256 off
    ) internal pure returns (bytes32) {
        bytes32[L] memory chainEnds;
        uint256 pkAdrsU = uint256(wotsBase) | (ADRS_WOTS_PK << 96);
        for (uint256 i = 0; i < L; ++i) {
            uint256 digit = (uint256(wotsMsg) >> (i * LOG_W)) & W_MASK;
            bytes32 val = _loadN(sigBase, off + i * N_BYTES);
            uint256 chainAdrs = uint256(wotsBase) | (i << 32); // word2 = chain address
            for (uint256 j = 0; j < MAX_CHAIN_STEPS - digit; ++j) {
                val = _tweakN(seed, bytes32(chainAdrs | (digit + j)), val);
            }
            chainEnds[i] = val;
        }
        return _tweakPackedN(seed, bytes32(pkAdrsU), _packL(chainEnds));
    }

    /// Hash one subtree Merkle authentication path (SUBTREE_H levels).
    function _merkleWalk(
        bytes32 seed,
        bytes32 treeBase,
        bytes32 node,
        uint256 leafIdx,
        uint256 sigBase,
        uint256 off
    ) internal pure returns (bytes32) {
        uint256 mIdx = leafIdx;
        uint256 authOff = off + WOTS_SIG_BYTES + 4;
        for (uint256 level = 0; level < MERKLE_AUTH_NODES; ++level) {
            bytes32 sibling = _loadN(sigBase, authOff + level * N_BYTES);
            uint256 parentIdx = mIdx >> 1;
            node = _tweakPackedN(
                seed,
                bytes32(uint256(treeBase) | ((level + 1) << 32) | parentIdx),
                _merklePair(node, sibling, mIdx)
            );
            mIdx = parentIdx;
        }
        return node;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    function _isCanonical(bytes32 x) internal pure returns (bool) {
        return x == bytes32(uint256(x) & N_MASK);
    }

    /// Load an n-byte (16 B) value from calldata, left-aligned in a bytes32.
    /// `sigBase` is the raw calldata pointer (sig.offset), captured once at the
    /// external entry point — avoids re-passing calldata slices through
    /// multiple internal frames (legacy-codegen aliasing hazard).
    function _loadN(uint256 sigBase, uint256 off) internal pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := and(calldataload(add(sigBase, off)), N_MASK)
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
