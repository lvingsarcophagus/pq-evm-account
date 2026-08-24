// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import "./HelpersConstants.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SphincsMinusVerifier} from "../verifiers/SphincsMinusVerifier.sol";

/**
 * @title HybridPQAccount
 * @notice ERC-4337 smart account requiring TWO signatures over every UserOp:
 *         a classical ECDSA signature AND a post-quantum SPHINCS- C13 signature,
 *         both over the same `userOpHash`.
 *
 *         Rationale: the PQ verifier is new code. Hybrid mode means an
 *         implementation bug in either scheme alone cannot move funds.
 *
 *         Signature layout (userOp.signature):
 *           [0        ..3688 ) SPHINCS- C13 signature
 *           [3688     ..3753 ) ECDSA (r,s,v) over userOpHash, 65 bytes
 */
contract HybridPQAccount is BaseAccount {
    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------
    error BadSignatureLength();

    // ------------------------------------------------------------------
    // Immutable configuration
    // ------------------------------------------------------------------
    IEntryPoint private immutable _entryPoint;
    address public immutable ecdsaOwner;
    bytes32 public pqSeed;
    bytes32 public pqRoot;

    SphincsMinusVerifier public immutable pqVerifier;

    uint256 internal constant PQ_SIG_LEN = 3688;
    uint256 internal constant ECDSA_SIG_LEN = 65;

    constructor(IEntryPoint entryPoint_, address _ecdsaOwner, bytes32 _pqSeed, bytes32 _pqRoot) {
        _entryPoint = entryPoint_;
        ecdsaOwner = _ecdsaOwner;
        pqSeed = bytes32(0);
        pqRoot = bytes32(0);
        pqVerifier = new SphincsMinusVerifier();
    }

    /// @notice Both signatures must be valid; either one failing fails the op.
    /// @dev Returns SIG_VALIDATION_FAILED (1) instead of reverting on bad
    ///      signatures, per ERC-4337 semantics ("simulation without sigs").
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        bytes calldata sig = userOp.signature;
        if (sig.length != PQ_SIG_LEN + ECDSA_SIG_LEN) revert BadSignatureLength();

        // --- Classical layer: ECDSA ---------------------------------------
        bytes32 r = bytes32(sig[PQ_SIG_LEN:PQ_SIG_LEN + 32]);
        bytes32 s = bytes32(sig[PQ_SIG_LEN + 32:PQ_SIG_LEN + 64]);
        uint8 v = uint8(sig[PQ_SIG_LEN + 64]);
        if (ecrecover(userOpHash, v, r, s) != ecdsaOwner) {
            return SIG_VALIDATION_FAILED;
        }

        // --- Post-quantum layer: SPHINCS- C13 ------------------------------
        bool pqOk = pqVerifier.verify(pqSeed, pqRoot, userOpHash, sig[:PQ_SIG_LEN]);
        if (!pqOk) {
            return SIG_VALIDATION_FAILED;
        }

        validationData = SIG_VALIDATION_SUCCESS;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    // ------------------------------------------------------------------
    // PQ key management
    // ------------------------------------------------------------------

    event PQKeysRotated(bytes32 indexed newSeed, bytes32 indexed newRoot);

    /// @notice Rotate the post-quantum key pair. Only the ECDSA owner may call.
    /// @dev Deliberate design choice: every SPEND still requires both signatures,
    ///      so rotating PQ keys with ECDSA authority alone does not weaken
    ///      per-operation security; it only changes which PQ key must co-sign.
    function setPQKeys(bytes32 newSeed, bytes32 newRoot) external {
        require(msg.sender == ecdsaOwner, "not owner");
        require(newSeed == bytes32(uint256(newSeed) & _N_MASK), "non-canonical seed");
        require(newRoot == bytes32(uint256(newRoot) & _N_MASK), "non-canonical root");
        pqSeed = newSeed;
        pqRoot = newRoot;
        emit PQKeysRotated(newSeed, newRoot);
    }

    uint256 internal constant _N_MASK =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    /// @notice Accept deposits for gas prepayment via the EntryPoint.
    receive() external payable {}

    function getDeposit() public view returns (uint256) {
        return _entryPoint.balanceOf(address(this));
    }

    function addDeposit() public payable {
        _entryPoint.depositTo{value: msg.value}(address(this));
    }
}
