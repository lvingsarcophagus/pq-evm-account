// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SphincsMinusVerifier} from "../verifiers/SphincsMinusVerifier.sol";

/**
 * @title ThresholdHybridAccount
 * @notice ERC-4337 smart account with risk-based post-quantum protection:
 *         ordinary low-risk operations authenticate with ECDSA alone
 *         (normal cost, normal UX); operations flagged as risky by policy
 *         additionally require a SPHINCS- C13 post-quantum signature.
 *
 * Risk classification (any match ⇒ hybrid ECDSA+PQ required):
 *   - global kill-switch `requireHybridForAll`
 *   - transfer value >= `valueThreshold` (0 disables the value trigger)
 *   - callee not in the trusted-target allowlist (fail-closed default)
 *   - self-targeted calls (admin surface: policy + PQ key rotation)
 *   - callData that does not decode to a known execute selector
 *
 * Security posture: the ECDSA owner has NO direct privileged entry point.
 * `setPQKeys` and `setPolicy` are only reachable through self-execution,
 * which is always classified high-risk — so a quantum adversary holding
 * only the ECDSA key cannot weaken the policy or swap PQ keys.
 * Sole exception: initial PQ provisioning while keys are still zeroed.
 */
contract ThresholdHybridAccount is BaseAccount {
    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------
    error BadSignatureLength();
    error KeysAlreadyProvisioned();
    error NotOwner();

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------
    uint256 internal constant PQ_SIG_LEN = 3688;
    uint256 internal constant ECDSA_SIG_LEN = 65;
    uint256 internal constant HYBRID_SIG_LEN = PQ_SIG_LEN + ECDSA_SIG_LEN;
    uint256 internal constant N_MASK =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    bytes4 internal constant EXECUTE_SEL =
        bytes4(keccak256("execute(address,uint256,bytes)"));
    bytes4 internal constant BATCH_SEL =
        bytes4(keccak256("executeBatch((address,uint256,bytes)[])"));

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------
    IEntryPoint private immutable _entryPoint;
    address public immutable ecdsaOwner;
    SphincsMinusVerifier public immutable pqVerifier;

    bytes32 public pqSeed;
    bytes32 public pqRoot;

    struct Policy {
        bool requireHybridForAll;
        uint256 valueThreshold; // wei; 0 = value trigger disabled
    }
    Policy public policy;
    mapping(address => bool) public trustedTargets;

    event PQKeysRotated(bytes32 indexed newSeed, bytes32 indexed newRoot);
    event PolicyUpdated(bool requireHybridForAll, uint256 valueThreshold);
    event TrustedTargetSet(address indexed target, bool trusted);

    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;

    constructor(IEntryPoint entryPoint_, address ecdsaOwner_) {
        _entryPoint = entryPoint_;
        ecdsaOwner = ecdsaOwner_;
        pqVerifier = new SphincsMinusVerifier();
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    // ------------------------------------------------------------------
    // Signature validation (risk-based)
    // ------------------------------------------------------------------

    /// @inheritdoc BaseAccount
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        bytes calldata sig = userOp.signature;
        bool risky = _isRiskyCall(userOp.callData);

        if (sig.length == HYBRID_SIG_LEN) {
            // Full hybrid path: valid for risky AND (defensively) non-risky ops.
            if (_ecdsaOk(sig[PQ_SIG_LEN:PQ_SIG_LEN + 65], userOpHash)) {
                bool pqOk =
                    pqVerifier.verify(pqSeed, pqRoot, userOpHash, sig[:PQ_SIG_LEN]);
                if (pqOk) return SIG_VALIDATION_SUCCESS;
            }
            return SIG_VALIDATION_FAILED;
        }

        if (sig.length == ECDSA_SIG_LEN) {
            // Cheap path: only for operations classified non-risky.
            if (risky) return SIG_VALIDATION_FAILED;
            if (_ecdsaOk(sig, userOpHash)) return SIG_VALIDATION_SUCCESS;
            return SIG_VALIDATION_FAILED;
        }

        revert BadSignatureLength();
    }

    function _ecdsaOk(bytes calldata ecdsaSig, bytes32 userOpHash)
        internal
        view
        returns (bool)
    {
        bytes32 r = bytes32(ecdsaSig[0:32]);
        bytes32 s = bytes32(ecdsaSig[32:64]);
        uint8 v = uint8(ecdsaSig[64]);
        return ecrecover(userOpHash, v, r, s) == ecdsaOwner;
    }

    // ------------------------------------------------------------------
    // Risk classification
    // ------------------------------------------------------------------

    /// @notice Decide whether a UserOp's calldata demands hybrid validation.
    function _isRiskyCall(bytes calldata data) internal view returns (bool) {
        if (policy.requireHybridForAll) return true;
        if (data.length < 4) return true; // malformed/empty → fail closed

        bytes4 sel = bytes4(data[:4]);

        if (sel == EXECUTE_SEL) {
            if (data.length < 4 + 96) return true;
            address target = address(bytes20(data[16:36]));
            uint256 value = uint256(bytes32(data[36:68]));
            return _callIsRisky(target, value);
        }

        if (sel == BATCH_SEL) {
            if (data.length < 4 + 32) return true;
            uint256 arrOff = 4 + uint256(bytes32(data[4:36]));
            if (data.length < arrOff + 32) return true;
            uint256 count = uint256(bytes32(data[arrOff:arrOff + 32]));
            uint256 base = arrOff + 32;
            // each tuple head = 3 words (target, value, dataOffset)
            if (data.length < base + count * 96) return true;
            for (uint256 i = 0; i < count; ++i) {
                uint256 e = base + i * 96;
                address target = address(bytes20(data[e + 12:e + 32]));
                uint256 value = uint256(bytes32(data[e + 32:e + 64]));
                if (_callIsRisky(target, value)) return true;
            }
            return false;
        }

        return true; // unknown selector → fail closed
    }

    function _callIsRisky(address target, uint256 value)
        internal
        view
        returns (bool)
    {
        if (target == address(this)) return true; // admin surface
        if (policy.valueThreshold != 0 && value >= policy.valueThreshold) {
            return true;
        }
        return !trustedTargets[target]; // fail-closed default
    }

    // ------------------------------------------------------------------
    // Administration (reachable only through hybrid-validated self-calls,
    // plus one-time initial PQ provisioning by the ECDSA owner)
    // ------------------------------------------------------------------

    /// @notice Rotate the post-quantum key pair.
    /// Two legitimate paths:
    ///   1. Initial provisioning: ECDSA owner may set keys while still zeroed.
    ///   2. Rotation afterwards: only via self-execution inside a UserOp whose
    ///      validation was hybrid (self-calls are always classified risky).
    function setPQKeys(bytes32 newSeed, bytes32 newRoot) external {
        if (msg.sender == address(this)) {
            // self-call: caller already passed hybrid validation upstream
        } else if (
            msg.sender == ecdsaOwner && pqSeed == bytes32(0) && pqRoot == bytes32(0)
        ) {
            // one-time initial provisioning
        } else {
            revert NotOwner();
        }
        require(newSeed == bytes32(uint256(newSeed) & N_MASK), "non-canonical seed");
        require(newRoot == bytes32(uint256(newRoot) & N_MASK), "non-canonical root");
        pqSeed = newSeed;
        pqRoot = newRoot;
        emit PQKeysRotated(newSeed, newRoot);
    }

    /// @notice Update the risk policy.
    /// Callable via self-execution (hybrid-gated) always; by the ECDSA owner
    /// directly only during bootstrap (PQ keys still unprovisioned).
    function setPolicy(bool requireHybridForAll_, uint256 valueThreshold_)
        external
    {
        require(_canConfigure(), "not authorized");
        policy = Policy(requireHybridForAll_, valueThreshold_);
        emit PolicyUpdated(requireHybridForAll_, valueThreshold_);
    }

    /// @notice Allow/deny a transfer target for the cheap ECDSA-only path.
    /// Same authorization rules as `setPolicy`.
    function setTrustedTarget(address target, bool trusted) external {
        require(_canConfigure(), "not authorized");
        trustedTargets[target] = trusted;
        emit TrustedTargetSet(target, trusted);
    }

    /// Bootstrap rule: once PQ protection is live (keys non-zero), policy can
    /// only change through hybrid-validated self-execution.
    function _canConfigure() internal view returns (bool) {
        return msg.sender == address(this)
            || (msg.sender == ecdsaOwner && pqSeed == bytes32(0));
    }

    // ------------------------------------------------------------------
    // Deposits
    // ------------------------------------------------------------------

    receive() external payable {}

    function getDeposit() public view returns (uint256) {
        return _entryPoint.balanceOf(address(this));
    }

    function addDeposit() public payable {
        _entryPoint.depositTo{value: msg.value}(address(this));
    }
}
