// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Exec} from "account-abstraction/utils/Exec.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {ThresholdHybridAccount} from "./ThresholdHybridAccount.sol";

/**
 * @title OptimisticThresholdAccount
 * @notice OPTIONAL alternative verification path (Phase 5): risky operations
 *         are validated with ECDSA alone, parked behind a challenge window,
 *         and executed only after the window passes unchallenged. Anyone may
 *         cancel a pending operation during the window by providing the PQ
 *         signature over the original userOpHash and demonstrating that it
 *         FAILS verification.
 *
 * Economics (the naysayer inversion): honest users never pay the 98K PQ
 * verification gas — it is spent only when a forgery is challenged. The
 * trust assumption shifts accordingly: between validation and execution
 * there is a window in which a stolen-ECDSA-key attacker CAN queue a large
 * transfer, and fund safety depends on at least one watcher running the
 * free off-chain PQ check and paying cancellation gas for forgeries.
 *
 * ⚠️ Different security tradeoff, strictly opt-in (`enableOptimistic` is a
 * hybrid-gated self-call). Default remains immediate full verification.
 */
contract OptimisticThresholdAccount is ThresholdHybridAccount {
    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------
    error NotAuthorized();
    error WindowStillActive();
    error WindowExpired();
    error SignatureWasValid();

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------
    struct Pending {
        bytes32 userOpHash;
        address target;
        uint256 value;
        bytes data;
        uint64 executableAfter;
        bool active;
    }

    /// id => pending operation
    mapping(uint256 => Pending) public pendingOps;
    /// userOpHash => pending id (prevents duplicate parking of one op)
    mapping(bytes32 => uint256) public pendingByHash;

    uint256 public challengeWindow = 1 hours;
    uint256 internal nextPendingId = 1;
    bool public optimisticEnabled;

    event OptimisticToggled(bool enabled, uint256 window);
    event PendingCreated(uint256 indexed id, bytes32 indexed userOpHash, address target, uint256 value);
    event PendingExecuted(uint256 indexed id);
    event PendingCancelled(uint256 indexed id, address indexed challenger);

    constructor(IEntryPoint ep_, address owner_) ThresholdHybridAccount(ep_, owner_) {}

    // ------------------------------------------------------------------
    // Opt-in configuration (hybrid-gated self-call only)
    // ------------------------------------------------------------------

    function enableOptimistic(bool enabled_, uint256 windowSeconds) external {
        require(msg.sender == address(this), "self-call only");
        require(windowSeconds >= 10 minutes, "window too short");
        optimisticEnabled = enabled_;
        challengeWindow = windowSeconds;
        emit OptimisticToggled(enabled_, windowSeconds);
    }

    // ------------------------------------------------------------------
    // Validation: risky ops pass ECDSA-only when optimistic mode is on
    // ------------------------------------------------------------------

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        bytes calldata sig = userOp.signature;
        bool risky = _isRiskyCall(userOp.callData);

        // Optimistic fast lane: risky op + plain ECDSA + mode enabled.
        if (
            optimisticEnabled &&
            risky &&
            sig.length == ECDSA_SIG_LEN &&
            _ecdsaOk(sig, userOpHash)
        ) {
            _setFastLane(true);
            return SIG_VALIDATION_SUCCESS;
        }
        _setFastLane(false);

        return super._validateSignature(userOp, userOpHash);
    }

    // ------------------------------------------------------------------
    // Execution interception: risky calls park instead of firing
    // ------------------------------------------------------------------

    function execute(address target, uint256 value, bytes calldata data)
        external
        virtual
        override
    {
        _requireForExecute();

        // Park only operations that entered via the optimistic fast lane
        // (ECDSA-only validation of a risky call). Hybrid-validated ops —
        // including administrative self-calls whose PQ signature was just
        // verified — execute immediately.
        if (optimisticEnabled && _getFastLane() && _callIsRisky(target, value)) {
            bytes32 opHash = _currentOrDerivedHash(data);
            require(pendingByHash[opHash] == 0, "already pending");
            uint256 id = nextPendingId++;
            pendingOps[id] = Pending({
                userOpHash: opHash,
                target: target,
                value: value,
                data: data,
                executableAfter: uint64(block.timestamp + challengeWindow),
                active: true
            });
            pendingByHash[opHash] = id;
            emit PendingCreated(id, opHash, target, value);
            return;
        }

        bool ok = Exec.call(target, value, data, gasleft());
        if (!ok) Exec.revertWithReturnData();
    }

    // The validator records the current userOpHash in TRANSIENT storage
    // (cleared automatically at end of transaction); execute() reads it to
    // identify the pending slot. Falls back to a content-derived id for
    // direct self-calls outside the AA flow.
    function _setLastOpHash(bytes32 h) internal {
        assembly ("memory-safe") {
            tstore(0xb5cb462c6383a2bc2f3e855d8691f4478fddf93b546f3f12d11a69441c871f0, h)
        }
    }

    uint256 private constant FAST_LANE_SLOT = 0xb5cb462c6383a2bc2f3e855d8691f4478fddf93b546f3f12d11a69441c871f1;

    function _setFastLane(bool v_) internal {
        assembly ("memory-safe") {
            tstore(FAST_LANE_SLOT, v_)
        }
    }

    function _getFastLane() internal view returns (bool v_) {
        assembly ("memory-safe") {
            v_ := tload(FAST_LANE_SLOT)
        }
    }

    function _getLastOpHash() internal view returns (bytes32 h) {
        assembly ("memory-safe") {
            h := tload(0xb5cb462c6383a2bc2f3e855d8691f4478fddf93b546f3f12d11a69441c871f0)
        }
    }

    function _currentOrDerivedHash(bytes calldata data)
        internal
        view
        returns (bytes32)
    {
        bytes32 last = _getLastOpHash();
        if (last != bytes32(0)) return last;
        return keccak256(abi.encode(block.chainid, address(this), data));
    }

    // Hook: record the hash being validated (called by EntryPoint flow),
    // then replay BaseAccount.validateUserOp's body (external functions
    // cannot be reached via `super`).
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual override returns (uint256 validationData) {
        _requireFromEntryPoint();
        _setLastOpHash(userOpHash);
        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
        _payPrefund(missingAccountFunds);
    }

    // ------------------------------------------------------------------
    // Challenge window lifecycle
    // ------------------------------------------------------------------

    /// @notice Execute a pending operation whose challenge window elapsed.
    function claimPending(uint256 id) external {
        Pending storage p = pendingOps[id];
        require(p.active, "unknown pending");
        if (block.timestamp < p.executableAfter) revert WindowStillActive();
        p.active = false;
        bool ok = Exec.call(p.target, p.value, p.data, gasleft());
        if (!ok) Exec.revertWithReturnData();
        emit PendingExecuted(id);
    }

    /// @notice Cancel a pending operation by proving its PQ signature is
    ///         INVALID (naysayer step). Anyone may call; the PQ signature
    ///         over the original userOpHash is checked with the full verifier.
    /// @param id          pending id
    /// @param pqSignature the 3688-byte SPHINCS- signature from the original UserOp
    function cancelPending(uint256 id, bytes calldata pqSignature) external {
        Pending storage p = pendingOps[id];
        require(p.active, "unknown pending");
        if (block.timestamp >= p.executableAfter) revert WindowExpired();

        bool pqValid =
            pqVerifier.verify(pqSeed, pqRoot, p.userOpHash, pqSignature);
        if (pqValid) revert SignatureWasValid(); // op is legitimate; cannot cancel

        p.active = false;
        delete pendingByHash[p.userOpHash];
        emit PendingCancelled(id, msg.sender);
    }
}
