// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {IERC1271} from "./IERC1271.sol";
import {LibAuthenticatedHooks} from "./LibAuthenticatedHooks.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @title COWShedWithExecutorSigner
/// @notice A COWShed variant that is itself an EIP-1271 signer. When a trusted executor
///         contract is configured it delegates order signature validity to it; otherwise
///         it accepts the owner's own ECDSA signature.
/// @dev Intended for setups where a manager/wrapper contract (the trusted executor)
///      drives the shed and decides which digests the shed will "sign" on-chain
///      (e.g. by blessing a settlement digest in transient storage), without the
///      owner having to sign every order. When no executor contract is set, the shed
///      behaves as a plain owner-signed smart account for CoW orders.
contract COWShedWithExecutorSigner is COWShed, IERC1271 {
    /// @inheritdoc IERC1271
    /// @dev When a trusted executor *contract* is set, forwards to its `isValidSignature`
    ///      and lets it be authoritative. When no executor contract is set (unset or an EOA,
    ///      neither of which can implement EIP-1271), falls back to verifying the owner's
    ///      own ECDSA signature over `hash`. Returns `bytes4(0)` otherwise.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        address executor = _state().trustedExecutor;
        if (executor.code.length != 0) {
            return IERC1271(executor).isValidSignature(hash, signature);
        }

        // No executor contract configured: accept the owner's own ECDSA signature.
        // `tryRecoverCalldata` returns address(0) for malformed signatures (never reverts).
        address recovered = ECDSA.tryRecoverCalldata(hash, signature);
        if (recovered != address(0) && recovered == _admin()) {
            return LibAuthenticatedHooks.MAGIC_VALUE_1271;
        }
        return bytes4(0);
    }
}
