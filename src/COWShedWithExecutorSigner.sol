// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {IERC1271} from "./IERC1271.sol";

/// @title COWShedWithExecutorSigner
/// @notice A COWShed variant that is itself an EIP-1271 signer, delegating order
///         signature validity to the shed's trusted executor.
/// @dev Intended for setups where a manager/wrapper contract (the trusted executor)
///      drives the shed and decides which digests the shed will "sign" on-chain
///      (e.g. by blessing a settlement digest in transient storage), without the
///      owner having to sign every order. The executor implements the full policy;
///      the shed simply forwards to it.
contract COWShedWithExecutorSigner is COWShed, IERC1271 {
    /// @inheritdoc IERC1271
    /// @dev Forwards to the trusted executor's own `isValidSignature`. Fails closed
    ///      (returns `bytes4(0)`) when the executor is unset or an EOA, since an EOA
    ///      cannot implement EIP-1271. The executor may implement any policy it likes,
    ///      including an owner-signature fallback.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        address executor = _state().trustedExecutor;
        if (executor.code.length == 0) {
            return bytes4(0);
        }
        return IERC1271(executor).isValidSignature(hash, signature);
    }
}
