// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {IERC1271} from "./IERC1271.sol";
import {LibAuthenticatedHooks} from "./LibAuthenticatedHooks.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @title COWShedWithOwnerSigner
/// @notice A COWShed variant that is itself an EIP-1271 signer: it "signs" any
///         digest (e.g. a CoW Protocol order) that carries a valid ECDSA
///         signature from the shed's owner (admin).
/// @dev Intended for setups where an EOA holds the funds, uses its shed as the
///      order trader, and authorizes each order by signing the order digest
///      directly. The settlement contract validates the order via
///      `isValidSignature`, which recovers the signer and checks it matches the
///      owner. No per-order on-chain state is needed.
contract COWShedWithOwnerSigner is COWShed, IERC1271 {
    /// @inheritdoc IERC1271
    /// @dev Returns the magic value iff `signature` is a valid ECDSA signature
    ///      over `hash` produced by the shed's owner (admin). Fails closed
    ///      (returns `bytes4(0)`) on a malformed signature or signer mismatch.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        address recovered = ECDSA.tryRecoverCalldata(hash, signature);
        if (recovered != address(0) && recovered == _admin()) {
            return LibAuthenticatedHooks.MAGIC_VALUE_1271;
        }
        return bytes4(0);
    }
}
