// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {IERC1271} from "./IERC1271.sol";
import {LibAuthenticatedHooks} from "./LibAuthenticatedHooks.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @title COWShedWithExecutorSigner
/// @notice A COWShed variant that is itself an EIP-1271 signer. When a trusted executor
///         contract is configured it delegates order signature validity to it; otherwise
///         it accepts the owner's own ECDSA signature, bound to this shed.
/// @dev Intended for setups where a manager/wrapper contract (the trusted executor)
///      drives the shed and decides which digests the shed will "sign" on-chain
///      (e.g. by blessing a settlement digest in transient storage), without the
///      owner having to sign every order. When no executor contract is set, the shed
///      behaves as an owner-signed smart account for CoW orders.
contract COWShedWithExecutorSigner is COWShed, IERC1271 {
    /// @dev EIP-712 type hash for an owner-signed CoW order digest. The digest is wrapped in
    ///      this struct and hashed under the shed's own domain separator so a signature is only
    ///      ever valid for THIS shed (see `isValidSignature`).
    bytes32 internal constant SIGNED_COW_ORDER_TYPE_HASH = keccak256("SignedCowOrder(bytes32 orderDigest)");

    /// @inheritdoc IERC1271
    /// @dev When a trusted executor *contract* is set, forwards to its `isValidSignature` and
    ///      lets it be authoritative. When no executor contract is set (unset or an EOA, neither
    ///      of which can implement EIP-1271), verifies the owner's ECDSA signature over the
    ///      shed-bound wrapper of `hash` (`SignedCowOrder(orderDigest)` under this shed's domain
    ///      separator). Binding to the shed's domain separator is what prevents a signature from
    ///      being replayed to the owner's EOA (which would sign the raw order digest) or to any
    ///      other shed the owner controls (different `verifyingContract`). Returns `bytes4(0)`
    ///      otherwise.
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

        // No executor contract configured: accept the owner's own ECDSA signature, bound to
        // this shed. `tryRecoverCalldata` returns address(0) for malformed signatures (never
        // reverts), so an empty/garbage signature simply fails the owner check below.
        address recovered = ECDSA.tryRecoverCalldata(_ownerSignedHash(hash), signature);
        if (recovered != address(0) && recovered == _admin()) {
            return LibAuthenticatedHooks.MAGIC_VALUE_1271;
        }
        return bytes4(0);
    }

    /// @notice The EIP-712 digest the owner must sign to authorize a CoW order digest for this
    ///         shed. Exposed so integrations can construct the signature off-chain.
    /// @param orderDigest The GPv2 order digest passed by settlement to `isValidSignature`.
    function ownerSignedHash(bytes32 orderDigest) external view returns (bytes32) {
        return _ownerSignedHash(orderDigest);
    }

    function _ownerSignedHash(bytes32 orderDigest) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(SIGNED_COW_ORDER_TYPE_HASH, orderDigest));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
    }
}
