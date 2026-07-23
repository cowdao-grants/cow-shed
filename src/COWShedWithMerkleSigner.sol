// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {ERC1271MerkleValidator} from "./ERC1271MerkleValidator.sol";

/**
 * @title COWShed With Merkle Signer
 * @notice A COWShed implementation that validates CoW Protocol orders via proof of
 *         inclusion in an owner-signed merkle root, with zero on-chain storage.
 * @dev Mirrors `COWShedForComposableCoW` (COWShed + ERC1271Forwarder). Here the shed
 *      is itself the EIP-1271 order owner, and `isValidSignature` is served directly by
 *      the merkle validator rather than forwarded to ComposableCoW.
 */
contract COWShedWithMerkleSigner is COWShed, ERC1271MerkleValidator {
    /// @dev The proxy owner/admin authorizes roots.
    function _rootSigner() internal view override returns (address) {
        return _admin();
    }

    /// @dev Reuse the shed's EIP-712 domain (chain id + proxy address).
    function _domainSeparatorV4() internal view override returns (bytes32) {
        return domainSeparator();
    }

    /// @notice Revoke an entire authorized root (bulk cancel). Only the owner.
    function revokeRoot(bytes32 root) external onlyAdmin {
        _revokeRoot(root);
    }

    /// @notice Revoke several roots in a single call. Only the owner.
    function revokeRoots(bytes32[] calldata roots) external onlyAdmin {
        for (uint256 i; i < roots.length; i++) {
            _revokeRoot(roots[i]);
        }
    }

    /// @notice Revoke a single order by its digest, even if its root remains valid. Only the owner.
    function revokeOrder(bytes32 orderDigest) external onlyAdmin {
        _revokeOrder(orderDigest);
    }

    /// @notice Revoke several order digests in a single call. Only the owner.
    function revokeOrders(bytes32[] calldata orderDigests) external onlyAdmin {
        for (uint256 i; i < orderDigests.length; i++) {
            _revokeOrder(orderDigests[i]);
        }
    }
}
