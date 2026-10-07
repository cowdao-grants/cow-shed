// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {IERC1271} from "./IERC1271.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title ERC1271 Merkle Validator
 * @notice Validates CoW Protocol orders by proving their inclusion in an
 *         owner-signed merkle root of order digests.
 * @dev Zero on-chain storage: the root, the owner's signature over the root, and the
 *      inclusion proof are ALL carried in the ERC-1271 `signature` bytes (supplied by
 *      the solver in the settlement). The owner signs one root off-chain that commits
 *      to an arbitrary number of orders; no per-order presign / SSTORE is needed.
 *
 *      The settlement computes the GPv2 order digest and passes it as `_hash`, so this
 *      contract never decodes the order — it only checks that the owner authorized that
 *      digest. The digest is already bound to the settlement domain + chain, and the
 *      root signature is bound to this proxy's domain + chain, so neither the leaf nor
 *      the root can be replayed across chains or across proxies.
 *
 *      Revocation is intentionally out of scope for this contract: authorization is
 *      time-bounded via `validTo`. On-chain (per-root / per-order) revocation is a
 *      planned follow-up that would layer a storage check on top of this path.
 */
abstract contract ERC1271MerkleValidator is IERC1271 {
    /// @dev EIP-712 typehash for the owner's root commitment.
    bytes32 internal constant ROOT_TYPE_HASH = keccak256("OrderRoot(bytes32 root,uint256 validTo)");

    /// @dev ERC-1271 magic value returned on successful validation.
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    /// @dev The payload the solver carries in the settlement's `signature` field.
    struct MerkleSignature {
        bytes32 root; // merkle root of authorized order digests
        uint256 validTo; // batch-level authorization deadline (unix seconds)
        bytes rootSignature; // owner signature (EOA or ERC-1271) over OrderRoot(root, validTo)
        bytes32[] proof; // inclusion proof for this order's digest
    }

    /// @notice Domain separator binding the root signature to this proxy + chain.
    function _domainSeparatorV4() internal view virtual returns (bytes32);

    /// @notice The address whose signature authorizes a root (the proxy owner/admin).
    function _rootSigner() internal view virtual returns (address);

    /**
     * @param _hash GPv2 order digest, computed and passed by the settlement.
     * @param signature abi.encoded `MerkleSignature`.
     * @return `MAGIC_VALUE` if the order is authorized, `bytes4(0)` otherwise (fail closed).
     */
    function isValidSignature(bytes32 _hash, bytes memory signature) public view override returns (bytes4) {
        MerkleSignature memory sig = abi.decode(signature, (MerkleSignature));

        // Ensure the signature hasn't expired
        if (block.timestamp > sig.validTo) {
            return bytes4(0);
        }

        // Verify the owner's signature of the EIP-712 message. The message contains the merkle root and the validTo
        bytes32 toSign = _rootDigest(sig.root, sig.validTo);
        if (!SignatureCheckerLib.isValidSignatureNow(_rootSigner(), toSign, sig.rootSignature)) {
            return bytes4(0);
        }

        // Verify the order being verified (_hash) is included in the merkle root. Uses the proof and the verified merkle root
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(_hash))));
        if (!MerkleProofLib.verify(sig.proof, sig.root, leaf)) {
            return bytes4(0);
        }

        return MAGIC_VALUE;
    }

    function _rootDigest(bytes32 root, uint256 validTo) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(ROOT_TYPE_HASH, root, validTo));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }
}
