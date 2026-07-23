// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Vm} from "forge-std/Test.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {COWShedWithMerkleSigner} from "src/COWShedWithMerkleSigner.sol";
import {ERC1271MerkleValidator} from "src/ERC1271MerkleValidator.sol";
import {BaseTest} from "test/BaseTest.sol";

contract COWShedWithMerkleSignerTest is BaseTest {
    /// @dev ERC-1271 magic value.
    bytes4 internal constant MAGIC = 0x1626ba7e;
    /// @dev must match ERC1271MerkleValidator.ROOT_TYPE_HASH.
    bytes32 internal constant ROOT_TYPE_HASH = keccak256("OrderRoot(bytes32 root,uint256 validTo)");

    COWShedWithMerkleSigner internal merkleImpl;
    COWShedFactory internal merkleFactory;

    // EOA-owned merkle proxy (owner == user.addr)
    address internal merkleProxyAddr;
    COWShedWithMerkleSigner internal merkleProxy;

    // contract-owned merkle proxy (owner == smartWalletAddr, exercises the ERC-1271 owner path)
    address internal swMerkleProxyAddr;
    COWShedWithMerkleSigner internal swMerkleProxy;

    // sample order digests committed to the tree; index 0 is the one we prove
    bytes32[4] internal digests;

    function setUp() public override {
        super.setUp();

        merkleImpl = new COWShedWithMerkleSigner();
        merkleFactory = new COWShedFactory(address(merkleImpl));

        merkleProxyAddr = merkleFactory.proxyOf(user.addr);
        merkleFactory.initializeProxy(user.addr);
        merkleProxy = COWShedWithMerkleSigner(payable(merkleProxyAddr));

        swMerkleProxyAddr = merkleFactory.proxyOf(smartWalletAddr);
        merkleFactory.initializeProxy(smartWalletAddr);
        swMerkleProxy = COWShedWithMerkleSigner(payable(swMerkleProxyAddr));

        digests[0] = keccak256("order-0");
        digests[1] = keccak256("order-1");
        digests[2] = keccak256("order-2");
        digests[3] = keccak256("order-3");
    }

    function test_isValidSignature_happyPath() public {
        (bytes32 root, bytes32[] memory proof) = _rootAndProofForFirstDigest();
        uint256 validTo = block.timestamp + 1 hours;
        bytes memory rootSig = _signRootEOA(user, merkleProxyAddr, root, validTo);
        bytes memory sig = _encodeSig(root, validTo, rootSig, proof);

        assertEq(merkleProxy.isValidSignature(digests[0], sig), MAGIC, "authorized order should validate");
    }

    function test_isValidSignature_expiredBatchFailsClosed() public {
        // Move time forward so we can set validTo in the past without underflow.
        vm.warp(1_000_000);
        (bytes32 root, bytes32[] memory proof) = _rootAndProofForFirstDigest();
        uint256 validTo = block.timestamp - 1;
        bytes memory rootSig = _signRootEOA(user, merkleProxyAddr, root, validTo);
        bytes memory sig = _encodeSig(root, validTo, rootSig, proof);

        assertEq(merkleProxy.isValidSignature(digests[0], sig), bytes4(0), "expired batch must fail closed");
    }

    function test_isValidSignature_orderNotInTreeFailsClosed() public {
        (bytes32 root, bytes32[] memory proof) = _rootAndProofForFirstDigest();
        uint256 validTo = block.timestamp + 1 hours;
        bytes memory rootSig = _signRootEOA(user, merkleProxyAddr, root, validTo);
        // Proof is for digests[0]; ask about an unrelated digest.
        bytes memory sig = _encodeSig(root, validTo, rootSig, proof);

        assertEq(merkleProxy.isValidSignature(keccak256("not-in-tree"), sig), bytes4(0), "non-member must fail closed");
    }

    function test_isValidSignature_wrongSignerFailsClosed() public {
        Vm.Wallet memory attacker = vm.createWallet("attacker");
        (bytes32 root, bytes32[] memory proof) = _rootAndProofForFirstDigest();
        uint256 validTo = block.timestamp + 1 hours;
        // Root signed by someone who is not the proxy owner.
        bytes memory rootSig = _signRootEOA(attacker, merkleProxyAddr, root, validTo);
        bytes memory sig = _encodeSig(root, validTo, rootSig, proof);

        assertEq(merkleProxy.isValidSignature(digests[0], sig), bytes4(0), "root from non-owner must fail closed");
    }

    function test_isValidSignature_tamperedValidToFailsClosed() public {
        (bytes32 root, bytes32[] memory proof) = _rootAndProofForFirstDigest();
        uint256 signedValidTo = block.timestamp + 1 hours;
        bytes memory rootSig = _signRootEOA(user, merkleProxyAddr, root, signedValidTo);
        // Present a different validTo than the one that was signed.
        bytes memory sig = _encodeSig(root, signedValidTo + 1, rootSig, proof);

        assertEq(merkleProxy.isValidSignature(digests[0], sig), bytes4(0), "tampered validTo must fail closed");
    }

    function test_isValidSignature_contractOwnerPath() public {
        (bytes32 root, bytes32[] memory proof) = _rootAndProofForFirstDigest();
        uint256 validTo = block.timestamp + 1 hours;

        // The BaseTest SmartWallet validates a signature iff it was pre-stored for the hash.
        bytes32 rootDigest = _rootDigest(swMerkleProxyAddr, root, validTo);
        bytes memory rootSig = abi.encode(rootDigest);
        vm.prank(smartWallet.owner());
        smartWallet.sign(rootDigest, rootSig);

        bytes memory sig = _encodeSig(root, validTo, rootSig, proof);
        assertEq(swMerkleProxy.isValidSignature(digests[0], sig), MAGIC, "contract owner (ERC-1271) should validate");
    }

    // --- helpers ---------------------------------------------------------

    /// @dev leaf hashing matches @openzeppelin/merkle-tree StandardMerkleTree, leafEncoding ["bytes32"].
    function _leaf(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(digest))));
    }

    /// @dev sorted-pair hashing, matching solady MerkleProofLib / OZ MerkleProof.
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    /// @dev Build a 4-leaf balanced tree and return the root + inclusion proof for digests[0].
    function _rootAndProofForFirstDigest() internal view returns (bytes32 root, bytes32[] memory proof) {
        bytes32 l0 = _leaf(digests[0]);
        bytes32 l1 = _leaf(digests[1]);
        bytes32 l2 = _leaf(digests[2]);
        bytes32 l3 = _leaf(digests[3]);
        bytes32 n01 = _hashPair(l0, l1);
        bytes32 n23 = _hashPair(l2, l3);
        root = _hashPair(n01, n23);

        proof = new bytes32[](2);
        proof[0] = l1;
        proof[1] = n23;
    }

    function _rootDigest(address proxy, bytes32 root, uint256 validTo) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(ROOT_TYPE_HASH, root, validTo));
        return
            keccak256(
                abi.encodePacked("\x19\x01", COWShedWithMerkleSigner(payable(proxy)).domainSeparator(), structHash)
            );
    }

    function _signRootEOA(Vm.Wallet memory wallet, address proxy, bytes32 root, uint256 validTo)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, _rootDigest(proxy, root, validTo));
        return abi.encodePacked(r, s, v);
    }

    function _encodeSig(bytes32 root, uint256 validTo, bytes memory rootSig, bytes32[] memory proof)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(ERC1271MerkleValidator.MerkleSignature(root, validTo, rootSig, proof));
    }
}
