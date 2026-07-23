// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {COWShedExecutorFactory} from "./COWShedExecutorFactory.sol";
import {CowWrapper, ICowSettlement} from "./CowWrapper.sol";
import {Call} from "./ICOWAuthHook.sol";
import {IERC1271} from "./IERC1271.sol";
import {LibCowOrder} from "./LibCowOrder.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibBitmap} from "solady/utils/LibBitmap.sol";

/// @title CowShedHooksWrapper
/// @notice Enforceable hooks for cow-shed: given `preHooks`, a CoW `order`, and `postHooks`, the
///         order fills only if the pre-hooks run before it and the post-hooks run after it, all in
///         the same settlement. Any hook revert (or an unfilled order) reverts the whole
///         settlement, so the order never executes / is rolled back.
/// @dev This wrapper is the shed's `trustedExecutor`: it runs the hooks as the shed via
///      `trustedExecuteHooks`, and "blesses" the order digest in transient storage so the shed's
///      executor-delegated EIP-1271 (`COWShedWithExecutorSigner`) validates the order only during
///      this settlement. Approach A: each bundle is authorized by an owner EIP-712 signature.
contract CowShedHooksWrapper is CowWrapper, IERC1271 {
    using LibBitmap for LibBitmap.Bitmap;

    error MustBeFinalWrapper();
    error Reentrancy();
    error NoItems();
    error TooManyItems();
    error NonZeroReceiver();
    error BadSignature();
    error ShedNotConfigured();
    error NonceAlreadyUsed();
    error OrderAlreadyFilled();
    error OrderNotSettled();

    event Settled(address indexed shed, uint256 nonce);
    event NonceCancelled(address indexed shed, uint256 nonce);

    bytes4 internal constant MAGIC_VALUE_1271 = 0x1626ba7e;
    uint256 internal constant MAX_ITEMS = 32;

    bytes32 private constant T_IN = keccak256("CowShedHooksWrapper.IN");
    bytes32 private constant T_EPOCH = keccak256("CowShedHooksWrapper.EPOCH");

    bytes32 private constant EIP712_DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant HOOKS_ORDER_TYPE_HASH = keccak256(
        "HooksOrder(address owner,bytes32 salt,bytes32 preHooksHash,bytes32 postHooksHash,bytes32 orderDigest,uint256 expectedFill,uint256 nonce)"
    );

    string public constant VERSION = "1.0.0";

    /// @notice Factory used to derive the deterministic shed address from (owner, this, salt).
    COWShedExecutorFactory public immutable factory;

    /// @notice per-shed nonce bitmap for bundle replay protection.
    mapping(address => LibBitmap.Bitmap) internal _nonces;

    /// @dev One enforceable bundle, supplied by the solver at settle time.
    struct HooksOrderExec {
        address owner;
        bytes32 salt;
        Call[] preHooks;
        Call[] postHooks;
        LibCowOrder.Data order;
        uint256 expectedFill;
        uint256 nonce;
        bytes signature; // owner EIP-712 signature over the HooksOrder struct
    }

    constructor(ICowSettlement settlement_, COWShedExecutorFactory factory_) CowWrapper(settlement_) {
        factory = factory_;
    }

    /// @inheritdoc IERC1271
    /// @dev The shed delegates here (so `msg.sender` is the shed). Valid only for a digest blessed
    ///      during the currently-executing settlement.
    function isValidSignature(bytes32 hash, bytes calldata) external view override returns (bytes4) {
        return isBlessed(msg.sender, hash) ? MAGIC_VALUE_1271 : bytes4(0);
    }

    /// @notice Whether `digest` is blessed for `shed` in the active settlement.
    function isBlessed(address shed, bytes32 digest) public view returns (bool) {
        if (_tload(T_IN) != 1) return false;
        return _tload(_blessSlot(_tload(T_EPOCH), shed, digest)) == 1;
    }

    function isNonceUsed(address shed, uint256 nonce) external view returns (bool) {
        return _nonces[shed].get(nonce);
    }

    /// @notice Owner cancels/burns a bundle nonce for their own shed.
    function cancelNonce(bytes32 salt, uint256 nonce) external {
        address shed = factory.proxyOf(msg.sender, address(this), salt);
        _nonces[shed].set(nonce);
        emit NonceCancelled(shed, nonce);
    }

    /// @notice EIP-712 domain separator used to sign bundles.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPE_HASH,
                keccak256("CowShedHooksWrapper"),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        override
    {
        if (_tload(T_IN) != 0) revert Reentrancy();
        if (remainingWrapperData.length != 0) revert MustBeFinalWrapper();

        HooksOrderExec[] memory ex = abi.decode(wrapperData, (HooksOrderExec[]));
        uint256 k = ex.length;
        if (k == 0) revert NoItems();
        if (k > MAX_ITEMS) revert TooManyItems();

        uint256 epoch = _tload(T_EPOCH) + 1;
        _tstore(T_EPOCH, epoch);
        _tstore(T_IN, 1);

        bytes32 ds = SETTLEMENT.domainSeparator();
        address[] memory sheds = new address[](k);
        bytes32[] memory digests = new bytes32[](k);
        bytes[] memory uids = new bytes[](k);

        // PASS 1: authorize each bundle, freeze its nonce, require the order is unfilled.
        for (uint256 i; i < k; ++i) {
            HooksOrderExec memory e = ex[i];
            if (e.order.receiver != address(0)) revert NonZeroReceiver();

            bytes32 digest = LibCowOrder.hash(e.order, ds);
            address shed = _authorize(e, digest);

            bytes memory uid = abi.encodePacked(digest, shed, e.order.validTo);
            if (SETTLEMENT.filledAmount(uid) != 0) revert OrderAlreadyFilled();

            sheds[i] = shed;
            digests[i] = digest;
            uids[i] = uid;
        }

        // PASS 2: run each pre-hook as the shed.
        for (uint256 i; i < k; ++i) {
            COWShed(payable(sheds[i])).trustedExecuteHooks(ex[i].preHooks);
        }

        // PASS 3: bless each digest for this epoch, then descend into settlement.
        for (uint256 i; i < k; ++i) {
            _tstore(_blessSlot(epoch, sheds[i], digests[i]), 1);
        }

        _next(settleData, remainingWrapperData);

        // Close the bless window.
        _tstore(T_IN, 0);

        // PASS 4: verify each order filled, then run its post-hook as the shed.
        for (uint256 i; i < k; ++i) {
            if (SETTLEMENT.filledAmount(uids[i]) < ex[i].expectedFill) revert OrderNotSettled();
            COWShed(payable(sheds[i])).trustedExecuteHooks(ex[i].postHooks);
            emit Settled(sheds[i], ex[i].nonce);
        }
    }

    /// @dev Verify the owner signature, resolve + check the shed, and consume the nonce.
    function _authorize(HooksOrderExec memory e, bytes32 digest) internal returns (address shed) {
        bytes32 structHash = keccak256(
            abi.encode(
                HOOKS_ORDER_TYPE_HASH,
                e.owner,
                e.salt,
                keccak256(abi.encode(e.preHooks)),
                keccak256(abi.encode(e.postHooks)),
                digest,
                e.expectedFill,
                e.nonce
            )
        );
        bytes32 signHash = keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
        if (ECDSA.recover(signHash, e.signature) != e.owner) revert BadSignature();

        shed = factory.proxyOf(e.owner, address(this), e.salt);
        if (shed.code.length == 0 || COWShed(payable(shed)).trustedExecutor() != address(this)) {
            revert ShedNotConfigured();
        }

        if (_nonces[shed].get(e.nonce)) revert NonceAlreadyUsed();
        _nonces[shed].set(e.nonce);
    }

    function _blessSlot(uint256 epoch, address shed, bytes32 digest) private pure returns (bytes32) {
        return keccak256(abi.encode("CowShedHooksWrapper.BLESS", epoch, shed, digest));
    }

    function _tload(bytes32 slot) private view returns (uint256 v) {
        assembly ("memory-safe") {
            v := tload(slot)
        }
    }

    function _tstore(bytes32 slot, uint256 v) private {
        assembly ("memory-safe") {
            tstore(slot, v)
        }
    }
}
