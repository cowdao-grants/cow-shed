// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {COWShedExecutorFactory} from "./COWShedExecutorFactory.sol";
import {Call} from "./ICOWAuthHook.sol";
import {IERC1271} from "./IERC1271.sol";
import {LibCowOrder} from "./LibCowOrder.sol";
import {CowWrapper, ICowSettlement, ICowWrapper} from "./vendor/CowWrapper.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibBitmap} from "solady/utils/LibBitmap.sol";

/// @dev GPv2Settlement exposes filled amounts per order UID, but the vendored `ICowSettlement`
///      (kept minimal upstream) omits it. Declared locally and cast over the settlement address.
interface ISettlementFilled {
    function filledAmount(bytes calldata orderUid) external view returns (uint256);
}

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

    /// @dev This wrapper isn't the last hop before settlement; the bless window must span only the
    ///      `settle` call this wrapper makes, so it must be the final wrapper in the chain.
    error MustBeFinalWrapper();

    /// @dev `_wrap` was re-entered while a settlement it started is still active.
    error Reentrancy();

    /// @dev The bundle array is empty; there is nothing to settle.
    error NoItems();

    /// @dev An order's `receiver` is not `address(0)`; it must pay the shed (the order owner).
    error NonZeroReceiver();

    /// @dev The bundle signature does not recover to the order owner.
    error BadSignature();

    /// @dev The derived shed is not deployed, or its `trustedExecutor` is not this wrapper.
    error ShedNotConfigured();

    /// @dev The bundle nonce has already been consumed (or was cancelled by the owner).
    error NonceAlreadyUsed();

    /// @dev The order already had a non-zero filled amount before settlement (replay / stale).
    error OrderAlreadyFilled();
    
    /// @dev After settlement the order's filled amount was below `expectedFill`.
    error OrderNotSettled();

    event Settled(address indexed shed, uint256 nonce);
    event NonceCancelled(address indexed shed, uint256 nonce);

    bytes4 internal constant MAGIC_VALUE_1271 = 0x1626ba7e;

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

    /// @dev Set while a settlement orchestrated by this wrapper is executing. Gates blessings
    ///      (`isBlessed`) and guards against reentrancy; cleared before the post-hooks run.
    bool private transient _inSettlement;

    /// @dev Monotonic per-`_wrap` counter that namespaces the bless slots, so a stale blessing
    ///      from an earlier settlement in the same transaction can never be reused.
    uint256 private transient _epoch;

    /// @notice One enforceable bundle, supplied by the solver at settle time: the owner-signed
    ///         `(preHooks, order, postHooks)` to run atomically around the fill.
    struct Bundle {
        address owner;
        bytes32 salt;
        Call[] preHooks;
        Call[] postHooks;
        LibCowOrder.Data order;
        uint256 expectedFill;
        uint256 nonce;
        bytes signature; // owner EIP-712 signature over the `HooksOrder` type
    }

    /// @dev Per-bundle values resolved in pass 1 and reused across the later passes.
    struct Prepared {
        address shed;
        bytes32 digest; // GPv2 order digest
        bytes uid; // GPv2 order UID
    }

    constructor(ICowSettlement settlement_, COWShedExecutorFactory factory_) CowWrapper(settlement_) {
        factory = factory_;
    }

    /// @inheritdoc ICowWrapper
    function name() external pure override returns (string memory) {
        return "CowShedHooksWrapper";
    }

    /// @inheritdoc ICowWrapper
    /// @dev Lightweight structural validation of the settle-time bundle payload (signatures and
    ///      nonces are checked in `_wrap` at execution time).
    function validateWrapperData(bytes calldata wrapperData) external pure override {
        Bundle[] memory bundles = abi.decode(wrapperData, (Bundle[]));
        uint256 count = bundles.length;
        if (count == 0) revert NoItems();
        for (uint256 i; i < count; ++i) {
            if (bundles[i].order.receiver != address(0)) revert NonZeroReceiver();
        }
    }

    /// @inheritdoc IERC1271
    /// @dev The shed delegates here (so `msg.sender` is the shed). Valid only for a digest blessed
    ///      during the currently-executing settlement.
    function isValidSignature(bytes32 hash, bytes calldata) external view override returns (bytes4) {
        return isBlessed(msg.sender, hash) ? MAGIC_VALUE_1271 : bytes4(0);
    }

    /// @notice Whether `digest` is blessed for `shed` in the active settlement.
    function isBlessed(address shed, bytes32 digest) public view returns (bool) {
        if (!_inSettlement) return false;
        return _tload(_blessSlot(_epoch, shed, digest)) == 1;
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
        if (_inSettlement) revert Reentrancy();
        if (remainingWrapperData.length != 0) revert MustBeFinalWrapper();

        Bundle[] memory bundles = abi.decode(wrapperData, (Bundle[]));
        uint256 count = bundles.length;
        if (count == 0) revert NoItems();

        uint256 epoch = _epoch + 1;
        _epoch = epoch;
        _inSettlement = true;

        bytes32 cowDomainSeparator = SETTLEMENT.domainSeparator();
        Prepared[] memory prepared = new Prepared[](count);

        // PASS 1: authorize each bundle, freeze its nonce, and require the order is not yet filled.
        for (uint256 i; i < count; ++i) {
            Bundle memory bundle = bundles[i];
            // receiver must be zero so the filled order pays the shed (the order owner)
            if (bundle.order.receiver != address(0)) revert NonZeroReceiver();

            bytes32 digest = LibCowOrder.hash(bundle.order, cowDomainSeparator);
            address shed = _authorize(bundle, digest);
            bytes memory uid = _orderUid(digest, shed, bundle.order.validTo);
            if (_filledAmount(uid) != 0) revert OrderAlreadyFilled();

            prepared[i] = Prepared({shed: shed, digest: digest, uid: uid});
        }

        // PASS 2: run each pre-hook as the shed.
        for (uint256 i; i < count; ++i) {
            COWShed(payable(prepared[i].shed)).trustedExecuteHooks(bundles[i].preHooks);
        }

        // PASS 3: bless each order digest for this epoch, then descend into settlement.
        for (uint256 i; i < count; ++i) {
            _tstore(_blessSlot(epoch, prepared[i].shed, prepared[i].digest), 1);
        }

        _next(settleData, remainingWrapperData);

        // close the bless window before any post-hook runs
        _inSettlement = false;

        // PASS 4: require each order filled, then run its post-hook as the shed.
        for (uint256 i; i < count; ++i) {
            if (_filledAmount(prepared[i].uid) < bundles[i].expectedFill) revert OrderNotSettled();
            COWShed(payable(prepared[i].shed)).trustedExecuteHooks(bundles[i].postHooks);
            emit Settled(prepared[i].shed, bundles[i].nonce);
        }
    }

    /// @dev Verify the owner signature, resolve + check the shed, and consume the nonce.
    function _authorize(Bundle memory bundle, bytes32 digest) internal returns (address shed) {
        bytes32 structHash = keccak256(
            abi.encode(
                HOOKS_ORDER_TYPE_HASH,
                bundle.owner,
                bundle.salt,
                keccak256(abi.encode(bundle.preHooks)),
                keccak256(abi.encode(bundle.postHooks)),
                digest,
                bundle.expectedFill,
                bundle.nonce
            )
        );
        bytes32 signHash = keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
        if (ECDSA.recover(signHash, bundle.signature) != bundle.owner) revert BadSignature();

        shed = factory.proxyOf(bundle.owner, address(this), bundle.salt);
        if (shed.code.length == 0 || COWShed(payable(shed)).trustedExecutor() != address(this)) {
            revert ShedNotConfigured();
        }

        if (_nonces[shed].get(bundle.nonce)) revert NonceAlreadyUsed();
        _nonces[shed].set(bundle.nonce);
    }

    function _filledAmount(bytes memory uid) private view returns (uint256) {
        return ISettlementFilled(address(SETTLEMENT)).filledAmount(uid);
    }

    /// @dev GPv2 order UID layout: `orderDigest (32) ‖ owner (20) ‖ validTo (4)`; the owner is the shed.
    function _orderUid(bytes32 digest, address shed, uint32 validTo) private pure returns (bytes memory) {
        return abi.encodePacked(digest, shed, validTo);
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
