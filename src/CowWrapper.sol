// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

/// @notice CoW Protocol solver allowlist.
interface ICowAuthentication {
    function isSolver(address prospectiveSolver) external view returns (bool);
}

/// @notice Minimal view of GPv2Settlement used by wrappers. `settle` is called opaquely with a
///         pre-encoded calldata blob, so it is not declared here.
interface ICowSettlement {
    function authenticator() external view returns (ICowAuthentication);
    function domainSeparator() external view returns (bytes32);
    function filledAmount(bytes calldata orderUid) external view returns (uint256);
}

interface ICowWrapper {
    function wrappedSettle(bytes calldata settleData, bytes calldata chainedWrapperData) external returns (bytes4);
}

/// @title CowWrapper
/// @notice Abstract base for a chain of CoW settlement wrappers that sandwich a `GPv2Settlement.settle`
///         call with custom logic. Adapted for cow-shed from the `CowWrapper` in
///         koeppelmann/Cowswap-pro (feat/onchain-leverage).
/// @dev The wrapper (and any solver that kicks off the chain) must be allowlisted in the CoW
///      `ICowAuthentication` contract, since the terminal hop calls `settle` with the wrapper as
///      `msg.sender`. `chainedWrapperData` is self-describing: `[uint16 len][len bytes wrapperData]
///      [remaining...]`, where `remaining` is either empty (terminate → call settlement) or
///      `[20-byte next wrapper][next chainedWrapperData]`.
abstract contract CowWrapper is ICowWrapper {
    error NotASolver(address caller);
    error InvalidSettleData();
    error InvalidNextWrapper(address nextWrapper);

    /// @dev `GPv2Settlement.settle(address[],uint256[],Trade[],Interaction[][3])` selector.
    bytes4 internal constant SETTLE_SELECTOR = 0x13d79a0b;

    ICowSettlement public immutable SETTLEMENT;
    ICowAuthentication public immutable AUTHENTICATOR;

    constructor(ICowSettlement settlement_) {
        SETTLEMENT = settlement_;
        AUTHENTICATOR = settlement_.authenticator();
    }

    /// @inheritdoc ICowWrapper
    function wrappedSettle(bytes calldata settleData, bytes calldata chainedWrapperData)
        external
        returns (bytes4)
    {
        if (!AUTHENTICATOR.isSolver(msg.sender)) revert NotASolver(msg.sender);

        uint256 nextWrapperDataLen = uint256(uint16(bytes2(chainedWrapperData[0:2])));
        uint256 remainingStart = 2 + nextWrapperDataLen;
        _wrap(settleData, chainedWrapperData[2:remainingStart], chainedWrapperData[remainingStart:]);

        return ICowWrapper.wrappedSettle.selector;
    }

    /// @dev Subclass hook. Must call `_next(settleData, remainingWrapperData)` exactly once to
    ///      continue the chain into settlement.
    function _wrap(bytes calldata settleData, bytes calldata wrapperData, bytes calldata remainingWrapperData)
        internal
        virtual;

    /// @dev Continue the chain: terminate by calling settlement, or forward to the next wrapper.
    function _next(bytes calldata settleData, bytes calldata remainingWrapperData) internal {
        if (remainingWrapperData.length == 0) {
            if (bytes4(settleData[:4]) != SETTLE_SELECTOR) revert InvalidSettleData();
            _callWithBubbleRevert(address(SETTLEMENT), settleData);
        } else {
            address nextWrapper = address(bytes20(remainingWrapperData[:20]));
            bytes memory ret = _callWithBubbleRevert(
                nextWrapper, abi.encodeCall(ICowWrapper.wrappedSettle, (settleData, remainingWrapperData[20:]))
            );
            if (ret.length != 32 || bytes32(ret) != bytes32(ICowWrapper.wrappedSettle.selector)) {
                revert InvalidNextWrapper(nextWrapper);
            }
        }
    }

    function _callWithBubbleRevert(address target, bytes memory data) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}
