// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import { ECDSA } from "solady/utils/ECDSA.sol";
import { Call } from "./ICOWAuthHook.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

library LibAuthenticatedHooks {
    error InvalidSignature();
    error DeadlineElapsed();

    /// @dev EIP712 Call typehash
    bytes32 internal constant CALL_TYPE_HASH =
        keccak256("Call(address target,uint256 value,bytes callData,bool allowFailure,bool isDelegateCall)");
    /// @dev EIP712 ExecuteHooks typehash
    bytes32 internal constant EXECUTE_HOOKS_TYPE_HASH = keccak256(
        "ExecuteHooks(Call[] calls,bytes32 nonce,uint256 deadline)Call(address target,uint256 value,bytes callData,bool allowFailure,bool isDelegateCall)"
    );
    /// @dev magic value that is returned on successful validation of a signature from a EIP1271 smart account.
    bytes4 internal constant MAGIC_VALUE_1271 = 0x1626ba7e;

    /// @dev verifies the deadline of the message and the signature against the executing payload.
    function authenticateHooks(
        Call[] calldata calls,
        bytes32 nonce,
        uint256 deadline,
        address user,
        bytes calldata signature,
        bytes32 domainSeparator
    ) internal view returns (bool) {
        if (block.timestamp > deadline) {
            revert DeadlineElapsed();
        }
        bytes32 toSign = hashToSign(calls, nonce, deadline, domainSeparator);

        // smart contract signer
        if (user.code.length > 0) {
            bool isAuthorized = IERC1271(user).isValidSignature(toSign, signature) == MAGIC_VALUE_1271;
            return (isAuthorized);
        }
        // eoa signer
        else {
            (bytes32 r, bytes32 s, uint8 v) = decodeEOASignature(signature);
            address recovered = ECDSA.recover(toSign, v, r, s);
            return user == recovered;
        }
    }

    /// @dev the EIP712 hash to sign.
    function hashToSign(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32 _toSign)
    {
        bytes32 messageHash = executeHooksMessageHash(calls, nonce, deadline);
        _toSign = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, messageHash));
    }

    /// @dev the `hashStruct` encoded hash for the given `ExecuteHooks` message.
    function executeHooksMessageHash(Call[] calldata calls, bytes32 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32 hash)
    {
        bytes32 callshash = callsHash(calls);
        bytes32 executeHooksTypeHash = EXECUTE_HOOKS_TYPE_HASH;
        hash = keccak256(abi.encode(executeHooksTypeHash, callshash, nonce, deadline));
    }

    /// @dev the `encodeData` output for the provided calls' dynamic array.
    function callsHash(Call[] calldata calls) internal pure returns (bytes32 _callsHash) {
        uint256 nCalls = calls.length;
        bytes32[] memory hashes = new bytes32[](nCalls);

        for (uint256 i = 0; i < nCalls;) {
            hashes[i] = callHash(calls[i]);
            unchecked {
                ++i;
            }
        }

        assembly {
            _callsHash := keccak256(add(hashes, 0x20), mul(nCalls, 0x20))
        }
    }

    /// @dev the `hashStruct` output for given call.
    function callHash(Call calldata cll) internal pure returns (bytes32 _callHash) {
        address target = cll.target;
        uint256 value = cll.value;
        bytes32 callDataHash = keccak256(cll.callData);
        bool allowFailure = cll.allowFailure;
        bool isDelegateCall = cll.isDelegateCall;
        bytes32 callTypeHash = CALL_TYPE_HASH;

        _callHash = keccak256(abi.encode(callTypeHash, target, value, callDataHash, allowFailure, isDelegateCall));
    }

    /// @dev execute given calls
    function executeCalls(Call[] calldata calls) internal {
        for (uint256 i = 0; i < calls.length;) {
            Call memory call = calls[i];
            bool success;
            bytes memory ret;
            if (call.isDelegateCall) {
                (success, ret) = call.target.delegatecall(call.callData);
            } else {
                (success, ret) = call.target.call{ value: call.value }(call.callData);
            }
            if (!success && !call.allowFailure) {
                // bubble up the revert message
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @dev decodes signatures for EOA as `<r><s><v>` from a packed message.
    function decodeEOASignature(bytes calldata signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        if (signature.length != 65) {
            revert InvalidSignature();
        }
        uint256 mask = 0xff;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := and(calldataload(add(signature.offset, 0x21)), mask)
        }
    }
}
