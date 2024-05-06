import { ECDSA } from "solady/utils/ECDSA.sol";
import { Call } from "./ICOWAuthHook.sol";

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

library LibAuthenticatedHooks {
    error InvalidSignature();
    error DeadlineElapsed();

    bytes32 internal constant CALL_TYPE_HASH =
        keccak256("Call(address target,uint256 value,bytes callData,bool allowFailure,bool isDelegateCall)");
    bytes32 internal constant EXECUTE_HOOKS_TYPE_HASH = keccak256(
        "ExecuteHooks(Call[] calls,bytes32 nonce,uint256 deadline)Call(address target,uint256 value,bytes callData,bool allowFailure,bool isDelegateCall)"
    );
    bytes4 internal constant MAGIC_VALUE_1271 = 0x1626ba7e;

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

    function hashToSign(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32 _toSign)
    {
        bytes32 messageHash = executeHooksMessageHash(calls, nonce, deadline);

        assembly ("memory-safe") {
            let freeMemoryPointer := mload(0x40)

            mstore(0x00, 0x1901)
            mstore(0x20, domainSeparator)
            mstore(0x40, messageHash)

            _toSign := keccak256(0x1e, 0x42)

            // restore free memory pointer
            mstore(0x40, freeMemoryPointer)
        }
    }

    function executeHooksMessageHash(Call[] calldata calls, bytes32 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32 hash)
    {
        bytes32 callshash = callsHash(calls);
        bytes32 executeHooksTypeHash = EXECUTE_HOOKS_TYPE_HASH;

        assembly ("memory-safe") {
            let before := mload(0x40)
            mstore(0x00, executeHooksTypeHash)
            mstore(0x20, callshash)
            mstore(0x40, nonce)
            mstore(0x60, deadline)
            hash := keccak256(0x00, 0x80)

            // restore free memory pointer
            mstore(0x40, before)
            // restore the zero slot
            mstore(0x60, 0)
        }
    }

    function callsHash(Call[] calldata calls) internal pure returns (bytes32 _callsHash) {
        uint256 nCalls = calls.length;
        bytes32[] memory hashes = new bytes32[](nCalls);

        for (uint256 i = 0; i < nCalls; i++) {
            hashes[i] = callHash(calls[i]);
        }

        assembly ("memory-safe") {
            _callsHash := keccak256(add(hashes, 0x20), mul(nCalls, 0x20))
        }
    }

    function callHash(Call calldata cll) internal pure returns (bytes32 _callHash) {
        address target = cll.target;
        uint256 value = cll.value;
        bytes32 callDataHash = keccak256(cll.callData);
        bool allowFailure = cll.allowFailure;
        bool isDelegateCall = cll.isDelegateCall;
        bytes32 callTypeHash = CALL_TYPE_HASH;

        assembly ("memory-safe") {
            let freeMemoryPointer := mload(0x40)
            let firstSlot := mload(0x80)
            let secondSlot := mload(0xa0)

            mstore(0x00, callTypeHash)
            mstore(0x20, target)
            mstore(0x40, value)
            mstore(0x60, callDataHash)
            mstore(0x80, allowFailure)
            mstore(0xa0, isDelegateCall)
            _callHash := keccak256(0x00, 0xc0)

            // restore free memory pointer
            mstore(0x40, freeMemoryPointer)
            // restore 0 slot
            mstore(0x60, 0x00)
            // restore first slot
            mstore(0x80, firstSlot)
            // restore second slot
            mstore(0xa0, secondSlot)
        }
    }

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
