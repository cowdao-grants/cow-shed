import { LibAuthenticatedHooks, Call } from "src/LibAuthenticatedHooks.sol";
import { Test } from "forge-std/Test.sol";

contract CalldataProxy {
    function executeHooksMessageHash(Call[] calldata calls, bytes32 nonce) external pure returns (bytes32) {
        return LibAuthenticatedHooks.executeHooksMessageHash(calls, nonce);
    }

    function hashToSign(Call[] calldata calls, bytes32 nonce, bytes32 domainSeparator)
        external
        pure
        returns (bytes32)
    {
        return LibAuthenticatedHooks.hashToSign(calls, nonce, domainSeparator);
    }

    function callsHash(Call[] calldata calls) external pure returns (bytes32) {
        return LibAuthenticatedHooks.callsHash(calls);
    }
}

contract LibAuthenticatedHooksTest is Test {
    CalldataProxy calldataProxy = new CalldataProxy();

    function testExecuteHooksHash() external view {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({ target: address(0), callData: hex"1223", value: 20, allowFailure: false });
        calls[1] = Call({ target: address(0), callData: hex"00112233", value: 200000000, allowFailure: false });

        bytes32 nonce = bytes32(uint256(1));
        bytes32 messageHash = calldataProxy.executeHooksMessageHash(calls, nonce);
        bytes32 domainSeparator = 0xee788037c7d4fa9c073bf2b8e7afce63bf881a78fcf90302e3f8cad15ca4af07;
        bytes32 hashToSign = calldataProxy.hashToSign(calls, nonce, domainSeparator);

        assertEq(messageHash, 0x0a78eaec6ae080d4d88364ab85a2b538fa9d13de20978359e50648eb35a936f0, "!messageHash");
        assertEq(hashToSign, 0xf5c0edcb586b37c8dfdbdf32b25ce7b151e5ba4ae2c67d42d15247b83352edb5, "!hashToSign");
    }

    function testCallHash() external pure {
        Call memory call1 = Call({ target: address(0), callData: hex"1223", value: 20, allowFailure: false });
        Call memory call2 = Call({ target: address(0), callData: hex"00112233", value: 200000000, allowFailure: false });

        assertEq(
            LibAuthenticatedHooks.callHash(call1),
            0x65ae2bbeaa5da85dd45f563d3feef6f9aea38138474bb748b142d193f1b6cace,
            "!callHash call1"
        );
        assertEq(
            LibAuthenticatedHooks.callHash(call2),
            0x8cd5bdd9f36a3fa11a240f1607a4de06fec37e2e8d581985e540a974b28b2d8d,
            "!callHash call2"
        );
    }

    function testCallsHash() external view {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({ target: address(0), callData: hex"1223", value: 20, allowFailure: false });
        calls[1] = Call({ target: address(0), callData: hex"00112233", value: 200000000, allowFailure: false });

        assertEq(
            calldataProxy.callsHash(calls),
            0xe6b3545d63155e33472ceaaf3bb7536ebe748edf721e23e430c9eb16c2893924,
            "!callsHash"
        );
    }
}
