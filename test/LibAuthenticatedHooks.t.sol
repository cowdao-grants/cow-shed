import { LibAuthenticatedHooks, Call } from "src/LibAuthenticatedHooks.sol";
import { Test } from "forge-std/Test.sol";
import { BaseTest } from "./BaseTest.sol";

contract LibAuthenticatedHooksTest is BaseTest {
    function setUp() external override { }

    function testExecuteHooksHash() external view {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({ target: address(0), callData: hex"1223", value: 20, allowFailure: false });
        calls[1] = Call({ target: address(0), callData: hex"00112233", value: 200000000, allowFailure: false });

        bytes32 nonce = bytes32(uint256(1));
        uint256 deadline = 1714971380;
        bytes32 messageHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        bytes32 domainSeparator = 0xee788037c7d4fa9c073bf2b8e7afce63bf881a78fcf90302e3f8cad15ca4af07;
        bytes32 hashToSign = cproxy.hashToSign(calls, nonce, deadline, domainSeparator);

        assertEq(messageHash, 0xdf2a2245607caac188878c5177f384415d6bbbdd7687d86979b89fc96c15fa2a, "!messageHash");
        assertEq(hashToSign, 0x6eaf52b8339dba7c32dd6f6e699c25188dbbd12f525121ef6477e96c1f072e1c, "!hashToSign");
    }

    function testCallHash() external view {
        Call memory call1 = Call({ target: address(0), callData: hex"1223", value: 20, allowFailure: false });
        Call memory call2 = Call({ target: address(0), callData: hex"00112233", value: 200000000, allowFailure: false });

        assertEq(
            cproxy.callHash(call1),
            0x65ae2bbeaa5da85dd45f563d3feef6f9aea38138474bb748b142d193f1b6cace,
            "!callHash call1"
        );
        assertEq(
            cproxy.callHash(call2),
            0x8cd5bdd9f36a3fa11a240f1607a4de06fec37e2e8d581985e540a974b28b2d8d,
            "!callHash call2"
        );
    }

    function testCallsHash() external view {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({ target: address(0), callData: hex"1223", value: 20, allowFailure: false });
        calls[1] = Call({ target: address(0), callData: hex"00112233", value: 200000000, allowFailure: false });

        assertEq(
            cproxy.callsHash(calls), 0xe6b3545d63155e33472ceaaf3bb7536ebe748edf721e23e430c9eb16c2893924, "!callsHash"
        );
    }

    function testDecodeEOASignature(bytes32 r, bytes32 s, uint8 v) external view {
        (bytes32 ar, bytes32 as_, uint8 av) = cproxy.decodeEOASignature(abi.encodePacked(r, s, v));
        assertEq(ar, r, "!r");
        assertEq(as_, s, "!s");
        assertEq(av, v, "!v");
    }
}
