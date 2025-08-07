// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {Call} from "src/LibAuthenticatedHooks.sol";
import {LibAuthenticatedHooksCalldataProxy} from "test/lib/LibAuthenticatedHooksCalldataProxy.sol";

// mostly testing the eip712 encoding, hashing, etc.
// it is differentially tested against the output of ethers' code for
// doing the same. See [./ts/testUtil.ts]
contract LibAuthenticatedHooksTest is Test {
    LibAuthenticatedHooksCalldataProxy cproxy = new LibAuthenticatedHooksCalldataProxy();

    function testExecuteHooksHash() external view {
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(0), callData: hex"1223", value: 20, allowFailure: false, isDelegateCall: false});
        calls[1] = Call({
            target: address(0),
            callData: hex"00112233",
            value: 200000000,
            allowFailure: false,
            isDelegateCall: false
        });

        bytes32 nonce = bytes32(uint256(1));
        uint256 deadline = 1714971380;
        bytes32 messageHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        bytes32 domainSeparator = 0xee788037c7d4fa9c073bf2b8e7afce63bf881a78fcf90302e3f8cad15ca4af07;
        bytes32 hashToSign = cproxy.hashToSign(calls, nonce, deadline, domainSeparator);

        assertEq(messageHash, 0xfdfaa629a4ccbc74f5c5e09411b43f43bf784226ea9bb2429b5590d1fb1dd61c, "!messageHash");
        assertEq(hashToSign, 0xe4425792fb560082f152a9507016920e2d06c299ed99e9735a9746af8ed2cca4, "!hashToSign");
    }

    function testCallHash() external view {
        Call memory call1 =
            Call({target: address(0), callData: hex"1223", value: 20, allowFailure: false, isDelegateCall: false});
        Call memory call2 = Call({
            target: address(0),
            callData: hex"00112233",
            value: 200000000,
            allowFailure: false,
            isDelegateCall: false
        });

        assertEq(
            cproxy.callHash(call1),
            0x6505d7fa293f4e4fb4490e893a91a8e38fab543fe3aa1bd49a27e37bf0780042,
            "!callHash call1"
        );
        assertEq(
            cproxy.callHash(call2),
            0x6dd53e776c087d4bf391dc9ae7b7b97e46d7596b38466bc5a515f1b595057d97,
            "!callHash call2"
        );
    }

    function testCallsHash() external view {
        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({target: address(0), callData: hex"1223", value: 20, allowFailure: false, isDelegateCall: false});
        calls[1] = Call({
            target: address(0),
            callData: hex"00112233",
            value: 200000000,
            allowFailure: false,
            isDelegateCall: false
        });

        assertEq(
            cproxy.callsHash(calls), 0xe65450745395eb2e3a3ffec0004f7ba31fdb304a65c1d7d4e443a59110c5e6f3, "!callsHash"
        );
    }

    function testDecodeEOASignature(bytes32 r, bytes32 s, uint8 v) external view {
        (bytes32 ar, bytes32 as_, uint8 av) = cproxy.decodeEOASignature(abi.encodePacked(r, s, v));
        assertEq(ar, r, "!r");
        assertEq(as_, s, "!s");
        assertEq(av, v, "!v");
    }
}
