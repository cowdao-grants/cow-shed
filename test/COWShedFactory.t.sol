// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import { COWShedFactory } from "src/COWShedFactory.sol";
import { Vm, Test } from "forge-std/Test.sol";
import { LibAuthenticatedHooks, Call } from "src/LibAuthenticatedHooks.sol";
import { COWShed } from "src/COWShed.sol";
import { BaseTest } from "./BaseTest.sol";
import { LibString } from "solady/utils/LibString.sol";

contract COWShedFactoryTest is BaseTest {
    function testExecuteHooks() external {
        Vm.Wallet memory wallet = vm.createWallet("testWallet");
        address addr1 = makeAddr("addr1");
        address addr2 = makeAddr("addr2");

        Call[] memory calls = new Call[](2);
        calls[0] =
            Call({ target: addr1, value: 0, callData: hex"00112233", allowFailure: false, isDelegateCall: false });

        calls[1] = Call({ target: addr2, value: 0, callData: hex"11", allowFailure: false, isDelegateCall: false });

        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        bytes32 nonce = "nonce";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), wallet);
        vm.expectCall(addr1, calls[0].callData);
        vm.expectCall(addr2, calls[1].callData);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);
        assertGt(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is still empty");

        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);
    }

    function testDomainSeparators() external {
        Vm.Wallet memory user1 = vm.createWallet("user1");
        Vm.Wallet memory user2 = vm.createWallet("user2");

        _initializeUserProxy(user1);
        _initializeUserProxy(user2);

        COWShed proxy1 = COWShed(payable(factory.proxyOf(user1.addr)));
        COWShed proxy2 = COWShed(payable(factory.proxyOf(user2.addr)));

        vm.label(address(proxy1), "proxy1");
        vm.label(address(proxy2), "proxy2");

        assertTrue(
            proxy1.domainSeparator() != proxy2.domainSeparator(),
            "different proxies should have different domain separators"
        );
    }

    function testForwardResolve() external view {
        assertEq(
            _resolveAddr(
                vm.ensNamehash(
                    string(abi.encodePacked(LibString.toHexString(user.addr), ".", LibString.fromSmallString(baseName)))
                )
            ),
            userProxyAddr
        );
        assertEq(
            _resolveAddr(
                vm.ensNamehash(
                    string(
                        abi.encodePacked(
                            LibString.toHexStringChecksummed(user.addr), ".", LibString.fromSmallString(baseName)
                        )
                    )
                )
            ),
            userProxyAddr
        );
    }

    function testReverseResolve() external view {
        assertEq(
            _reverseResolve(userProxyAddr),
            string(
                abi.encodePacked(LibString.toHexStringChecksummed(user.addr), ".", LibString.fromSmallString(baseName))
            )
        );
    }
}
