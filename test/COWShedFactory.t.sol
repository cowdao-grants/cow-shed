// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShedFactory} from "src/COWShedFactory.sol";
import {Vm, Test} from "forge-std/Test.sol";
import {LibAuthenticatedHooks, Call} from "src/LibAuthenticatedHooks.sol";
import {COWShed} from "src/COWShed.sol";
import {BaseTest} from "./BaseTest.sol";
import {LibString} from "solady/utils/LibString.sol";
import {ENS} from "src/ens.sol";

contract COWShedFactoryTest is BaseTest {
    error ErrorSettingEns();

    Vm.Wallet wallet = vm.createWallet("testWallet");

    function testDeploymentFailsIfImplementationHasNoCode() external {
        address emptyImplementation = makeAddr("empty COWShed");
        assertEq(emptyImplementation.code, hex"");
        vm.expectRevert(COWShedFactory.NoCodeAtImplementation.selector);
        new COWShedFactory(emptyImplementation, baseName, baseNode);
    }

    function testExecuteHooks() external {
        // GIVEN: a proxy for the user hasn't been initialized
        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        // WHEN: Execute the signed hooks
        bytes32 nonce = "nonce";
        Call[] memory calls = _getCalls();
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), wallet);
        vm.expectCall(calls[0].target, calls[0].callData);
        vm.expectCall(calls[1].target, calls[1].callData);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);

        // THEN: The proxy is initialized
        assertGt(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is still empty");
    }

    function testExecuteHooksNonceAlreadyUsed() external {
        // WHEN: Given a pre-initialized proxy, with a consumed nonce
        bytes32 nonce = "nonce";
        Call[] memory calls = _getCalls();
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), wallet);
        vm.expectCall(calls[0].target, calls[0].callData);
        vm.expectCall(calls[1].target, calls[1].callData);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);

        // WHEN: We try to execute the same hooks again
        // THEN: It should revert
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);
    }

    function testSignHooksSuccess() external {
        // GIVEN: A wallet that hasn't initialized a proxy
        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        // WHEN: We sign the hooks
        Call[] memory calls = _getCalls();
        factory.signHooks(calls, _deadline(), true, wallet.addr);

        // THEN: The proxy is initialized
        assertGt(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is still empty");

        // THEN: The proxy should have the hooks pre-signed
        userProxy.executePreSignedHooks(calls, _deadline());
        vm.expectCall(calls[0].target, calls[0].callData);
        vm.expectCall(calls[1].target, calls[1].callData);
    }

    function testSignHooksNotAdmin() external {
        // GIVEN: A wallet that hasn't initialized a proxy
        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        // WHEN: We sign the hooks as a non-admin
        // THEN: It should revert
        Call[] memory calls = _getCalls();
        vm.expectRevert(COWShed.OnlyAdmin.selector);
        address notAdmin = makeAddr("notAdmin");
        vm.prank(notAdmin);
        factory.signHooks(calls, _deadline(), true, wallet.addr);

        // THEN: The proxy should not be initialized
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        // THEN: The proxy should not have the hooks pre-signed
        vm.expectRevert(COWShed.NonceNotPreApproved.selector);
        userProxy.executePreSignedHooks(calls, _deadline());
    }

    function testExecuteHooksForRevertingEns() external {
        // revert setSubnodeRecord, but only for the factory's ens
        vm.mockCallRevert(
            address(ENS),
            abi.encodePacked(ENS.setSubnodeRecord.selector, baseNode),
            abi.encodePacked(ErrorSettingEns.selector)
        );

        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        bytes32 nonce = "nonce";
        Call[] memory calls = _getCalls();
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), wallet);
        vm.expectCall(calls[0].target, calls[0].callData);
        vm.expectCall(calls[1].target, calls[1].callData);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);
        assertGt(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is still empty");
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
        _assertForwardResolve(user.addr, userProxyAddr);
    }

    function testReverseResolve() external view {
        _assertReverseResolve(user.addr, userProxyAddr);
    }

    function testInitializeProxyWithEns() external {
        address userAddr = makeAddr("user1");
        address proxyAddr = factory.proxyOf(userAddr);
        assertEq(proxyAddr.code.length, 0, "proxy is already initialized");
        factory.initializeProxy(userAddr, true);
        _assertForwardResolve(userAddr, proxyAddr);
        _assertReverseResolve(userAddr, proxyAddr);
        assertGt(proxyAddr.code.length, 0, "proxy is still not initialized");
    }

    function testInitializeProxyWithoutEns() external {
        address userAddr = makeAddr("user1");
        address proxyAddr = factory.proxyOf(userAddr);
        assertEq(proxyAddr.code.length, 0, "proxy is already initialized");
        factory.initializeProxy(userAddr, false);
        try this.resolveAddr(userAddr) {
            revert("resolution didnt fail");
        } catch (bytes memory) {}
        assertGt(proxyAddr.code.length, 0, "proxy is still not initialized");
    }

    function resolveAddr(address userAddr) external view returns (address) {
        return _resolveAddr(
            vm.ensNamehash(
                string(abi.encodePacked(LibString.toHexString(userAddr), ".", LibString.fromSmallString(baseName)))
            )
        );
    }

    function _assertForwardResolve(address userAddr, address expectedResolution) internal view {
        assertEq(
            _resolveAddr(
                vm.ensNamehash(
                    string(abi.encodePacked(LibString.toHexString(userAddr), ".", LibString.fromSmallString(baseName)))
                )
            ),
            expectedResolution,
            "forward resolution for lower case address failed"
        );
        assertEq(
            _resolveAddr(
                vm.ensNamehash(
                    string(
                        abi.encodePacked(
                            LibString.toHexStringChecksummed(userAddr), ".", LibString.fromSmallString(baseName)
                        )
                    )
                )
            ),
            expectedResolution,
            "forward resolution for checksummed address failed"
        );
    }

    function _assertReverseResolve(address userAddr, address proxyAddr) internal view {
        assertEq(
            _reverseResolve(proxyAddr),
            string(
                abi.encodePacked(LibString.toHexStringChecksummed(userAddr), ".", LibString.fromSmallString(baseName))
            ),
            "reverse resolution failed"
        );
    }

    function _getCalls() internal returns (Call[] memory) {
        address addr1 = makeAddr("addr1");
        address addr2 = makeAddr("addr2");

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: addr1, value: 0, callData: hex"00112233", allowFailure: false, isDelegateCall: false});
        calls[1] = Call({target: addr2, value: 0, callData: hex"11", allowFailure: false, isDelegateCall: false});

        return calls;
    }
}
