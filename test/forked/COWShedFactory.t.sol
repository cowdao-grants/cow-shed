// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseForkedTest} from "./BaseForkedTest.sol";
import {Vm} from "forge-std/Test.sol";
import {LibString} from "solady/utils/LibString.sol";
import {COWShed} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {Call} from "src/LibAuthenticatedHooks.sol";
import {ENS} from "src/ens.sol";

contract ForkedCOWShedFactoryTest is BaseForkedTest {
    error ErrorSettingEns();

    function testExecuteHooksForRevertingEns() external {
        // revert setSubnodeRecord, but only for the factory's ens
        vm.mockCallRevert(
            address(ENS),
            abi.encodePacked(ENS.setSubnodeRecord.selector, LibString.toSmallString(baseEns)),
            abi.encodePacked(ErrorSettingEns.selector)
        );

        Vm.Wallet memory wallet = vm.createWallet("testWallet");
        address addr1 = makeAddr("addr1");
        address addr2 = makeAddr("addr2");

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: addr1, value: 0, callData: hex"00112233", allowFailure: false, isDelegateCall: false});
        calls[1] = Call({target: addr2, value: 0, callData: hex"11", allowFailure: false, isDelegateCall: false});

        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        bytes32 nonce = "nonce";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), wallet);
        vm.expectCall(addr1, calls[0].callData);
        vm.expectCall(addr2, calls[1].callData);
        factory.executeHooks(calls, nonce, _deadline(), wallet.addr, signature);
        assertGt(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is still empty");
    }

    function testForwardResolve() external {
        factory.initializeEns(user.addr);
        _assertForwardResolve(user.addr, userProxyAddr);
    }

    function testReverseResolve() external {
        factory.initializeEns(user.addr);
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

    function resolveAddr(address userAddr) external view returns (address) {
        return _resolveAddr(vm.ensNamehash(string(abi.encodePacked(LibString.toHexString(userAddr), ".", baseEns))));
    }

    function _assertForwardResolve(address userAddr, address expectedResolution) internal view {
        assertEq(
            _resolveAddr(vm.ensNamehash(string(abi.encodePacked(LibString.toHexString(userAddr), ".", baseEns)))),
            expectedResolution,
            "forward resolution for lower case address failed"
        );
        assertEq(
            _resolveAddr(
                vm.ensNamehash(string(abi.encodePacked(LibString.toHexStringChecksummed(userAddr), ".", baseEns)))
            ),
            expectedResolution,
            "forward resolution for checksummed address failed"
        );
    }

    function _assertReverseResolve(address userAddr, address proxyAddr) internal view {
        assertEq(
            _reverseResolve(proxyAddr),
            string(abi.encodePacked(LibString.toHexStringChecksummed(userAddr), ".", baseEns)),
            "reverse resolution failed"
        );
    }
}
