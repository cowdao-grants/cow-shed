// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseTest} from "./BaseTest.sol";
import {COWShed, COWShedStorage, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {COWShedProxy} from "src/COWShedProxy.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";
import {Stub} from "test/lib/Stub.sol";

contract COWShedTest is BaseTest {
    Stub stub;
    Call callWithValue;
    Call callWillRevert;

    function setUp() public override {
        super.setUp();
        stub = new Stub();

        callWithValue = Call({
            target: address(stub),
            value: 0.05 ether,
            allowFailure: false,
            callData: abi.encodeCall(stub.callWithValue, ()),
            isDelegateCall: false
        });

        callWillRevert = Call({
            target: address(stub),
            value: 0,
            allowFailure: true,
            callData: abi.encodeCall(stub.willRevert, ()),
            isDelegateCall: false
        });
    }

    function testExecuteHooks() external {
        // fund the proxy
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = callWithValue;
        calls[1] = callWillRevert;

        bytes32 nonce = "1";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        factory.executeHooks(calls, nonce, _deadline(), user.addr, signature);

        // same signature shouldn't work more than once
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        factory.executeHooks(calls, nonce, _deadline(), user.addr, signature);

        assertEq(address(stub).balance, 0.05 ether, "didnt send value as expected");

        // test that allowFailure works as expected
        calls[1].allowFailure = false;
        nonce = "2";
        signature = _signForProxy(calls, nonce, _deadline(), user);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        vm.expectRevert(Stub.Revert.selector);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);
    }

    function testExecuteHooks_revertsOnInvalidEcdsaSignature() external {
        Call[] memory calls = new Call[](0);
        bytes32 nonce = "1337";
        uint256 deadline = _deadline();
        bytes memory signature = _signForProxy(calls, nonce, deadline, user);

        // Corrupt signature, to force `ECDSA.recover()` to return the wrong address
        unchecked {
            // Unchecked: overflowing is intended behavior.
            signature[0] = bytes1(uint8(signature[0]) + 1);
        }

        vm.expectRevert(LibAuthenticatedHooks.InvalidSignature.selector);
        userProxy.executeHooks(calls, nonce, deadline, signature);
    }

    function testExecuteHooksDeadline() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0), value: 0, allowFailure: false, callData: hex"0011", isDelegateCall: false});
        bytes32 nonce = "deadline-nonce";
        uint256 deadline = block.timestamp - 1;
        bytes memory signature = _signForProxy(calls, nonce, deadline, user);
        vm.expectRevert(LibAuthenticatedHooks.DeadlineElapsed.selector);
        userProxy.executeHooks(calls, nonce, deadline, signature);
    }

    function testExecuteHooksDelegateCall() external {
        bytes32 randomSlot = keccak256("randomSlot");
        bytes32 randomValue = keccak256("randomValue");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(stub),
            callData: abi.encodeCall(Stub.storeAt, (randomSlot, randomValue)),
            value: 0,
            allowFailure: false,
            isDelegateCall: true
        });
        bytes32 nonce = "delegatecall-nonce";
        uint256 deadline = _deadline();

        bytes32 prev = vm.load(userProxyAddr, randomSlot);
        assertEq(prev, bytes32(0), "randomSlot is already set");

        bytes memory signature = _signForProxy(calls, nonce, deadline, user);
        userProxy.executeHooks(calls, nonce, deadline, signature);

        bytes32 aftr = vm.load(userProxyAddr, randomSlot);
        assertEq(aftr, randomValue, "randomSlot not set as expected from the delegatecall");
    }

    function testRevokeNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0), callData: hex"0011", value: 0, allowFailure: false, isDelegateCall: false});
        bytes32 nonce = "nonce-to-revoke";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        assertFalse(userProxy.nonces(nonce), "nonce is already used");

        vm.prank(user.addr);
        userProxy.revokeNonce(nonce);
        assertTrue(userProxy.nonces(nonce), "nonce is not used yet");

        vm.expectRevert(COWShedStorage.NonceAlreadyUsed.selector);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);
    }

    function testUpdateTrustedHook() external {
        address addr = makeAddr("addr");
        assertFalse(COWShed(payable(userProxy)).trustedExecutor() == addr, "should not be a trusted executor");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(userProxy),
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (addr)),
            allowFailure: false,
            value: 0,
            isDelegateCall: false
        });
        bytes32 nonce = "1";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);

        assertTrue(COWShed(payable(userProxy)).trustedExecutor() == addr, "should be a trusted executor");
    }

    function testTrustedExecuteHooks_executeCallsFromNewTrustedExecutor() external {
        // GIVEN: an address that is not the trusted executor
        address addr = makeAddr("addr");
        COWShed cowShed = COWShed(payable(userProxy));
        address trustedExecutor = cowShed.trustedExecutor();
        assertNotEq(trustedExecutor, addr, "should not be a trusted executor");

        // GIVEN: the address is not the admin neither
        vm.prank(address(userProxy));
        address admin = COWShedProxy(payable(userProxy)).admin();
        assertFalse(admin == addr, "should not be the admin");

        // GIVEN: the admin is not the trusted executor
        assertNotEq(admin, trustedExecutor, "trustedExecutor should not be the admin");

        // GIVEN: the address becomes the trusted executor
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(userProxy),
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (addr)),
            allowFailure: false,
            value: 0,
            isDelegateCall: false
        });
        bytes32 nonce = "1";
        bytes memory signature = _signForProxy(calls, nonce, _deadline(), user);
        userProxy.executeHooks(calls, nonce, _deadline(), signature);

        // WHEN: this new trusted executor executes a call
        // THEN: the call is executed
        vm.prank(addr);
        vm.expectCall(address(0), hex"1234");
        calls[0].target = address(0);
        calls[0].callData = hex"1234";
        userProxy.trustedExecuteHooks(calls);
    }

    function testTrustedExecuteHooks_trustedExecutorSuccess() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;

        // WHEN: the trusted executor executes a call
        // THEN: the call is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        vm.prank(COWShed(payable(userProxy)).trustedExecutor());
        userProxy.trustedExecuteHooks(calls);

        // THEN: the proxy sent 0.05 ether to the stub
        assertEq(callWithValue.target.balance, 0.05 ether, "didnt send value as expected");
        assertEq(address(userProxy).balance, 0.95 ether, "didnt send value as expected");
    }

    function testTrustedExecuteHooks_adminSuccess() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;

        // WHEN: the admin executes a call
        // THEN: the call is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        vm.prank(user.addr);
        userProxy.trustedExecuteHooks(calls);

        // THEN: the proxy sent 0.05 ether to the stub
        assertEq(callWithValue.target.balance, 0.05 ether, "didnt send value as expected");
        assertEq(address(userProxy).balance, 0.95 ether, "didnt send value as expected");
    }

    function testTrustedExecuteHooks_neitherAdminNorTrustedExecutorError() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;

        // WHEN: someone other than the trusted executor or the admin executes a call
        // THEN: the call should revert
        vm.expectRevert(COWShed.OnlyTrustedRole.selector);
        address neitherAdminNorTrustedExecutor = makeAddr("neitherAdminNorTrustedExecutor");
        vm.prank(neitherAdminNorTrustedExecutor);
        userProxy.trustedExecuteHooks(calls);
    }

    function testUpdateImplementation() external {
        vm.prank(user.addr);
        userProxy.updateImplementation(address(stub));
        assertImpl(userProxyAddr, address(stub));
        assertEq(Stub(userProxyAddr).returnUint(), 420, "didnt update as expected");
    }

    function testExecuteHooksForSmartAccount() external {
        // fund the proxy
        vm.deal(smartWalletProxyAddr, 1 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = callWithValue;
        calls[1] = callWillRevert;
        bytes32 nonce = "1";
        bytes memory sig =
            _signWithSmartWalletForProxy(calls, nonce, _deadline(), smartWalletAddr, smartWalletProxyAddr);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        smartWalletProxy.executeHooks(calls, nonce, _deadline(), sig);

        // same sig shouldn't work more than once
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        smartWalletProxy.executeHooks(calls, nonce, _deadline(), sig);

        assertEq(address(stub).balance, 0.05 ether, "didnt send value as expected");
    }

    function testExecuteHooks_revertsForInvalidSmartAccountSignature() external {
        Call[] memory calls = new Call[](0);
        bytes32 nonce = "1337";
        bytes memory sig = "invalid";
        vm.expectRevert(COWShed.InvalidSignature.selector);
        smartWalletProxy.executeHooks(calls, nonce, _deadline(), sig);
    }

    function testIsPreSignedHook() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed a hook
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is pre-signed
        assertTrue(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHookUnsigned() external view {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed a hook
        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHookRevoked() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user had a hook signed, and then revoked it
        _presignForProxy(calls, nonce, deadline, true, user);
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreUnsignedForDifferentNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce1 = "1";
        bytes32 nonce2 = "2";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls, nonce1, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the nonce
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce2, deadline), "hook is pre-signed");
    }

    function testIsPreSignedRevokeUnsigned() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook
        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreUnsignedForDifferentDeadline() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the deadline
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline + 1), "hook is pre-signed");
    }

    function testIsPreUnsignedForDifferentCalls() external {
        Call[] memory calls1 = new Call[](1);
        calls1[0] = callWithValue;

        Call[] memory calls2 = new Call[](1);
        calls2[0] = callWillRevert;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls1, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the calls
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls2, nonce, deadline), "hook is pre-signed");
    }

    function testPreSignFlowSuccess() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook to send ether to the stub
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // THEN: the proxy sent ether to the stub
        assertEq(callWithValue.target.balance, callWithValue.value, "didn't send value as expected");
        assertEq(address(userProxy).balance, 1 ether - callWithValue.value, "didn't send value as expected");
    }

    function testPreSignFlowUnsigned() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook

        // WHEN: pre-sign the hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testPreSignFlowRevoke() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testPreSignFlowRevokeUnsigned() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed hook

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testPreSignFlowRevertsOnSecondExecution() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: A user executes has already executed a pre-signed hook
        _presignForProxy(calls, nonce, deadline, true, user);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // WHEN: execute the pre-signed hook
        // THEN: reverts with NonceAlreadyUsed
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }
}
