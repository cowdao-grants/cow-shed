// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Stub} from "../lib/Stub.sol";
import {BaseForkedTest} from "./BaseForkedTest.sol";
import {COWShed, COWShedStorage, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";

contract ForkedCOWShedPreSignTest is BaseForkedTest {
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

    function testPreSignStorage_uninitializeReturnZero() external view {
        // GIVEN: user never set the pre-sign storage

        // WHEN: checking the pre-sign storage
        // THEN: returns the zero-address
        assertEq(userProxy.preSignStorage(), address(0));
    }

    function testPreSignStorage_initializedReturnValue() external {
        // GIVEN: user initialized the storage
        address storageAddress = makeAddr("mockStorage");
        _setPreSignStorage(storageAddress, user);

        // WHEN: checking the pre-sign storage
        // THEN: returns the address we set
        assertEq(userProxy.preSignStorage(), storageAddress);
    }

    function testPreSignStorage_replacedAddressReturnsValue() external {
        // GIVEN: user initialized the storage
        address storageAddress1 = makeAddr("storageAddress1");
        _setPreSignStorage(storageAddress1, user);

        // GIVEN: user replaces it to a new storage
        address storageAddress2 = makeAddr("storageAddress2");
        _setPreSignStorage(storageAddress2, user);

        // WHEN: checking the pre-sign storage
        // THEN: returns the latest storage the user set
        assertEq(userProxy.preSignStorage(), storageAddress2);
    }

    function testInitializePreSignStorage_uninitialized() external {
        // GIVEN: user never initialized the pre-sign storage

        // WHEN: initializing the pre-sign storage
        vm.prank(user.addr);
        userProxy.initializePreSignStorage();

        // THEN: the pre-sign storage has been initialized
        address storageAddress = userProxy.preSignStorage();
        assertNotEq(storageAddress, address(0));
        assertTrue(storageAddress.code.length > 0);
    }

    function testInitializePreSignStorage_alreadyInitialized() external {
        // GIVEN: user never initialized the pre-sign storage
        _initializePreSignStorage(user);
        address storageAddressOld = userProxy.preSignStorage();

        // WHEN: initializing the pre-sign storage again
        vm.prank(user.addr);
        userProxy.initializePreSignStorage();

        // THEN: the pre-sign storage has been re-assigned to a new contract
        address storageAddressNew = userProxy.preSignStorage();
        assertNotEq(storageAddressNew, storageAddressOld);
        assertNotEq(storageAddressNew, address(0));
        assertTrue(storageAddressNew.code.length > 0);
    }

    function testSetPreSignStorage_setZeroAddress() external {
        // GIVEN: user never set the pre-sign storage

        // WHEN: setting the pre-sign storage to zero
        vm.prank(user.addr);
        userProxy.setPreSignStorage(address(0));

        // THEN: returns the zero-address
        assertEq(userProxy.preSignStorage(), address(0));
    }

    function testSetPreSignStorage_setNonZeroAddress() external {
        // GIVEN: user never set the pre-sign storage

        // WHEN: setting the pre-sign storage to zero
        address storageAddress = makeAddr("storageAddress");
        vm.prank(user.addr);
        userProxy.setPreSignStorage(storageAddress);

        // THEN: returns the storageAddress
        assertEq(userProxy.preSignStorage(), storageAddress);
    }

    function testSetPreSignStorage_setZeroAddressToInitializedStorage() external {
        // GIVEN: user had set the pre-sign storage
        address storageAddress = makeAddr("storageAddress");
        _setPreSignStorage(storageAddress, user);

        // WHEN: setting the pre-sign storage to zero
        vm.prank(user.addr);
        userProxy.setPreSignStorage(address(0));

        // THEN: returns the zero-address
        assertEq(userProxy.preSignStorage(), address(0));
    }

    function testPreSignHooks_initializedStorage() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user initialized the pre-sign storage
        _initializePreSignStorage(user);

        // WHEN: execute pre-signed the hook
        vm.prank(user.addr);
        userProxy.preSignHooks(calls, nonce, deadline, true);

        // THEN: the hook is pre-signed
        assertTrue(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testPreSignHooks_storageNotSet_presign() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user never set the pre-sign storage

        // WHEN: pre-sign a hook from the admin account
        // THEN: reverts with PreSignStorageNotSet
        vm.expectRevert(COWShedStorage.PreSignStorageNotSet.selector);
        vm.prank(user.addr);
        userProxy.preSignHooks(calls, nonce, deadline, true);
    }

    function testPreSignHooks_storageNotSet_revoke() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user never set the pre-sign storage

        // WHEN: revoking the pre-sign of a hook from the admin account
        // THEN: reverts with PreSignStorageNotSet
        vm.expectRevert(COWShedStorage.PreSignStorageNotSet.selector);
        vm.prank(user.addr);
        userProxy.preSignHooks(calls, nonce, deadline, false);
    }

    function testSetPreSignStorage_replaceAddress() external {
        // GIVEN: user had set the pre-sign storage
        address storageAddressOld = makeAddr("storageAddressOld");
        _setPreSignStorage(storageAddressOld, user);

        // WHEN: setting the pre-sign storage to a new address
        address storageAddressNew = makeAddr("storageAddressNew");
        vm.prank(user.addr);
        userProxy.setPreSignStorage(storageAddressNew);

        // THEN: returns the new address
        assertEq(userProxy.preSignStorage(), storageAddressNew);
    }

    function testIsPreSignedHooks_storageNotSetReturnsFalse() external view {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user never set the pre-sign storage

        // WHEN: check if the hook is pre-signed
        // THEN: returns false
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHooks_signed() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed a hook
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is pre-signed
        assertTrue(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHooks_unsigned() external view {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed a hook
        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_revoked() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user had a hook signed, and then revoked it
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce1 = "1";
        bytes32 nonce2 = "2";

        // GIVEN: user has pre-signed the hook
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce1, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the nonce
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce2, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_revokeUnsigned() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook
        _initializePreSignStorage(user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentDeadline() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the deadline
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline + 1), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentCalls() external {
        Call[] memory calls1 = new Call[](1);
        calls1[0] = callWithValue;

        Call[] memory calls2 = new Call[](1);
        calls2[0] = callWillRevert;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _initializePreSignStorage(user);
        _presignForProxy(calls1, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the calls
        // THEN: the hook is not pre-signed
        assertFalse(userProxy.isPreSignedHooks(calls2, nonce, deadline), "hook is pre-signed");
    }

    function testExecutePreSignedHooks_success() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook to send ether to the stub
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        vm.expectCall(callWithValue.target, callWithValue.callData);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // THEN: the proxy sent ether to the stub
        assertEq(callWithValue.target.balance, callWithValue.value, "didn't send value as expected");
        assertEq(address(userProxy).balance, 1 ether - callWithValue.value, "didn't send value as expected");
    }

    function testExecutePreSignedHooks_unsignedReverts() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook
        _initializePreSignStorage(user);

        // WHEN: pre-sign the hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revokedPreSignReverts() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revokedUnsignedReverts() external {
        // GIVEN: user has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed hook
        _initializePreSignStorage(user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsOnSecondExecution() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: A user executes has already executed a pre-signed hook
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // WHEN: execute the pre-signed hook
        // THEN: reverts with NonceAlreadyUsed
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsAfterSetPreSignStorageToZero() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: they set the pre-sign storage to zero
        _setPreSignStorage(address(0), user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is not pre-signed anymore
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsAfterReinitializePreSignStorage() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed hook to send ether to the stub
        _initializePreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: they re-initialized the pre-sign storage
        _initializePreSignStorage(user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }
}
