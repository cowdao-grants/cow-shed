// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseTest} from "./BaseTest.sol";
import {COWShed, COWShedStorage, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {IPreSignStorage} from "src/IPreSignStorage.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";
import {LibAuthenticatedHooksCalldataProxy} from "test/lib/LibAuthenticatedHooksCalldataProxy.sol";
import {Stub} from "test/lib/Stub.sol";

event PreSignStorageChanged(address indexed newStorage);

contract ForkedCOWShedPreSignTest is BaseTest {
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
        assertPreSignStorageEq(userProxy.preSignStorage(), EMPTY_PRE_SIGN_STORAGE);
    }

    function testPreSignStorage_initializedReturnValue() external {
        // GIVEN: user initialized the storage
        IPreSignStorage presignStorage = IPreSignStorage(makeAddr("mockStorage"));
        _setPreSignStorage(presignStorage, user);

        // WHEN: checking the pre-sign storage
        // THEN: returns the address we set
        assertPreSignStorageEq(userProxy.preSignStorage(), presignStorage);
    }

    function testPreSignStorage_replacedAddressReturnsValue() external {
        // GIVEN: user initialized the storage
        _setPreSignStorage(IPreSignStorage(makeAddr("storage1")), user);

        // GIVEN: user replaces it to a new storage
        IPreSignStorage newStorage = IPreSignStorage(makeAddr("storage2"));
        _setPreSignStorage(newStorage, user);

        // WHEN: checking the pre-sign storage
        // THEN: returns the latest storage the user set
        assertPreSignStorageEq(userProxy.preSignStorage(), newStorage);
    }

    function testResetPreSignStorage_unauthorized() external {
        // GIVEN: a user that is not the admin
        address notAdmin = makeAddr("notAdmin");

        // WHEN: resetting the pre-sign storage from a non-admin address
        // THEN: reverts with OnlyAdmin
        vm.expectRevert(COWShed.OnlyAdmin.selector);
        vm.prank(notAdmin);
        userProxy.resetPreSignStorage();
    }

    function testResetPreSignStorage_uninitialized() external {
        // GIVEN: user never initialized the pre-sign storage

        // WHEN: initializing the pre-sign storage
        // THEN: An event with the zero-address is emitted
        vm.prank(user.addr);
        IPreSignStorage storageReturned = userProxy.resetPreSignStorage();

        // THEN: the pre-sign storage has been initialized to a new contract
        assertNotEq(address(storageReturned), address(EMPTY_PRE_SIGN_STORAGE));
        assertTrue(address(storageReturned).code.length > 0);

        // THEN: the contract matches the one returned in the reset function
        IPreSignStorage storageGetter = userProxy.preSignStorage();
        assertPreSignStorageEq(storageGetter, storageReturned);
    }

    function testResetPreSignStorage_alreadyInitialized() external {
        // GIVEN: user never initialized the pre-sign storage
        IPreSignStorage storageOld = _resetPreSignStorage(user);

        // WHEN: initializing the pre-sign storage again
        vm.prank(user.addr);
        IPreSignStorage storageReturned = userProxy.resetPreSignStorage();

        // THEN: the storage changed
        assertNotEq(address(storageOld), address(storageReturned));

        // THEN: The storage is not the empty pre-sign storage
        assertNotEq(address(storageReturned), address(EMPTY_PRE_SIGN_STORAGE));

        // THEN: the pre-sign storage matches the one returned in the reset function
        IPreSignStorage storageAddressNew = userProxy.preSignStorage();
        assertPreSignStorageEq(storageAddressNew, storageReturned);
    }

    function testResetPreSignStorage_emitsEvent() external {
        // GIVEN: user never initialized the pre-sign storage

        // WHEN: initializing the pre-sign storage
        // THEN: An event with the newly deployed contract is emitted
        uint256 nonce = vm.getNonce(address(userProxy));
        address expectedStorageAddress = vm.computeCreateAddress(address(userProxy), nonce);
        vm.prank(user.addr);
        vm.expectEmit(address(userProxy));
        emit PreSignStorageChanged(expectedStorageAddress);
        userProxy.resetPreSignStorage();
    }

    function testSetPreSignStorage_unauthorized() external {
        // GIVEN: a user that is not the admin
        address notAdmin = makeAddr("notAdmin");

        // WHEN: setting the pre-sign storage for a non-admin address
        // THEN: reverts with OnlyAdmin
        vm.expectRevert(COWShed.OnlyAdmin.selector);
        vm.prank(notAdmin);
        userProxy.setPreSignStorage(EMPTY_PRE_SIGN_STORAGE);
    }

    function testSetPreSignStorage_setZeroAddress() external {
        // GIVEN: user never set the pre-sign storage

        // WHEN: setting the pre-sign storage to zero
        // THEN: An event with the zero-address is emitted
        vm.prank(user.addr);
        vm.expectEmit(address(userProxy));
        emit PreSignStorageChanged(address(EMPTY_PRE_SIGN_STORAGE));
        IPreSignStorage storageReturned = userProxy.setPreSignStorage(EMPTY_PRE_SIGN_STORAGE);

        // THEN: the returned storage is the zero-address
        assertPreSignStorageEq(storageReturned, EMPTY_PRE_SIGN_STORAGE);

        // THEN: the current storage is also the zero-address
        assertPreSignStorageEq(userProxy.preSignStorage(), EMPTY_PRE_SIGN_STORAGE);
    }

    function testSetPreSignStorage_setNonZeroAddress() external {
        // GIVEN: user never set the pre-sign storage

        // WHEN: setting the pre-sign storage to some address
        // THEN: An event with the pre-sign storage address is emitted
        IPreSignStorage presignStorage = IPreSignStorage(makeAddr("presignStorage"));
        vm.prank(user.addr);
        vm.expectEmit(address(userProxy));
        emit PreSignStorageChanged(address(presignStorage));
        IPreSignStorage storageReturned = userProxy.setPreSignStorage(presignStorage);

        // THEN: returns the presignStorage
        assertPreSignStorageEq(storageReturned, presignStorage);
        assertPreSignStorageEq(userProxy.preSignStorage(), presignStorage);
    }

    function testSetPreSignStorage_setZeroAddressToInitializedStorage() external {
        // GIVEN: user had set the pre-sign storage
        _setPreSignStorage(IPreSignStorage(makeAddr("storageAddress")), user);

        // WHEN: setting the pre-sign storage to zero
        // THEN: An event with the zero-address is emitted
        vm.prank(user.addr);
        vm.expectEmit(address(userProxy));
        emit PreSignStorageChanged(address(EMPTY_PRE_SIGN_STORAGE));
        IPreSignStorage storageReturned = userProxy.setPreSignStorage(EMPTY_PRE_SIGN_STORAGE);

        // THEN: returns the zero-address
        assertPreSignStorageEq(storageReturned, EMPTY_PRE_SIGN_STORAGE);
        assertPreSignStorageEq(userProxy.preSignStorage(), EMPTY_PRE_SIGN_STORAGE);
    }

    function testPreSignHooks_unauthorized() external {
        // GIVEN: a user that is not the admin
        address notAdmin = makeAddr("notAdmin");

        // WHEN: pre-signing a hook from a non-admin address
        // THEN: reverts with OnlyAdmin
        vm.expectRevert(COWShed.OnlyAdmin.selector);
        vm.prank(notAdmin);
        userProxy.preSignHooks(new Call[](0), "1", _deadline(), true);
    }

    function testPreSignHooks_initializedStorage() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user initialized the pre-sign storage
        IPreSignStorage presignStorage = _resetPreSignStorage(user);

        // WHEN: execute pre-signed the hook
        // THEN: A call to the storage is made
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage),
            abi.encodeWithSelector(IPreSignStorage.setPreSigned.selector, expectedHash, true),
            1
        );
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
        IPreSignStorage storageAddressOld = IPreSignStorage(makeAddr("storageAddressOld"));
        _setPreSignStorage(storageAddressOld, user);

        // WHEN: setting the pre-sign storage to a new address
        // THEN: An event with the new storage address is emitted
        IPreSignStorage storageAddressNew = IPreSignStorage(makeAddr("storageAddressNew"));
        vm.prank(user.addr);
        vm.expectEmit(address(userProxy));
        emit PreSignStorageChanged(address(storageAddressNew));
        userProxy.setPreSignStorage(storageAddressNew);

        // THEN: returns the new address
        assertPreSignStorageEq(userProxy.preSignStorage(), storageAddressNew);
    }

    function testIsPreSignedHooks_storageNotSetReturnsFalse() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";
        IPreSignStorage presignStorage = userProxy.preSignStorage();

        // GIVEN: user never set the pre-sign storage

        // WHEN: check if the hook is pre-signed
        // THEN: no call is done to the zero address
        // THEN: isPreSignedHooks returns false
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage),
            abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash),
            0 // no calls expected
        );
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHooks_signed() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed a hook
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed
        // THEN: a call to the storage is made
        // THEN: the hook is pre-signed
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
        assertTrue(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is not pre-signed");
    }

    function testIsPreSignedHooks_unsigned() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";
        IPreSignStorage presignStorage = userProxy.preSignStorage();

        // GIVEN: user has not pre-signed a hook
        // WHEN: check if the hook is pre-signed
        // THEN: no call is made to the pre-sign storage
        // THEN: the hook is not pre-signed
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage),
            abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash),
            0 // Expect no calls
        );
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_revoked() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user had a hook signed, and then revoked it
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: a call is made to the pre-sign storage
        // THEN: the hook is not pre-signed
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce1 = "1";
        bytes32 nonce2 = "2";

        // GIVEN: user has pre-signed the hook
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce1, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the nonce
        // THEN: the hook is not pre-signed
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce2, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
        assertFalse(userProxy.isPreSignedHooks(calls, nonce2, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_revokeUnsigned() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has not pre-signed the hook
        IPreSignStorage presignStorage = _resetPreSignStorage(user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: check if the hook is pre-signed
        // THEN: the hook is not pre-signed
        // THEN: a call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, deadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentDeadline() external {
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the deadline
        // THEN: the hook is not pre-signed
        // THEN: a call is made to the pre-sign storage
        uint256 newDeadline = deadline + 1;
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, newDeadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
        assertFalse(userProxy.isPreSignedHooks(calls, nonce, newDeadline), "hook is pre-signed");
    }

    function testIsPreSignedHooks_signedForDifferentCalls() external {
        Call[] memory calls1 = new Call[](1);
        calls1[0] = callWithValue;

        Call[] memory calls2 = new Call[](1);
        calls2[0] = callWillRevert;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed the hook
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls1, nonce, deadline, true, user);

        // WHEN: check if the hook is pre-signed if we change the calls
        // THEN: the hook is not pre-signed
        // THEN: a call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls2, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
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
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        // THEN: a call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
        vm.expectCall(callWithValue.target, callWithValue.value, callWithValue.callData);
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
        IPreSignStorage presignStorage = _resetPreSignStorage(user);

        // WHEN: pre-sign the hook
        // THEN: the call should revert
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
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
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        // THEN: a call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
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
        IPreSignStorage presignStorage = _resetPreSignStorage(user);

        // GIVEN: the user revokes the pre-signed hook
        _presignForProxy(calls, nonce, deadline, false, user);

        // WHEN: execute the pre-signed hook
        // THEN: the call should revert
        // THEN: a call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
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

        // GIVEN: A user has already executed a pre-signed hook
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);
        userProxy.executePreSignedHooks(calls, nonce, deadline);

        // WHEN: execute the pre-signed hook
        // THEN: reverts with NonceAlreadyUsed
        // THEN: a call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
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
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: they set the pre-sign storage to zero
        _setPreSignStorage(EMPTY_PRE_SIGN_STORAGE, user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is not pre-signed anymore
        // THEN: No call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(EMPTY_PRE_SIGN_STORAGE),
            abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash),
            0
        );
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsAfterReresetPreSignStorage() external {
        // GIVEN: shed has 1 ether
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 deadline = _deadline();
        bytes32 nonce = "1";

        // GIVEN: user has pre-signed a hook
        _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, deadline, true, user);

        // GIVEN: they re-initialized the pre-sign storage
        IPreSignStorage presignStorage = _resetPreSignStorage(user);

        // WHEN: execute the pre-signed hook
        // THEN: the hook is executed
        // THEN: a call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, deadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 1
        );
        vm.expectRevert(COWShed.NotPreSigned.selector);
        userProxy.executePreSignedHooks(calls, nonce, deadline);
    }

    function testExecutePreSignedHooks_revertsAfterHookExpires() external {
        // GIVEN: a hook with an expired deadline
        Call[] memory calls = new Call[](1);
        calls[0] = callWithValue;
        uint256 expiredDeadline = block.timestamp - 1; // expired deadline
        bytes32 nonce = "1";

        // GIVEN: user pre-signs the expired hook
        IPreSignStorage presignStorage = _resetPreSignStorage(user);
        _presignForProxy(calls, nonce, expiredDeadline, true, user);

        // WHEN: execute the pre-signed hook
        // THEN: It reverts because the hook has expired
        // THEN: no call is made to the pre-sign storage
        bytes32 expectedHash = cproxy.executeHooksMessageHash(calls, nonce, expiredDeadline);
        vm.expectCall(
            address(presignStorage), abi.encodeWithSelector(IPreSignStorage.isPreSigned.selector, expectedHash), 0
        );
        vm.expectRevert(LibAuthenticatedHooks.DeadlineElapsed.selector);
        userProxy.executePreSignedHooks(calls, nonce, expiredDeadline);
    }
}
