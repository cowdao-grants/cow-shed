import { COWShed, COWShedProxy, Call } from "src/COWShed.sol";
import { Test, Vm } from "forge-std/Test.sol";
import { COWShedFactory } from "src/COWShedFactory.sol";
import { BaseTest } from "./BaseTest.sol";

contract Stub {
    error Revert();

    function willRevert() external pure {
        revert Revert();
    }

    function callWithValue() external payable { }

    function returnUint() external pure returns (uint256) {
        return 420;
    }
}

contract COWShedTest is BaseTest {
    Stub stub = new Stub();

    function testExecuteHooks() external {
        // fund the proxy
        vm.deal(userProxyAddr, 1 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(stub),
            value: 0.05 ether,
            allowFailure: false,
            callData: abi.encodeCall(stub.callWithValue, ())
        });
        calls[1] =
            Call({ target: address(stub), value: 0, allowFailure: true, callData: abi.encodeCall(stub.willRevert, ()) });
        bytes32 nonce = "1";

        bytes memory signature = _signForProxy(calls, nonce, user);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        factory.executeHooks(calls, nonce, user.addr, signature);

        // same sig shouldnt work more than once
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        factory.executeHooks(calls, nonce, user.addr, signature);

        assertEq(address(stub).balance, 0.05 ether, "didnt send value as expected");

        // test that allowFailure works as expected
        calls[1].allowFailure = false;
        nonce = "2";
        signature = _signForProxy(calls, nonce, user);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        vm.expectRevert(Stub.Revert.selector);
        userProxy.executeHooks(calls, nonce, signature);
    }

    function testRevokeNonce() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({ target: address(0), callData: hex"0011", value: 0, allowFailure: false });
        bytes32 nonce = "nonce-to-revoke";
        bytes memory signature = _signForProxy(calls, nonce, user);
        assertFalse(userProxy.nonces(nonce), "nonce is already used");

        vm.prank(user.addr);
        userProxy.revokeNonce(nonce);
        assertTrue(userProxy.nonces(nonce), "nonce is not used yet");

        vm.expectRevert(COWShed.NonceAlreadyUsed.selector);
        userProxy.executeHooks(calls, nonce, signature);
    }

    function testTrustedExecuteHooks() external {
        address addr = makeAddr("addr");
        assertFalse(COWShed(payable(userProxy)).trustedExecutor() == addr, "should not be a trusted executor");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(userProxy),
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (addr)),
            allowFailure: false,
            value: 0
        });
        bytes32 nonce = "1";
        bytes memory signature = _signForProxy(calls, nonce, user);
        userProxy.executeHooks(calls, nonce, signature);

        vm.prank(addr);
        vm.expectCall(address(0), hex"1234");
        calls[0].target = address(0);
        calls[0].callData = hex"1234";
        userProxy.trustedExecuteHooks(calls);
    }

    function testUpdateTrustedHook() external {
        address addr = makeAddr("addr");
        assertFalse(COWShed(payable(userProxy)).trustedExecutor() == addr, "should not be a trusted executor");

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(userProxy),
            callData: abi.encodeCall(COWShed.updateTrustedExecutor, (addr)),
            allowFailure: false,
            value: 0
        });
        bytes32 nonce = "1";
        bytes memory signature = _signForProxy(calls, nonce, user);
        userProxy.executeHooks(calls, nonce, signature);

        assertTrue(COWShed(payable(userProxy)).trustedExecutor() == addr, "should be a trusted executor");
    }

    function testUpdateImplementation() external {
        vm.prank(user.addr);
        userProxy.updateImplementation(address(stub));
        assertAdminAndImpl(userProxyAddr, user.addr, address(stub));
        assertEq(Stub(userProxyAddr).returnUint(), 420, "didnt update as expected");
    }

    function testExecuteHooksForSmartAccount() external {
        // fund the proxy
        vm.deal(smartWalletProxyAddr, 1 ether);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(stub),
            value: 0.05 ether,
            allowFailure: false,
            callData: abi.encodeCall(stub.callWithValue, ())
        });
        calls[1] =
            Call({ target: address(stub), value: 0, allowFailure: true, callData: abi.encodeCall(stub.willRevert, ()) });
        bytes32 nonce = "1";
        bytes memory sig = _signWithSmartWalletForProxy(calls, nonce, smartWalletAddr, smartWalletProxyAddr);
        vm.expectCall(address(stub), abi.encodeCall(stub.callWithValue, ()));
        vm.expectCall(address(stub), abi.encodeCall(stub.willRevert, ()));
        smartWalletProxy.executeHooks(calls, nonce, sig);

        // same sig shouldnt work more than once
        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        smartWalletProxy.executeHooks(calls, nonce, sig);

        assertEq(address(stub).balance, 0.05 ether, "didnt send value as expected");
    }
}
