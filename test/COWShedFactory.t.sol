import { COWShedFactory } from "src/COWShedFactory.sol";
import { Vm, Test } from "forge-std/Test.sol";
import { LibAuthenticatedHooks, Call } from "src/LibAuthenticatedHooks.sol";
import { CalldataProxy } from "./LibAuthenticatedHooks.t.sol";
import { ADMIN_STORAGE_SLOT, COWShed } from "src/COWShed.sol";

contract COWShedFactoryTest is Test {
    CalldataProxy cproxy = new CalldataProxy();
    COWShed cowshed = new COWShed();
    COWShedFactory factory = new COWShedFactory(address(cowshed));

    function testExecuteHooks() external {
        Vm.Wallet memory wallet = vm.createWallet("testWallet");
        address addr1 = makeAddr("addr1");
        address addr2 = makeAddr("addr2");

        Call[] memory calls = new Call[](2);
        calls[0] = Call({ target: addr1, value: 0, callData: hex"00112233", allowFailure: false });

        calls[1] = Call({ target: addr2, value: 0, callData: hex"11", allowFailure: false });

        bytes32 nonce = "nonce";
        bytes32 hash = cproxy.hashToSign(calls, nonce, factory.domainSeparator());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet, hash);

        address expectedProxyAddress = factory.proxyOf(wallet.addr);
        assertEq(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is not empty");

        vm.expectCall(addr1, calls[0].callData);
        vm.expectCall(addr2, calls[1].callData);
        factory.executeHooks(calls, nonce, r, s, v);
        assertGt(expectedProxyAddress.code.length, 0, "expectedProxyAddress code is still empty");

        assertEq(
            address(uint160(uint256(vm.load(expectedProxyAddress, ADMIN_STORAGE_SLOT)))),
            wallet.addr,
            "proxy admin not as expected"
        );

        vm.expectRevert(COWShedFactory.NonceAlreadyUsed.selector);
        factory.executeHooks(calls, nonce, r, s, v);
    }
}
