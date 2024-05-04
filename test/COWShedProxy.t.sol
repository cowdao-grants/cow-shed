import { COWShedProxy, COWShed, Call, IMPLEMENTATION_STORAGE_SLOT, ADMIN_STORAGE_SLOT } from "src/COWShed.sol";
import { Test } from "forge-std/Test.sol";

contract COWShedProxyTest is Test {
    function testProxyInitialization() external {
        COWShed cowshed = new COWShed();

        // should not be able to use proxy before initialization
        COWShedProxy proxy = new COWShedProxy();
        assertAdminAndImpl(address(proxy), address(0), address(0));

        vm.expectRevert(COWShedProxy.InvalidInitialization.selector);
        COWShed(payable(address(proxy))).trustedExecuteHooks(new Call[](0));

        COWShed(payable(address(proxy))).initialize(address(cowshed), address(this), new Call[](0));
        assertAdminAndImpl(address(proxy), address(this), address(cowshed));

        address(proxy).call{ value: 1 ether }("");
    }

    function assertAdminAndImpl(address proxy, address expectedAdmin, address expectedImpl) internal {
        address actualAdmin = address(uint160(uint256(vm.load(proxy, ADMIN_STORAGE_SLOT))));
        address actualImpl = address(uint160(uint256(vm.load(proxy, IMPLEMENTATION_STORAGE_SLOT))));

        assertEq(actualAdmin, expectedAdmin, "!admin");
        assertEq(actualImpl, expectedImpl, "!impl");
    }
}
