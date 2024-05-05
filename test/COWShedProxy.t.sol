import { COWShedProxy, COWShed, Call, IMPLEMENTATION_STORAGE_SLOT, ADMIN_STORAGE_SLOT } from "src/COWShed.sol";
import { BaseTest } from "./BaseTest.sol";

contract COWShedProxyTest is BaseTest {
    function testProxyInitialization() external {
        COWShed cowshed = new COWShed();

        // should not be able to use proxy before initialization
        COWShedProxy proxy = new COWShedProxy();
        assertAdminAndImpl(address(proxy), address(0), address(0));

        vm.expectRevert(COWShedProxy.InvalidInitialization.selector);
        COWShed(payable(address(proxy))).domainSeparator();

        COWShed(payable(address(proxy))).initialize(address(cowshed), address(this), new Call[](0));
        assertAdminAndImpl(address(proxy), address(this), address(cowshed));

        // shouldnt initialize again
        vm.expectRevert(COWShed.AlreadyInitialized.selector);
        COWShed(payable(address(proxy))).initialize(address(cowshed), address(this), new Call[](0));
    }
}
