import { COWShed, Call } from "src/COWShed.sol";
import { BaseTest } from "./BaseTest.sol";
import { IMPLEMENTATION_STORAGE_SLOT, ADMIN_STORAGE_SLOT } from "src/COWShedStorage.sol";
import { COWShedProxy } from "src/COWShedProxy.sol";

contract COWShedProxyTest is BaseTest {
    function testProxyInitialization() external {
        COWShed cowshed = new COWShed();

        // should not be able to use proxy before initialization
        COWShedProxy proxy = new COWShedProxy(address(cowshed), user.addr);
        assertAdminAndImpl(address(proxy), address(0), address(cowshed));

        vm.expectRevert(COWShedProxy.InvalidInitialization.selector);
        COWShed(payable(address(proxy))).trustedExecuteHooks(new Call[](0));

        COWShed(payable(address(proxy))).initialize(address(this), address(factory));
        assertAdminAndImpl(address(proxy), address(this), address(cowshed));

        // shouldnt initialize again
        vm.expectRevert(COWShed.AlreadyInitialized.selector);
        COWShed(payable(address(proxy))).initialize(address(this), address(factory));
    }
}
