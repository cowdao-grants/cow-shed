import { Test, Vm } from "forge-std/Test.sol";
import { COWShed, Call, ADMIN_STORAGE_SLOT, IMPLEMENTATION_STORAGE_SLOT } from "src/COWShed.sol";
import { LibAuthenticatedHooks } from "src/LibAuthenticatedHooks.sol";
import { COWShedFactory } from "src/COWShedFactory.sol";

contract LibAuthenticatedHooksCalldataProxy {
    function executeHooksMessageHash(Call[] calldata calls, bytes32 nonce) external pure returns (bytes32) {
        return LibAuthenticatedHooks.executeHooksMessageHash(calls, nonce);
    }

    function hashToSign(Call[] calldata calls, bytes32 nonce, bytes32 domainSeparator)
        external
        pure
        returns (bytes32)
    {
        return LibAuthenticatedHooks.hashToSign(calls, nonce, domainSeparator);
    }

    function callsHash(Call[] calldata calls) external pure returns (bytes32) {
        return LibAuthenticatedHooks.callsHash(calls);
    }

    function callHash(Call calldata cll) external pure returns (bytes32) {
        return LibAuthenticatedHooks.callHash(cll);
    }
}

contract BaseTest is Test {
    Vm.Wallet user;
    address userProxyAddr;
    COWShed userProxy;
    COWShed cowshedImpl = new COWShed();
    COWShedFactory factory = new COWShedFactory(address(cowshedImpl));
    LibAuthenticatedHooksCalldataProxy cproxy = new LibAuthenticatedHooksCalldataProxy();

    function setUp() external {
        user = vm.createWallet("user");
        userProxyAddr = factory.proxyOf(user.addr);
        userProxy = COWShed(payable(userProxyAddr));
        _initializeUserProxy(user);
    }

    function _initializeUserProxy(Vm.Wallet memory _wallet) internal returns (bytes32 r, bytes32 s, uint8 v) {
        Call[] memory calls = new Call[](0);
        bytes32 nonce = "nonce1";
        bytes32 digest = cproxy.hashToSign(calls, nonce, factory.domainSeparator());
        (v, r, s) = vm.sign(_wallet.privateKey, digest);

        factory.executeHooks(calls, nonce, r, s, v);
        address proxyAddress = factory.proxyOf(_wallet.addr);
        assertGt(proxyAddress.code.length, 0, "user proxy didnt initialize as expected");
        assertAdminAndImpl(proxyAddress, _wallet.addr, address(cowshedImpl));
    }

    function assertAdminAndImpl(address proxy, address expectedAdmin, address expectedImpl) internal view {
        address actualAdmin = address(uint160(uint256(vm.load(proxy, ADMIN_STORAGE_SLOT))));
        address actualImpl = address(uint160(uint256(vm.load(proxy, IMPLEMENTATION_STORAGE_SLOT))));

        assertEq(actualAdmin, expectedAdmin, "!admin");
        assertEq(actualImpl, expectedImpl, "!impl");
    }

    function _signForFactory(Call[] memory calls, bytes32 nonce, Vm.Wallet memory _wallet)
        internal
        view
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        bytes32 digest = cproxy.hashToSign(calls, nonce, factory.domainSeparator());
        (v, r, s) = vm.sign(_wallet.privateKey, digest);
    }

    function _signForProxy(address proxy, Call[] memory calls, bytes32 nonce, Vm.Wallet memory _wallet)
        internal
        view
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        bytes32 domainSeparator = COWShed(payable(proxy)).domainSeparator();
        bytes32 digest = cproxy.hashToSign(calls, nonce, domainSeparator);
        (v, r, s) = vm.sign(_wallet.privateKey, digest);
    }
}
