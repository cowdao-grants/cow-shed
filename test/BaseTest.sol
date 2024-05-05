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

    function decodeEOASignature(bytes calldata signature) external pure returns (bytes32 r, bytes32 s, uint8 v) {
        return LibAuthenticatedHooks.decodeEOASignature(signature);
    }
}

contract SmartWallet {
    error OnlyOwner();

    address public immutable owner;
    mapping(bytes32 => bytes) signatures;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert OnlyOwner();
        }
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    function sign(bytes32 hash, bytes calldata signature) external onlyOwner {
        signatures[hash] = signature;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return (keccak256(signature) == keccak256(signatures[hash]) && signatures[hash].length > 0)
            ? LibAuthenticatedHooks.MAGIC_VALUE_1271
            : bytes4(0);
    }
}

contract BaseTest is Test {
    Vm.Wallet user;
    address userProxyAddr;
    COWShed userProxy;
    COWShed cowshedImpl = new COWShed();
    COWShedFactory factory = new COWShedFactory(address(cowshedImpl));
    LibAuthenticatedHooksCalldataProxy cproxy = new LibAuthenticatedHooksCalldataProxy();

    address smartWalletAddr;
    SmartWallet smartWallet;
    address smartWalletProxyAddr;
    COWShed smartWalletProxy;

    function setUp() external virtual {
        user = vm.createWallet("user");
        userProxyAddr = factory.proxyOf(user.addr);
        userProxy = COWShed(payable(userProxyAddr));
        _initializeUserProxy(user);

        smartWallet = new SmartWallet(user.addr);
        smartWalletAddr = address(smartWallet);
        smartWalletProxyAddr = factory.proxyOf(smartWalletAddr);
        smartWalletProxy = COWShed(payable(smartWalletProxyAddr));
        _initializeSmartWalletProxy(smartWalletAddr);
    }

    function _initializeUserProxy(Vm.Wallet memory _wallet) internal returns (bytes memory signature) {
        Call[] memory calls = new Call[](0);
        bytes32 nonce = "nonce1";
        bytes32 digest = cproxy.hashToSign(calls, nonce, factory.domainSeparator());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_wallet.privateKey, digest);
        signature = abi.encodePacked(r, s, v);

        factory.executeHooks(calls, nonce, _wallet.addr, signature);
        address proxyAddress = factory.proxyOf(_wallet.addr);
        assertGt(proxyAddress.code.length, 0, "user proxy didnt initialize as expected");
        assertAdminAndImpl(proxyAddress, _wallet.addr, address(cowshedImpl));
    }

    function _initializeSmartWalletProxy(address _smartWallet) internal returns (bytes memory signature) {
        Call[] memory calls = new Call[](0);
        bytes32 nonce = "nonce1";
        signature = _signWithSmartWalletForFactory(calls, nonce, smartWalletAddr);
        factory.executeHooks(calls, nonce, _smartWallet, signature);
        address proxyAddress = factory.proxyOf(_smartWallet);
        assertGt(proxyAddress.code.length, 0, "user proxy didnt initialize as expected");
        assertAdminAndImpl(proxyAddress, _smartWallet, address(cowshedImpl));
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
        returns (bytes memory)
    {
        bytes32 digest = cproxy.hashToSign(calls, nonce, factory.domainSeparator());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_wallet.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signForProxy(address proxy, Call[] memory calls, bytes32 nonce, Vm.Wallet memory _wallet)
        internal
        view
        returns (bytes memory)
    {
        bytes32 domainSeparator = COWShed(payable(proxy)).domainSeparator();
        bytes32 digest = cproxy.hashToSign(calls, nonce, domainSeparator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_wallet.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signWithSmartWalletForFactory(Call[] memory calls, bytes32 nonce, address _smartWallet)
        internal
        returns (bytes memory)
    {
        bytes32 digest = cproxy.hashToSign(calls, nonce, factory.domainSeparator());
        vm.prank(SmartWallet(_smartWallet).owner());
        bytes memory sig = abi.encode(digest);
        SmartWallet(_smartWallet).sign(digest, sig);
        return sig;
    }

    function _signWithSmartWalletForProxy(Call[] memory calls, bytes32 nonce, address _smartWallet, address proxy)
        internal
        returns (bytes memory)
    {
        bytes32 domainSeparator = COWShed(payable(proxy)).domainSeparator();
        bytes32 digest = cproxy.hashToSign(calls, nonce, domainSeparator);
        bytes memory sig = abi.encode(digest);
        vm.prank(SmartWallet(_smartWallet).owner());
        SmartWallet(_smartWallet).sign(digest, sig);
        return sig;
    }
}
