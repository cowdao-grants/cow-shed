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

        address proxyAddress = factory.proxyOf(_wallet.addr);
        signature = _signForProxy(calls, nonce, _wallet);
        factory.executeHooks(calls, nonce, _wallet.addr, signature);
        assertGt(proxyAddress.code.length, 0, "user proxy didnt initialize as expected");
        assertAdminAndImpl(proxyAddress, _wallet.addr, address(cowshedImpl));
        assertEq(
            COWShed(payable(proxyAddress)).domainSeparator(),
            _computeDomainSeparatorForProxy(proxyAddress),
            "computed domain separator is incorrect"
        );
    }

    function _initializeSmartWalletProxy(address _smartWallet) internal returns (bytes memory signature) {
        Call[] memory calls = new Call[](0);
        bytes32 nonce = "nonce1";
        address proxyAddress = factory.proxyOf(_smartWallet);
        signature = _signWithSmartWalletForProxy(calls, nonce, smartWalletAddr, proxyAddress);
        factory.executeHooks(calls, nonce, _smartWallet, signature);
        assertGt(proxyAddress.code.length, 0, "user proxy didnt initialize as expected");
        assertAdminAndImpl(proxyAddress, _smartWallet, address(cowshedImpl));
    }

    function assertAdminAndImpl(address proxy, address expectedAdmin, address expectedImpl) internal view {
        address actualAdmin = address(uint160(uint256(vm.load(proxy, ADMIN_STORAGE_SLOT))));
        address actualImpl = address(uint160(uint256(vm.load(proxy, IMPLEMENTATION_STORAGE_SLOT))));

        assertEq(actualAdmin, expectedAdmin, "!admin");
        assertEq(actualImpl, expectedImpl, "!impl");
    }

    function _signForProxy(Call[] memory calls, bytes32 nonce, Vm.Wallet memory _wallet)
        internal
        view
        returns (bytes memory)
    {
        address proxy = factory.proxyOf(_wallet.addr);
        bytes32 domainSeparator = _proxyDomainSeparator(proxy);
        bytes32 digest = cproxy.hashToSign(calls, nonce, domainSeparator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_wallet.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signWithSmartWalletForProxy(Call[] memory calls, bytes32 nonce, address _smartWallet, address proxy)
        internal
        returns (bytes memory)
    {
        bytes32 domainSeparator = _proxyDomainSeparator(proxy);
        bytes32 digest = cproxy.hashToSign(calls, nonce, domainSeparator);
        bytes memory sig = abi.encode(digest);
        vm.prank(SmartWallet(_smartWallet).owner());
        SmartWallet(_smartWallet).sign(digest, sig);
        return sig;
    }

    function _computeDomainSeparatorForProxy(address proxy) internal view returns (bytes32) {
        bytes32 domainTypeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        string memory name = "COWShed";
        string memory version = "1.0.0";
        uint256 chainId = block.chainid;
        address verifyingContract = proxy;
        return keccak256(
            abi.encode(domainTypeHash, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract)
        );
    }

    function _proxyDomainSeparator(address proxy) internal view returns (bytes32 domainSeparator) {
        if (proxy.code.length > 0) {
            domainSeparator = COWShed(payable(proxy)).domainSeparator();
        } else {
            domainSeparator = _computeDomainSeparatorForProxy(proxy);
        }
    }
}
