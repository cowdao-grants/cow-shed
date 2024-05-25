import { Test, Vm } from "forge-std/Test.sol";
import { COWShed, Call } from "src/COWShed.sol";
import { LibAuthenticatedHooks } from "src/LibAuthenticatedHooks.sol";
import { COWShedFactory } from "src/COWShedFactory.sol";
import { IMPLEMENTATION_STORAGE_SLOT } from "src/COWShedStorage.sol";
import { ENS, INameResolver, IAddrResolver } from "src/ens.sol";
import { LibString } from "solady/utils/LibString.sol";

contract LibAuthenticatedHooksCalldataProxy {
    function executeHooksMessageHash(Call[] calldata calls, bytes32 nonce, uint256 deadline)
        external
        pure
        returns (bytes32)
    {
        return LibAuthenticatedHooks.executeHooksMessageHash(calls, nonce, deadline);
    }

    function hashToSign(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes32 domainSeparator)
        external
        pure
        returns (bytes32)
    {
        return LibAuthenticatedHooks.hashToSign(calls, nonce, deadline, domainSeparator);
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
    bytes32 baseName = "cowhooks.eth";
    bytes32 baseNode = vm.ensNamehash(LibString.fromSmallString(baseName));

    COWShedFactory factory;
    LibAuthenticatedHooksCalldataProxy cproxy = new LibAuthenticatedHooksCalldataProxy();

    address smartWalletAddr;
    SmartWallet smartWallet;
    address smartWalletProxyAddr;
    COWShed smartWalletProxy;

    function setUp() external virtual {
        uint256 nonce = vm.getNonce(address(this));
        address factoryAddressExpected = vm.computeCreateAddress(address(this), nonce);
        _setOwnerForEns(baseNode, address(factoryAddressExpected));
        factory = new COWShedFactory(address(cowshedImpl), baseName, baseNode);
        assertEq(address(factory), factoryAddressExpected, "factory address as not expected");

        user = vm.createWallet("user");
        userProxyAddr = factory.proxyOf(user.addr);
        userProxy = COWShed(payable(userProxyAddr));
        _initializeUserProxy(user);

        smartWallet = new SmartWallet(user.addr);
        smartWalletAddr = address(smartWallet);
        smartWalletProxyAddr = factory.proxyOf(smartWalletAddr);
        smartWalletProxy = COWShed(payable(smartWalletProxyAddr));
        _initializeSmartWalletProxy(smartWalletAddr);

        assertEq(
            _reverseResolve(0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045), "vitalik.eth", "reverse resolve impl failed"
        );
    }

    function _initializeUserProxy(Vm.Wallet memory _wallet) internal returns (bytes memory signature) {
        Call[] memory calls = new Call[](0);
        bytes32 nonce = "nonce1";
        address proxyAddress = factory.proxyOf(_wallet.addr);
        signature = _signForProxy(calls, nonce, _deadline(), _wallet);
        factory.executeHooks(calls, nonce, _deadline(), _wallet.addr, signature);
        assertGt(proxyAddress.code.length, 0, "user proxy didnt initialize as expected");
        assertImpl(proxyAddress, address(cowshedImpl));
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
        signature = _signWithSmartWalletForProxy(calls, nonce, _deadline(), smartWalletAddr, proxyAddress);
        factory.executeHooks(calls, nonce, _deadline(), _smartWallet, signature);
        assertGt(proxyAddress.code.length, 0, "user proxy didnt initialize as expected");
        assertImpl(proxyAddress, address(cowshedImpl));
    }

    function assertImpl(address proxy, address expectedImpl) internal view {
        address actualImpl = address(uint160(uint256(vm.load(proxy, IMPLEMENTATION_STORAGE_SLOT))));
        assertEq(actualImpl, expectedImpl, "!impl");
    }

    function _signForProxy(Call[] memory calls, bytes32 nonce, uint256 deadline, Vm.Wallet memory _wallet)
        internal
        view
        returns (bytes memory)
    {
        address proxy = factory.proxyOf(_wallet.addr);
        bytes32 domainSeparator = _proxyDomainSeparator(proxy);
        bytes32 digest = cproxy.hashToSign(calls, nonce, deadline, domainSeparator);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_wallet.privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signWithSmartWalletForProxy(
        Call[] memory calls,
        bytes32 nonce,
        uint256 deadline,
        address _smartWallet,
        address proxy
    ) internal returns (bytes memory) {
        bytes32 domainSeparator = _proxyDomainSeparator(proxy);
        bytes32 digest = cproxy.hashToSign(calls, nonce, deadline, domainSeparator);
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

    function _deadline() internal view returns (uint256) {
        return block.timestamp + 1 hours;
    }

    function _resolveAddr(bytes32 node) internal view returns (address) {
        return IAddrResolver(ENS.resolver(node)).addr(node);
    }

    function _reverseResolve(address addr) internal view returns (string memory) {
        bytes32 node =
            vm.ensNamehash(string(abi.encodePacked(LibString.toHexStringNoPrefix(addr), ".", "addr.reverse")));
        return INameResolver(ENS.resolver(node)).name(node);
    }

    function _recordOwnerSlotInEns(bytes32 node) internal pure returns (bytes32) {
        // records mapping is in slot 0
        // rest determined with https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#mappings-and-dynamic-arrays
        return keccak256(abi.encode(node, 0));
    }

    function _setOwnerForEns(bytes32 node, address owner) internal {
        vm.store(address(ENS), _recordOwnerSlotInEns(node), bytes32(uint256(uint160(address(owner)))));
        assertEq(ENS.owner(node), address(owner), "ens owner not set as expected");
    }
}
