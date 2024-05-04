import { COWShedProxy, COWShed } from "./COWShed.sol";
import { Call } from "./ICOWAuthHook.sol";
import { LibAuthenticatedHooks } from "./LibAuthenticatedHooks.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

contract COWShedFactory is EIP712 {
    error InvalidSignature();
    error NonceAlreadyUsed();
    error Bug();

    bytes32 public immutable initCodeHash;
    address public immutable implementation;

    mapping(address => mapping(bytes32 => bool)) nonces;

    constructor(address impl) payable {
        initCodeHash = keccak256(type(COWShedProxy).creationCode);
        implementation = impl;
    }

    function executeHooks(Call[] calldata calls, bytes32 nonce, bytes32 r, bytes32 s, uint8 v) external {
        (bool authorized, address recovered) =
            LibAuthenticatedHooks.authenticateHooks(calls, nonce, r, s, v, _domainSeparator());
        if (!authorized) {
            revert InvalidSignature();
        }

        if (nonces[recovered][nonce]) {
            revert NonceAlreadyUsed();
        }
        nonces[recovered][nonce] = true;

        address proxy = proxyOf(recovered);
        if (proxy.code.length == 0) {
            COWShedProxy newProxy = new COWShedProxy{ salt: bytes32(uint256(uint160(recovered))) }();
            COWShed(payable(address(newProxy))).initialize(implementation, recovered, calls);
        } else {
            COWShed(payable(proxy)).trustedExecuteHooks(calls);
        }
    }

    function proxyOf(address who) public view returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(hex"ff", address(this), bytes32(uint256(uint160(who))), initCodeHash))
                )
            )
        );
    }

    function domainSeparator() public view returns (bytes32) {
        return _domainSeparator();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "COWShedFactory";
        version = "1.0.0";
    }
}
