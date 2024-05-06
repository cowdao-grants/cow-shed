import { COWShedProxy, COWShed } from "./COWShed.sol";
import { Call } from "./ICOWAuthHook.sol";

contract COWShedFactory {
    error InvalidSignature();
    error NonceAlreadyUsed();

    bytes32 public immutable initCodeHash;
    address public immutable implementation;

    constructor(address impl) payable {
        initCodeHash = keccak256(type(COWShedProxy).creationCode);
        implementation = impl;
    }

    function executeHooks(Call[] calldata calls, bytes32 nonce, address user, bytes calldata signature) external {
        address proxy = proxyOf(user);
        if (proxy.code.length == 0) {
            COWShedProxy newProxy = new COWShedProxy{ salt: bytes32(uint256(uint160(user))) }();
            COWShed(payable(address(newProxy))).initialize(implementation, user, address(this), calls);
        }
        COWShed(payable(proxy)).executeHooks(calls, nonce, signature);
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
}
