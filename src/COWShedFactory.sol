import { COWShed } from "./COWShed.sol";
import { Call } from "./ICOWAuthHook.sol";
import { COWShedProxy } from "./COWShedProxy.sol";

contract COWShedFactory {
    error InvalidSignature();
    error NonceAlreadyUsed();

    event COWShedBuilt(address user, address shed);

    address public immutable implementation;

    constructor(address impl) payable {
        implementation = impl;
    }

    function executeHooks(
        Call[] calldata calls,
        bytes32 nonce,
        uint256 deadline,
        address user,
        bytes calldata signature
    ) external {
        address proxy = proxyOf(user);
        if (proxy.code.length == 0) {
            COWShedProxy newProxy = new COWShedProxy{ salt: bytes32(uint256(uint160(user))) }(implementation, user);
            COWShed(payable(proxy)).initialize(user, address(this));
            emit COWShedBuilt(user, address(newProxy));
        }
        COWShed(payable(proxy)).executeHooks(calls, nonce, deadline, signature);
    }

    function proxyOf(address who) public view returns (address) {
        // unfortunately cannot cache the init hash since we use a constructor, which we need to use
        // to have an immutable admin variable in proxy, which is optimal for gas vs using a storage
        // variable in proxy.
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(type(COWShedProxy).creationCode, abi.encode(implementation, who)));
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(hex"ff", address(this), bytes32(uint256(uint160(who))), initCodeHash))
                )
            )
        );
    }
}
