import { Script } from "forge-std/Script.sol";
import { COWShedFactory, COWShed } from "src/COWShedFactory.sol";
import { LibString } from "solady/utils/LibString.sol";

contract DeployScript is Script {
    function run(string calldata baseEns) external {
        bytes32 bName = LibString.toSmallString(baseEns);
        bytes32 bNode = vm.ensNamehash(baseEns);

        vm.startBroadcast();
        COWShed cowshed = new COWShed();
        COWShedFactory factory = new COWShedFactory(address(cowshed), bName, bNode);
        bytes memory initCode = vm.getCode("src/COWShedProxy.sol:COWShedProxy");

        string memory addrJson = "deploymentAddresses.json";
        vm.serializeAddress(addrJson, "factory", address(factory));
        vm.serializeBytes(addrJson, "proxyInitCode", initCode);
        string memory serialized = vm.serializeAddress(addrJson, "implementation", address(cowshed));
        vm.writeJson(serialized, "deploymentAddresses.json");
    }
}
