// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

import {DeployScript} from "script/Deploy.s.sol";
import {COWShed, COWShedFactory, COWShedProxy} from "src/COWShedFactory.sol";
import {PreSignStateStorage} from "src/PreSignStateStorage.sol";

contract COWShedFactoryTest is Test {
    string constant baseEns = "testcowhooks.eth";
    COWShed shed;
    COWShedFactory factory;

    function setUp() external {
        DeployScript s = new DeployScript();
        DeployScript.Deployment memory deployment = s.deploy(baseEns);
        shed = deployment.cowShed;
        factory = deployment.factory;
    }

    function testExposesExpectedCreationCode() external view {
        assertEq(factory.PROXY_CREATION_CODE(), type(COWShedProxy).creationCode);
    }

    function testDeploysExpectedProxyWithNoEns() external {
        address user = makeAddr("proxy owner");
        address expected = factory.proxyOf(user);
        assertEq(address(expected).code.length, 0);
        factory.initializeProxy(user, false);
        assertGt(address(expected).code.length, 0);
    }

    function testDeployPreSignStateStorage_success() external {
        // GIVEN: A valid COWShed address
        address cowShed = makeAddr("cowShed");

        // WHEN: Deploying a PreSignStateStorage contract for the COWShed
        address storageContract = factory.deployPreSignStateStorage(cowShed);

        // THEN: The contract should be deployed and have the correct cowShed address
        assertGt(storageContract.code.length, 0);
        PreSignStateStorage storageInstance = PreSignStateStorage(storageContract);
        assertEq(storageInstance.cowShed(), cowShed);
    }

    function testDeployPreSignStateStorage_redeploy() external {
        // GIVEN: A valid COWShed address
        address cowShed = makeAddr("cowShed");

        // GIVEN: A PreSignStateStorage contract already deployed
        address storageContract1 = factory.deployPreSignStateStorage(cowShed);

        // WHEN: Deploying a PreSignStateStorage contract for the second time
        address storageContract2 = factory.deployPreSignStateStorage(cowShed);

        // THEN: The contract should be deployed and have the correct cowShed address
        assertGt(storageContract2.code.length, 0);
        PreSignStateStorage storageInstance = PreSignStateStorage(storageContract2);
        assertEq(storageInstance.cowShed(), cowShed);

        // THEN: The redeployment address should be different from the first deployment
        assertNotEq(storageContract1, storageContract2);
    }

    function testDeployPreSignStateStorageForUser_success() external {
        // GIVEN: A test user address
        address user = makeAddr("user");

        // WHEN: Deploying a PreSignStateStorage contract for the user
        address storageContract = factory.deployPreSignStateStorageForUser(user);

        // THEN: The contract should be deployed and point to the user's proxy
        assertGt(storageContract.code.length, 0);
        address userProxy = factory.proxyOf(user);
        PreSignStateStorage storageInstance = PreSignStateStorage(storageContract);
        assertEq(storageInstance.cowShed(), userProxy);
    }

    function testDeployPreSignStateStorageForUser_redeploy() external {
        // GIVEN: A test user address
        address user = makeAddr("user");

        // GIVEN: A PreSignStateStorage contract already deployed
        address storageContract1 = factory.deployPreSignStateStorageForUser(user);

        // WHEN: Deploying a PreSignStateStorage contract for the second time
        address storageContract2 = factory.deployPreSignStateStorageForUser(user);

        // THEN: The contract should be deployed and point to the user's proxy
        assertGt(storageContract2.code.length, 0);
        address userProxy = factory.proxyOf(user);
        PreSignStateStorage storageInstance = PreSignStateStorage(storageContract2);
        assertEq(storageInstance.cowShed(), userProxy);

        // THEN: The redeployment address should be different from the first deployment
        assertNotEq(storageContract1, storageContract2);
    }

    function testMultiplePreSignStateStorageDeployments() external {
        // GIVEN: Two different users
        address user1 = makeAddr("user1");
        address user2 = makeAddr("user2");

        // WHEN: Deploying storage contracts for different users
        address storage1 = factory.deployPreSignStateStorageForUser(user1);
        address storage2 = factory.deployPreSignStateStorageForUser(user2);

        // THEN: Different contracts should be deployed pointing to correct proxies
        assertTrue(storage1 != storage2);
        PreSignStateStorage storageInstance1 = PreSignStateStorage(storage1);
        PreSignStateStorage storageInstance2 = PreSignStateStorage(storage2);
        assertEq(storageInstance1.cowShed(), factory.proxyOf(user1));
        assertEq(storageInstance2.cowShed(), factory.proxyOf(user2));
    }
}
