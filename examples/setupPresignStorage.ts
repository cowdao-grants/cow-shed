import { ethers } from "ethers";
import {
  COWShed__factory,
  PreSignStateStorage__factory,
  PreSignStateStorageFactory__factory,
} from "../ts";

// Example script showing how to set up presign storage for a COWShed
async function setupPresignStorage() {
  // This is an example - you would need to provide actual addresses and signer
  const signer = new ethers.Wallet("your-private-key");
  const provider = new ethers.JsonRpcProvider("your-rpc-url");

  // Get your COWShed contract address first
  const cowShedAddress = "your-cowshed-address";

  // Deploy the factory
  const factory = new PreSignStateStorageFactory__factory(signer);
  const factoryContract = await factory.deploy();
  await factoryContract.waitForDeployment();

  // Deploy a storage contract for your COWShed
  const storageContract = await factoryContract.deployPreSignStateStorage(
    cowShedAddress
  );
  await storageContract.waitForDeployment();

  // Get your COWShed contract
  const cowShed = COWShed__factory.connect(cowShedAddress, signer);

  // Set the presign storage contract
  const tx = await cowShed.setPreSignStorage(
    await storageContract.getAddress()
  );
  await tx.wait();

  console.log("Presign storage setup complete!");
  console.log("Storage contract:", await storageContract.getAddress());
  console.log("COWShed presign storage:", await cowShed.preSignStorage());
}

// Example of how to clear presigned hashes in emergency
async function clearPresignedHashes() {
  const signer = new ethers.Wallet("your-private-key");
  const cowShedAddress = "your-cowshed-address";

  const cowShed = COWShed__factory.connect(cowShedAddress, signer);

  // Deploy a new storage contract
  const factory = new PreSignStateStorageFactory__factory(signer);
  const newStorageContract = await factory.deployPreSignStateStorage(
    cowShedAddress
  );
  await newStorageContract.waitForDeployment();

  // Update the COWShed to use the new storage contract
  const tx = await cowShed.setPreSignStorage(
    await newStorageContract.getAddress()
  );
  await tx.wait();

  console.log("All presigned hashes cleared by replacing storage contract!");
  console.log("New storage contract:", await newStorageContract.getAddress());
}

// Example of how to presign hooks
async function presignHooks() {
  const signer = new ethers.Wallet("your-private-key");
  const cowShedAddress = "your-cowshed-address";

  const cowShed = COWShed__factory.connect(cowShedAddress, signer);

  // Example calls to presign
  const calls = [
    {
      target: "0x...", // target contract
      value: 0,
      callData: "0x...", // encoded function call
      allowFailure: false,
      isDelegateCall: false,
    },
  ];

  const nonce = ethers.randomBytes(32);
  const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

  // Presign the hooks
  const tx = await cowShed.preSignHooks(calls, nonce, deadline, true);
  await tx.wait();

  console.log("Hooks presigned successfully!");
  console.log("Nonce:", nonce);
  console.log("Deadline:", deadline);
}

export { setupPresignStorage, clearPresignedHashes, presignHooks };
