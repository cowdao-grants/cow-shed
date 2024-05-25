import { createAnvil } from '@viem/anvil';
import { join } from 'path';
import fs from 'fs';
import { ethers } from 'ethers_v6';
import { exec } from 'child_process';
import {
  Order,
  OrderBalance,
  OrderKind,
  SigningScheme,
  computeOrderUid,
} from '@cowprotocol/contracts';
import { MetadataApi, v1_1_0 } from '@cowprotocol/app-data';
import { settlementAbi } from './abi';

const getEnv = (env: string, def?: string) => {
  const val = process.env[env];
  if (!val) {
    if (!def) throw new Error(`Environment var not set: ${env}`);
    return def;
  }
  return val;
};

// spawn anvil instance
const setupAnvil = async () => {
  const homeDir = getEnv('HOME');
  const defaultAnvilPath = join(homeDir, '.foundry', 'bin', 'anvil');
  const exists = fs.existsSync(defaultAnvilPath);
  if (!exists) throw new Error('anvil not found');

  const forkUrl = getEnv('FORK_URL');
  const forkBlockNumber = getEnv('FORK_BLOCK_NUMBER', 'latest');

  const anvil = createAnvil({
    anvilBinary: defaultAnvilPath,
    forkUrl: forkUrl,
    forkBlockNumber:
      forkBlockNumber === 'latest' ? undefined : +forkBlockNumber,
    autoImpersonate: true,
  });
  return anvil;
};

const toHex = (num: bigint) => `0x${num.toString(16)}`;

// sets balance for given address in the anvil instance
const setBalance = (
  provider: ethers.JsonRpcProvider,
  address: string,
  balance: bigint
) => {
  return provider.send('anvil_setBalance', [address, toHex(balance)]);
};

// deploys the cowshed contracts and also impersonates ownership of the cowhooks.eth
// to the factory contract. After deployment it reads the deployed addresses and init
// code from the deploymentAddresses.json file that the script writes to
const deployCowShed = async (provider: ethers.JsonRpcProvider, key: string) => {
  const homeDir = getEnv('HOME');
  const forgePath = join(homeDir, '.foundry', 'bin', 'forge');
  const parentDir = join(__dirname, '..');
  const ensName = 'cowhooks.eth';

  const execPromise = new Promise((resolve, reject) => {
    exec(
      `${forgePath} script ./script/Deploy.s.sol:DeployScript --sig "run(string)" ${ensName} --broadcast --rpc-url ${provider._getConnection().url
      } --private-key ${key}`,
      { cwd: parentDir },
      (error) => {
        if (error) reject(error);
        else resolve(undefined);
      }
    );
  });
  await execPromise;

  const deploymentAddressesPath = join(parentDir, 'deploymentAddresses.json');
  const addresses: {
    factory: string;
    implementation: string;
    proxyInitCode: string;
  } = JSON.parse(
    await fs.promises.readFile(deploymentAddressesPath, {
      encoding: 'utf-8',
    })
  );

  // verify that the contracts were actually deployed.
  const verifyHasCode = async (address: string) => {
    const code = await provider.getCode(address);
    if (code.length === 2)
      throw new Error(`No code found at: ${address}, code: ${code}`);
  };

  console.log('verifying deployed addresses has code...');
  await Promise.all([
    verifyHasCode(addresses.factory),
    verifyHasCode(addresses.implementation),
  ]);

  console.log('impersonating ENS ownership for', ensName);
  await setOwnerForEns(provider, ensName, addresses.factory);

  return addresses;
};

// Runs the given callback function after setting up a local anvil fork with
// all the necessary contracts.
export const withAnvilProvider = async (
  callback: (
    provider: ethers.JsonRpcProvider,
    signers: ethers.Wallet[],
    addresses: Awaited<ReturnType<typeof deployCowShed>>
  ) => Promise<void>,
  postCallbackSleep: number
) => {
  console.log('Starting anvil...');
  const anvil = await setupAnvil();
  await anvil.start();

  const rpcUrl = `http://${anvil.host}:${anvil.port}`;
  console.log(`anvil started at: ${rpcUrl}`);
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  const defaultSigners = [
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
    '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
    '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
    '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a',
    '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba',
    '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',
    '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356',
    '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97',
    '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6',
  ].map((key) => new ethers.Wallet(key, provider));
  const targetBalance = ethers.parseEther('10000');

  console.log(
    `Default signers:\n${defaultSigners
      .map((signer) => `${signer.privateKey} => ${signer.address}`)
      .join('\n')}`
  );

  // set balance if not already set
  console.log(
    `ensuring all default signers have ${ethers.formatEther(
      targetBalance
    )} ether`
  );
  await Promise.all(
    defaultSigners.map(async (signer) => {
      const address = await signer.getAddress();
      const balance = await provider.getBalance(address);
      if (balance !== targetBalance) {
        await setBalance(provider, address, balance);
      }
    })
  );

  console.log('Deploying COWShed...');
  const deploymentAddresses = await deployCowShed(
    provider,
    defaultSigners[0].signingKey.privateKey
  );
  console.log('COWShed deployed', deploymentAddresses);

  try {
    await callback(provider, defaultSigners, deploymentAddresses);
  } catch (err) {
    console.error(err);
  }
  // sleep incase the user wants to investigate the anvil state
  await sleep(postCallbackSleep);
  console.log('Stopping anvil');
  await anvil.stop();
};

// wrap ether from given account
export const wrapEther = async (
  provider: ethers.JsonRpcProvider,
  address: string,
  amount: bigint
) => {
  console.log(`wrapping ${ethers.formatEther(amount)} ether for ${address}...`);
  const signer = await getSigner(provider, address);
  const tx = await signer.sendTransaction({
    to: WETH,
    data: fnSelector('deposit()'),
    value: amount,
  });
  const receipt = await tx.wait();
  if (receipt?.status === 0) throw new Error('Wrapping ether failed');
  return receipt;
};

// approves token for given account
export const approveToken = async (
  provider: ethers.JsonRpcProvider,
  token: string,
  owner: string,
  spender: string,
  amount: bigint
) => {
  console.log(
    `approving ${amount}(n) ${token}(token) tokens of ${owner}(owner) to ${spender}(spender)...`
  );
  const signer = await getSigner(provider, owner);
  const tx = await signer.sendTransaction({
    to: token,
    data: fnCalldata(
      'approve(address,uint256)',
      ABI_CODER.encode(['address', 'uint'], [spender, amount])
    ),
  });
  const receipt = await tx.wait();
  if (receipt?.status === 0) throw new Error('Approving token failed');
  return receipt;
};

// sets presignature for given order for given user. it uses the appdata package
// to compute the appdata hash using the hooks data
export const createOrder = async (
  provider: ethers.JsonRpcProvider,
  order: Order,
  hooks: v1_1_0.OrderInteractionHooks,
  owner: string
) => {
  console.log(`Creating order for user: ${owner}`, order);
  const metadataApi = new MetadataApi();
  const appDataDoc = await metadataApi.generateAppDataDoc({
    appCode: 'CoW Swap',
    environment: 'production',
    metadata: {
      hooks,
    },
  });
  const { appDataHex } = await metadataApi.appDataToCid(appDataDoc);
  order.appData = appDataHex;

  const domain = {
    name: 'Gnosis Protocol',
    version: 'v2',
    chainId: 1,
    verifyingContract: SETTLEMENT_CONTRACT,
  };
  const orderId = computeOrderUid(domain, order, owner);
  const signer = await getSigner(provider, owner);
  const tx = await signer.sendTransaction({
    to: SETTLEMENT_CONTRACT,
    data: fnCalldata(
      'setPreSignature(bytes,bool)',
      ABI_CODER.encode(['bytes', 'bool'], [orderId, true])
    ),
  });
  const receipt = await tx.wait();
  if (receipt?.status === 0) throw new Error('create order failed');
  return receipt;
};

// settles given order from the tokens that are already in the settlement contract.
// for orders that cannot be fulfiled with the settlement balance this call will fail.
// it constructs the pre/post hook interactions for the order from the passed hooks data.
export const settleOrder = async (
  provider: ethers.JsonRpcProvider,
  order: Order,
  hooks: v1_1_0.OrderInteractionHooks,
  owner: string
) => {
  console.log(`Settling order for user: ${owner}`, order);
  const settlementBalance = await getTokenBalance(
    provider,
    order.buyToken,
    SETTLEMENT_CONTRACT
  );
  if (settlementBalance < order.buyAmount)
    throw new Error(
      `Settlement contract cannot fund the swap. balance: ${settlementBalance}, required: ${order.buyAmount}`
    );

  const signer = await getSigner(provider, SOLVER);
  const settlementContract = new ethers.Contract(
    SETTLEMENT_CONTRACT,
    settlementAbi,
    signer
  );
  const sellAmount = BigInt(order.sellAmount.toString());
  const buyAmount = BigInt(order.buyAmount.toString());
  const [sellTokenPrice, buyTokenPrice]: [bigint, bigint] =
    sellAmount > buyAmount
      ? [1n, sellAmount / buyAmount]
      : [buyAmount / sellAmount, 1n];

  const tx: ethers.TransactionResponse = await settlementContract.settle(
    [order.sellToken, order.buyToken],
    [sellTokenPrice, buyTokenPrice],
    [
      {
        sellTokenIndex: 0,
        buyTokenIndex: 1,
        receiver: order.receiver || owner,
        sellAmount,
        buyAmount,
        validTo: order.validTo,
        appData: order.appData,
        feeAmount: order.feeAmount,
        flags: getOrderFlags(order, SigningScheme.PRESIGN),
        executedAmount: sellAmount,
        signature: ethers.solidityPacked(['address'], [owner]),
      },
    ],
    [
      (hooks.pre || []).map((x) => ({
        target: x.target,
        value: 0n,
        callData: x.callData,
      })),
      [],

      (hooks.post || []).map((x) => ({
        target: x.target,
        value: 0n,
        callData: x.callData,
      })),
    ]
  );
  const receipt = await tx.wait();
  if (receipt?.status === 0) throw new Error('Settle failed');
  return receipt;
};

// fetch token balance of given user
export const getTokenBalance = async (
  provider: ethers.JsonRpcProvider,
  token: string,
  owner: string
) => {
  const ret = await provider.call({
    to: token,
    data: fnCalldata(
      'balanceOf(address)',
      ABI_CODER.encode(['address'], [owner])
    ),
  });
  const bal = ABI_CODER.decode(['uint'], ret)[0];
  return bal;
};

const SETTLEMENT_CONTRACT = '0x9008D19f58AAbD9eD0D60971565AA8510560ab41';
const SOLVER = '0x4339889FD9dFCa20a423fbA011e9dfF1C856CAEb';
const ENS = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';
export const VAULT_RELAYER = '0xC92E8bdf79f0507f65a392b0ab4667716BFE0110';
export const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
export const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
export const ABI_CODER = new ethers.AbiCoder();

const fnSelector = (sig: string) => ethers.id(sig).slice(0, 10);

// simple calldata encoding. used in multiple places where the function calls
// are simple and one off uses. its just cleaner to handcode it instead of
// bloating it all with abis and ethers.Contract usages.
export const fnCalldata = (sig: string, encodedData: string) =>
  ethers.solidityPacked(['bytes4', 'bytes'], [fnSelector(sig), encodedData]);

// encodes the order options into the order flag
// see: https://github.com/cowprotocol/contracts/blob/main/src/contracts/libraries/GPv2Trade.sol#L58-L94
const getOrderFlags = (order: Order, signingScheme: SigningScheme) => {
  let flags = 0;
  flags = order.kind === OrderKind.BUY ? (flags |= 0x01) : flags;
  flags = order.partiallyFillable ? (flags |= 0x02) : flags;

  if (order.sellTokenBalance === OrderBalance.EXTERNAL) flags |= 0x08;
  if (order.sellTokenBalance === OrderBalance.INTERNAL) flags |= 0x0c;

  if (order.buyTokenBalance === OrderBalance.INTERNAL) flags |= 0x10;

  switch (signingScheme) {
    case SigningScheme.EIP712: {
      // do nothing
    }
    case SigningScheme.ETHSIGN: {
      flags |= 0x20;
    }
    case SigningScheme.EIP1271: {
      flags |= 0x40;
    }
    case SigningScheme.PRESIGN: {
      flags |= 0x60;
    }
  }

  return flags;
};

// sleep for given milliseconds
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// try and get signer, if not available, impersonate and then get signer
const getSigner = async (provider: ethers.JsonRpcProvider, who: string) => {
  try {
    return await provider.getSigner(who);
  } catch (err) {
    await provider.send('anvil_impersonateAccount', [who]);
    return await provider.getSigner(who);
  }
};

// set owner for given node directly in the ens contract state
const setOwnerForEns = (
  provider: ethers.JsonRpcProvider,
  ens: string,
  owner: string
) => {
  const node = ethers.namehash(ens);
  const slot = ethers.keccak256(
    ABI_CODER.encode(['bytes32', 'uint'], [node, 0])
  );
  const value = ethers.zeroPadValue(owner, 32);
  return provider.send('anvil_setStorageAt', [ENS, slot, value]);
};
