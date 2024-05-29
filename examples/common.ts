import { createAnvil } from '@viem/anvil';
import { join } from 'path';
import fs from 'fs';
import { MaxUint256, ethers, zeroPadBytes } from 'ethers_v6';
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
import { hexZeroPad } from 'ethers/lib/utils';

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

  await deployWeiroll(provider);

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
  // to simulate execution surplus, buyAmount is the minOut, we are giong to simulate
  // that it receives 100 units more
  const buyAmountForExecution = BigInt(order.buyAmount.toString()) + 100n;
  const [sellTokenPrice, buyTokenPrice]: [bigint, bigint] =
    sellAmount > buyAmountForExecution
      ? [1n, sellAmount / buyAmountForExecution]
      : [buyAmountForExecution / sellAmount, 1n];
  const buyAmount = BigInt(order.buyAmount.toString());

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
export const USDC_BALANCE_OF_SLOT = 0x09n;
export const VAULT_RELAYER = '0xC92E8bdf79f0507f65a392b0ab4667716BFE0110';
export const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
export const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
export const VAT = '0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B';
export const ETH_A_JOIN = '0x2F0b23f53734252Bda2277357e97e1517d6B042A';
export const DAI_JOIN = '0x9759A6Ac90977b93B58547b4A71c78317f391A28';
export const DAI = '0x6b175474e89094c44da98b954eedeac495271d0f';
export const COW = '0xdef1ca1fb7fbcdc777520aa7f396b4e015f497ab';
export const ABI_CODER = new ethers.AbiCoder();

export const fnSelector = (sig: string) => ethers.id(sig).slice(0, 10);

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
export const sleep = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

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

export const balanceOfSlot = (mappingSlot: bigint, owner: string) => {
  return ethers.keccak256(
    ABI_CODER.encode(['address', 'uint256'], [owner, mappingSlot])
  );
};

export const estimateGasForExecuteHooks = async (
  provider: ethers.JsonRpcProvider,
  to: string,
  calldata: string,
  mockBalance: () => Promise<any>,
  resetBalance: () => Promise<any>
) => {
  await mockBalance();
  try {
    return await provider.estimateGas({ to, data: calldata });
  } catch (err) {
    throw new Error("couldn't estimate gas");
  } finally {
    await resetBalance();
  }
};

export const mockUsdcBalance = async (
  provider: ethers.JsonRpcProvider,
  user: string,
  balance: bigint
) => {
  const mask = MaxUint256 >> 1n;
  if (balance > mask)
    throw new Error(
      'cannot set balance > 255 bits, first bit is a blacklist flag, setting it to 1 will consider the contract blacklisted'
    );
  const balanceToSet = balance & mask;
  const balanceString = (() => {
    const hexString = balanceToSet.toString(16);
    if (hexString.length % 2 !== 0) return '0x0' + hexString;
    else return '0x' + hexString;
  })();
  const args = [
    USDC,
    balanceOfSlot(USDC_BALANCE_OF_SLOT, user),
    hexZeroPad(balanceString, 32),
  ];
  console.log('setStorageAt', args);
  return await provider.send('anvil_setStorageAt', args);
};

const deployWeiroll = async (provider: ethers.JsonRpcProvider) => {
  provider.send('anvil_setCode', [WEIROLL_ADDRESS, WEIROLL_CODE]);
};

export const WEIROLL_ADDRESS = hexZeroPad('0x03e14011', 20);
// deployedBytecode.object for TestableVM as seen here:
//    https://github.com/meetmangukiya/weiroll/blob/main/src/test/TestableVM.sol
const WEIROLL_CODE =
  '0x60806040526004361061001e5760003560e01c8063de792d5f14610023575b600080fd5b610036610031366004610a4c565b61004c565b6040516100439190610bec565b60405180910390f35b6060610059848484610063565b90505b9392505050565b606060008080808487825b8181101561041e578a8a8281811061008857610088610c50565b905060200201359650602087901b60f81c60ff169550604086166000146100d4578a8a826100b581610c7c565b93508181106100c6576100c6610c50565b9050602002013594506100e5565b602887901b6001600160d01b031794505b6003861661015a576001600160a01b0387166101028a898861042d565b60405161010f9190610c95565b600060405180830381855af49150503d806000811461014a576040519150601f19603f3d011682016040523d82523d6000602084013e61014f565b606091505b509094509250610382565b600160038716036101c4576001600160a01b03871661017a8a898861042d565b6040516101879190610c95565b6000604051808303816000865af19150503d806000811461014a576040519150601f19603f3d011682016040523d82523d6000602084013e61014f565b6002600387160361022c576001600160a01b0387166101e48a898861042d565b6040516101f19190610c95565b600060405180830381855afa9150503d806000811461014a576040519150601f19603f3d011682016040523d82523d6000602084013e61014f565b600380871603610347576000808a8760f81c60ff168151811061025157610251610c50565b6020026020010151905080516020146102c65760405162461bcd60e51b815260206004820152602c60248201527f5f657865637574653a2076616c75652063616c6c20686173206e6f2076616c7560448201526b329034b73234b1b0ba32b21760a11b60648201526084015b60405180910390fd5b602081015191506001600160a01b038916826102ea8d8c60088c901b60ff1761042d565b6040516102f79190610c95565b60006040518083038185875af1925050503d8060008114610334576040519150601f19603f3d011682016040523d82523d6000602084013e610339565b606091505b509096509450610382915050565b60405162461bcd60e51b815260206004820152601060248201526f496e76616c69642063616c6c7479706560801b60448201526064016102bd565b836103e757825115610395576044830192505b60008760001c60008551116103c957604051806040016040528060078152602001662ab735b737bbb760c91b8152506103cb565b845b60405163ef3dcb2f60e01b81526004016102bd93929190610cb1565b6080861615610404576103ff89605889901b856107a2565b610416565b61041389605889901b85610847565b98505b60010161006e565b50969998505050505050505050565b606060008060606000805b60208110156106025786816020811061045357610453610c50565b1a915060fe198201156106025760808216156105685760fe82036104b057825160000361049d578860405160200161048b9190610bec565b60405160208183030381529060405292505b82516104a99086610ce4565b94506105f3565b600089607f8416815181106104c7576104c7610c50565b60200260200101515190506020816104df9190610cfd565b1561054b5760405162461bcd60e51b815260206004820152603660248201527f44796e616d6963207374617465207661726961626c6573206d7573742062652060448201527561206d756c7469706c65206f6620333220627974657360501b60648201526084016102bd565b610556816020610ce4565b6105609087610ce4565b9550506105f3565b88607f83168151811061057d5761057d610c50565b6020026020010151516020146105e55760405162461bcd60e51b815260206004820152602760248201527f537461746963207374617465207661726961626c6573206d75737420626520336044820152663220627974657360c81b60648201526084016102bd565b6105f0602086610ce4565b94505b60209390930192600101610438565b5061060e846004610ce4565b67ffffffffffffffff811115610626576106266109b9565b6040519080825280601f01601f191660200182016040528015610650576020820181803683370190505b5094508660208601526000935060005b60208110156107965786816020811061067b5761067b610c50565b1a915060fe198201156107965760808216156107585760fe82036106e6578585016024018490526106c7836020886106b4886004610ce4565b602088516106c29190610d1f565b61099f565b602083516106d59190610d1f565b6106df9085610ce4565b9350610787565b600089607f8416815181106106fd576106fd610c50565b602002602001015151905084866024890101526107468a607f85168151811061072857610728610c50565b60200260200101516000898860046107409190610ce4565b8561099f565b6107508186610ce4565b945050610787565b600089607f84168151811061076f5761076f610c50565b60200260200101519050602081015186602489010152505b60209490940193600101610660565b50505050509392505050565b60f882901c60fe1981016107b65750505050565b6000825160206107c69190610ce4565b67ffffffffffffffff8111156107de576107de6109b9565b6040519080825280601f01601f191660200182016040528015610808576020820181803683370190505b5085838151811061081b5761081b610c50565b602002602001018190529050610837836000836020875161099f565b8251806020830152505050505050565b606060f883901c60fe198101610860578491505061005c565b60808116156109125760fe810361088c57828060200190518101906108859190610d32565b9450610996565b6020838101519081146108f45760405162461bcd60e51b815260206004820152602a60248201527f4f6e6c79206f6e652072657475726e2076616c7565207065726d697474656420604482015269287661726961626c652960b01b60648201526084016102bd565b508251601f19016020848101918252607f8316810287010152610996565b82516020146109745760405162461bcd60e51b815260206004820152602860248201527f4f6e6c79206f6e652072657475726e2076616c7565207065726d697474656420604482015267287374617469632960c01b60648201526084016102bd565b8285607f83168151811061098a5761098a610c50565b60200260200101819052505b50929392505050565b808260208501018286602089010160045afa505050505050565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff811182821017156109f8576109f86109b9565b604052919050565b600067ffffffffffffffff821115610a1a57610a1a6109b9565b5060051b60200190565b600067ffffffffffffffff821115610a3e57610a3e6109b9565b50601f01601f191660200190565b60008060006040808587031215610a6257600080fd5b843567ffffffffffffffff80821115610a7a57600080fd5b818701915087601f830112610a8e57600080fd5b813581811115610a9d57600080fd5b602089818360051b8601011115610ab357600080fd5b808401975081965080890135935082841115610ace57600080fd5b838901935089601f850112610ae257600080fd5b83359150610af7610af283610a00565b6109cf565b82815260059290921b8401810191818101908b841115610b1657600080fd5b8286015b84811015610b8a57803586811115610b325760008081fd5b8701603f81018e13610b445760008081fd5b84810135610b54610af282610a24565b8181528f8b838501011115610b695760008081fd5b818b8401888301376000918101870191909152845250918301918301610b1a565b50809750505050505050509250925092565b60005b83811015610bb7578181015183820152602001610b9f565b50506000910152565b60008151808452610bd8816020860160208601610b9c565b601f01601f19169290920160200192915050565b600060208083016020845280855180835260408601915060408160051b87010192506020870160005b82811015610c4357603f19888603018452610c31858351610bc0565b94509285019290850190600101610c15565b5092979650505050505050565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b600060018201610c8e57610c8e610c66565b5060010190565b60008251610ca7818460208701610b9c565b9190910192915050565b8381526001600160a01b0383166020820152606060408201819052600090610cdb90830184610bc0565b95945050505050565b80820180821115610cf757610cf7610c66565b92915050565b600082610d1a57634e487b7160e01b600052601260045260246000fd5b500690565b81810381811115610cf757610cf7610c66565b60006020808385031215610d4557600080fd5b825167ffffffffffffffff80821115610d5d57600080fd5b818501915085601f830112610d7157600080fd5b8151610d7f610af282610a00565b81815260059190911b83018401908481019088831115610d9e57600080fd5b8585015b83811015610e1257805185811115610dba5760008081fd5b8601603f81018b13610dcc5760008081fd5b878101516040610dde610af283610a24565b8281528d82848601011115610df35760008081fd5b610e02838c8301848701610b9c565b8652505050918601918601610da2565b509897505050505050505056fea264697066735822122078e4fff709224c7e1fd6634b0b8ad029002108889fe2bdcd3ee6ba1b4411f5fe64736f6c63430008190033';
const makeTransaction = async (
  signer: ethers.Signer,
  txData: ethers.TransactionRequest,
  ctx?: string
) => {
  const tx = await signer.sendTransaction(txData);
  const receipt = await tx.wait();
  if (receipt?.status === 0)
    throw new Error(`transaction failed: ${ctx || ''}`);
  console.log(`tx succeeded: ${ctx}: ${receipt!.hash}`);
  return receipt!;
};

// allow `toHope` to control `user`'s position
export const vatHope = async (
  provider: ethers.JsonRpcProvider,
  who: string,
  usr: string
) => {
  console.log(`user ${who} hopes ${usr}..`);
  const signer = await getSigner(provider, who);
  return makeTransaction(
    signer,
    {
      to: VAT,
      data: fnCalldata('hope(address)', ABI_CODER.encode(['address'], [usr])),
    },
    'vat.hope'
  );
};

// deposit collateral
export const joinEth = async (
  provider: ethers.JsonRpcProvider,
  usr: string,
  wad: bigint
) => {
  const signer = await getSigner(provider, usr);
  return makeTransaction(
    signer,
    {
      to: ETH_A_JOIN,
      data: fnCalldata(
        'join(address,uint256)',
        ABI_CODER.encode(['address', 'uint'], [usr, wad])
      ),
    },
    'mcd_eth_a.join'
  );
};

export const resolveName = (provider: ethers.JsonRpcProvider, name: string) => {
  console.log('resolving name', name);
  return provider.resolveName(name);
};

export const getIlk = (provider: ethers.JsonRpcProvider, join: string) => {
  const contract = new ethers.Contract(
    join,
    ['function ilk() external view returns (bytes32)'],
    provider
  );

  return contract.ilk();
};
