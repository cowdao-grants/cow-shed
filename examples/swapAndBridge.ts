import { Order, OrderBalance, OrderKind } from '@cowprotocol/contracts';
import {
  ABI_CODER,
  USDC,
  USDC_BALANCE_OF_SLOT,
  VAULT_RELAYER,
  WETH,
  approveToken,
  createOrder,
  estimateGasForExecuteHooks,
  fnCalldata,
  getTokenBalance,
  mockUsdcBalance,
  settleOrder,
  sleep,
  withAnvilProvider,
  wrapEther,
} from './common';
import { MaxUint256, ethers } from 'ethers_v6';
import { CowShedSdk, ICall } from '../ts';

// bridge contract address on ethereum mainnet
const GNOSIS_CHAIN_BRIDGE = '0x88ad09518695c6c3712AC10a214bE5109a655671';

const swapAndBridge: Parameters<typeof withAnvilProvider>[0] = async (
  provider: ethers.JsonRpcProvider,
  signers: ethers.Wallet[],
  { factory, implementation, proxyInitCode }
) => {
  const user = signers[1];
  const userAddr = await user.getAddress();

  // wrap the ether and approve to cowswap
  const amt = ethers.parseEther('1');
  const wrapTx = await wrapEther(provider, userAddr, amt);
  console.log('ether wrapped', wrapTx?.hash);
  const approveTx = await approveToken(
    provider,
    WETH,
    userAddr,
    VAULT_RELAYER,
    amt
  );
  console.log('weth approved', approveTx?.hash);

  // compute the proxy address with CowShedSdk
  const shedSdk = new CowShedSdk({
    factoryAddress: factory,
    implementationAddress: implementation,
    chainId: 1,
    proxyCreationCode: proxyInitCode,
  });
  const proxyAddress = shedSdk.computeProxyAddress(userAddr);
  console.log('Computed proxy address for user', userAddr, 'is', proxyAddress);

  const buyAmount = 10_000_000n;
  const validTo = Math.floor(new Date().getTime() / 1000) + 7200;

  const order: Order = {
    sellToken: WETH,
    buyToken: USDC,
    receiver: proxyAddress,
    sellAmount: amt,
    buyAmount,
    validTo,
    appData: '',
    feeAmount: 0n,
    kind: OrderKind.SELL,
    partiallyFillable: true,
    sellTokenBalance: OrderBalance.ERC20,
    buyTokenBalance: OrderBalance.ERC20,
  };

  // post hooks
  const calls: ICall[] = [
    // approve the bridge to spend the swapped usdc
    {
      target: USDC,
      callData: fnCalldata(
        'approve(address,uint256)',
        ABI_CODER.encode(
          ['address', 'uint256'],
          [GNOSIS_CHAIN_BRIDGE, buyAmount]
        )
      ),
      value: 0n,
      isDelegateCall: false,
      allowFailure: false,
    },
    // bridge the usdc
    {
      target: GNOSIS_CHAIN_BRIDGE,
      callData: fnCalldata(
        'relayTokens(address,address,uint256)',
        ABI_CODER.encode(
          ['address', 'address', 'uint'],
          [USDC, userAddr, buyAmount]
        )
      ),
      value: 0n,
      isDelegateCall: false,
      allowFailure: false,
    },
  ];
  const nonce = ethers.encodeBytes32String('first');

  // signing the hooks intent
  const hashToSign = shedSdk.hashToSignWithUser(
    calls,
    nonce,
    BigInt(validTo),
    userAddr
  );
  console.log('hash to sign', hashToSign);
  const signature = user.signingKey.sign(hashToSign);
  console.log('actual signature', signature.r, signature.s, signature.v);
  const encodedSignature = CowShedSdk.encodeEOASignature(
    BigInt(signature.r),
    BigInt(signature.s),
    signature.v
  );

  const hooksCalldata = CowShedSdk.encodeExecuteHooksForFactory(
    calls,
    nonce,
    BigInt(validTo),
    userAddr,
    encodedSignature
  );

  const prevBalance = await getTokenBalance(provider, USDC, proxyAddress);
  const newBalance = MaxUint256 >> 1n;
  const setProxyBalance = async () =>
    mockUsdcBalance(provider, proxyAddress, newBalance);
  const resetProxyBalance = async () =>
    mockUsdcBalance(provider, proxyAddress, prevBalance);

  const gasLimit = (
    await estimateGasForExecuteHooks(
      provider,
      factory,
      hooksCalldata,
      setProxyBalance,
      resetProxyBalance
    )
  ).toString();

  const hooks = {
    post: [{ target: factory, callData: hooksCalldata, gasLimit }],
  };

  // create order
  const orderTx = await createOrder(provider, order, hooks, userAddr);
  console.log('Create order tx', orderTx?.hash);

  // settle order
  const settleTx = await settleOrder(provider, order, hooks, userAddr);
  console.log('Settle tx', settleTx?.hash);

  // check if the tokens got bridge
  const bridgeInitiatedLog = settleTx!.logs.find(
    (log) =>
      log.topics[0] ===
      '0x59a9a8027b9c87b961e254899821c9a276b5efc35d1f7409ea4f291470f1629a' &&
      log.address.toLowerCase() === GNOSIS_CHAIN_BRIDGE.toLowerCase()
  );
  if (bridgeInitiatedLog === undefined) {
    console.log('Bridge didnt happen!!!');
    return;
  }

  const tokenBridged = ABI_CODER.decode(
    ['address'],
    bridgeInitiatedLog.topics[1]
  )[0];
  const amountBridged = ABI_CODER.decode(['uint'], bridgeInitiatedLog.data)[0];
  const sender = ABI_CODER.decode(['address'], bridgeInitiatedLog.topics[2])[0];
  console.log({ tokenBridged, amountBridged, sender, proxyAddress });

  const resolvedAddressLowerCase = await resolveName(
    provider,
    `${userAddr.toLowerCase()}.cowhooks.eth`
  );
  const resolvedAddressChecksummed = await resolveName(
    provider,
    `${ethers.getAddress(userAddr)}.cowhooks.eth`
  );
  const proxyName = await provider.lookupAddress(proxyAddress);
  console.log({
    resolvedAddressLowerCase,
    resolvedAddressChecksummed,
    proxyName,
    proxyAddress,
    userAddr,
  });
};

const resolveName = (provider: ethers.JsonRpcProvider, name: string) => {
  console.log('resolving name', name);
  return provider.resolveName(name);
};

const main = async () => {
  await withAnvilProvider(swapAndBridge, 6_000_000);
};

main();
