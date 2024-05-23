import { Order, OrderBalance, OrderKind } from '@cowprotocol/contracts';
import {
  ABI_CODER,
  USDC,
  VAULT_RELAYER,
  WEIROLL_ADDRESS,
  WETH,
  approveToken,
  createOrder,
  estimateGasForExecuteHooks,
  fnCalldata,
  fnSelector,
  getTokenBalance,
  mockUsdcBalance,
  resolveName,
  settleOrder,
  withAnvilProvider,
  wrapEther,
} from './common';
import { MaxUint256, ethers } from 'ethers_v6';
import { CowShedSdk, ICall } from '../ts';
import {
  CallType,
  END_OF_ARGS,
  encodeCommand,
  encodeFlag,
  encodeInput,
  encodeInputArg,
  encodeWeirollExecuteCall,
} from './weiroll';
import { hexZeroPad } from 'ethers/lib/utils';

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

  // weiroll required since swap output amount is not known
  // at tx time. need to fetch it at execution time.
  const weirollCommands = [
    // balanceOf staticcall
    encodeCommand(
      fnSelector('balanceOf(address)'),
      // it should be a static call
      encodeFlag(false, false, CallType.StaticCall),
      encodeInput(
        // balanceOf takes one arg, the address whose balance is being queried
        // it is fixed length input, and stored at state index 0
        encodeInputArg(true, 0),
        // all remainder args are unused
        END_OF_ARGS,
        END_OF_ARGS,
        END_OF_ARGS,
        END_OF_ARGS,
        END_OF_ARGS
      ),
      // this tells the VM that the output of balanceOf is also
      // of fixed length and that it should store it in state index 1
      encodeInputArg(true, 1),
      // target address, this is whats called
      USDC
    ),
    // bridge relay tokens call
    encodeCommand(
      fnSelector('relayTokens(address,address,uint256)'),
      // it is a Call
      encodeFlag(false, false, CallType.Call),
      encodeInput(
        // token address, fixed length input, read from state index 2
        encodeInputArg(true, 2),
        // user address, fixed length input, read from state index 0
        encodeInputArg(true, 0), // user address
        // balance, fixed length input, read from state index 1, this is where
        // previous command stored it
        encodeInputArg(true, 1), // balance
        // other 3 input args are unused
        END_OF_ARGS,
        END_OF_ARGS,
        END_OF_ARGS
      ),
      // this commands output is not used/important, hence ignored
      END_OF_ARGS,
      // target address, this is whats called
      GNOSIS_CHAIN_BRIDGE
    ),
  ];

  const state = [
    hexZeroPad(proxyAddress, 32), // address to query the balance of
    '0x', // this is where balance output will be written
    hexZeroPad(USDC, 32), // USDC token address, used in relayTokens call argument
  ];

  // post hooks
  const calls: ICall[] = [
    // approve the bridge to spend the swapped usdc
    {
      target: USDC,
      callData: fnCalldata(
        'approve(address,uint256)',
        ABI_CODER.encode(
          ['address', 'uint256'],
          [GNOSIS_CHAIN_BRIDGE, MaxUint256]
        )
      ),
      value: 0n,
      isDelegateCall: false,
      allowFailure: false,
    },
    // bridge the full output by using weiroll
    {
      target: WEIROLL_ADDRESS,
      callData: encodeWeirollExecuteCall(weirollCommands, state),
      value: 0n,
      isDelegateCall: true,
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
  const newBalance = buyAmount * 2n;
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
      // TokensBridgingInitiated(address,address,uint256,bytes32)
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
  const proxyUsdcBalanceAfterBridge = await getTokenBalance(
    provider,
    USDC,
    proxyAddress
  );
  console.log({
    resolvedAddressLowerCase,
    resolvedAddressChecksummed,
    proxyName,
    proxyAddress,
    userAddr,
    proxyUsdcBalanceAfterBridge,
  });
};

const main = async () => {
  await withAnvilProvider(swapAndBridge, 6_000_000);
};

main();
