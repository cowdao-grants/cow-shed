import { Order, OrderBalance, OrderKind } from "@cowprotocol/contracts";
import {
  ABI_CODER,
  COW,
  VAULT_RELAYER,
  WETH,
  approveToken,
  createOrder,
  fnCalldata,
  getSigner,
  getTokenBalance,
  settleOrder,
  withAnvilProvider,
  wrapEther,
} from "./common";
import { ethers, getAddress, parseEther } from "ethers_v6";
import { CowShedSdk, ICall } from "../ts";
import { hexDataSlice } from "ethers/lib/utils";

const VESTING_ESCROW_FACTORY = "0xcf61782465ff973638143d6492b51a85986ab347"; // llama pay

export const createVest = async (
  provider: ethers.JsonRpcProvider,
  funder: string,
  token: string,
  receiver: string,
  amount: bigint,
  vesting_duration: bigint
) => {
  await approveToken(provider, token, funder, VESTING_ESCROW_FACTORY, amount);
  console.log(`creating vesting contract`);
  const signer = await getSigner(provider, funder);
  const tx = await signer.sendTransaction({
    to: VESTING_ESCROW_FACTORY,
    data: fnCalldata(
      "deploy_vesting_contract(address,address,uint256,uint256)",
      ABI_CODER.encode(
        ["address", "address", "uint256", "uint256"],
        [token, receiver, amount, vesting_duration]
      )
    ),
  });
  const receipt = await tx.wait();
  if (receipt?.status === 0)
    throw new Error("Vesting contract creation failed");

  const vestingContractAddr = getAddress(
    hexDataSlice(receipt?.logs[0].topics[2] as string, 12)
  );
  console.log(`vesting contract created at ${vestingContractAddr}`);
  return vestingContractAddr as string;
};

const claimAndSwap: Parameters<typeof withAnvilProvider>[0] = async (
  provider: ethers.JsonRpcProvider,
  signers: ethers.Wallet[],
  { factory, implementation, proxyInitCode }
) => {
  const funder = signers[0];
  const user = signers[1];
  const funderAddr = await funder.getAddress();
  const userAddr = await user.getAddress();
  const amount = parseEther("1");

  await wrapEther(provider, funderAddr, amount);

  const vestingContractAddr = await createVest(
    provider,
    funderAddr,
    WETH,
    userAddr,
    amount,
    500n
  );

  await provider.send("evm_increaseTime", [501]);

  // compute the proxy address with CowShedSdk
  const shedSdk = new CowShedSdk({
    factoryAddress: factory,
    implementationAddress: implementation,
    chainId: 1,
    proxyCreationCode: proxyInitCode,
  });

  const validTo = Math.floor(new Date().getTime() / 1000) + 7200;

  const order: Order = {
    sellToken: WETH,
    buyToken: COW,
    receiver: userAddr,
    sellAmount: amount,
    buyAmount: parseEther("1000"),
    validTo,
    appData: "",
    feeAmount: 0n,
    kind: OrderKind.SELL,
    partiallyFillable: true,
    sellTokenBalance: OrderBalance.ERC20,
    buyTokenBalance: OrderBalance.ERC20,
  };

  // pre-hooks
  const calls: ICall[] = [
    // approve the bridge to spend the swapped usdc
    {
      target: vestingContractAddr,
      callData: fnCalldata(
        "claim(address)",
        ABI_CODER.encode(["address"], [userAddr])
      ),
      value: 0n,
      isDelegateCall: false,
      allowFailure: false,
    },
  ];
  const nonce = ethers.encodeBytes32String("first");

  // signing the hooks intent
  const hashToSign = shedSdk.hashToSignWithUser(
    calls,
    nonce,
    BigInt(validTo),
    userAddr
  );
  console.log("hash to sign", hashToSign);
  const signature = user.signingKey.sign(hashToSign);
  console.log("actual signature", signature.r, signature.s, signature.v);
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

  const hooks = {
    pre: [
      {
        target: factory,
        callData: hooksCalldata,
        gasLimit: "9999999999999999999999",
      },
    ],
  };

  const approveTx = await approveToken(
    provider,
    WETH,
    userAddr,
    VAULT_RELAYER,
    amount
  );
  console.log("Approved WETH to vault relayer", approveTx?.hash);

  const orderTx = await createOrder(provider, order, hooks, userAddr);
  console.log("Create order tx", orderTx?.hash);

  // settle order
  const settleTx = await settleOrder(provider, order, hooks, userAddr);
  console.log("Settle tx", settleTx?.hash);
  // check if the tokens got claimed

  const claimedLog = settleTx!.logs.find((log) => {
    return log.address.toLowerCase() === vestingContractAddr.toLowerCase();
  });
  if (claimedLog === undefined) {
    console.log("Claim didnt happen!!!");
    return;
  }
  const amountClaimed = ABI_CODER.decode(["uint256"], claimedLog.data)[0];
  const recipient = ABI_CODER.decode(["address"], claimedLog.topics[1])[0];
  console.log(`${recipient} claimed ${amountClaimed} tokens`);
  const receiverCOWBalance = await getTokenBalance(provider, COW, userAddr);
  console.log("COW balance after swap", receiverCOWBalance.toString());
};

const main = async () => {
  await withAnvilProvider(claimAndSwap, 6_000_000);
};

main();
