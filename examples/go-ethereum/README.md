# Turnkey + go-ethereum examples

This directory shows how to integrate Turnkey as the signer for Ethereum transactions using [`go-ethereum`](https://github.com/ethereum/go-ethereum), across three common integration levels:

- **Manual EIP-1559 transaction construction**
- **Drop-in signing for [bind.SignerFn](https://pkg.go.dev/github.com/ethereum/go-ethereum/accounts/abi/bind) flows**
- **Typed smart-contract calls generated with [`abigen`](https://geth.ethereum.org/docs/tools/abigen)**

---

These examples mirror real-world integration paths people take when adopting Turnkey:

1. **eip1559-unsigned — “I just want to sign a raw tx”**  

You already know how to build a transaction (or you have one coming from elsewhere) and just need to:
- format it the way Turnkey expects,  
- sign it with Turnkey
- and broadcast the signed bytes.

2. **bindsigner-basic — “I want a drop-in signer for go-ethereum”**  

Instead of manually building RLP payloads all over the place, you want a **single reusable `bind.SignerFn`** that:
- takes any EIP-1559 `*types.Transaction`,  
- normalizes it (e.g. ensures the chain ID is present),  
- signs it with Turnkey,
- and returns a fully signed transaction.  

3. **bindsigner-abigen — “I’m using abigen-generated contract bindings”**  

Use abigen-generated bindings to encode contract calls and submit them with a Turnkey-backed signer.

This example shows how to:
- initialize the generated ERC-20 wrapper,
- pack calldata with methods such as `erc.PackTransfer(to, amount)`,
- plug a Turnkey-powered `SignerFn` into `bind.TransactOpts`,
- build a normal EIP-1559 transaction containing that calldata,
- let Turnkey sign it inside the `SignerFn`,
- and broadcast the signed transaction through JSON-RPC.

---

## `eip1559-unsigned`

**Goal:**  
Manually build an unsigned EIP-1559 transaction, RLP-encode it in the exact format Turnkey expects, sign it with Turnkey, and broadcast it.

**How it works:**

- Constructs a `types.DynamicFeeTx` manually.
- Builds the unsigned payload:
  ```text
  [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList]
  ```
- RLP-encodes that array and prepends the EIP-1559 type byte `0x02`.
- Signs the resulting hex string with Turnkey.
- Decodes the signed RLP back into *types.Transaction.
- Broadcasts via `ethclient.Client.SendTransaction`.

## `bindsigner-basic`

**Goal:**  
Provide a reusable Turnkey-backed `bind.SignerFn` that can sign any EIP-1559 transaction created by `go-ethereum`.

**How it works:**

- Defines `MakeTurnkeySignerFn(client, signWith, chainID)` which returns a `bind.SignerFn` compatible with `accounts/abi/bind/v2`.
- Inside the signer:
  - verifies the transaction’s `from` address matches the Turnkey signer address,
  - ensures the transaction is EIP-1559 (`DynamicFeeTxType`),
  - injects the correct chain ID if omitted by upstream code,
  - builds the unsigned EIP-1559 payload Turnkey expects,
  - RLP-encodes it and prepends the `0x02` type byte,
  - sends the payload to Turnkey’s `SignTransactionV2`,
  - reconstructs and returns a fully signed `*types.Transaction`.
- You then broadcast the signed transaction using `ethclient.Client.SendTransaction`.

## `bindsigner-abigen`

**Goal:**  
Use abigen-generated contract bindings (v2) together with a Turnkey-backed signer, allowing you to encode typed contract calls while Turnkey signs the resulting transaction.

**How it works:**

- Uses `abigen --v2` to generate a typed ERC-20 binding from `ERC20.abi`.
- Loads the binding and creates a contract instance:
```go
erc := erc20.NewErc20()
contract := erc.Instance(rpc, tokenAddr)
```
- Constructs `bind.TransactOpts` using the same `MakeTurnkeySignerFn`.

```go
auth := &bind.TransactOpts{
    From:   turnkeyAddress,
    Signer: signerFn,
}
```
- Encodes the contract call using the generated helper:
```go
data := erc.PackTransfer(to, amount)
```
- builds a normal EIP-1559 transaction containing that calldata (your code constructs it using `PackTransfer`)
- The transaction is then passed into your SignerFn, which sends the unsigned payload to Turnkey and returns a fully signed transaction.
- You broadcast the signed tx using your JSON-RPC provider:

```go
rpc.SendTransaction(ctx, signedTx)
```

Under the hood:
- abigen v2 encodes the ABI call (`PackTransfer`),
- you build the transaction (gas, nonce, to, value, data),
- Turnkey signs it via your `SignerFn`,
- you broadcast it normally.

**About the ERC-20 binding:**

The erc20.go file included in this directory was generated with:
```bash
abigen --abi ERC20.abi --pkg erc20 --out erc20.go --v2
```
You **do not** need to regenerate it to run this example.


## Prerequisites

Before running any of the examples, you’ll need:

- A Turnkey [organization](https://docs.turnkey.com/getting-started/quickstart) with:
  - an API key (P-256),
  - and an Ethereum wallet account (the address you’ll sign with).
- A working Ethereum JSON-RPC endpoint (e.g. Sepolia from Alchemy, Infura, etc.).

Once you've gathered these values, add them to a new `.env` file. Notice that your private key should be securely managed and never be committed to git.

```bash
cd go-sdk/examples/go-ethereum
cp .env.example .env
```

Now open `.env` and add the missing environment variables:

```bash
TURNKEY_ORGANIZATION_ID="<Turnkey organization ID>"
TURNKEY_API_PUBLIC_KEY="<Turnkey API public key (starts with 02 or 03)>"
TURNKEY_API_PRIVATE_KEY="<Turnkey API private key>"

RPC_URL="<Ethereum RPC provider URL>"
SIGN_WITH="<Turnkey-managed Ethereum address>"

# Only needed for the abigen ERC20 example:
CONTRACT_ADDRESS="<ERC20 contract address>"
```

## Running the examples

Each example is fully independent and can be executed directly:

```bash
go run eip1559-unsigned/main.go
```

```bash
go run bindsigner-basic/main.go
```

```bash
go run bindsigner-abigen/main.go
```