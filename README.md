# navcoin-js

Navcoin Javascript wallet library. Use Node >= 15.

Minimal working examples in `example.js` and `web/`

## Specification

```angular2html
const njs = require('navcoin-js');
```

## Static methods.

### wallet.Init()

Required before making any operation with the wallet. Initialises the cryptographic modules.

Parameters: `none`

Returns: `Promise`

Example:

````javascript
njs.wallet.Init().then(async () => {
    console.log(`library initialised`);
}
````

### wallet.WalletFile(parameters)

Creates a new Wallet object. Loads a wallet from storage or creates a new one if the name of the database does not exist.

Parameters: `parameters` object:

| Key        | Description                                                                                                                              | Default value |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| file             | Name of the wallet database. Will store in memory if `undefined`                                                                         |  undefined    |
| mnemonic         | When creating a new wallet, it will try to import the specified mnemonic.                                                                | undefined     |
| type             | Mnemonic type. Options: `navcoin-js-v1` (this library), `navcash`, `next`, `navcoin-core` or `navpay`                                    | navcoin-js-v1 |
| password         | Password used to encrypt the wallet data base. User will need to specify it every time the wallet is loaded.                             | undefined     |
| spendingPassword | When a new wallet is created, sets the password used to encrypt the wallet private keys. User will need to specify it every time it spends coins or wants to see a private key. | undefined     |
| zapwallettxes    | Wipe up all wallet entries and resync if set to `true`                                                                                   | false         |
| log              | Prints extra log to the console.                                                                                                         | false         |

Returns: `Wallet object`

Example:

````javascript
const wallet = new njs.wallet.WalletFile({file: 'wallet.db', password: 'myw4ll3tp455w0rd'})
````

### wallet.ListWallets()

Lists the names of the already created wallets.

Parameters: `none`

Returns: `Promise<Array>`

Example:

````javascript
const listWallets = await njs.wallet.ListWallets();

console.log("List of wallets:\n");
for (var wallet in listWallets) {
    console.log(listWallets[wallet]);
}
````

### wallet.RemoveWallet(name)

Remove the wallet with the specified name.

Parameters: `wallet database file name`

Returns: `Promise`

Example:

```javascript
await njs.wallet.RemoveWallet("wallet.db");
````

## Wallet methods

### Load()

Loads the wallet.

Parameters: `none`

Returns: `Promise`

Example:

```javascript
await wallet.Load();
````

Emits: `loaded` when wallet has been loaded

### Connect(parameters)

Connects to the Navcoin network.

Parameters: `parameters` object:

| key        | Description                                                                                                                              | Default value |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| host             | Electrum server host.                                             |  electrum4.nav.community    |
| port             | Electrum server port.                                             | 40004     |
| proto            | Electrum server protocol.                                         | wss |

Returns: `promise`

Example:
````javascript
await wallet.Connect({host: 'electrum1.nav.community'})
````

Emits: 'connected' when connection has been established

### Disconnect()

Disconnects from the electrum server.

Parameters: `none`

Returns: `void`

Example:

```javascript
wallet.Disconnect()
```

### NavReceivingAddresses()

Returns the list of addresses to receive NAV.

Returns: `Promise<Array>`

Example:

````javascript
console.log('NAV receiving address: '+ (await wallet.NavReceivingAddresses(false))[0].address);
````

### xNavReceivingAddresses()

Returns the list of addresses to receive xNAV.

Returns: `Promise<Array>`

Example:

````javascript
console.log('xNAV receiving address: '+ (await wallet.xNavReceivingAddresses(false))[0].address);
````


### NavGetPrivateKeys(spendingPassword, address)

Returns the list of private keys for the NAV addresses

Parameters:

`spendingPassword` The spending password of the wallet.

`address` Return the private key only for one specific address.


Returns: `Promise<Array>`

Example:

````javascript
console.log('NAV private keys: '+ (await wallet.NavGetPrivateKeys()));
````

### GetHistory()

Returns an ordered list of wallet balance changes and transactions.

Returns: `Promise<Array>`

Example:

````javascript
console.log('Wallet history: '+ (await wallet.GetHistory()));
````

### GetBalance()

Returns the current NAV and xNAV balance. Only needed to update when events `new_tx`, `remove_tx` or `sync_finished`.

Returns: `Promise<Object>`

Example:

````javascript
console.log('Wallet balance: '+ (await wallet.GetBalance()));
````

### NavCreateTransaction(destination, amount, memo, spendingPassword, subtractFee, fee)

Creates a transaction which sends NAV.

Parameters:

- `destination` The address destination. Can be NAV or xNAV.
- `amount` The amount to send.
- `memo` Only applies when destination is xNAV.
- `spendingPassword` The wallet spending password.
- `subtractFee` Should the fee be subtracted from the specified amount. Default: `true`.
- `fee` Use a custom fee

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.


Example:

````javascript
try {
    let tx = await wallet.NavCreateTransaction("NhSoiAPHvjiTLePzW1qKy9RZr2Bkny2ZF3", 10 * 1e8, undefined, "myw4ll3tp455w0rd")
    console.log(`transaction {tx.tx} with fee ${tx.fee}`)
    
} catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### xNavCreateTransaction(destination, amount, memo, spendingPassword, subtractFee, fee)

Creates a transaction which sends xNAV.

Parameters:

- `destination` The address destination. Can be NAV or xNAV.
- `amount` The amount to send.
- `memo` Only applies when destination is xNAV.
- `spendingPassword` The wallet spending password.
- `subtractFee` Should the fee be subtracted from the specified amount. Default: `true`.

Returns: `Promise<Object>` with the transaction encoded in hex and the fee. Use `try` to catch error.

Example:

````javascript
try {
    let hash = await wallet.xNavCreateTransaction("NhSoiAPHvjiTLePzW1qKy9RZr2Bkny2ZF3", 10 * 1e8, undefined, "myw4ll3tp455w0rd")
    console.log(`transaction {tx.tx} with fee ${tx.fee}`)
    
} catch(e)
{
    console.log(`error creating transaction: ${e}`);
}
````

### SendTransaction(tx)

Broadcasts a transaction.

Parameters:

- `tx` The hex encoded transaction.

Returns: `Promise<String>` with the transaction hash or `Promise<void>` if transaction failed. Use `try` to catch error.


Example:

````javascript
try {
    let hash = await wallet.SendTransaction(tx)
    console.log(`transaction sent ${hash}`)
    
} catch(e)
{
    console.log(`error sending transaction: ${e}`);
}
````

### ImportPrivateKey(key, spendingKey)

Imports the specified private key `key` to the wallet.

Returns: `Promise`

Example:

````javascript
await wallet.ImportPrivateKey('P123123123123123123121', 'myw4ll3tp4ssw0rd')
````

### Sign(privateKey, message)

Signs a message with the specified private key.

### VerifySignature(address, message, signature)

Verifies a signed message.


## Events

### new_mnemonic

Emitted when a new wallet is created.

Example:

````javascript
wallet.on('new_mnemonic', (mnemonic) => console.log(`wallet created with mnemonic ${mnemonic} - please back it up!`));
````

### loaded

Emitted when the wallet has been loaded.

Example:

````javascript
wallet.on('loaded', async () => {     
    console.log('wallet loaded')
    
    console.log('NAV receiving address: '+ (await wallet.NavReceivingAddresses(false))[0].address);
        
    await wallet.Connect();
});
````


### connected

Emitted when a connection has been established to the electrum server.

Example:

````javascript
wallet.on('connected', () => console.log('connected. waiting for sync'));
````

### sync_started

Emitted when the wallet started synchronizing the transaction history of a specific address or script.

````javascript
wallet.on('sync_started', (scripthash) => console.log('started syncing '+scripthash));
````

### sync_status

Emitted to update on the sync progress of a specific scripthash

````javascript
wallet.on('sync_status', (progress, scripthash) => console.log('script hash '+scripthash+' sync status: '+progress+'%'));
````

### sync_finished

Emitted when the wallet finishes synchronizing the transaction history of a specific address or script.

````javascript
wallet.on('sync_finished', (scripthash) => console.log('finished syncing '+scripthash));
````

### new_tx

Emitted when a new transaction affecting the wallet has been received.

````javascript
wallet.on('new_tx', async (list) => {
    console.log(`Received transaction ${JSON.stringify(list)}`)
    console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`)
});
````

### remove_tx

Emitted when a previously announced transaction is not part of the blockchain anymore.

````javascript
wallet.on('remove_tx', async (txid) => {
    console.log(`Removed tx transaction ${txid}`)
});
````