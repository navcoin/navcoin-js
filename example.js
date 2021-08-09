const njs = require('./index');

const walletFile = 'wallet.db'; // File name of the wallet database
const password = undefined; // Password used to encrypt and open the wallet database
const spendingPassword = undefined; // Password used to send transactions
const mnemonic = undefined; // Mnemonic to import
const type = undefined; // Wallet type next or navcoin-js-v1
const zapwallettxes = false; // Should the wallet be cleared of its history?
const log = true; // Log to console

let alreadySent = false;

njs.wallet.Init().then(async () => {
    const wallet = new njs.wallet.WalletFile({file: walletFile, mnemonic: mnemonic, type: type, password: password, spendingPassword: spendingPassword, zapwallettxes: zapwallettxes, log: log})

    wallet.on('new_mnemonic', (mnemonic) => console.log(`wallet created with mnemonic ${mnemonic} - please back it up!`));

    wallet.on('loaded', async () => {
        console.log('wallet loaded')

        console.log('xNAV receiving address: '+ (await wallet.xNavReceivingAddresses(false))[0].address);
        console.log('NAV receiving address: '+ (await wallet.NavReceivingAddresses(false))[0].address);

        await wallet.Connect();
    });

    wallet.on('connected', () => console.log('connected. waiting for sync'));

    wallet.on('sync_status', async (progress, scripthash) => {
        console.log(`Sync ${progress}%`)
        if (progress == 100 && scripthash == "6032c38c0bc0e91e726f1e55e1832e434509001a7aed5cfd881b6ef07215e84a") {
            if (!alreadySent)
            {
                let txHash = await wallet.xNavSend((await wallet.xNavReceivingAddresses(false))[0].address, 1e6, 'memo for xnav payment', spendingPassword);
                console.log(`Transaction sent to ${(await wallet.xNavReceivingAddresses(false))[0].address}.... with hash ${txHash}`);
                alreadySent = true;
            }
            console.log(await wallet.GetHistory())
        }
    });

    wallet.on('new_tx', async (list) => {
        console.log(`Received transaction ${JSON.stringify(list)}`)
        console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`)
    });

    wallet.on('remove_tx', async (txid) => {
        console.log(`Removed tx transaction ${txid}`)
    });

    await wallet.Load();

    // console.log(await wallet.GetHistory());
    // console.log(`Last block: ${await wallet.GetTip()}`);

    // let txHash = await wallet.xNavSend('xN123124fa123123123212131231', 10*1e8, 'memo for xnav payment', spendingPassword);
    // console.log(`Transaction sent to xN1231.... with hash ${txHash}`);

    // txHash = await wallet.xNavSend('N123124fa123121', 10*1e8, '', spendingPassword);
    // console.log(`Transaction sent to N1231.... with hash ${txHash}`);

});
