import * as njs from 'navcoin-js';

njs.wallet.Init().then(async () => {
    const wallet = new njs.wallet.WalletFile({file: 'wallet2.db'})
    console.log('loaded')

    wallet.on('new_mnemonic', (mnemonic) => alert(`wallet created with mnemonic ${mnemonic} - please back it up!`));

    wallet.on('loaded', async () => {
        console.log('wallet loaded')

        console.log('xNAV receiving address: '+ (await wallet.xNavReceivingAddresses(false))[0].address);
        console.log('NAV receiving address: '+ (await wallet.NavReceivingAddresses(false))[0].address);

        await wallet.Connect();
    });

    wallet.on('connected', () => console.log('connected. waiting for sync'));

    wallet.on('sync_status', async (progress, scripthash) => {
        console.log(`Sync ${progress}% ${scripthash}`)
    });

    wallet.on('new_tx', async (list) => {
        alert(`Received transaction ${JSON.stringify(list)}`)
        console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`)
    });

    wallet.on('remove_tx', async (txid) => {
        console.log(`Removed tx transaction ${txid}`)
    });

    await wallet.Load()
})

