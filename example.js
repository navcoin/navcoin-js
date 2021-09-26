require("fake-indexeddb/auto");
const njs = require("./index");

const walletFile = undefined; // File name of the wallet database
const password = undefined; // Password used to encrypt and open the wallet database
const spendingPassword = undefined; // Password used to send transactions
const mnemonic = undefined; // Mnemonic to import 'problem shrimp bottom mouse canyon moment dirt beyond cage hazard phrase animal';
const type = undefined; // Wallet type next, navcoin-core or navcoin-js-v1
const zapwallettxes = false; // Should the wallet be cleared of its history?
const log = true; // Log to console
const network = "mainnet";

let alreadySent = false;

njs.wallet.Init().then(async () => {
  console.log({
    file: walletFile,
    mnemonic: mnemonic,
    type: type,
    password: password,
    spendingPassword: spendingPassword,
    zapwallettxes: zapwallettxes,
    log: log,
    network: network,
  });
  const wallet = new njs.wallet.WalletFile({
    file: walletFile,
    mnemonic: mnemonic,
    type: type,
    password: password,
    spendingPassword: spendingPassword,
    zapwallettxes: zapwallettxes,
    log: log,
    network: network,
  });

  wallet.on("new_mnemonic", (mnemonic) =>
    console.log(`wallet created with mnemonic ${mnemonic} - please back it up!`)
  );

  wallet.on("loaded", async () => {
    console.log("wallet loaded");

    console.log(
      "xNAV receiving address: " +
        (await wallet.xNavReceivingAddresses(true))[0].address
    );
    console.log(
      "NAV receiving address: " +
        (await wallet.NavReceivingAddresses(true))[0].address
    );

    let pk = (await wallet.NavGetPrivateKeys())[0].privateKey;

    let sig = wallet.Sign(pk, "hola");
    console.log(
      wallet.VerifySignature(
        (await wallet.NavGetPrivateKeys())[0].address,
        "hola",
        sig
      )
    );

    await wallet.Connect();
  });

  wallet.on("connected", () => console.log("connected. waiting for sync"));

  wallet.on("sync_status", async (progress, pending) => {
    console.log(`Sync ${progress}%`);
    if (progress == 100 && !alreadySent) {
      alreadySent = true;
      if ((await wallet.GetBalance()).xnav.confirmed > 0) {
        let tx = await wallet.xNavCreateTransaction(
          (
            await wallet.xNavReceivingAddresses(true)
          )[0].address,
          1e6,
          "memo for xnav payment",
          spendingPassword
        );
        /*let hash = await wallet.SendTransaction(tx.tx)
                console.log(`Transaction sent to ${(await wallet.xNavReceivingAddresses(false))[0].address}.... with hash ${hash}`);*/
      }

      if ((await wallet.GetBalance()).nav.confirmed > 0) {
        let tx = await wallet.NavCreateTransaction(
          (
            await wallet.NavReceivingAddresses(true)
          )[0].address,
          1e6,
          undefined,
          spendingPassword
        );
        /*let hash = await wallet.SendTransaction(tx.tx)
                console.log(`Transaction sent to ${(await wallet.NavReceivingAddresses(false))[0].address}.... with hash ${hash}`);*/
      }
    }
  });

  wallet.on("sync_finished", async () => {
    console.log("sync_finished");
    console.log(await wallet.GetBalance());
  });

  wallet.on("new_tx", async (list) => {
    console.log(`Received transaction ${JSON.stringify(list)}`);
    console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`);
  });

  wallet.on("remove_tx", async (txid) => {
    console.log(`Removed tx transaction ${txid}`);
  });

  await wallet.Load({ bootstrap: njs.wallet.xNavBootstrap });

  // console.log(await wallet.GetHistory());
  // console.log(`Last block: ${await wallet.GetTip()}`);

  // let txHash = await wallet.xNavSend('xN123124fa123123123212131231', 10*1e8, 'memo for xnav payment', spendingPassword);
  // console.log(`Transaction sent to xN1231.... with hash ${txHash}`);

  // txHash = await wallet.xNavSend('N123124fa123121', 10*1e8, '', spendingPassword);
  // console.log(`Transaction sent to N1231.... with hash ${txHash}`);
});
