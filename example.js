require("fake-indexeddb/auto");
const njs = require("./index");

const walletFile = undefined; // File name of the wallet database, persistence using dexie db backend only works on the browser
const password = undefined; // Password used to encrypt and open the wallet database
const spendingPassword = undefined; // Password used to send transactions
const mnemonic = undefined; // Mnemonic to import 'problem shrimp bottom mouse canyon moment dirt beyond cage hazard phrase animal';
const type = undefined; // Wallet type next, navcoin-core or navcoin-js-v1
const zapwallettxes = false; // Should the wallet be cleared of its history?
const log = true; // Log to console
const network = "mainnet";

njs.wallet.Init().then(async () => {
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

    await wallet.Connect();
  });

  wallet.on("connected", () => console.log("connected. waiting for sync"));

  wallet.on("sync_status", async (progress, pending) => {
    console.log(`Sync ${progress}%`);
  });

  wallet.on("sync_finished", async () => {
    console.log("sync_finished");
  });

  wallet.on("new_tx", async (list) => {
    console.log(`Received transaction ${JSON.stringify(list)}`);
    console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`);
  });

  await wallet.Load({
    bootstrap: njs.wallet.xNavBootstrap,
  });
});
