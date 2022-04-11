global.window = global;
const setGlobalVars = require("indexeddbshim");
setGlobalVars(null, { checkOrigin: false });

const njs = require("./index.js");
const repl = require("repl");

const walletFile = undefined; // File name of the wallet database, persistence using dexie db backend only works on the browser
const password = undefined; // Password used to encrypt and open the wallet database
const spendingPassword = undefined; // Password used to send transactions
const mnemonic =
  "bracket shrug kit web three run stem resist barrel spring bounce clock";
const type = undefined; // Wallet type next, navcoin-core or navcoin-js-v1
const zapwallettxes = true; // Should the wallet be cleared of its history?
const log = true; // Log to console
const network = "testnet";

let wallet;

const prompt = repl.start("> ");

njs.wallet.Init().then(async () => {
  wallet = new njs.wallet.WalletFile({
    file: walletFile,
    mnemonic: mnemonic,
    type: type,
    password: password,
    spendingPassword: spendingPassword,
    zapwallettxes: zapwallettxes,
    log: log,
    network: network,
  });

  prompt.context.wallet = wallet;

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

  wallet.on("db_load_error", async (err) => {
    console.log(`Error Load DB: ${err}`);
    process.exit(1);
  });

  wallet.on("sync_started", async () => {
    console.log("sync_started");
  });

  wallet.on("sync_finished", async () => {
    console.log("sync_finished");
    console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`);
  });

  wallet.on("bootstrap_started", () => {
    console.log("bootstrap_started");
  });

  wallet.on("bootstrap_progress", (count) => {
    //console.log("bootstrap_progress", count);
  });

  wallet.on("bootstrap_finished", () => {
    console.log("bootstrap_finished");
  });

  wallet.on("new_tx", async (list) => {
    console.log(`Received transaction ${JSON.stringify(list)}`);
    console.log(`Balance ${JSON.stringify(await wallet.GetBalance())}`);
  });

  await wallet.Load({
    bootstrap: njs.wallet.xNavBootstrap,
  });
});
