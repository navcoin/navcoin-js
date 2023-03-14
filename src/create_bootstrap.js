"use strict";

global.window = global;

const setGlobalVars = require("indexeddbshim");

setGlobalVars(null, {
  checkOrigin: false,
});

const njs = require("./index.js");
const fs = require("fs");

const network = process.argv[2] || "mainnet";
let wallet;
let lastProgress = undefined;
njs.wallet.Init().then(async () => {
  wallet = new njs.wallet.WalletFile({
    mnemonic:
      "record clap flush target road finger price wrong file ethics time suit", // it is important that this mnemonic is empty and has no transactions
    file: "bootstrap_" + network,
    network: network,
  });
  wallet.on("loaded", async () => {
    await wallet.Connect();
  });
  wallet.on("connected", () => console.log("connected. waiting for sync"));
  wallet.on("sync_status", async (progress, pending) => {
    if (progress != lastProgress) console.log("Sync ".concat(progress, "%"));
    lastProgress = progress;
  });
  wallet.on("db_load_error", async (err) => {
    console.log("Error Load DB: ".concat(err));
    process.exit(1);
  });
  wallet.on("sync_finished", async () => {
    let path = `./src/lib/xnav_bootstrap_${network}.js`;
    fs.writeFile(
      path,
      JSON.stringify(await wallet.db.GetAllTxKeys()),
      (err) => {
        if (err) throw err;
        console.log("Data written to " + path);
      }
    );
  });
  await wallet.Load({
    bootstrap: njs.wallet.xNavBootstrap,
  });
});
//# sourceMappingURL=example.js.map
