import * as crypto from "crypto";
import * as Db from "./db/index.js";
import * as events from "events";
import { default as List } from "./utils/list.js";

import { default as Mnemonic } from "@aguycalled/bitcore-mnemonic";
import * as electrumMnemonic from "electrum-mnemonic";
import { default as bitcore } from "@aguycalled/bitcore-lib";
import { default as electrum } from "@aguycalled/electrum-client-js";
import { default as _ } from "lodash";
import { default as Message } from "@aguycalled/bitcore-message";
export { default as bitcore } from "@aguycalled/bitcore-lib";
export { default as Mnemonic } from "@aguycalled/bitcore-mnemonic";
export * as electrumMnemonic from "electrum-mnemonic";

import { default as nodes } from "./nodes/index.js";
import { default as queue } from "./utils/queue.js";
import { default as OutputTypes } from "./utils/output_types.js";
import { default as AddressTypes } from "./utils/address_types.js";
export { default as OutputTypes } from "./utils/output_types.js";
export { default as AddressTypes } from "./utils/address_types.js";

import * as constants from "./utils/constants";
import { sha256sha256 } from "@aguycalled/bitcore-lib/lib/crypto/hash";

import { Logger } from './logger.js';
import { GetAddress } from "./get_address.js";
import { errObj, RECONNECT_NODE } from "./utils/error.js";
import { GetInfo } from "./get_info.js";
import { AssetBalance } from "./asset_balance.js";
import { getTip } from "./get_tip.js";
export { default as getTip } from "./get_tip.js";
import { isMyName, getMyTokens, addName, getMyNames, getStatusHashForScriptHash, getPoolSize } from "./db_requests.js";
export { isMyName, getMyTokens, addName, getMyNames, getPoolSize } from "./db_requests.js";
import { isValidDotNavKey, isValidDotNavName } from './validate_value.js';
export { isValidDotNavKey, isValidDotNavName } from "./validate_value.js";
import { getMasterKey, getMasterSpendKey, getMasterViewKey, getPrivateKey, setMasterKey, navGetPrivateKeys } from "./key_request.js";
export { getMasterKey, getMasterSpendKey, getMasterViewKey, getPrivateKey, setMasterKey, navGetPrivateKeys } from "./key_request.js";
import { TxProcessor } from "./tx_processor.js";
import { StakingAddress } from "./staking_address.js";
import { encrypt, decrypt } from "./crypt.js";
const p2p = require("@aguycalled/bitcore-p2p").Pool;

export * as xNavBootstrap from "./xnav_bootstrap.js";

let db = Db["Dexie"].default;

export const Init = async () => {
  await blsct.Init();
};

export const SetBackendDb = (backend) => {
  db = backend;
};

const blsct = bitcore.Transaction.Blsct;
const ripemd160 = bitcore.crypto.Hash.ripemd160;
const sha256 = bitcore.crypto.Hash.sha256;

function msleep(n) {
  return new Promise((resolve) => setTimeout(resolve, n));
}
function sleep(n) {
  msleep(n * 1000);
}

export class WalletFile extends events.EventEmitter {
  constructor(options) {
    super();

    options = options || {};

    this.file = options.file;
    this.type = options.type || "navcoin-js-v1";
    this.mnemonic = options.mnemonic;
    this.spendingPassword = options.spendingPassword;
    this.secret = options.password || "secret navcoinjs";
    this.zapwallettxes = options.zapwallettxes || false;
    this.log = options.log || false;
    this.dbBackend = options.dbBackend || Db["Dexie"].default;
    this.indexedDB = options.indexedDB;
    this.IDBKeyRange = options.IDBKeyRange;

    this.queue = new queue(options.queueSize);
    this.p2pPool = undefined;


    this.queue.on("progress", (progress, pending, total) => {
      this.emit("sync_status", progress, pending, total);
    });

    this.queue.on("end", async () => {
      if ((await getPoolSize(this.db, AddressTypes.XNAV)) < this.GetMinPoolSize()) {
        this.Log.Message("Need to fill the xNAV key pool");
        await this.xNavFillKeyPool(
          this.spendingPassword,
          this.GetMinPoolSize() * 2
        );
      } else {
        this.spendingPassword = "";
        this.emit("sync_finished");
      }
    });

    this.queue.on("started", () => {
      this.emit("sync_started");
    });

    this.network = options.network || "mainnet";
    this.db = new this.dbBackend();

    this.db.on("db_load_error", (e) => {
      this.emit("db_load_error", e);
      this.Disconnect();
    });

    this.db.on("db_open", () => {
      this.Log.Message("Database is Open....")
      this.emit("db_open");
    });

    this.db.on("db_closed", () => {
      this.emit("db_closed");
      this.Disconnect();
    });

    this.Log = new Logger(this.log);
    this.assetBalance = new AssetBalance({ client: this.client, db: this.db, log: this.log });
    this.getAddress = new GetAddress({
      client: this.client,
      db: this.db,
      assetBalance: this.assetBalance,
      log: this.log
    });
    this.getInfo = new GetInfo(this.client, this.db);
    this.txProcessor = new TxProcessor({
      client: this.client,
      db: this.db,
      network: this.network,
      error: this.ManageElectrumError,
      addOutput: this.AddOutput,
      deriveSpendingKeyFromStringHash: this.DeriveSpendingKeyFromStringHash,
      spendingPassword: this.spendingPassword,
      log: this.log,
    });
    this.stakingAddress = new StakingAddress({ db: this.db, sync: this.Sync, network: this.network })


  }

  async InitDb(options = {}) {
    await this.db.Open(
      this.file,
      this.secret,
      this.indexedDB,
      this.IDBKeyRange
    );

    delete this.secret;
  }

  CloseDb() {
    this.removeAllListeners();
    this.db.Close();
  }

  static async ListWallets() {

    return await db.ListWallets();
  }

  static async SetBackend(indexedDB, IDBKeyRange) {
    return await db.SetBackend(indexedDB, IDBKeyRange);
  }

  static async RemoveWallet(filename) {
    return await db.RemoveWallet(filename);
  }


  async ManageElectrumError(e) {
    if (
      e == errObj.closeConnect ||
      e == errObj.notEstablished ||
      e
        .toString()
        .substr(0, errObj.electrumServer.length) ==
      errObj.electrumServer ||
      e == errObj.serverBusy
    ) {
      this.connected = false;
      this.electrumNodeIndex =
        (this.electrumNodeIndex + 1) % this.electrumNodes.length;

      this.emit(errObj.failedConnection);

      if (this.client) this.client.close();

      this.failedConnections = this.failedConnections + 1;

      this.Log.Message(`${RECONNECT_NODE} ${this.electrumNodeIndex}`);

      if (this.failedConnections >= this.electrumNodes.length) {
        this.emit(errObj.noServer);
        sleep(5);
        await this.Connect(true);

      } else {
        sleep(1);
        await this.Connect(false);

      }
    }

    if (e === errObj.serverBusy) {
      sleep(5);
    }
  }

  GetMinPoolSize() {
    return this.minPoolSize || 10;
  }

  async Load(options) {
    if (!this.db) throw new Error("DB did not load.");

    await this.InitDb();

    options = options || {};

    this.daoConsultations = {};
    this.daoProposals = {};
    this.minPoolSize = options.minPoolSize;
    this.useP2p = options.useP2p === undefined ? true : options.useP2p;

    if (!this.db.open) throw new Error("DB did not load.");

    let network = await this.db.GetValue("network");
    this.Log.Message(network, ' NETWORK');

    if (!network) {
      await this.db.SetValue("network", this.network);
    } else {
      this.network = network;
    }

    if (!(await this.db.GetValue("masterPubKey"))) {
      await this.db.SetValue("walletType", this.type);
      let mnemonic = this.mnemonic;

      if (!this.mnemonic) {
        this.newWallet = true;
        mnemonic = new Mnemonic().toString();
        this.emit("new_mnemonic", mnemonic);
      }

      await this.db.AddMasterKey("mnemonic", mnemonic, this.spendingPassword);

      if (this.type === "watch" && options.watch) {
        await this.ImportWatchAddress(options.watch);

        let masterKey = await new Mnemonic(mnemonic).toHDPrivateKeyAsync(
          "",
          this.network
        );

        await setMasterKey(this.db, masterKey, this.spendingPassword, this.type);
      } else if (this.type === "next") {
        let value = Buffer.from(new Mnemonic(mnemonic).toString());
        let hash = bitcore.crypto.Hash.sha256(value);
        let bn = bitcore.crypto.BN.fromBuffer(hash);
        let pk = new bitcore.PrivateKey(bn);

        await this.ImportPrivateKey(pk, this.spendingPassword);

        let masterKey = await new Mnemonic(mnemonic).toHDPrivateKeyAsync(
          "",
          this.network
        );

        await setMasterKey(this.db, masterKey, this.spendingPassword, this.type);
      } else if (this.type === "navcoin-core") {
        let keyMaterial = Mnemonic.mnemonicToData(mnemonic);

        await setMasterKey(this.db, keyMaterial, this.spendingPassword, this.type);
      } else if (this.type === "navcash") {
        let masterKey = bitcore.HDPrivateKey.fromSeed(
          await electrumMnemonic.mnemonicToSeed(mnemonic, {
            prefix: electrumMnemonic.PREFIXES.standard,
          })
        );

        await setMasterKey(this.db, masterKey, this.spendingPassword, this.type);
      } else {
        let masterKey = await new Mnemonic(mnemonic).toHDPrivateKeyAsync(
          "",
          this.network
        );

        await setMasterKey(this.db, masterKey, this.spendingPassword, this.type);
      }

      if (options.bootstrap) {
        let bootstrap = options.bootstrap[this.network]
          ? options.bootstrap[this.network]
          : options.bootstrap;
        for (let i in bootstrap) {
          bootstrap[i].hash = bootstrap[i].txidkeys;
          delete bootstrap[i].txidkeys;
        }

        await this.db.BulkRawInsert(bootstrap);
      }
    }

    this.type = (await this.db.GetValue("walletType")) || "navcoin-js-v1";

    this.electrumNodes =
      options.nodes && option.nodes[this.network]
        ? option.nodes[this.network]
        : nodes[this.network];

    if (!this.electrumNodes.length) {
      throw new Error("Wrong network");
    }

    this.electrumNodeIndex = Math.floor(
      Math.random() * this.electrumNodes.length
    );

    this.mvk = await getMasterViewKey(this.db);

    this.firstSynced = {};
    this.firstSyncCompleted = false;
    this.creationTip = undefined;
    this.failedConnections = 0;

    let creationTipDb = await this.db.GetValue("creationTip");

    if (creationTipDb) {
      this.creationTip = creationTipDb;
    } else if (options.syncFromBlock) {
      this.creationTip = options.syncFromBlock;
      await this.db.SetValue("creationTip", this.creationTip);
    }

    if (await getMasterKey("nav", this.spendingPassword, this.db)) {
      await this.xNavFillKeyPool(this.spendingPassword, this.GetMinPoolSize());
      await this.NavFillKeyPool(this.spendingPassword, this.GetMinPoolSize());
    }

    if (this.newWallet || (await this.db.GetStakingAddresses())?.length == 0) {
      let pool =
        this.network == "mainnet"
          ? "NfLgDYL4C3KKXDS8tLRAFM7spvLykV8v9A"
          : "n3uJuww32YGUbsoywpmG1LmgVQYMsg5Ace";
      await this.stakingAddress.AddStakingAddress(pool, undefined, false);
      await this.db.AddLabel(pool, "NavCash Pool");
    }

    this.poolFilled = true;

    this.mnemonic = "";

    let forceZap = false;

    if (
      (await this.db.GetUtxos(true)).length > 0 &&
      (await this.db.GetTxs()).length == 0
    )
      forceZap = true;

    if (this.zapwallettxes || forceZap) {
      await this.db.ZapWalletTxes();
    }

    this.emit("loaded");
  }

  async xNavFillKeyPool(spendingPassword, count = 10) {
    let mk = await getMasterKey("xNavSpend", spendingPassword, this.db);

    if (!mk) return;

    let filled = 0;

    while ((await getPoolSize(this.db, AddressTypes.XNAV)) < count) {
      filled++;
      await this.xNavCreateSubaddress(spendingPassword);
    }

    if (this.poolFilled && filled > 0) {
      this.Log.Message("xNAV pool was filled with " + filled + " new keys. Resyncing.");
      await this.SyncScriptHash(
        Buffer.from(
          bitcore.crypto.Hash.sha256(
            bitcore.Script.fromHex("51").toBuffer()
          ).reverse()
        ).toString("hex"),
        undefined,
        true
      );
    }
  }

  async NavFillKeyPool(spendingPassword, count = 10) {
    if (this.type === "next" || this.type == "watch") return;

    let mk = await getMasterKey("nav", spendingPassword, this.db);

    if (!mk) return;

    let filled = 0;

    while ((await getPoolSize(this.db, AddressTypes.NAV)) < count) {
      filled++;
      await this.NavCreateAddress(spendingPassword);
    }

    if (this.type == "navcash" || this.type == "navcoin-core") {
      while ((await getPoolSize(this.db, AddressTypes.NAV, 1)) < count) {
        filled++;
        await this.NavCreateAddress(spendingPassword, 1);
      }
    }

    this.Log.Message("NAV pool was filled with " + filled + " new keys.");
  }

  async xNavCreateSubaddress(sk, acct = 0) {
    let masterViewKey = this.mvk;

    let masterSpendKey = await getMasterSpendKey(this.db, sk);

    if (!masterSpendKey) return;

    let index = 0;

    let dbLastIndex = await this.db.GetCounter("xNav" + acct);

    index = dbLastIndex || index;

    let { viewKey, spendKey } = blsct.DerivePublicKeys(
      masterViewKey,
      masterSpendKey,
      acct,
      index
    );

    let hashId = new Buffer(ripemd160(sha256(spendKey.serialize()))).toString(
      "hex"
    );

    await this.db.UpdateCounter("xNav" + acct, index + 1);
    try {
      await this.db.AddKey(
        hashId,
        [acct, index],
        AddressTypes.XNAV,
        blsct.KeysToAddress(viewKey, spendKey).toString(),
        false,
        false,
        acct + "/" + parseInt(index)
      );
    } catch (e) {
      console.log(e.message);
    }
  }

  async NavCreateAddress(sk, change = 0) {
    if (this.type === "next") return;

    let mk = await getMasterKey("nav", sk, this.db);

    if (!mk) return;

    let labelCounter =
      change == 2 ? "NavVote" : change == 1 ? "NavChange" : "Nav";

    let dbLastIndex = await this.db.GetCounter(labelCounter);

    let index = dbLastIndex || 0;

    let path = "m/44'/130'/0'/" + change + "/" + index;
    let privK;

    if (this.type === "next") {
      if (index === 0 && !change) {
        index++;
      }

      path = "m/" + change + "/" + index;
      privK = bitcore.HDPrivateKey(mk).deriveChild(path);
    } else if (this.type === "navcash") {
      path = "m/" + change + "/" + index;
      privK = bitcore.HDPrivateKey(mk).deriveChild(path);
    } else if (this.type === "navcoin-js-v1") {
      privK = bitcore.HDPrivateKey(mk).deriveChild(path);
    } else if (this.type === "navpay") {
      path = "m/44'/0'/0'/" + change + "/" + index;
      privK = bitcore.HDPrivateKey(mk).deriveChild(path);
    } else if (this.type === "navcoin-core") {
      path = "m/0'/" + change + "'/" + index + "'";
      privK = bitcore.HDPrivateKey(mk).deriveChild(path);
    }

    let pk = privK.publicKey;
    let hashId = new Buffer(ripemd160(sha256(pk.toBuffer()))).toString("hex");
    let addrStr = bitcore.Address(pk, this.network).toString();

    await this.db.UpdateCounter(labelCounter, index + 1);
    try {
      await this.db.AddKey(
        hashId,
        privK.toString(),
        AddressTypes.NAV,
        addrStr,
        false,
        change,
        path,
        sk
      );
    } catch (e) {
      console.log(e.message);
    }

    if (this.poolFilled) {
      await this.SyncScriptHash(this.AddressToScriptHash(addrStr));
    }
  }

  async ImportPrivateKey(privK, key) {
    if (_.isString(privK)) {
      return this.ImportPrivateKey(bitcore.PrivateKey.fromWIF(privK), key);
    }

    let path = "imported";
    let pk = privK.publicKey;
    let hashId = new Buffer(ripemd160(sha256(pk.toBuffer()))).toString("hex");

    try {
      await this.db.AddKey(
        hashId,
        privK.toString(),
        AddressTypes.NAV,
        bitcore.Address(pk, this.network).toString(),
        false,
        false,
        path,
        key
      );
    } catch (e) {
      console.log(e.message);
    }

    if (this.connected) {
      await this.Sync();
    }
  }

  async ImportWatchAddress(address, key) {
    if (_.isString(address)) {
      return this.ImportWatchAddress(bitcore.Address(address), key);
    }

    let path = "watch";
    let pk = address;
    let hashId = pk.toObject().hash;
    try {
      await this.db.AddKey(
        hashId,
        address.toString(),
        AddressTypes.NAV,
        bitcore.Address(pk, this.network).toString(),
        false,
        false,
        path,
        key
      );
    } catch (e) {
      console.log(e.message);
    }

    if (this.connected) {
      await this.Sync();
    }
  }

  async SetTip(height) {
    this.lastBlock = height;
    this.emit("new_block", height);
    await this.db.SetValue("ChainTip", height);
  }


  AddressToScriptHash(address) {
    return this.ScriptToScriptHash(bitcore.Script.fromAddress(address));
  }

  ScriptToScriptHash(script) {
    return Buffer.from(
      bitcore.crypto.Hash.sha256(script.toBuffer()).reverse()
    ).toString("hex");
  }

  async ResolveName(name, subdomains = false) {
    try {
      return this.client.blockchain_dotnav_resolveName(name, subdomains);
    } catch (e) {
      console.log("ResolveName", e);
      await this.ManageElectrumError(e);
      return await this.ResolveName(name, subdomains);
    }
  }

  async GetScriptHashes(stakingAddress = undefined) {
    if (!this.client) return;

    let ret = [];

    let addresses = await this.db.GetNavAddresses();

    for (let i in addresses) {
      if (!stakingAddress) {
        if (!this.requestedStakingKeys) {
          let stakingAddresses = await this.client.blockchain_staking_getKeys(
            new Buffer(addresses[i].hash, "hex").reverse().toString("hex")
          );

          for (let j in stakingAddresses) {
            await this.stakingAddress.AddStakingAddress(
              stakingAddresses[j][0],
              stakingAddresses[j][1],
              false
            );
          }
        }

        ret.push(this.AddressToScriptHash(addresses[i].address));
      } else {
        ret.push(
          this.ScriptToScriptHash(
            new bitcore.Script.fromAddresses(
              stakingAddress,
              bitcore.Address(addresses[i].address)
            )
          )
        );
      }
    }

    this.requestedStakingKeys = true;

    if (!stakingAddress)
      ret.push(
        Buffer.from(
          bitcore.crypto.Hash.sha256(
            bitcore.Script.fromHex("51").toBuffer()
          ).reverse()
        ).toString("hex")
      );

    return ret;
  }

  ClearNodeList() {
    this.electrumNodes = [];
  }

  AddNode(host, port, proto) {
    this.electrumNodes.push({
      host,
      port,
      proto,
    });
  }

  async Connect(resetFailed = true) {
    if (this.client && this.client.status == 1) return false;

    this.Disconnect();

    console.log("this.electrumNodes[this.electrumNodeIndex]..", this.electrumNodes[this.electrumNodeIndex])

    if (!this.electrumNodes[this.electrumNodeIndex]) this.electrumNodeIndex = 0;

    if (!this.electrumNodes[this.electrumNodeIndex])
      throw new Error("No nodes in the list, use AddNode");

    this.emit("connecting");

    this.client = new electrum(
      this.electrumNodes[this.electrumNodeIndex].host,
      this.electrumNodes[this.electrumNodeIndex].port,
      this.electrumNodes[this.electrumNodeIndex].proto
    );

    this.Log.Message(
      `Trying to connect to ${this.electrumNodes[this.electrumNodeIndex].host
      }:${this.electrumNodes[this.electrumNodeIndex].port}`
    );

    this.client.subscribe.on("socket.error", async (e) => {
      this.connected = false;
      this.emit("disconnected");
      this.emit("connection_failed");
      console.error(
        `error connecting to electrum ${this.electrumNodes[this.electrumNodeIndex].host
        }:${this.electrumNodes[this.electrumNodeIndex].port}: ${e}`
      );

      await this.ManageElectrumError(e);
    });

    this.client.subscribe.on("ready", async () => {
      console.log("I am connected    ")
      this.emit(
        "connected",
        this.electrumNodes[this.electrumNodeIndex].host +
        ":" +
        this.electrumNodes[this.electrumNodeIndex].port
      );

      console.info(
        `success connecting to electrum ${this.electrumNodes[this.electrumNodeIndex].host
        }:${this.electrumNodes[this.electrumNodeIndex].port}`
      );

      this.connected = true;

      if (resetFailed) this.failedConnections = 0;

      this.emit("bootstrap_started");

      let tip = (await this.client.blockchain_headers_subscribe()).height;
      this.client.blockchain_consensus_subscribe().then((consensus) => {
        this.db.WriteConsensusParameters(consensus);
      });
      await this.client.blockchain_dao_subscribe();

      await this.SetTip(tip);

      if (this.newWallet && !this.creationTip && this.type != "watch") {
        this.creationTip = tip;
        await this.db.SetValue("creationTip", tip);
      }

      this.client.subscribe.on(
        "blockchain.headers.subscribe",
        async (event) => {
          await this.SetTip(event[0].height);
        }
      );

      this.client.subscribe.on(
        "blockchain.outpoint.subscribe",
        async (event) => {
          if (event[1] && event[1].spender_txhash)
            await this.db.RemoveTxCandidate(
              event[0][0] + ":" + event[0][1],
              this.network
            );
        }
      );

      this.client.subscribe.on(
        "blockchain.consensus.subscribe",
        async (event) => {
          await this.db.WriteConsensusParameters(event);
        }
      );

      let candidates = await this.db.GetCandidates(this.network);

      for (let i in candidates) {
        let currentStatus = await this.client.blockchain_outpoint_subscribe(
          candidates[i].input.split(":")[0],
          candidates[i].input.split(":")[1]
        );
        if (currentStatus && currentStatus.spender_txhash)
          await this.db.RemoveTxCandidate(candidates[i].input, this.network);
      }

      if (this.useP2p) {
        this.p2pPool = new p2p({
          dnsSeed: false, // prevent seeding with DNS discovered known peers upon connecting
          listenAddr: false, // prevent new peers being added from addr messages
          network: this.network,
          maxSize: 1,
          addrs: [
            // initial peers to connect to
            {
              ip: {
                v4: this.electrumNodes[this.electrumNodeIndex].host,
              },
            },
          ],
        });
      }

      if (this.p2pPool && (await this.GetCandidates()).length < 100) {
        console.log("connecting to p2p");
        this.p2pPool.on("candidate", this.NewCandidate);
        this.p2pPool.on("peerready", (_, server) => {
          if (this.p2pPool) {
            let sessionId = this.p2pPool.startSession();
            console.log("started session", sessionId);
          }
        });
        this.p2pPool.connect();
      }

      this.client.subscribe.on("blockchain.dao.subscribe", async (event) => {
        let type =
          event[0].t == "c" ? this.daoConsultations : this.daoProposals;
        let hash = event[0].w.hash;
        let remove = event[0].r;

        if (event[0].t == "c") {
          this.emit(
            remove ? "dao_consultation_remove" : "dao_consultation",
            event[0].w
          );
        } else if (event[0].t == "p") {
          this.emit(
            remove ? "dao_proposal_remove" : "dao_proposal",
            event[0].w
          );
        }

        if (remove) {
          delete type[hash];
        } else {
          type[hash] = event[0].w;
        }
      });
      if (!this.client) return;

      await this.Sync();

      this.client.subscribe.on(
        "blockchain.scripthash.subscribe",
        async (event) => {
          console.log("event  ", event, event[0], event[1])
          await this.ReceivedScriptHashStatus(event[0], event[1]);
        }
      );
    });

    await this.client.connect("navcoin-js", "1.5");

    if (this.client.status == 0) return false;
  }

  async GetCandidates() {
    return await this.db.GetCandidates(this.network);
  }

  async GetConsensusParameters() {
    return await this.db.GetConsensusParameters();
  }

  GetConsultations() {
    return this.daoConsultations;
  }

  GetProposals() {
    return this.daoProposals;
  }

  async QueueTx(hash, inMine, height, requestInputs, priority) {
    this.queue.add(
      this,
      this.txProcessor.GetTx,
      [hash, inMine, height, requestInputs],
      priority
    );
  }

  async QueueTxKeys(hash, height, useCache, priority) {
    this.queue.add(this, this.GetTxKeys, [hash, height, useCache], priority);
  }

  async Sync(staking = undefined) {
    if (!this.client || this.client.status === 0) {
      await this.Connect();
    }

    let txs = new List();

    this.emit("bootstrap_started");

    txs.on("push", () => {
      this.emit("bootstrap_progress", txs.list.length);
    });

    await this.SyncTxHashes(staking, txs);

    for (let tx of txs.list) {
      await this.QueueTxKeys(tx[0], tx[1], tx[2]);
    }

    this.emit("bootstrap_finished");

    if (txs.list.length == 0) {
      this.spendingPassword = "";
      this.emit("sync_finished");
    }
  }

  async SyncTxHashes(staking = undefined, txs) {
    let scriptHashes = await this.GetScriptHashes(staking);

    if (!this.alreadyQueued && !staking) {
      let pending = await this.db.GetPendingTxs();

      for (let j in pending) {
        txs.push([pending[j].tx_hash, pending[j].height, true], false);
      }

      this.emit("bootstrap_progress", txs.list.length);

      this.Log.Message(`Queuing ${pending.length} pending transactions`);
      this.alreadyQueued = true;

      for (let i in scriptHashes) {
        let s = scriptHashes[i];
        this.firstSynced[s] = false;
      }
    }

    for (let i in scriptHashes) {
      let s = scriptHashes[i];

      try {
        this.firstSynced[s] = false;
        if (!this.client) continue;
        let currentStatus = await this.client.blockchain_scripthash_subscribe(
          s
        );
        await this.ReceivedScriptHashStatus(s, currentStatus, txs);
      } catch (e) {
        if (
          e ==
          "TypeError: Cannot read properties of undefined (reading 'blockchain_scripthash_subscribe')"
        )
          break;
        console.log("ReceivedScriptHashStatus", e);
        await this.ManageElectrumError(e);
        return await this.SyncTxHashes(staking, txs);
      }
    }

    if (!staking) {
      let stakingAddresses = await this.getAddress.GetStakingAddresses();

      for (let k in stakingAddresses) {
        let address = stakingAddresses[k];
        await this.SyncTxHashes(address, txs);
      }
    }
  }


  Disconnect() {
    if (this.client) this.client.close();
    this.connected = false;
    this.queue.stop();

    if (this.p2pPool) this.p2pPool.disconnect();
    this.p2pPool = undefined;

    delete this.client;
    this.emit("disconnected");
  }

  async ReceivedScriptHashStatus(s, status, txs) {
    // console.log("ReceivedScriptHashStatus  ", s, status, txs)
    let prevStatus = await getStatusHashForScriptHash(this.db, s);
    // console.log("prevStatus  ",prevStatus)

    if (status && status !== prevStatus) {
      await this.db.SetStatusForScriptHash(s, status);

      this.Log.Message(`Received new status ${status} for ${s}. Syncing.`);

      if (!txs) {
        this.queue.add(
          this,
          this.SyncScriptHash,
          [s],
          true,
          !this.firstSyncCompleted
        );
      } else {
        await this.SyncScriptHash(s, txs);
      }
    } else {
      this.firstSynced[s] = true;

      if (!this.firstSyncCompleted) {
        this.firstSyncCompleted = true;

        for (let i in this.firstSynced) {
          this.firstSyncCompleted &= this.firstSynced[i];
        }
      }
    }
  }

  async SyncScriptHash(scripthash, txs, reset = false) {
    let currentHistory = [];
    let prevMaxHeight = -10;
    let lb = this.lastBlock + 0;

    this.Log.Message("Syncing " + scripthash);

    let historyRange = {};

    while (true) {
      try {
        currentHistory = await this.db.GetScriptHashHistory(scripthash);
      } catch (e) {
        this.Log.Message(`error getting history from db: ${e}`);
      }

      let currentLastHeight = this.creationTip ? this.creationTip : 0;

      if (!reset) {
        for (let i in currentHistory) {
          if (currentHistory[i].height > currentLastHeight)
            currentLastHeight = currentHistory[i].height;
        }
      }

      let filteredHistory = currentHistory.filter(
        (e) => e.height >= 0 && e.height < Math.max(1, currentLastHeight - 10)
      );
      historyRange = currentHistory
        .filter((x) => !filteredHistory.includes(x))
        .reduce(function (map, obj) {
          map[obj.tx_hash] = obj;
          return map;
        }, {});
      currentHistory = filteredHistory;

      await this.db.CleanScriptHashHistory(
        scripthash,
        0,
        Math.max(1, currentLastHeight - 10)
      );

      let newHistory = [];

      try {
        this.Log.Message(
          `requesting tx history for ${scripthash} from ${currentLastHeight - 10
          }`
        );

        if (!this.client) return;

        newHistory = await this.client.blockchain_scripthash_getHistory(
          scripthash,
          Math.max(0, currentLastHeight - 10)
        );
        this.Log.Message(
          `${scripthash}: received ${newHistory.history.length} transactions`
        );
      } catch (e) {
        this.Log.Message(`error getting history: ${e}`);
        await this.ManageElectrumError(e);
        return false;
      }

      if (!newHistory.history.length || newHistory.history.length == 0) break;

      let maxHeight;

      for (let i in newHistory.history) {
        if (newHistory.history[i].height > maxHeight)
          maxHeight = newHistory.history[i].height;
      }

      if (maxHeight == prevMaxHeight) break;

      prevMaxHeight = maxHeight;

      currentLastHeight = 0;
      let reachedMempool = newHistory.to_height == -1;
      let toAddBulk = [];

      for (let j in newHistory.history) {
        if (newHistory.history[j].height > currentLastHeight)
          currentLastHeight = newHistory.history[j].height;

        if (newHistory.history[j].height <= 0) reachedMempool = true;

        currentHistory.push(newHistory.history[j]);

        toAddBulk.push({
          id: scripthash + "_" + newHistory.history[j].tx_hash,
          scriptHash: scripthash,
          tx_hash: newHistory.history[j].tx_hash,
          height: newHistory.history[j].height,
          fetched: 0,
        });

        let hash = newHistory.history[j].tx_hash;
        let height = newHistory.history[j].height;
      }

      await this.db.BulkRawInsertHistory(toAddBulk);

      for (var i in toAddBulk) {
        if (txs) {
          txs.push([toAddBulk[i].tx_hash, toAddBulk[i].height, true], false);
          if (i % 100 == 0) this.emit("bootstrap_progress", txs.list.length);
        } else {
          await this.QueueTxKeys(
            toAddBulk[i].tx_hash,
            toAddBulk[i].height,
            true
          );

          if (i % 100 == 0) this.queue.emitProgress();
        }
      }

      if (txs) {
        this.emit("bootstrap_progress", txs.list.length);
      }

      toAddBulk = [];

      this.queue.emitProgress();

      if (reachedMempool || (currentLastHeight >= lb && lb > 0)) break;
    }

    this.Log.Message(`Finished receiving transaction list for script ${scripthash}`);

    /*for (let e in historyRange)
      {
          await this.db.asyncRemove({wallettxid: historyRange[e].tx_hash}, { multi: true })
          await this.db.asyncRemove({outPoint: {$regex: new RegExp(`^${historyRange[e].tx_hash}:`)}}, { multi: true })

          let tx = await this.GetTx(historyRange[e].tx_hash)

          for (let i in tx.tx.inputs)
          {
              let input = tx.tx.inputs[i].toObject();

              await this.Spend(`${input.prevTxId}:${input.outputIndex}`, '')

              await this.db.asyncRemove({outPoint: `${input.prevTxId}:${input.outputIndex}`}, { multi: true })
          }

          this.emit('remove_tx', historyRange[e].tx_hash);
      }*/

    if (!this.firstSynced) return;

    this.firstSynced[scripthash] = true;

    if (!this.firstSyncCompleted) {
      this.firstSyncCompleted = true;

      for (let i in this.firstSynced) {
        this.firstSyncCompleted &= this.firstSynced[i];
      }

      if (this.firstSyncCompleted) {
        //this.emit("sync_started");
      }
    } else {
      //this.emit("sync_started");
    }
  }

  Sign(key, msg) {
    if (_.isString(key)) {
      return this.Sign(bitcore.PrivateKey.fromWIF(key), msg);
    }
    return Message(msg).sign(key);
  }

  VerifySignature(address, msg, sig) {
    return Message(msg).verify(address, sig);
  }

  async GetHistory() {
    return await this.db.GetWalletHistory();
  }

  /** Get Unspent transaction output **/
  async GetUtxos(
    type = OutputTypes.NAV | OutputTypes.STAKED,
    address = undefined,
    tokenId = new Buffer(new Uint8Array(32)),
    tokenNftId = -1
  ) {
    if (address instanceof bitcore.Address)
      return await this.GetUtxos(type, address.hashBuffer, tokenId, tokenNftId);

    if (typeof address === "string" && !bitcore.util.js.isHexa(address))
      return await this.GetUtxos(
        type,
        bitcore.Address(address),
        tokenId,
        tokenNftId
      );

    if (typeof address === "object") address = address.toString("hex");

    let utxos = await this.db.GetUtxos();

    let tip = await getTip(this.db);

    let ret = [];

    for (let u in utxos) {
      let utxo = utxos[u];

      if (!(utxo.type & type)) continue;

      let outpoint = utxo.id.split(":");
      let tx = await this.db.GetTx(outpoint[0]);

      let pending = false;

      if (
        (tx.pos < 2 && tip - tx.height < 120) ||
        (tx.height <= 0 && type == OutputTypes.XNAV)
      )
        pending = true;

      if (!pending) {
        let out = bitcore.Transaction.Output.fromBufferReader(
          new bitcore.encoding.BufferReader(new Buffer(utxo.out, "hex"))
        );

        out.tokenId = out.tokenId;

        if (
          out.tokenId &&
          out.tokenNftId &&
          !(
            out.tokenId.toString("hex") == tokenId.toString("hex") &&
            out.tokenNftId == tokenNftId
          )
        )
          continue;

        if (address) {
          if (utxo.type & OutputTypes.STAKED && utxo.stakingPk != address) {
            continue;
          } else if (
            utxo.type & OutputTypes.NAV &&
            utxo.spendingPk != address
          ) {
            continue;
          }
          if (utxo.type & OutputTypes.VOTING && utxo.votingPk != address) {
            continue;
          }
        }

        let item = {
          txid: outpoint[0],
          vout: outpoint[1],
          output: out,
          amount: utxo.amount,
          type: utxo.type,
          tokenId: out.tokenId.toString("hex"),
          tokenNftId: out.tokenNftId == -1 ? undefined : out.tokenNftId,
          stakingPk: utxo.stakingPk,
          votingPk: utxo.votingPk,
          spendingPk: utxo.spendingPk,
        };

        if (out.isCt() || out.isNft()) {
          let hashid = new Buffer(blsct.GetHashId(out, this.mvk)).toString(
            "hex"
          );
          item.accIndex = await this.db.GetKey(hashid);
        }

        ret.push(item);
      }
    }

    return ret;
  }

  async AddOutput(outpoint, out, height) {
    let amount = out.amount ? out.amount : out.satoshis;
    let label = out.isCt()
      ? out.memo
      : out.script.toAddress(this.network).toString();
    let isCold =
      out.script.isColdStakingOutP2PKH() || out.script.isColdStakingV2Out();

    let type = 0x0;

    if (out.isCt() || out.isNft()) type |= OutputTypes.XNAV;
    else {
      if (isCold) type |= OutputTypes.STAKED;
      else type |= OutputTypes.NAV;
    }

    try {
      let stakingPk;
      let spendingPk;
      let votingPk;
      let hashId;

      if (out.script.isColdStakingOutP2PKH()) {
        spendingPk = out.script.getPublicKeyHash().toString("hex");
        stakingPk = out.script.getStakingPublicKeyHash().toString("hex");
      } else if (out.script.isColdStakingV2Out()) {
        spendingPk = out.script.getPublicKeyHash().toString("hex");
        stakingPk = out.script.getStakingPublicKeyHash().toString("hex");
        votingPk = out.script.getVotingPublicKeyHash().toString("hex");
      } else if (out.script.isPublicKeyOut()) {
        spendingPk = ripemd160(sha256(out.script.getPublicKey())).toString(
          "hex"
        );
      } else if (out.script.isPublicKeyHashOut()) {
        spendingPk = out.script.getPublicKeyHash().toString("hex");
      }

      if (out.isCt() || out.isNft()) {
        hashId = new Buffer(blsct.GetHashId(out, this.mvk)).toString("hex");
      }

      await this.db.AddUtxo(
        outpoint,
        out.toBufferWriter().toBuffer().toString("hex"),
        "",
        amount,
        label,
        type,
        spendingPk,
        stakingPk,
        votingPk,
        hashId
      );

      if (!(out.isCt() || out.isNft())) {
        await this.db.UseNavAddress(
          out.script.toAddress(this.network).toString()
        );
        if (
          (await getPoolSize(this.db, AddressTypes.NAV)) < this.GetMinPoolSize()
        ) {
          this.Log.Message("Filling NAV key pool");
          await this.NavFillKeyPool(
            this.spendingPassword,
            this.GetMinPoolSize() * 2
          );
        }
      } else {
        await this.db.UseXNavAddress(hashId);
      }

      return true;
    } catch (e) {
      return false;
    }
  }

  async LockOrderInputs(order) {
    const tx = bitcore.Transaction(order.tx[0]);

    for (let input of tx.inputs) {
      let outPoint = input.prevTxId.toString("hex") + ":" + input.outputIndex;
      await this.db.SpendUtxo(outPoint, "locked-order");
    }

    this.emit("new_tx", []);
  }

  async UnlockOrderInputs(order) {
    const tx = bitcore.Transaction(order.tx[0]);

    for (let input of tx.inputs) {
      let outPoint = input.prevTxId.toString("hex") + ":" + input.outputIndex;

      let currentStatus = await this.client.blockchain_outpoint_subscribe(
        input.prevTxId.toString("hex"),
        input.outputIndex
      );
      await this.client.blockchain_outpoint_unsubscribe(
        input.prevTxId.toString("hex"),
        input.outputIndex
      );

      if (currentStatus && currentStatus.spender_txhash)
        await this.db.SpendUtxo(outPoint, currentStatus.spender_txhash);
      else await this.db.SpendUtxo(outPoint, "");
    }

    this.emit("new_tx", []);
  }


  async GetTxKeys(hash, height, useCache = true) {
    let txKeys;

    if (useCache) {
      let cacheTx = await this.db.GetTxKeys(hash);
      if (cacheTx) {
        txKeys = cacheTx;
      }
    }

    if (!txKeys) {
      try {
        if (!this.client) return;
        txKeys = await this.client.blockchain_transaction_getKeys(hash);
      } catch (e) {
        this.Log.Message(`error getting tx keys ${hash}: ${e}`);
        await this.ManageElectrumError(e);
        sleep(3);
        return await this.GetTxKeys(hash, height, useCache);
      }
      txKeys.txidkeys = hash;

      try {
        await this.db.AddTxKeys(txKeys);
      } catch (e) { }
    }

    let inMine = [];
    let isMine = false;

    for (let i in txKeys.vin) {
      let input = txKeys.vin[i];
      let thisMine = await this.txProcessor.IsMine(input);

      if (thisMine) {
        //await this.GetTx(input.txid, undefined, undefined, false)
        isMine = true;
      }

      inMine.push(thisMine);
    }

    for (let j in txKeys.vout) {
      let output = txKeys.vout[j];
      isMine |= await this.txProcessor.IsMine(output);
    }

    if (isMine) {
      await this.QueueTx(hash, inMine, height, true);
    } else {
      await this.db.MarkAsFetched(hash);
    }

    txKeys.txid = hash;

    return txKeys;
  }

  async DeriveSpendingKeyFromStringHash(prefix, name, spendingPassword) {
    if (typeof name === "string") {
      name = bitcore.crypto.Hash.sha256sha256(
        Buffer.concat([new Buffer([name.length]), new Buffer(name, "utf-8")])
      );
    }

    if (!name.reverse) {
      throw new Error(`name should be of type string but it is ${typeof name}`);
    }

    let sh = prefix + name.reverse().toString("hex");
    let hash = bitcore.crypto.Hash.sha256sha256(
      Buffer.concat([new Buffer([sh.length]), new Buffer(sh, "utf-8")])
    );

    let msk = await getMasterSpendKey(this.db, spendingPassword);

    if (!msk) return;

    msk = new Buffer(msk.serialize());
    let ret = new Buffer(32);
    msk.copy(ret, 32 - msk.length);

    for (let i = 0; i < 8; i++) {
      let index =
        ((hash[i * 4] << 24) |
          (hash[i * 4 + 1] << 16) |
          (hash[i * 4 + 2] << 8) |
          hash[i * 4 + 3]) >>>
        0;
      msk = blsct.DeriveChildSK(ret, index);
      msk.copy(ret, 32 - msk.length);
    }
    let retFr = new blsct.mcl.Fr();
    retFr.setLittleEndianMod(new Uint8Array(ret));
    return retFr.serialize();
  }

  async xNavCreateTransactionMultiple(
    dest,
    spendingPassword,
    subtractFee = false,
    tokenId = new Buffer(new Uint8Array(32)),
    tokenNftId = -1
  ) {
    let mvk = this.mvk;
    let msk = await getMasterSpendKey(this.db, spendingPassword);

    if (!(msk && mvk)) return;

    let utx = await this.GetUtxos(OutputTypes.XNAV);
    let utxos = [];

    for (const out_i in utx) {
      let out = utx[out_i];

      if (!(out.output.isCt() || out.output.isNft())) continue;

      utxos.push(out);
    }

    if (!utxos.length) throw new Error("No available xNAV outputs");

    for (let i in dest) {
      if (
        typeof dests[i].dest === "string" &&
        dest[i].dest.substring(
          dests[i].dest.length - 4,
          dest[i].dest.length
        ) === ".nav"
      ) {
        let resolvedDest = (await this.ResolveName(dest[i].dest))["."]?.nav;
        if (!resolvedDest) throw new Error("Can't resolve " + dest[i].dest);
        dest[i].dest = resolvedDest;
      }
    }

    let tx = await blsct.CreateTransaction(
      utxos,
      dest,
      mvk,
      msk,
      dest.length == 0 && subtractFee,
      tokenId,
      tokenNftId
    );

    return { tx: [tx.toString()], fee: tx.feeAmount };
  }

  async xNavCreateTransaction(
    dest,
    amount,
    memo,
    spendingPassword,
    subtractFee = true,
    tokenId = new Buffer(new Uint8Array(32)),
    tokenNftId = -1,
    vData = new Buffer([]),
    extraKey = undefined,
    extraIn = 0,
    aggFee = 0,
    from = [],
    useFullAmount = false
  ) {
    if (typeof tokenId === "string") {
      return await this.xNavCreateTransaction(
        dest,
        amount,
        memo,
        spendingPassword,
        subtractFee,
        Buffer.from(tokenId, "hex"),
        tokenNftId,
        vData,
        extraKey,
        extraIn,
        aggFee
      );
    }
    if (amount < 0) throw new TypeError("Amount must be positive");

    let mvk = this.mvk;
    let msk = await getMasterSpendKey(this.db, spendingPassword);

    if (!(msk && mvk)) return;

    let utx = await this.GetUtxos(OutputTypes.XNAV);
    let utxos = [];
    let utxoAmount = 0;

    for (const out_i in utx) {
      let out = utx[out_i];

      if (!(out.output.isCt() || out.output.isNft())) continue;

      if (from.length && from.indexOf(out.txid + ":" + out.vout) == -1)
        continue;

      utxoAmount += out.amount ? out.amount : out.satoshis;

      utxos.push(out);
    }

    if (!utxos.length) throw new Error("No available xNAV outputs");

    if (
      typeof dest === "string" &&
      dest.substring(dest.length - 4, dest.length) === ".nav"
    ) {
      let resolvedDest = (await this.ResolveName(dest))["."]?.nav;
      if (!resolvedDest) throw new Error("Can't resolve " + dest);
      dest = resolvedDest;
    }

    let dests = [
      {
        dest: dest,
        amount: useFullAmount ? utxoAmount : amount,
        memo: memo,
        vData: vData,
        extraKey: extraKey,
      },
    ];

    if (dests.length == 0) subtractFee = false;

    let tx = await blsct.CreateTransaction(
      utxos,
      dests,
      mvk,
      msk,
      useFullAmount ? true : subtractFee,
      tokenId,
      tokenNftId,
      extraIn,
      aggFee
    );

    return { tx: [tx.toString()], fee: tx.feeAmount };
  }

  async tokenCreateTransaction(
    dest,
    amount,
    memo,
    spendingPassword,
    tokenId = new Buffer(new Uint8Array(32)).toString("hex"),
    tokenNftId = -1,
    vData = new Buffer([]),
    extraKey = undefined,
    ignoreInputs = false,
    ignoreFees = false,
    aggFee = 0,
    from = [],
    useFullAmount = false
  ) {
    let consensus = await this.GetConsensusParameters();

    if (consensus[24]?.value != 1)
      throw new Error("Private Tokens and NFTs are not active yet");

    if (amount < 0) throw new TypeError("Amount must be positive");

    tokenId = new Buffer(tokenId, "hex");

    let mvk = this.mvk;
    let msk = await getMasterSpendKey(this.db, spendingPassword);

    if (!(msk && mvk)) return;

    let utx = await this.GetUtxos(OutputTypes.XNAV);
    let utxTok = await this.GetUtxos(
      OutputTypes.XNAV,
      undefined,
      tokenId,
      tokenNftId
    );
    let utxos = [];
    let utxosTok = [];

    let utxoAmount = 0;

    if (!ignoreInputs) {
      for (const out_i in utx) {
        let out = utx[out_i];

        if (!(out.output.isCt() || out.output.isNft())) continue;

        utxos.push(out);
      }

      for (const out_i in utxTok) {
        let out = utxTok[out_i];

        if (!(out.output.isCt() || out.output.isNft())) continue;

        if (from.length && from.indexOf(out.txid + ":" + out.vout) == -1)
          continue;

        utxoAmount += out.amount ? out.amount : out.satoshis;

        utxosTok.push(out);
      }

      if (!utxos.length) throw new Error("No available xNAV outputs");
      if (
        !utxosTok.length &&
        (!vData.length || (vData.length && vData[0] != 3))
      )
        throw new Error("No available Token outputs");
    }

    let dests = _.isArray(dest)
      ? dest
      : [
        {
          dest: dest,
          amount: useFullAmount ? utxoAmount : amount,
          memo: memo,
          vData: vData,
          extraKey: extraKey,
        },
      ];

    for (let i in dests) {
      if (
        typeof dests[i].dest === "string" &&
        dests[i].dest.substring(
          dests[i].dest.length - 4,
          dests[i].dest.length
        ) === ".nav"
      ) {
        let resolvedDest = (await this.ResolveName(dests[i].dest))["."]?.nav;
        if (!resolvedDest) throw new Error("Can't resolve " + dests[i].dest);
        dests[i].dest = resolvedDest;
      }
    }

    let txTok = await blsct.CreateTransaction(
      utxosTok,
      dests,
      mvk,
      msk,
      false,
      tokenId,
      tokenNftId
    );

    let txxNav = !ignoreFees
      ? await blsct.CreateTransaction(
        utxos,
        [],
        mvk,
        msk,
        false,
        new Buffer(new Uint8Array(32)),
        -1,
        txTok.feeAmount,
        aggFee
      )
      : undefined;

    let toCombine = [txTok.toString()];

    if (!ignoreFees) {
      toCombine.push(txxNav.toString());
    }

    let combinedTx = blsct.CombineTransactions(toCombine);

    return { tx: [combinedTx.toString()], fee: combinedTx.feeAmount };
  }

  async CreateCancelOrder(order, spendingPassword) {
    const tx = bitcore.Transaction(order.tx[0]);

    if (!tx.inputs[0]) return;

    let prevOutPoint =
      tx.inputs[0].prevTxId.toString("hex") + ":" + tx.inputs[0].outputIndex;
    let prevTx = await this.txProcessor.GetTx(tx.inputs[0].prevTxId.toString("hex"));
    let output = prevTx.tx.outputs[tx.inputs[0].outputIndex];
    let prevTokenId = output.tokenId
      ? Buffer.from(output.tokenId, "hex")
      : new Buffer(new Uint8Array(32));
    let prevTokenNftId = output.tokenNftId;

    if (
      prevTokenId.toString("hex") ==
      new Buffer(new Uint8Array(32)).toString("hex")
    ) {
      return await this.xNavCreateTransaction(
        (
          await this.getAddress.xNavReceivingAddresses(true)
        )[0].address,
        0,
        undefined,
        spendingPassword,
        true,
        new Buffer(new Uint8Array(32)),
        -1,
        undefined,
        undefined,
        0,
        0,
        [prevOutPoint],
        true
      );
    } else {
      return await this.tokenCreateTransaction(
        (
          await this.getAddress.xNavReceivingAddresses(true)
        )[0].address,
        0,
        undefined,
        spendingPassword,
        prevTokenId,
        prevTokenNftId,
        undefined,
        undefined,
        false,
        false,
        0,
        [prevOutPoint],
        true
      );
    }
  }

  async VerifyOrder(order) {
    if (!this.client) return;
    const tx = bitcore.Transaction(order.tx[0]);

    let valueKey;

    for (let input of tx.inputs) {
      let currentStatus = await this.client.blockchain_outpoint_subscribe(
        input.prevTxId.toString("hex"),
        input.outputIndex
      );
      await this.client.blockchain_outpoint_unsubscribe(
        input.prevTxId.toString("hex"),
        input.outputIndex
      );
      if (currentStatus && currentStatus.spender_txhash)
        throw new Error("Inputs are spent");

      let prevTx = await this.txProcessor.GetTx(input.prevTxId.toString("hex"));

      let output = prevTx.tx.outputs[input.outputIndex];
      blsct.H(output.tokenId, parseInt(output.tokenNftId.toString()));

      if (output.isCt()) {
        if (!valueKey) valueKey = output.bp.V[0];
        else valueKey = blsct.mcl.add(valueKey, output.bp.V[0]);
      } else {
        let vFr = new blsct.mcl.Fr();
        vFr.setInt(output.amount ? output.amount : output.satoshis);
        let vComm = blsct.mcl.mul(
          blsct.H(output.tokenId, parseInt(output.tokenNftId.toString())),
          vFr
        );
        if (!valueKey) valueKey = vComm;
        else valueKey = blsct.mcl.add(valueKey, vComm);
      }
    }

    for (let output of order.pay) {
      blsct.H(output.tokenId, output.tokenNftId);

      let vFr = new blsct.mcl.Fr();
      vFr.setInt(output.amount ? output.amount : output.satoshis);
      let vComm = blsct.mcl.mul(
        blsct.H(output.tokenId, output.tokenNftId),
        vFr
      );
      if (!valueKey) valueKey = vComm;
      else valueKey = blsct.mcl.add(valueKey, vComm);
    }

    for (let output of order.receive) {
      blsct.H(output.tokenId, output.tokenNftId);

      let vFr = new blsct.mcl.Fr();
      vFr.setInt(output.amount ? output.amount : output.satoshis);
      let vComm = blsct.mcl.mul(
        blsct.H(output.tokenId, output.tokenNftId),
        vFr
      );
      if (!valueKey) valueKey = blsct.mcl.inv(vComm);
      else valueKey = blsct.mcl.sub(valueKey, vComm);
    }

    for (let output of tx.outputs) {
      blsct.H(output.tokenId, parseInt(output.tokenNftId.toString()));

      if (output.isCt()) {
        if (!valueKey) valueKey = blsct.mcl.inv(output.bp.V[0]);
        else valueKey = blsct.mcl.sub(valueKey, output.bp.V[0]);
      } else {
        let vFr = new blsct.mcl.Fr();
        vFr.setInt(output.amount ? output.amount : output.satoshis);
        let vComm = blsct.mcl.mul(
          blsct.H(output.tokenId, parseInt(output.tokenNftId.toString())),
          vFr
        );
        if (!valueKey) valueKey = blsct.mcl.inv(vComm);
        else valueKey = blsct.mcl.sub(valueKey, vComm);
      }
    }

    return blsct.BalanceSigVerify(valueKey, tx.vchbalsig);
  }

  async SendTransaction(txs) {
    if (_.isArray(txs)) {
      let ret = [];

      for (const i in txs) {
        let tx = txs[i];
        try {
          let hash = await this.SendTransactionSingle(tx);

          ret.push(hash);
        } catch (e) {
          console.error(`error sending tx: ${e}`);
          await this.ManageElectrumError(e);
          return { hashes: ret, error: e };
        }
      }

      return { hashes: ret, error: undefined };
    } else {
      try {
        return {
          hashes: [await this.SendTransactionSingle(txs)],
          error: undefined,
        };
      } catch (e) {
        console.error(`error sending tx: ${e}`);
        await this.ManageElectrumError(e);
        return { hashes: [], error: e };
      }
    }
  }

  async SendTransactionSingle(tx) {
    if (!this.client) return;
    let ret = await this.client.blockchain_transaction_broadcast(tx);

    console.log("SendTransactionSingle ret", ret)
    let txObj = bitcore.Transaction(tx);

    let tx_ = { txid: ret, hex: tx };

    console.log("SendTransactionSingle ret", tx_)


    try {
      await this.db.AddTx(tx_);
    } catch (e) {
      console.log("AddTx", e);
    }

    tx_.tx = txObj;

    console.log("SendTransactionSingle txObj", txObj);


    await this.txProcessor.ValidateTx(tx_);

    return ret;
  }

  async RegisterName(name, spendingPassword) {
    name = name.toLowerCase();

    let nameResolve = {};

    try {
      nameResolve = await this.ResolveName(name);
    } catch (e) { }

    if (nameResolve["_key"]) throw new Error("Name is already registered");

    let derived = await this.DeriveSpendingKeyFromStringHash(
      "name/",
      name,
      spendingPassword
    );
    let key = blsct.SkToPubKey(new Buffer(derived).toString("hex"));

    let sh = name + key.serializeToHexStr();
    let nameHash = bitcore.crypto.Hash.sha256sha256(
      Buffer.concat([new Buffer([sh.length]), new Buffer(sh, "utf-8")])
    );

    let bufferHash = new Buffer(nameHash);

    let bk = new blsct.mcl.Fr();
    bk.setByCSPRNG();

    let destViewKey = blsct.SkToPubKey(this.mvk);

    let nonce = blsct.mcl.mul(destViewKey, bk);

    let encryptKey = bitcore.crypto.Blsct.HashG1Element(nonce, 1);
    let encryptedName = encrypt(
      name + ";" + key.serializeToHexStr(),
      encryptKey
    );

    let vData = Buffer.concat([
      new Buffer([6, 0, 0, 0]),
      bufferHash,
      new Buffer(blsct.SkToPubKey(bk).serialize()),
      encryptedName,
    ]);

    return await this.xNavCreateTransaction(
      bitcore.Script.fromHex("6ac1"),
      0,
      "",
      spendingPassword,
      false,
      new Buffer(new Uint8Array(32)),
      -1,
      vData
    );
  }

  async CreateToken(name, token_code, token_supply, spendingPassword) {
    let consensus = await this.GetConsensusParameters();

    if (consensus[24]?.value != 1)
      throw new Error("Private Tokens and NFTs are not active yet");

    let derived = await this.DeriveSpendingKeyFromStringHash(
      "token/",
      name + token_code,
      spendingPassword
    );
    let key = blsct.SkToPubKey(new Buffer(derived).toString("hex"));

    let vData = Buffer.concat([
      new Buffer([2, 0, 0, 0, 48]),
      new Buffer(key.serialize()),
      new Buffer(bitcore.encoding.Varint(name.length).buf),
      new Buffer(name, "utf-8"),
      new Buffer([0, 0, 0, 0, 0, 0, 0, 0]),
      new Buffer(bitcore.encoding.Varint(token_code.length).buf),
      new Buffer(token_code, "utf-8"),
      new Buffer(bitcore.crypto.Blsct.bytesArray(token_supply).reverse()),
    ]);

    let ret = await this.xNavCreateTransaction(
      bitcore.Script.fromHex("6ac1"),
      0,
      "",
      spendingPassword,
      false,
      new Buffer(new Uint8Array(32)),
      -1,
      vData,
      derived
    );

    ret.token_id = new Buffer(
      bitcore.crypto.Hash.sha256sha256(
        Buffer.concat([new Buffer([48]), new Buffer(key.serialize())])
      )
    )
      .reverse()
      .toString("hex");

    try {
      await this.db.AddKey(
        ret.token_id.toString("hex"),
        key.serialize().toString("hex"),
        AddressTypes.TOKEN,
        name,
        false,
        false,
        token_code,
        spendingPassword
      );
    } catch (e) {
      console.log(e.message);
    }
    return ret;
  }

  async MintToken(id, dest, amount, spendingPassword) {
    let consensus = await this.GetConsensusParameters();

    if (consensus[24]?.value != 1)
      throw new Error("Private Tokens and NFTs are not active yet");

    let token = await this.getInfo.GetTokenInfo(id);

    if (!token || (token && token.name == undefined))
      throw new Error("Unknown token");

    let derived = await this.DeriveSpendingKeyFromStringHash(
      "token/",
      token.name + token.code,
      spendingPassword
    );

    let key = blsct.SkToPubKey(new Buffer(derived).toString("hex"));

    if (new Buffer(token.key).toString("hex") != key.serializeToHexStr())
      throw new Error("You don't own the token");

    let vData = Buffer.concat([
      new Buffer([3, 0, 0, 0, 48]),
      new Buffer(key.serialize()),
      new Buffer(bitcore.crypto.Blsct.bytesArray(amount).reverse()),
      new Buffer([0]),
    ]);

    return await this.tokenCreateTransaction(
      dest,
      amount,
      "",
      spendingPassword,
      id,
      -1,
      vData,
      derived
    );
  }

  async CreateNft(name, scheme, token_supply, spendingPassword) {
    let consensus = await this.GetConsensusParameters();

    if (consensus[24]?.value != 1)
      throw new Error("Private Tokens and NFTs are not active yet");

    let derived = await this.DeriveSpendingKeyFromStringHash(
      "token/",
      name + scheme,
      spendingPassword
    );
    let key = blsct.SkToPubKey(new Buffer(derived).toString("hex"));

    let sh = name + key.serializeToHexStr();
    let nameHash = bitcore.crypto.Hash.sha256sha256(
      Buffer.concat([new Buffer([sh.length]), new Buffer(sh, "utf-8")])
    );

    let bufferHash = new Buffer(nameHash);

    let vData = Buffer.concat([
      new Buffer([2, 0, 0, 0, 48]),
      new Buffer(key.serialize()),
      new Buffer(bitcore.encoding.Varint(name.length).buf),
      new Buffer(name, "utf-8"),
      new Buffer([1, 0, 0, 0, 0, 0, 0, 0]),
      new Buffer(bitcore.encoding.Varint(scheme.length).buf),
      new Buffer(scheme, "utf-8"),
      new Buffer(bitcore.crypto.Blsct.bytesArray(token_supply).reverse()),
    ]);

    let ret = await this.xNavCreateTransaction(
      bitcore.Script.fromHex("6ac1"),
      0,
      "",
      spendingPassword,
      false,
      new Buffer(new Uint8Array(32)),
      -1,
      vData,
      derived
    );

    ret.token_id = new Buffer(
      bitcore.crypto.Hash.sha256sha256(
        Buffer.concat([new Buffer([48]), new Buffer(key.serialize())])
      )
    )
      .reverse()
      .toString("hex");

    try {
      await this.db
        .AddKey(
          ret.token_id.toString("hex"),
          key.serialize().toString("hex"),
          AddressTypes.TOKEN,
          name,
          false,
          false,
          scheme,
          spendingPassword
        )
        .catch();
    } catch (e) {
      console.log(e.message);
    }

    return ret;
  }

  async CreateNftProof(id, nftid, spendingPassword) {
    if (!this.client) throw new Error("Not connected");

    let utxTok = await this.GetUtxos(OutputTypes.XNAV, undefined, id, nftid);

    let nftInfo = await this.client.blockchain_token_getNft(
      id,
      parseInt(nftid),
      true
    );

    let hash = nftInfo.nfts[0].utxo.hash;
    let n = nftInfo.nfts[0].utxo.n;

    let prevOut = utxTok.filter(
      (el) =>
        parseInt(n) == parseInt(el.vout) && el.txid == nftInfo.nfts[0].utxo.hash
    );

    if (prevOut.length == 0) throw new Error("You don't own the NFT");

    let mvk = this.mvk;
    let msk = await getMasterSpendKey(this.db, spendingPassword);

    if (!(msk && mvk)) throw new Error("Wrong spending password");

    blsct.RecoverBLSCTOutput(
      prevOut[0].output,
      mvk,
      msk,
      prevOut[0].accIndex[0],
      prevOut[0].accIndex[1]
    );

    let msg =
      constants.NFT_PROOF_PREFIX +
      "_" +
      id +
      "_" +
      nftid +
      "_" +
      hash +
      "_" +
      n;
    let hashedMsg = sha256sha256(Buffer.from(msg, "utf-8"));

    let sig = await blsct.AugmentedSign(prevOut[0].output.sigk, hashedMsg);

    return { tokenId: id, nftId: nftid, sig: sig };
  }

  async VerifyNftProof(id, nftid, proof) {
    if (!this.client) throw new Error("Not connected");

    let nftInfo = await this.client.blockchain_token_getNft(
      id,
      parseInt(nftid),
      true
    );

    let hash = nftInfo.nfts[0].utxo.hash;
    let n = nftInfo.nfts[0].utxo.n;

    let msg =
      constants.NFT_PROOF_PREFIX +
      "_" +
      id +
      "_" +
      nftid +
      "_" +
      hash +
      "_" +
      n;
    let hashedMsg = sha256sha256(Buffer.from(msg, "utf-8"));

    let sigResult = await blsct.AugmentedVerify(
      nftInfo.nfts[0].utxo.spendingKey,
      hashedMsg,
      proof.sig
    );

    return { txid: hash, nout: n, result: sigResult };
  }

  async MintNft(id, nftid, dest, metadata, spendingPassword) {
    let consensus = await this.GetConsensusParameters();

    if (consensus[24]?.value != 1)
      throw new Error("Private Tokens and NFTs are not active yet");

    let token = await this.getInfo.GetTokenInfo(id);

    if (!token || (token && token.name == undefined))
      throw new Error("Unknown token");

    let derived = await this.DeriveSpendingKeyFromStringHash(
      "token/",
      token.name + token.code,
      spendingPassword
    );
    let key = blsct.SkToPubKey(new Buffer(derived).toString("hex"));

    if (new Buffer(token.key).toString("hex") != key.serializeToHexStr())
      throw new Error("You don't own the token");

    let vData = Buffer.concat([
      new Buffer([3, 0, 0, 0, 48]),
      new Buffer(key.serialize()),
      new Buffer(bitcore.crypto.Blsct.bytesArray(nftid).reverse()),
      new Buffer(bitcore.encoding.Varint(metadata.length).buf),
      new Buffer(new Buffer(metadata, "utf-8")),
    ]);

    return await this.tokenCreateTransaction(
      dest,
      1,
      "",
      spendingPassword,
      id,
      nftid,
      vData,
      derived
    );
  }

  async AcceptOrder(order, spendingPassword) {
    let mvk = this.mvk;
    let msk = await getMasterSpendKey(this.db, spendingPassword);

    if (!(msk && mvk)) throw new Error("Wrong spending password");

    for (let i in order.pay) {
      if (!order.pay[i].tokenId)
        order.pay[i].tokenId = new Buffer(new Uint8Array(32));
      if (!Buffer.isBuffer(order.receive[i].tokenId))
        order.pay[i].tokenId = new Buffer(order.pay[i].tokenId, "hex");
      if (!order.pay[i].tokenNftId === undefined) order.pay[i].tokenNftId = -1;
    }

    for (let i in order.receive) {
      if (!order.receive[i].tokenId)
        order.receive[i].tokenId = new Buffer(new Uint8Array(32));
      if (!Buffer.isBuffer(order.receive[i].tokenId))
        order.receive[i].tokenId = new Buffer(order.receive[i].tokenId, "hex");
      if (!order.receive[i].tokenNftId === undefined)
        order.receive[i].tokenNftId = -1;
    }

    let utxos = await this.GetUtxos(
      OutputTypes.XNAV,
      undefined,
      order.pay[0].tokenId,
      order.pay[0].tokenNftId
    );

    let dests = [
      {
        dest: bitcore.Script.fromHex("6a"),
        amount: order.pay[0].amount,
        tokenId: order.pay[0].tokenId,
        tokenNftId: order.pay[0].tokenNftId,
        ignore: true,
      },
      {
        dest: (await this.getAddress.xNavReceivingAddresses(true))[0].address,
        amount: order.receive[0].amount,
        tokenId: order.receive[0].tokenId,
        tokenNftId: order.receive[0].tokenNftId,
      },
    ];

    for (let i in dests) {
      if (
        typeof dests[i].dest === "string" &&
        dests[i].dest.substring(
          dests[i].dest.length - 4,
          dests[i].dest.length
        ) === ".nav"
      ) {
        let resolvedDest = (await this.ResolveName(dests[i].dest))["."]?.nav;
        if (!resolvedDest) throw new Error("Can't resolve " + dests[i].dest);
        dests[i].dest = resolvedDest;
      }
    }

    let takeTx = await blsct.CreateTransaction(
      utxos,
      dests,
      mvk,
      msk,
      false,
      order.pay[0].tokenId,
      order.pay[0].tokenNftId
    );

    let combinedTx = blsct.CombineTransactions([
      takeTx.toString(),
      order.tx[0],
    ]);

    return {
      tx: combinedTx.toString(),
      fee: combinedTx.feeAmount,
    };
  }

  async CreateMintNftOrder(
    id,
    nftid,
    payTo,
    price,
    metadata = "",
    spendingPassword
  ) {
    let token = await this.getInfo.GetTokenInfo(id);

    if (!token || (token && token.name == undefined))
      throw new Error("Unknown token");

    let derived = await this.DeriveSpendingKeyFromStringHash(
      "token/",
      token.name + token.code,
      spendingPassword
    );
    let key = blsct.SkToPubKey(new Buffer(derived).toString("hex"));

    if (new Buffer(token.key).toString("hex") != key.serializeToHexStr())
      throw new Error("You don't own the token");

    let vData = Buffer.concat([
      new Buffer([3, 0, 0, 0, 48]),
      new Buffer(key.serialize()),
      new Buffer(bitcore.crypto.Blsct.bytesArray(nftid).reverse()),
      new Buffer(bitcore.encoding.Varint(metadata.length).buf),
      new Buffer(new Buffer(metadata, "utf-8")),
    ]);

    return {
      tx: (
        await this.tokenCreateTransaction(
          [
            {
              dest: payTo,
              amount: price,
              memo: `${token.name.substr(0, 20)} ${nftid} mint`,
              tokenId: new Buffer(new Uint8Array(32)).toString("hex"),
              tokenNftId: -1,
            },
            {
              dest: bitcore.Script.fromHex("6ac1"),
              amount: 0,
              vData: vData,
              extraKey: derived,
              tokenId: new Buffer(id, "hex"),
              tokenNftId: nftid,
            },
          ],
          1,
          "",
          spendingPassword,
          id,
          nftid,
          undefined,
          derived,
          true,
          true
        )
      ).tx,
      pay: [{ amount: price }],
      receive: [{ amount: 1, tokenId: id, tokenNftId: nftid }],
    };
  }

  async CreateSellNftOrder(id, nftid, payTo, price, spendingPassword) {
    let token = await this.getInfo.GetTokenInfo(id);

    if (!token || (token && token.name == undefined))
      throw new Error("Unknown token");

    return {
      tx: (
        await this.tokenCreateTransaction(
          [
            {
              dest: payTo,
              amount: 1,
              memo: "",
              tokenId: new Buffer(id, "hex"),
              tokenNftId: nftid,
              ignore: true,
            },
            {
              dest: payTo,
              amount: price,
              memo: `${token.name.substr(0, 20)} ${nftid} sale`,
              tokenId: new Buffer(new Uint8Array(32)).toString("hex"),
              tokenNftId: -1,
            },
          ],
          1,
          "",
          spendingPassword,
          id,
          nftid,
          undefined,
          undefined,
          false,
          true
        )
      ).tx,
      pay: [{ amount: price }],
      receive: [{ amount: 1, tokenId: id, tokenNftId: nftid }],
    };
  }

  async CreateBuyNftOrder(id, nftid, payTo, price, spendingPassword) {
    let token = await this.getInfo.GetTokenInfo(id);

    if (!token || (token && token.name == undefined))
      throw new Error("Unknown token");

    return {
      tx: (
        await this.tokenCreateTransaction(
          [
            {
              dest: payTo,
              amount: price,
              memo: "",
              tokenId: new Buffer(new Uint8Array(32)).toString("hex"),
              tokenNftId: -1,
              ignore: true,
            },
            {
              dest: payTo,
              amount: 1,
              memo: `${token.name.substr(0, 20)} ${nftid} purchase`,
              tokenId: new Buffer(id, "hex"),
              tokenNftId: nftid,
            },
          ],
          1,
          "",
          spendingPassword,
          new Buffer(new Uint8Array(32)).toString("hex"),
          -1,
          undefined,
          undefined,
          false,
          true
        )
      ).tx,
      pay: [{ amount: 1, tokenId: id, tokenNftId: nftid }],
      receive: [{ amount: price }],
    };
  }

  async CreateTokenOrder(
    tokenInId,
    tokenInAmount,
    payTo,
    tokenOutId,
    tokenOutAmount,
    spendingPassword
  ) {
    let tokenIn = { name: "xNAV" };
    let tokenOut = { name: "xNAV" };

    tokenInId = tokenInId
      ? tokenInId
      : new Buffer(new Uint8Array(32)).toString("hex");
    tokenOutId = tokenOutId
      ? tokenOutId
      : new Buffer(new Uint8Array(32)).toString("hex");

    if (tokenInId == tokenOutId)
      throw new Error("tokenInId and tokenOutId must be different");

    if (tokenInId != new Buffer(new Uint8Array(32)).toString("hex")) {
      tokenIn = await this.getInfo.GetTokenInfo(tokenInId);

      if (!tokenIn || (tokenIn && tokenIn.name == undefined))
        throw new Error("Unknown tokenInId");
    }

    if (tokenOutId != new Buffer(new Uint8Array(32)).toString("hex")) {
      tokenOut = await this.getInfo.GetTokenInfo(tokenOutId);

      if (!tokenOut || (tokenOut && tokenOut.name == undefined))
        throw new Error("Unknown tokenInId");
    }

    return {
      tx: (
        await this.tokenCreateTransaction(
          [
            {
              dest: payTo,
              amount: tokenOutAmount,
              memo: "",
              tokenId: Buffer.from(tokenOutId, "hex"),
              tokenNftId: -1,
              ignore: true,
            },
            {
              dest: payTo,
              amount: tokenInAmount,
              memo: `${tokenIn.name.substr(0, 10)}/${tokenOut.name.substr(
                0,
                10
              )} trade`,
              tokenId: Buffer.from(tokenInId, "hex"),
              tokenNftId: -1,
            },
          ],
          tokenOutAmount,
          "",
          spendingPassword,
          Buffer.from(tokenOutId, "hex"),
          -1,
          undefined,
          undefined,
          false,
          true
        )
      ).tx,
      pay: [{ amount: tokenInAmount, tokenId: tokenInId }],
      receive: [{ amount: tokenOutAmount, tokenId: tokenOutId }],
    };
  }

  async UpdateName(name, subdomain, key, value, spendingPassword) {
    let consensus = await this.GetConsensusParameters();

    if (!consensus[22]) throw new Error("Could not read consensus parameters");

    let first = false;
    let size = 0;
    let nameResolve = {};

    name = name.toLowerCase();

    try {
      nameResolve = await this.ResolveName(name, true);
      if (Object.keys(nameResolve) && Object.keys(nameResolve).length == 0) {
        first = true;
      } else {
        for (var key_ in nameResolve) {
          if (_.isString(nameResolve[key_]))
            size += key_.length + nameResolve[key_].length;
          else {
            for (var key_2 in nameResolve[key_]) {
              if (_.isString(nameResolve[key_][key_2]))
                size += key_2.length + nameResolve[key_][key_2].length;
            }
          }
        }
      }
    } catch (e) {
      console.log(e);
      first = true;
    }

    size += key.length + value.length;

    let privk = await this.DeriveSpendingKeyFromStringHash(
      "name/",
      name,
      spendingPassword
    );
    let k = blsct.SkToPubKey(new Buffer(privk).toString("hex"));

    if (!first && k.serializeToHexStr() != nameResolve["_key"])
      throw new Error("You don't own the name.");

    let fee =
      (first ? consensus[22].value : 0) +
      Math.floor(size / consensus[26].value) * consensus[27].value;

    let vData = Buffer.concat([
      new Buffer([first ? 7 : 8, 0, 0, 0]),
      new Buffer([name.length]),
      new Buffer(name, "utf-8"),
      new Buffer([48]),
      new Buffer(k.serialize()),
      new Buffer([subdomain.length]),
      new Buffer(subdomain, "utf-8"),
      new Buffer([key.length]),
      new Buffer(key, "utf-8"),
      new Buffer([value.length]),
      new Buffer(value, "utf-8"),
      new Buffer(privk),
    ]);

    let ret = await this.xNavCreateTransaction(
      bitcore.Script.fromHex("6ac1"),
      fee,
      "",
      spendingPassword,
      false,
      new Buffer(new Uint8Array(32)),
      -1,
      vData,
      privk
    );

    ret.fee += fee;

    return ret;
  }

  async NavCreateTransaction(
    dest,
    amount,
    memo,
    spendingPassword,
    subtractFee = true,
    fee = 100000,
    type = OutputTypes.NAV,
    fromAddress = undefined,
    ret = { fee: 0, tx: [] },
    selectxnav = false
  ) {
    if (amount <= 0) throw new TypeError("Amount must be greater than 0");

    if (!(dest instanceof bitcore.Address)) {
      if (
        typeof dest === "string" &&
        dest.substring(dest.length - 4, dest.length) === ".nav"
      ) {
        let resolvedDest = (await this.ResolveName(dest))["."]?.nav;

        if (!resolvedDest) throw new Error("Can't resolve " + dest);
        dest = resolvedDest;
      }
      return await this.NavCreateTransaction(
        new bitcore.Address(dest),
        amount,
        memo,
        spendingPassword,
        subtractFee,
        fee,
        type,
        fromAddress,
        ret,
        selectxnav
      );
    }

    let msk = await getMasterKey("xNavSpend", spendingPassword, this.db);

    if (!msk) return;

    let utxos = await this.GetUtxos(type, fromAddress);
  
    let tx = bitcore.Transaction();
    let addedInputs = 0;
    let privateKeys = [];
    let gammaIns = new blsct.mcl.Fr();

    for (let u in utxos) {
      let out = utxos[u];

      if (out.output.isCt() || out.output.isNft())
        throw new TypeError("NavSend can only spend nav outputs");

      let prevtx = await this.txProcessor.GetTx(out.txid);
     
      if (prevtx.tx.outputs[out.vout].hasBlsctKeys() && !selectxnav) continue;
      if (!prevtx.tx.outputs[out.vout].hasBlsctKeys() && selectxnav) continue;

      let utxo = bitcore.Transaction.UnspentOutput({
        txid: out.txid,
        vout: parseInt(out.vout),
        scriptPubKey: out.output.script,
        satoshis: out.output.satoshis,
      });

      let hashId = new Buffer(
        out.output.script.isPublicKeyOut()
          ? ripemd160(sha256(out.output.script.getPublicKey()))
          : out.output.script.getPublicKeyHash()
      ).toString("hex");

      let privK = await getPrivateKey(this.db, hashId, spendingPassword, this.network);

      if (privK) {
        addedInputs += out.output.satoshis;

        tx.from(utxo);
        privateKeys.push(privK);
      }

      if (privK && addedInputs >= amount + (subtractFee ? 0 : fee)) break;
    }

    if (addedInputs < amount + (subtractFee ? 0 : fee)) {
      if (selectxnav) {
        throw new Error(
          `Not enough balance (required ${amount + (subtractFee ? 0 : fee)
          }, selected ${addedInputs})`
        );
      } else {
        await this.NavCreateTransaction(
          dest,
          amount + (subtractFee ? 0 : fee) - addedInputs,
          memo,
          spendingPassword,
          subtractFee,
          fee,
          type,
          fromAddress,
          ret,
          true
        );
        amount = addedInputs;
      }
    }

    if (dest.isXnav()) {
      if (amount >= (subtractFee ? fee : 0)) {
        let out = await blsct.CreateBLSCTOutput(
          dest,
          amount - (subtractFee ? fee : 0),
          memo
        );
        tx.addOutput(out);
        await blsct.SigBalance(tx, blsct.mcl.sub(gammaIns, out.gamma));
        tx.addOutput(
          new bitcore.Transaction.Output({
            satoshis: fee,
            script: bitcore.Script.fromHex("6a"),
          })
        );
      }
    } else {
      if (amount >= (subtractFee ? fee : 0)) {
        tx.to(dest, amount - (subtractFee ? fee : 0));
      }
      tx.strdzeel = memo;
    }

    if (addedInputs - (amount + (subtractFee ? 0 : fee)) > 0) {
      if (type == 0x2 && fromAddress) {
        tx.to(
          bitcore.Address.fromBuffers(
            [
              new Buffer([bitcore.Networks[this.network].coldstaking]),
              bitcore.Address(fromAddress).toBuffer().slice(1),
              bitcore
                .Address((await this.getAddress.NavReceivingAddresses())[0].address)
                .toBuffer()
                .slice(1),
            ],
            this.network,
            "coldstaking"
          ),
          addedInputs - (amount + (subtractFee ? 0 : fee))
        );
      } else {
        tx.to(
          (await this.getAddress.NavReceivingAddresses())[0].address,
          addedInputs - (amount + (subtractFee ? 0 : fee))
        );
      }
    }

    tx.settime(Math.floor(Date.now() / 1000)).sign(privateKeys);

    if (tx.inputs.length > 0) {
      ret.fee += fee;
      ret.tx.push(tx.toString());
    }
    return ret;
  }

  async AddCandidate(candidate, network) {
    if (!this.client) return;

    let currentStatus = await this.client.blockchain_outpoint_subscribe(
      candidate.tx.inputs[0].prevTxId.toString("hex"),
      candidate.tx.inputs[0].outputIndex
    );
    if (
      currentStatus &&
      !currentStatus.spender_txhash &&
      (await this.GetCandidates()).length < 100
    )
      await this.db.AddTxCandidate(candidate, network);
  }

  async NewCandidate(session, candidate) {
    if (this.p2pPool) {
      console.log("New candidate from session " + session, candidate);
      await this.AddCandidate(
        candidate,
        this.p2pPool.network.name == "livenet" ? "mainnet" : "testnet"
      );
    }
  }
  
}
