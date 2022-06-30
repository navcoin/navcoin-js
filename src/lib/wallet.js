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

const p2p = require("@aguycalled/bitcore-p2p").Pool;

export * as xNavBootstrap from "./xnav_bootstrap.js";

let db = Db["Dexie"].default;

const asyncFilter = async (arr, predicate) =>
  Promise.all(arr.map(predicate)).then((results) =>
    arr.filter((_v, index) => results[index])
  );

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

    let self = this;

    this.queue.on("progress", (progress, pending, total) => {
      self.emit("sync_status", progress, pending, total);
    });

    this.queue.on("end", async () => {
      if ((await self.GetPoolSize(AddressTypes.XNAV)) < 10) {
        this.Log("Need to fill the xNAV key pool");
        await self.xNavFillKeyPool(self.spendingPassword, 20);
      } else {
        self.spendingPassword = "";
        self.emit("sync_finished");
      }
    });

    this.queue.on("started", () => {
      self.emit("sync_started");
    });

    this.network = options.network || "mainnet";
    this.db = new this.dbBackend();

    this.db.on("db_load_error", (e) => {
      this.emit("db_load_error", e);
      this.Disconnect();
    });

    this.db.on("db_open", () => {
      this.emit("db_open");
    });

    this.db.on("db_closed", () => {
      this.emit("db_closed");
      this.Disconnect();
    });
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

  async GetPoolSize(type, change) {
    return await this.db.GetPoolSize(type, change);
  }

  Log(str) {
    if (!this.log) return;
    console.log(` [navcoin-js] ${str}`);
  }

  async Load(options) {
    if (!this.db) throw new Error("DB did not load.");

    await this.InitDb();

    options = options || {};

    this.daoConsultations = {};
    this.daoProposals = {};

    if (!this.db.open) throw new Error("DB did not load.");

    let network = await this.db.GetValue("network");

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

        await this.SetMasterKey(masterKey, this.spendingPassword);
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

        await this.SetMasterKey(masterKey, this.spendingPassword);
      } else if (this.type === "navcoin-core") {
        let keyMaterial = Mnemonic.mnemonicToData(mnemonic);

        await this.SetMasterKey(keyMaterial, this.spendingPassword);
      } else if (this.type === "navcash") {
        let masterKey = bitcore.HDPrivateKey.fromSeed(
          await electrumMnemonic.mnemonicToSeed(mnemonic, {
            prefix: electrumMnemonic.PREFIXES.standard,
          })
        );

        await this.SetMasterKey(masterKey, this.spendingPassword);
      } else {
        let masterKey = await new Mnemonic(mnemonic).toHDPrivateKeyAsync(
          "",
          this.network
        );

        await this.SetMasterKey(masterKey, this.spendingPassword);
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

    this.mvk = await this.GetMasterViewKey();

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

    if (await this.GetMasterKey("nav", this.spendingPassword)) {
      await this.xNavFillKeyPool(this.spendingPassword);
      await this.NavFillKeyPool(this.spendingPassword);
    }

    if (this.newWallet || (await this.db.GetStakingAddresses())?.length == 0) {
      let pool =
        this.network == "mainnet"
          ? "NfLgDYL4C3KKXDS8tLRAFM7spvLykV8v9A"
          : "n3uJuww32YGUbsoywpmG1LmgVQYMsg5Ace";
      await this.AddStakingAddress(pool, undefined, false);
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
    let mk = await this.GetMasterKey("xNavSpend", spendingPassword);

    if (!mk) return;

    let filled = 0;

    while ((await this.GetPoolSize(AddressTypes.XNAV)) < count) {
      filled++;
      await this.xNavCreateSubaddress(spendingPassword);
    }

    if (this.poolFilled && filled > 0) {
      this.Log("xNAV pool was filled with " + filled + " new keys. Resyncing.");
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

    let mk = await this.GetMasterKey("nav", spendingPassword);

    if (!mk) return;

    let filled = 0;

    while ((await this.GetPoolSize(AddressTypes.NAV)) < count) {
      filled++;
      await this.NavCreateAddress(spendingPassword);
    }

    if (this.type == "navcash" || this.type == "navcoin-core") {
      while ((await this.GetPoolSize(AddressTypes.NAV, 1)) < count) {
        filled++;
        await this.NavCreateAddress(spendingPassword, 1);
      }
    }

    this.Log("NAV pool was filled with " + filled + " new keys.");
  }

  async xNavReceivingAddresses(all = true) {
    return await this.db.GetXNavReceivingAddresses(all);
  }

  async NavReceivingAddresses(all = true) {
    return await this.db.GetNavReceivingAddresses(all);
  }

  async GetAllAddresses() {
    let ret = { spending: { public: {}, private: {} }, staking: {} };

    let receiving = await this.db.GetNavReceivingAddresses(true);

    for (let i in receiving) {
      let address = receiving[i];
      ret.spending.public[address.address] = {
        balances: await this.GetBalance(address.address),
        used: address.used,
      };

      let label = await this.db.GetLabel(address.address);

      if (label != address.address)
        ret.spending.public[address.address].label = label;
    }

    let xnav = await this.db.GetXNavReceivingAddresses(true);

    for (let i in xnav) {
      let address = xnav[i];
      ret.spending.private[address.address] = {
        balances: await this.GetBalance(address.hash),
        used: address.used,
      };

      let label = await this.db.GetLabel(address.address);

      if (label != address.address)
        ret.spending.private[address.address].label = label;
    }

    let staking = await this.db.GetStakingAddresses();

    for (let j in staking) {
      let address = staking[j];
      ret.staking[address.address] = {
        staking: (await this.GetBalance(address.address)).staked,
      };

      let label = await this.db.GetLabel(address.address);

      if (label != address.address) ret.staking[address.address].label = label;
    }

    return ret;
  }

  async NavGetPrivateKeys(spendingPassword, address) {
    let list = address
      ? [await this.db.GetNavAddress(address)]
      : await this.db.GetNavReceivingAddresses(true);

    for (let i in list) {
      list[i].privateKey = (
        await this.GetPrivateKey(list[i].hash, spendingPassword)
      ).toWIF();
      delete list[i].value;
    }

    return list;
  }

  async GetMasterKey(key, password) {
    if (!this.db) return undefined;

    let privK = await this.db.GetMasterKey("nav", password);

    if (!privK) return undefined;

    return privK;
  }

  async GetMasterSpendKey(key) {
    if (!this.db) return undefined;

    let privK = await this.db.GetMasterKey("xNavSpend", key);

    if (!privK) return undefined;

    return blsct.mcl.deserializeHexStrToFr(privK);
  }

  async GetMasterViewKey() {
    if (!this.db) return undefined;

    let pubK = await this.db.GetValue("masterViewKey");

    if (!pubK) return undefined;

    return blsct.mcl.deserializeHexStrToFr(pubK);
  }

  async xNavCreateSubaddress(sk, acct = 0) {
    let masterViewKey = this.mvk;

    let masterSpendKey = await this.GetMasterSpendKey(sk);

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
    await this.db.AddKey(
      hashId,
      [acct, index],
      AddressTypes.XNAV,
      blsct.KeysToAddress(viewKey, spendKey).toString(),
      false,
      false,
      acct + "/" + parseInt(index)
    );
  }

  async NavCreateAddress(sk, change = 0) {
    if (this.type === "next") return;

    let mk = await this.GetMasterKey("nav", sk);

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

    if (this.connected) {
      await this.Sync();
    }
  }

  async SetTip(height) {
    this.lastBlock = height;
    this.emit("new_block", height);
    await this.db.SetValue("ChainTip", height);
  }

  async GetTip() {
    return (await this.db.GetValue("ChainTip")) || -1;
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
            await this.AddStakingAddress(
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

  async GetStakingAddresses() {
    let ret = [];

    let addresses = await this.db.GetStakingAddresses();

    for (let i in addresses) {
      ret.push(addresses[i].address);
    }

    return ret;
  }

  async GetStatusHashForScriptHash(s) {
    return await this.db.GetStatusForScriptHash(s);
  }

  async SetMasterKey(masterkey, key) {
    if (await this.db.GetMasterKey(key)) return false;

    let masterKey = (
      this.type === "navcoin-core"
        ? bitcore.HDPrivateKey.fromSeed(masterkey)
        : masterkey
    ).toString();
    let masterPubKey = bitcore.HDPrivateKey(masterKey).hdPublicKey.toString();

    let { masterViewKey, masterSpendKey } = blsct.DeriveMasterKeys(
      this.type === "navcoin-core"
        ? bitcore.PrivateKey(masterkey)
        : bitcore.HDPrivateKey(masterKey)
    );
    let masterSpendPubKey = blsct.mcl.mul(blsct.G(), masterSpendKey);
    let masterViewPubKey = blsct.mcl.mul(blsct.G(), masterViewKey);

    await this.db.AddMasterKey("nav", masterKey, key);
    await this.db.AddMasterKey(
      "xNavSpend",
      masterSpendKey.serializeToHexStr(),
      key
    );
    await this.db.SetValue("masterViewKey", masterViewKey.serializeToHexStr());
    await this.db.SetValue(
      "masterSpendPubKey",
      masterSpendPubKey.serializeToHexStr()
    );
    await this.db.SetValue(
      "masterViewPubKey",
      masterViewPubKey.serializeToHexStr()
    );
    await this.db.SetValue("masterPubKey", masterPubKey);

    this.Log("master keys written");

    return true;
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

    if (!this.electrumNodes[this.electrumNodeIndex]) this.electrumNodeIndex = 0;

    if (!this.electrumNodes[this.electrumNodeIndex])
      throw new Error("No nodes in the list, use AddNode");

    this.emit("connecting");

    this.client = new electrum(
      this.electrumNodes[this.electrumNodeIndex].host,
      this.electrumNodes[this.electrumNodeIndex].port,
      this.electrumNodes[this.electrumNodeIndex].proto
    );

    this.Log(
      `Trying to connect to ${
        this.electrumNodes[this.electrumNodeIndex].host
      }:${this.electrumNodes[this.electrumNodeIndex].port}`
    );

    let self = this;

    this.client.subscribe.on("socket.error", async (e) => {
      this.connected = false;
      this.emit("disconnected");
      this.emit("connection_failed");
      console.error(
        `error connecting to electrum ${
          this.electrumNodes[this.electrumNodeIndex].host
        }:${this.electrumNodes[this.electrumNodeIndex].port}: ${e}`
      );

      await self.ManageElectrumError(e);
    });

    this.client.subscribe.on("ready", async () => {
      this.emit(
        "connected",
        this.electrumNodes[this.electrumNodeIndex].host +
          ":" +
          this.electrumNodes[this.electrumNodeIndex].port
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
          await self.SetTip(event[0].height);
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

      if ((await this.GetCandidates()).length < 100) {
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
          await self.ReceivedScriptHashStatus(event[0], event[1]);
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
      this.GetTx,
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

      this.Log(`Queuing ${pending.length} pending transactions`);
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
      let stakingAddresses = await this.GetStakingAddresses();

      for (let k in stakingAddresses) {
        let address = stakingAddresses[k];
        await this.SyncTxHashes(address, txs);
      }
    }
  }

  async ManageElectrumError(e) {
    if (
      e == "Error: close connect" ||
      e == "Error: connection not established" ||
      e
        .toString()
        .substr(0, "Error: failed to connect to electrum server:".length) ==
        "Error: failed to connect to electrum server:" ||
      e == "server busy - request timed out"
    ) {
      this.connected = false;
      this.electrumNodeIndex =
        (this.electrumNodeIndex + 1) % this.electrumNodes.length;

      this.emit("connection_failed");

      if (this.client) this.client.close();

      this.failedConnections = this.failedConnections + 1;

      this.Log(`Reconnecting to electrum node ${this.electrumNodeIndex}`);

      if (this.failedConnections >= this.electrumNodes.length) {
        this.emit("no_servers_available");
        sleep(5);
        await this.Connect(true);
      } else {
        sleep(1);
        await this.Connect(false);
      }
    }

    if (e === "server busy - request timed out") {
      sleep(5);
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
    let prevStatus = await this.GetStatusHashForScriptHash(s);

    if (status && status !== prevStatus) {
      await this.db.SetStatusForScriptHash(s, status);

      this.Log(`Received new status ${status} for ${s}. Syncing.`);

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

    this.Log("Syncing " + scripthash);

    let historyRange = {};

    while (true) {
      try {
        currentHistory = await this.db.GetScriptHashHistory(scripthash);
      } catch (e) {
        this.Log(`error getting history from db: ${e}`);
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
        this.Log(
          `requesting tx history for ${scripthash} from ${
            currentLastHeight - 10
          }`
        );

        if (!this.client) return;

        newHistory = await this.client.blockchain_scripthash_getHistory(
          scripthash,
          Math.max(0, currentLastHeight - 10)
        );
        this.Log(
          `${scripthash}: received ${newHistory.history.length} transactions`
        );
      } catch (e) {
        this.Log(`error getting history: ${e}`);
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

    this.Log(`Finished receiving transaction list for script ${scripthash}`);

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

    let tip = await this.GetTip();
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

  async GetBalance(address) {
    if (address instanceof bitcore.Address)
      return await this.GetBalance(address.hashBuffer);

    if (typeof address === "string" && !bitcore.util.js.isHexa(address))
      return await this.GetBalance(bitcore.Address(address));

    if (typeof address === "object") address = address.toString("hex");

    let utxos = await this.db.GetUtxos(true);

    let navConfirmed = bitcore.crypto.BN.Zero;
    let xNavConfirmed = bitcore.crypto.BN.Zero;
    let tokConfirmed = {};
    let coldConfirmed = bitcore.crypto.BN.Zero;
    let votingConfirmed = bitcore.crypto.BN.Zero;
    let navPending = bitcore.crypto.BN.Zero;
    let xNavPending = bitcore.crypto.BN.Zero;
    let tokPending = {};
    let coldPending = bitcore.crypto.BN.Zero;
    let votingPending = bitcore.crypto.BN.Zero;

    let tip = await this.GetTip();

    for (let u in utxos) {
      let utxo = utxos[u];
      let prevHash = utxo.id.split(":")[0];
      let prevOut = utxo.id.split(":")[1];

      let tx = await this.db.GetTx(prevHash);

      if (!tx) continue;

      let pending = false;

      if (
        (tx.pos < 2 && tip - tx.height < 120) ||
        tx.height <= 0 ||
        (tx.height == undefined && tx.pos == undefined)
      )
        pending = true;

      if (
        utxo.type & OutputTypes.XNAV &&
        (!address || utxo.hashId == address) &&
        utxo.amount > 0
      ) {
        let txObj = bitcore.Transaction(tx.hex);
        let tokId = {
          tokenId: txObj.outputs[prevOut].tokenId.toString("hex"),
          tokenNftId: txObj.outputs[prevOut].tokenNftId.toString(),
        };
        if (
          tokId.tokenId ==
            "0000000000000000000000000000000000000000000000000000000000000000" &&
          tokId.tokenNftId == -1
        ) {
          if (pending)
            xNavPending = xNavPending.add(new bitcore.crypto.BN(utxo.amount));
          else
            xNavConfirmed = xNavConfirmed.add(
              new bitcore.crypto.BN(utxo.amount)
            );
        } else {
          if (pending) {
            if (!tokPending[tokId.tokenId + ":" + tokId.tokenNftId])
              tokPending[tokId.tokenId + ":" + tokId.tokenNftId] = 0;
            tokPending[tokId.tokenId + ":" + tokId.tokenNftId] =
              tokPending[tokId.tokenId + ":" + tokId.tokenNftId] + utxo.amount;
          } else {
            if (!tokConfirmed[tokId.tokenId + ":" + tokId.tokenNftId])
              tokConfirmed[tokId.tokenId + ":" + tokId.tokenNftId] = 0;
            tokConfirmed[tokId.tokenId + ":" + tokId.tokenNftId] =
              tokConfirmed[tokId.tokenId + ":" + tokId.tokenNftId] +
              utxo.amount;
          }
        }
      } else {
        if (
          utxo.type & OutputTypes.STAKED &&
          (!address || utxo.stakingPk == address)
        ) {
          if (pending)
            coldPending = coldPending.add(new bitcore.crypto.BN(utxo.amount));
          else
            coldConfirmed = coldConfirmed.add(
              new bitcore.crypto.BN(utxo.amount)
            );
        } else if (
          utxo.type & OutputTypes.NAV &&
          (!address || utxo.spendingPk == address)
        ) {
          if (pending)
            navPending = navPending.add(new bitcore.crypto.BN(utxo.amount));
          else
            navConfirmed = navConfirmed.add(new bitcore.crypto.BN(utxo.amount));
        }
        if (
          utxo.type & OutputTypes.VOTING &&
          (!address || utxo.votingPk == address)
        ) {
          if (pending)
            votingPending = votingPending.add(
              new bitcore.crypto.BN(utxo.amount)
            );
          else
            votingConfirmed = votingConfirmed.add(
              new bitcore.crypto.BN(utxo.amount)
            );
        }
      }
    }

    let ret = {
      nav: {
        confirmed: navConfirmed.toNumber(),
        pending: navPending.toNumber(),
      },
      xnav: {
        confirmed: xNavConfirmed.toNumber(),
        pending: xNavPending.toNumber(),
      },
      tokens: {},
      nfts: {},
      staked: {
        confirmed: coldConfirmed.toNumber(),
        pending: coldPending.toNumber(),
      },
      voting: {
        confirmed: votingConfirmed.toNumber(),
        pending: votingPending.toNumber(),
      },
    };

    for (let i in tokConfirmed) {
      let tokenId = i.split(":")[0];
      let tokenNftId = i.split(":")[1];
      if (tokenNftId == -1) {
        if (!ret.tokens[tokenId]) {
          ret.tokens[tokenId] = {};

          let info = await this.GetTokenInfo(tokenId);
          ret.tokens[tokenId].name = info.name;
          ret.tokens[tokenId].code = info.code;
          ret.tokens[tokenId].supply = info.supply;
        }
        ret.tokens[tokenId].confirmed = tokConfirmed[i];
      } else {
        if (!ret.nfts[tokenId]) {
          ret.nfts[tokenId] = {};

          let info = await this.GetTokenInfo(tokenId);
          ret.nfts[tokenId].name = info.name;
          ret.nfts[tokenId].scheme = info.code;
          ret.nfts[tokenId].supply = info.supply;
          ret.nfts[tokenId].confirmed = {};
          ret.nfts[tokenId].pending = {};
        }
        let nftInfo = await this.GetNftInfo(tokenId, tokenNftId);

        ret.nfts[tokenId].confirmed[tokenNftId] = nftInfo
          ? nftInfo[0].metadata
          : "";
      }
    }

    for (let i in tokPending) {
      let tokenId = i.split(":")[0];
      let tokenNftId = i.split(":")[1];

      if (tokenNftId == -1) {
        if (!ret.tokens[tokenId]) {
          ret.tokens[tokenId] = {};

          let info = await this.GetTokenInfo(tokenId);
          ret.tokens[tokenId].name = info.name;
          ret.tokens[tokenId].code = info.code;
          ret.tokens[tokenId].supply = info.supply;
        }
        ret.tokens[tokenId].pending = tokPending[i];
      } else {
        if (!ret.nfts[tokenId]) {
          ret.nfts[tokenId] = {};

          let info = await this.GetTokenInfo(tokenId);
          ret.nfts[tokenId].name = info.name;
          ret.nfts[tokenId].scheme = info.code;
          ret.nfts[tokenId].supply = info.supply;
          ret.nfts[tokenId].pending = {};
          ret.nfts[tokenId].confirmed = {};
        }
        let nftInfo = await this.GetNftInfo(tokenId, tokenNftId);

        if (nftInfo)
          ret.nfts[tokenId].pending[tokenNftId] = nftInfo
            ? nftInfo[0].metadata
            : "";
      }
    }

    return ret;
  }

  async GetTokenInfo(id) {
    let ret = await this.db.GetTokenInfo(id);

    if (!this.client) return {};

    if (!ret || !ret.name) {
      try {
        let token = await this.client.blockchain_token_getToken(id);

        if (!token || (token && !token.name)) return {};

        await this.db.AddTokenInfo(
          token.id,
          token.name,
          token.token_code ? token.token_code : token.scheme,
          token.max_supply,
          token.version,
          token.pubkey
        );

        return {
          id: token.id,
          name: token.name,
          code: token.token_code ? token.token_code : token.scheme,
          supply: token.max_supply,
          version: token.version,
          key: token.pubkey,
        };
      } catch (e) {
        console.log(e);
        return {};
      }
    } else {
      return ret;
    }
  }

  async GetNftInfo(id, nftId) {
    let ret = await this.db.GetNftInfo(id, nftId);

    if (!this.client) return;

    if (!ret || !ret.metadata) {
      try {
        let token = await this.client.blockchain_token_getNft(
          id,
          parseInt(nftId)
        );
        if (!token || (token && !token.nfts)) return undefined;

        let retArray = [];

        for (let n in token.nfts) {
          if (nftId != -1 && token.nfts[n].index != nftId) continue;
          await this.db.AddNftInfo(
            token.id,
            token.nfts[n].index,
            token.nfts[n].metadata
          );
          retArray.push({
            id: token.nfts[n].index,
            metadata: token.nfts[n].metadata,
          });
        }

        return retArray;
      } catch (e) {
        console.log(e);
        return undefined;
      }
    } else {
      return [{ ...ret, id: parseInt(ret.id.split("-")[1]) }];
    }
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
        if ((await this.GetPoolSize(AddressTypes.NAV)) < 10) {
          this.Log("Filling NAV key pool");
          await this.NavFillKeyPool(this.spendingPassword, 20);
        }
      } else {
        await this.db.UseXNavAddress(hashId);
      }

      return true;
    } catch (e) {
      return false;
    }
  }

  async Spend(outPoint, spentIn) {
    let prev = await this.db.GetUtxo(outPoint);
    if (prev && prev.spentIn && spentIn && prev.spentIn == spentIn) {
      return false;
    }
    await this.db.SpendUtxo(outPoint, spentIn);
    return true;
  }

  async GetTx(hash, inMine, height, requestInputs = true) {
    let tx;
    let prevHeight;

    let cacheTx = await this.db.GetTx(hash);

    if (cacheTx) {
      cacheTx.tx = bitcore.Transaction(cacheTx.hex);
      tx = cacheTx;
      prevHeight = tx.height + 0;
    }

    if (!tx) {
      let tx_;
      try {
        if (!this.client) return;
        tx_ = await this.client.blockchain_transaction_get(hash, false);
      } catch (e) {
        this.Log(`error getting tx ${hash}: ${e}`);
        await this.ManageElectrumError(e);
        sleep(1);
        return await this.GetTx(hash, inMine, height, requestInputs);
      }

      tx = { txid: hash, hex: tx_ };

      try {
        await this.db.AddTx(tx);
      } catch (e) {
        console.log("AddTx", e);
      }

      tx.tx = bitcore.Transaction(tx.hex);
    }

    if (!tx.height || tx.height <= 0 || (height && height != tx.height)) {
      let heightBlock;
      try {
        if (!this.client) return;
        heightBlock = await this.client.blockchain_transaction_getMerkle(hash);
        tx.height = heightBlock.block_height;
        tx.pos = heightBlock.pos;
      } catch (e) {}
    }

    let mustNotify = false;

    if (tx.height != prevHeight) {
      if (tx.height) await this.db.SetTxHeight(hash, tx.height, tx.pos);
      mustNotify = true;
    }

    if (!requestInputs) return tx;

    await this.ProcessTx(tx, mustNotify);

    await this.db.MarkAsFetched(hash);

    return tx;
  }

  async ProcessTx(tx, mustNotify = true) {
    let mine = false;
    let memos = { in: [], out: [] };

    let deltaNav = 0;
    let deltaXNav = {};
    let deltaCold = 0;
    let addressesIn = { spending: [], staking: [] };
    let addressesOut = { spending: [], staking: [] };

    for (let i in tx.tx.inputs) {
      if (typeof inMine !== "undefined" && !inMine[i]) continue;

      let input = tx.tx.inputs[i].toObject();

      if (
        input.prevTxId ==
        "0000000000000000000000000000000000000000000000000000000000000000"
      )
        continue;

      let prevTx = (
        await this.GetTx(input.prevTxId, undefined, undefined, false)
      ).tx;
      let prevOut = prevTx.outputs[input.outputIndex];

      if (prevOut.isCt() || prevOut.isNft()) {
        let hid = blsct.GetHashId(prevOut, this.mvk);
        if (hid) {
          let hashId = new Buffer(hid).toString("hex");
          let acc = await this.db.HaveKey(hashId);
          if (acc) {
            if (
              blsct.RecoverBLSCTOutput(
                prevOut,
                this.mvk,
                undefined,
                acc[0],
                acc[1],
                prevOut.tokenId,
                prevOut.tokenNftId
              )
            ) {
              mine = true;
              let newOutput = await this.AddOutput(
                `${input.prevTxId}:${input.outputIndex}`,
                prevOut,
                prevTx.height
              );
              let newSpend = await this.Spend(
                `${input.prevTxId}:${input.outputIndex}`,
                `${tx.txid}:${i}`
              );
              if (newSpend || newOutput) mustNotify = true;
              if (
                !deltaXNav[
                  prevOut.tokenId.toString("hex") + ":" + prevOut.tokenNftId
                ]
              )
                deltaXNav[
                  prevOut.tokenId.toString("hex") + ":" + prevOut.tokenNftId
                ] = 0;
              deltaXNav[
                prevOut.tokenId.toString("hex") + ":" + prevOut.tokenNftId
              ] -= prevOut.amount ? prevOut.amount : prevOut.satoshis;
              memos.in.push(prevOut.memo);
            }
          }
        }
      } else if (
        prevOut.script.isPublicKeyHashOut() ||
        prevOut.script.isPublicKeyOut()
      ) {
        let hashPk = prevOut.script.isPublicKeyOut()
          ? ripemd160(sha256(prevOut.script.getPublicKey()))
          : prevOut.script.getPublicKeyHash();
        let hashId = new Buffer(hashPk).toString("hex");

        let add = bitcore
          .Address(hashPk, this.network, "pubkeyhash")
          .toString();
        if (addressesIn.spending.indexOf(add) == -1)
          addressesIn.spending.push(add);

        if (await this.db.HaveKey(hashId)) {
          mine = true;
          let newOutput = await this.AddOutput(
            `${input.prevTxId}:${input.outputIndex}`,
            prevOut,
            prevTx.height
          );
          let newSpend = await this.Spend(
            `${input.prevTxId}:${input.outputIndex}`,
            `${tx.txid}:${i}`
          );
          if (newSpend || newOutput) mustNotify = true;
          deltaNav -= prevOut.satoshis;
        }
      } else if (
        prevOut.script.isColdStakingOutP2PKH() ||
        prevOut.script.isColdStakingV2Out()
      ) {
        let hashPk = prevOut.script.getPublicKeyHash();
        let hashId = new Buffer(hashPk).toString("hex");

        let addSp = bitcore
          .Address(hashPk, this.network, "pubkeyhash")
          .toString();
        let addSt = bitcore
          .Address(
            prevOut.script.getStakingPublicKeyHash(),
            this.network,
            "pubkeyhash"
          )
          .toString();

        if (addressesIn.spending.indexOf(addSp) == -1) {
          addressesIn.spending.push(addSp);
        }

        if (addressesIn.staking.indexOf(addSt) == -1) {
          addressesIn.staking.push(addSt);
        }

        if (await this.db.HaveKey(hashId)) {
          mine = true;
          let newOutput = await this.AddOutput(
            `${input.prevTxId}:${input.outputIndex}`,
            prevOut,
            prevTx.height
          );
          let newSpend = await this.Spend(
            `${input.prevTxId}:${input.outputIndex}`,
            `${tx.txid}:${i}`
          );
          if (newSpend || newOutput) mustNotify = true;
          deltaCold -= prevOut.satoshis;
        }
      }
    }

    for (let i in tx.tx.outputs) {
      let out = tx.tx.outputs[i];

      if (out.isCt() || out.isNft()) {
        let hid = blsct.GetHashId(out, this.mvk);
        if (hid) {
          let hashId = new Buffer(hid).toString("hex");
          let acc = await this.db.HaveKey(hashId);

          if (acc) {
            if (
              blsct.RecoverBLSCTOutput(
                out,
                this.mvk,
                undefined,
                acc[0],
                acc[1],
                out.tokenId,
                out.tokenNftId
              )
            ) {
              mine = true;
              let newOutput = await this.AddOutput(
                `${tx.txid}:${i}`,
                out,
                tx.height
              );
              if (newOutput) mustNotify = true;
              if (
                !deltaXNav[out.tokenId.toString("hex") + ":" + out.tokenNftId]
              )
                deltaXNav[
                  out.tokenId.toString("hex") + ":" + out.tokenNftId
                ] = 0;
              deltaXNav[out.tokenId.toString("hex") + ":" + out.tokenNftId] +=
                out.amount ? out.amount : out.satoshis;
              memos.out.push(out.memo);
            }
          }
        }
      } else if (
        out.script.toHex() == "51" &&
        out.tokenNftId.toString() != -1
      ) {
        let hid = blsct.GetHashId(out, this.mvk);
        if (hid) {
          let hashId = new Buffer(hid).toString("hex");
          if (await this.db.HaveKey(hashId)) {
            mine = true;
            let newOutput = await this.AddOutput(
              `${tx.txid}:${i}`,
              out,
              tx.height
            );
            if (newOutput) mustNotify = true;
            if (!deltaXNav[out.tokenId.toString("hex") + ":" + out.tokenNftId])
              deltaXNav[out.tokenId.toString("hex") + ":" + out.tokenNftId] = 0;
            deltaXNav[out.tokenId.toString("hex") + ":" + out.tokenNftId] +=
              out.amount ? out.amount : out.satoshis;
          }
        }
      } else if (
        out.script.isPublicKeyHashOut() ||
        out.script.isPublicKeyOut()
      ) {
        let hashPk = out.script.isPublicKeyOut()
          ? ripemd160(sha256(out.script.getPublicKey()))
          : out.script.getPublicKeyHash();
        let hashId = new Buffer(hashPk).toString("hex");
        let add = bitcore
          .Address(hashPk, this.network, "pubkeyhash")
          .toString();
        if (addressesOut.spending.indexOf(add) == -1)
          addressesOut.spending.push(add);
        if (await this.db.HaveKey(hashId)) {
          mine = true;
          let newOutput = await this.AddOutput(
            `${tx.txid}:${i}`,
            out,
            tx.height
          );
          if (newOutput) mustNotify = true;
          deltaNav += out.satoshis;
        }
      } else if (
        out.script.isColdStakingOutP2PKH() ||
        out.script.isColdStakingV2Out()
      ) {
        let hashPk = out.script.getPublicKeyHash();
        let hashId = new Buffer(hashPk).toString("hex");

        let addSp = bitcore
          .Address(hashPk, this.network, "pubkeyhash")
          .toString();
        let addSt = bitcore
          .Address(
            out.script.getStakingPublicKeyHash(),
            this.network,
            "pubkeyhash"
          )
          .toString();

        if (addressesOut.spending.indexOf(addSp) == -1)
          addressesOut.spending.push(addSp);
        if (addressesOut.staking.indexOf(addSt) == -1)
          addressesOut.staking.push(addSt);

        if (await this.db.HaveKey(hashId)) {
          mine = true;
          let newOutput = await this.AddOutput(
            `${tx.txid}:${i}`,
            out,
            tx.height
          );
          if (newOutput) mustNotify = true;
          deltaCold += out.satoshis;
        }
      }

      if (out.vData[0] == 7 || out.vData[0] == 8) {
        try {
          let name = out.vData.slice(5, 5 + out.vData[4]).toString();
          if (await this.IsMyName(name)) {
            let data = await this.ResolveName(name);
            await this.AddName(name, undefined, data);
          }
        } catch (e) {
          console.log(e);
        }
      } else if (out.vData[0] == 2) {
        try {
          let values = bitcore.util.VData.parse(out.vData);
          let id = bitcore.crypto.Hash.sha256sha256(
            Buffer.concat([new Buffer([48]), values[1]])
          )
            .reverse()
            .toString("hex");
          this.emit("new_token", id);
          await this.db.AddTokenInfo(
            id,
            values[2].toString(),
            values[4].toString(),
            values[5] / (values[3] == 0 ? 1e8 : 1),
            values[3],
            values[1]
          );

          let derived = await this.DeriveSpendingKeyFromStringHash(
            "token/",
            values[2].toString() + values[4].toString(),
            this.spendingPassword
          );
          let key = blsct.SkToPubKey(new Buffer(derived).toString("hex"));

          let keyId = new Buffer(
            bitcore.crypto.Hash.sha256sha256(
              Buffer.concat([new Buffer([48]), new Buffer(key.serialize())])
            )
          )
            .reverse()
            .toString("hex");

          if (keyId == id) {
            await this.db.AddKey(
              keyId.toString("hex"),
              key.serialize().toString("hex"),
              AddressTypes.TOKEN,
              values[2],
              false,
              false,
              values[4],
              this.spendingPassword
            );
          }
        } catch (e) {
          console.log(e);
        }
      } else if (out.vData[0] == 3) {
        try {
          let values = bitcore.util.VData.parse(out.vData);
          let id = bitcore.crypto.Hash.sha256sha256(
            Buffer.concat([new Buffer([48]), values[1]])
          )
            .reverse()
            .toString("hex");
          console.log(`mint token ${id} ${values[2]} ${values[3]}`);
          if (values[3].length > 0) {
            await this.db.AddNftInfo(id, values[2], values[3]);
          }
        } catch (e) {
          console.log(e);
        }
      } else if (out.vData[0] == 6) {
        try {
          let ephKey = new blsct.mcl.G1();
          ephKey.deserialize(out.vData.slice(36, 84));
          let nonce = blsct.mcl.mul(ephKey, this.mvk);

          let decryptKey = bitcore.crypto.Blsct.HashG1Element(nonce, 1);
          let decrypted = this.Decrypt(
            out.vData.slice(84, out.vData.length),
            decryptKey
          )
            .toString()
            .split(";");
          let decryptedName = decrypted[0];
          let decryptedKey = decrypted[1];

          let sh = decryptedName + decryptedKey;
          let nameHash = bitcore.crypto.Hash.sha256sha256(
            Buffer.concat([new Buffer([sh.length]), new Buffer(sh, "utf-8")])
          );

          let bufferHash = new Buffer(nameHash);

          if (
            out.vData.slice(4, 36).toString("hex") == bufferHash.toString("hex")
          ) {
            this.emit("new_name", decryptedName.toString());
            await this.AddName(decryptedName.toString(), tx.height);
          }
        } catch (e) {}
      }
    }

    if (mustNotify && mine) {
      for (let d in deltaXNav) {
        if (deltaXNav[d] != 0 || memos.out.length) {
          let token = d.split(":")[0];
          let nftid = d.split(":")[1];
          let fisxnav =
            token ==
            "0000000000000000000000000000000000000000000000000000000000000000";
          let fistoken = nftid == "-1";
          let info = !fisxnav
            ? await this.GetTokenInfo(token)
            : { name: "xnav", code: "xnav" };
          this.emit("new_tx", {
            txid: tx.txid,
            amount: deltaXNav[d],
            type: fisxnav ? "xnav" : fistoken ? "token" : "nft",
            token_name: fisxnav ? "xnav" : info.name,
            token_code: fisxnav ? "xnav" : fistoken ? info.code : info.name,
            confirmed: tx.height > -0,
            height: tx.height,
            pos: tx.pos,
            timestamp: tx.tx.time,
            memos: memos,
            strdzeel: tx.strdzeel,
            token_id: token,
            nft_id: nftid,
          });
          await this.db.AddWalletTx(
            tx.txid,
            fisxnav ? "xnav" : fistoken ? "token" : "nft",
            deltaXNav[d],
            tx.height > 0,
            tx.height,
            tx.pos,
            tx.tx.time,
            memos,
            tx.strdzeel,
            addressesIn,
            addressesOut,
            fisxnav ? "xnav" : info.name,
            fisxnav ? "xnav" : fistoken ? info.code : info.name,
            token,
            nftid
          );
        }
      }
      if (deltaNav != 0) {
        this.emit("new_tx", {
          txid: tx.txid,
          amount: deltaNav,
          type: "nav",
          confirmed: tx.height > 0,
          height: tx.height,
          pos: tx.pos,
          timestamp: tx.tx.time,
          strdzeel: tx.strdzeel,
        });
        await this.db.AddWalletTx(
          tx.txid,
          "nav",
          deltaNav,
          tx.height > 0,
          tx.height,
          tx.pos,
          tx.tx.time,
          tx.strdzeel,
          addressesIn,
          addressesOut
        );
      }
      if (deltaCold != 0) {
        this.emit("new_tx", {
          txid: tx.txid,
          amount: deltaCold,
          type: "cold_staking",
          confirmed: tx.height > 0,
          height: tx.height,
          pos: tx.pos,
          timestamp: tx.tx.time,
          strdzeel: tx.strdzeel,
        });
        await this.db.AddWalletTx(
          tx.txid,
          "cold_staking",
          deltaCold,
          tx.height > 0,
          tx.height,
          tx.pos,
          tx.tx.time,
          tx.strdzeel,
          addressesIn,
          addressesOut
        );
      }
    }
  }

  async GetMyNames() {
    return await this.db.GetMyNames();
  }

  async GetMyTokens() {
    let allTokens = await this.db.GetMyTokens();

    return await asyncFilter(allTokens, async (token) => {
      return this.db.HaveKey(token.id);
    });
  }

  async AddName(name, height, data = {}) {
    try {
      let exists = await this.db.GetName(name);
      await this.db.AddName(name, height || exists.height, data);
      if (!exists) this.emit("new_name", name, height);
      else this.emit("update_name", name, exists.height, data);
      return true;
    } catch (e) {
      return false;
    }
  }

  IsValidDotNavName(name) {
    if (!name || !name.length) return false;

    if (name.length >= 64 || name.length < 5) return false;

    if (
      !/^[abcdefghijklmnopqrstuvwxyz01234566789][abcdefghijklmnopqrstuvwxyz01234566789-]*\.nav$/.test(
        name
      )
    )
      return false;

    return true;
  }

  IsValidDotNavKey(key) {
    if (!key || !key.length) return false;

    if (key.length >= 64 || key.length < 1) return false;

    if (
      !/^[abcdefghijklmnopqrstuvwxyz01234566789][abcdefghijklmnopqrstuvwxyz01234566789-]*$/.test(
        key
      )
    )
      return false;

    return true;
  }

  async IsMyName(name) {
    return await this.db.GetName(name);
  }

  async AddStakingAddress(pk, pk2, sync = false) {
    if (
      pk instanceof bitcore.Address ||
      (typeof pk === "string" && pk != "" && !bitcore.util.js.isHexa(pk))
    )
      pk = bitcore.Address(pk).toObject().hash;
    if (
      pk2 instanceof bitcore.Address ||
      (typeof pk2 === "string" && pk2 != "" && !bitcore.util.js.isHexa(pk2))
    )
      pk2 = bitcore.Address(pk2).toObject().hash;

    if (pk instanceof Buffer) pk = pk.toString("hex");

    if (pk2 instanceof Buffer) pk2 = pk2.toString("hex");

    let strAddress = bitcore
      .Address(new Buffer(pk, "hex"), this.network)
      .toString();

    let strAddress2 = pk2
      ? bitcore.Address(new Buffer(pk2, "hex"), this.network).toString()
      : "";

    let isInDb = await this.db.GetStakingAddress(strAddress, strAddress2);

    if (!isInDb) {
      try {
        await this.db.AddStakingAddress(strAddress, strAddress2, pk, pk2);

        this.emit("new_staking_address", strAddress, strAddress2);
        this.Log(`New staking address: ${strAddress} ${strAddress2}`);

        if (sync) await this.Sync(strAddress);
      } catch (e) {
        //console.log(e)
      }
    }
  }

  async IsMine(input) {
    if (input.script) {
      let script = bitcore.Script(input.script);

      if (script.isPublicKeyHashOut() || script.isPublicKeyOut()) {
        let hashId = new Buffer(
          script.isPublicKeyOut()
            ? ripemd160(sha256(script.getPublicKey()))
            : script.getPublicKeyHash()
        ).toString("hex");

        if (await this.db.HaveKey(hashId)) {
          return true;
        }
      } else if (script.isColdStakingOutP2PKH()) {
        let hashId = new Buffer(script.getPublicKeyHash()).toString("hex");

        if (await this.db.HaveKey(hashId)) {
          if (script.isColdStakingOutP2PKH()) {
            let stakingPk = script.getStakingPublicKeyHash();
            await this.AddStakingAddress(stakingPk, undefined, true);
          } else if (script.isColdStakingV2Out()) {
            let stakingPk = script.getStakingPublicKeyHash();
            let votingPk = script.getVotingPublicKeyHash();
            await this.AddStakingAddress(stakingPk, votingPk, true);
          }

          return true;
        }
      } else if (script.isColdStakingV2Out()) {
        let hashId = new Buffer(script.getPublicKeyHash()).toString("hex");
        let hashIdVoting = new Buffer(script.getVotingPublicKeyHash()).toString(
          "hex"
        );

        if (
          (await this.db.HaveKey(hashId)) ||
          (await this.db.HaveKey(hashIdVoting))
        ) {
          if (script.isColdStakingOutP2PKH()) {
            let stakingPk = script.getStakingPublicKeyHash();
            await this.AddStakingAddress(stakingPk, undefined, true);
          } else if (script.isColdStakingV2Out()) {
            let stakingPk = script.getStakingPublicKeyHash();
            let votingPk = script.getVotingPublicKeyHash();
            await this.AddStakingAddress(stakingPk, votingPk, true);
          }

          return true;
        }
      }
    } else if (input.spendingKey && input.outputKey) {
      let hid = blsct.GetHashId(
        { ok: input.outputKey, sk: input.spendingKey },
        this.mvk
      );
      if (hid) {
        let hashId = new Buffer(hid).toString("hex");
        if (hashId && (await this.db.HaveKey(hashId))) {
          return true;
        }
      }
    }

    return false;
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
        this.Log(`error getting tx keys ${hash}: ${e}`);
        await this.ManageElectrumError(e);
        sleep(3);
        return await this.GetTxKeys(hash, height, useCache);
      }
      txKeys.txidkeys = hash;

      try {
        await this.db.AddTxKeys(txKeys);
      } catch (e) {}
    }

    let inMine = [];
    let isMine = false;

    for (let i in txKeys.vin) {
      let input = txKeys.vin[i];
      let thisMine = await this.IsMine(input);

      if (thisMine) {
        //await this.GetTx(input.txid, undefined, undefined, false)
        isMine = true;
      }

      inMine.push(thisMine);
    }

    for (let j in txKeys.vout) {
      let output = txKeys.vout[j];
      isMine |= await this.IsMine(output);
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

    let msk = await this.GetMasterSpendKey(spendingPassword);

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
    let msk = await this.GetMasterSpendKey(spendingPassword);

    if (!(msk && mvk)) return;

    let utx = await this.GetUtxos(OutputTypes.XNAV);
    let utxos = [];

    for (const out_i in utx) {
      let out = utx[out_i];

      if (!(out.output.isCt() || out.output.isNft())) continue;

      utxos.push(out);
    }

    if (!utxos.length) throw new Error("No available xNAV outputs");

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
    aggFee = 0
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
    let msk = await this.GetMasterSpendKey(spendingPassword);

    if (!(msk && mvk)) return;

    let utx = await this.GetUtxos(OutputTypes.XNAV);
    let utxos = [];

    for (const out_i in utx) {
      let out = utx[out_i];

      if (!(out.output.isCt() || out.output.isNft())) continue;

      utxos.push(out);
    }

    if (!utxos.length) throw new Error("No available xNAV outputs");

    let dests = [
      {
        dest: dest,
        amount: amount,
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
      subtractFee,
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
    aggFee = 0
  ) {
    let consensus = await this.GetConsensusParameters();

    if (consensus[24]?.value != 1)
      throw new Error("Private Tokens and NFTs are not active yet");

    if (amount < 0) throw new TypeError("Amount must be positive");

    tokenId = new Buffer(tokenId, "hex");

    let mvk = this.mvk;
    let msk = await this.GetMasterSpendKey(spendingPassword);

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

    if (!ignoreInputs) {
      for (const out_i in utx) {
        let out = utx[out_i];

        if (!(out.output.isCt() || out.output.isNft())) continue;

        utxos.push(out);
      }

      for (const out_i in utxTok) {
        let out = utxTok[out_i];

        if (!(out.output.isCt() || out.output.isNft())) continue;

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
            amount: amount,
            memo: memo,
            vData: vData,
            extraKey: extraKey,
          },
        ];

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

      let prevTx = await this.GetTx(input.prevTxId.toString("hex"));

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
    let txObj = bitcore.Transaction(tx);

    let tx_ = { txid: ret, hex: tx };

    try {
      await this.db.AddTx(tx_);
    } catch (e) {
      console.log("AddTx", e);
    }

    tx_.tx = txObj;

    await this.ProcessTx(tx_);

    return ret;
  }

  Encrypt(plain, key) {
    const iv = crypto.randomBytes(16);
    const aes = crypto.createCipheriv("aes-256-cbc", key, iv);
    let ciphertext = aes.update(plain);
    ciphertext = Buffer.concat([iv, ciphertext, aes.final()]);
    return ciphertext;
  }

  Decrypt(cypher, key) {
    const ciphertextBytes = Buffer.from(cypher);
    const iv = ciphertextBytes.slice(0, 16);
    const data = ciphertextBytes.slice(16);
    const aes = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let plaintextBytes = Buffer.from(aes.update(data));
    plaintextBytes = Buffer.concat([plaintextBytes, aes.final()]);
    return plaintextBytes;
  }

  async RegisterName(name, spendingPassword) {
    name = name.toLowerCase();

    let nameResolve = {};

    try {
      nameResolve = await this.ResolveName(name);
    } catch (e) {}

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
    let encryptedName = this.Encrypt(
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
    return ret;
  }

  async MintToken(id, dest, amount, spendingPassword) {
    let consensus = await this.GetConsensusParameters();

    if (consensus[24]?.value != 1)
      throw new Error("Private Tokens and NFTs are not active yet");

    let token = await this.GetTokenInfo(id);

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

    await this.db.AddKey(
      ret.token_id.toString("hex"),
      key.serialize().toString("hex"),
      AddressTypes.TOKEN,
      name,
      false,
      false,
      scheme,
      spendingPassword
    );

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
    let msk = await this.GetMasterSpendKey(spendingPassword);

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

    let token = await this.GetTokenInfo(id);

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
    let msk = await this.GetMasterSpendKey(spendingPassword);

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
        dest: (await this.xNavReceivingAddresses(true))[0].address,
        amount: order.receive[0].amount,
        tokenId: order.receive[0].tokenId,
        tokenNftId: order.receive[0].tokenNftId,
      },
    ];

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
    let token = await this.GetTokenInfo(id);

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
    let token = await this.GetTokenInfo(id);

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
    let token = await this.GetTokenInfo(id);

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

    if (!(dest instanceof bitcore.Address))
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

    let msk = await this.GetMasterKey("xNavSpend", spendingPassword);

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

      let prevtx = await this.GetTx(out.txid);

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

      let privK = await this.GetPrivateKey(hashId, spendingPassword);

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
          `Not enough balance (required ${
            amount + (subtractFee ? 0 : fee)
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
                .Address((await this.NavReceivingAddresses())[0].address)
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
          (await this.NavReceivingAddresses())[0].address,
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

  async GetPrivateKey(hashId, key) {
    let ret = await this.db.GetKey(hashId, key);

    if (!ret) return;

    return ret.length > 100
      ? bitcore.HDPrivateKey(ret, this.network).privateKey
      : bitcore.PrivateKey(ret);
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
