// noinspection JSBitwiseOperatorUsage
const Db = require("./db/dexie");
const Mnemonic = require("bitcore-mnemonic");
const electrumMnemonic = require("electrum-mnemonic");
const bitcore = require("bitcore-lib");
const blsct = bitcore.Transaction.Blsct;
const EventEmitter = require("events");
const ripemd160 = bitcore.crypto.Hash.ripemd160;
const sha256 = bitcore.crypto.Hash.sha256;
const electrum = require("electrum-client-js");
const _ = require("lodash");
const Message = require("bitcore-message");
const nodes = require("./nodes");
const queue = require("./utils/queue");
const OutputTypes = require("./utils/output_types");
const AddressTypes = require("./utils/address_types");

function msleep(n) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, n);
}
function sleep(n) {
  msleep(n * 1000);
}

class WalletFile extends EventEmitter {
  constructor(options) {
    super();

    options = options || {};

    this.type = options.type || "navcoin-js-v1";
    this.mnemonic = options.mnemonic;
    this.spendingPassword = options.spendingPassword;
    this.zapwallettxes = options.zapwallettxes || false;
    this.log = options.log || false;
    this.queue = new queue();

    let self = this;

    this.queue.on("progress", (progress, pending, total) => {
      self.emit("sync_status", progress, pending, total);
    });

    this.queue.on("end", () => {
      self.emit("sync_finished");
    });

    this.network = options.network || "mainnet";

    this.electrumNodes = nodes[this.network];

    if (!this.electrumNodes.length) {
      throw new Error("Wrong network");
    }

    this.electrumNodeIndex = 0;

    let secret = options.password || "secret navcoinjs";

    this.db = new Db(options.file, secret);

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

  static CloseDb() {
    this.db.Close();
  }

  static async ListWallets() {
    return await Db.ListWallets();
  }

  static async RemoveWallet(filename) {
    return await Db.RemoveWallet(filename);
  }

  async GetPoolSize(type) {
    return await this.db.GetPoolSize(type);
  }

  async Log(str) {
    if (!this.log) return;
    console.log(` [navcoin-js] ${str}`);
  }

  async Load(options) {
    options = options || {};

    if (!(await this.db.GetValue("masterPubKey"))) {
      await this.db.SetValue("walletType", this.type);
      let mnemonic = this.mnemonic;

      if (!this.mnemonic) {
        this.newWallet = true;
        mnemonic = new Mnemonic().toString();
        this.emit("new_mnemonic", mnemonic);
      }

      await this.db.AddMasterKey("mnemonic", mnemonic, this.spendingPassword);

      if (this.type === "next") {
        let value = Buffer.from(new Mnemonic(mnemonic).toString());
        let hash = bitcore.crypto.Hash.sha256(value);
        let bn = bitcore.crypto.BN.fromBuffer(hash);
        let pk = new bitcore.PrivateKey(bn);

        await this.ImportPrivateKey(pk, this.spendingPassword);

        let masterKey = new Mnemonic(mnemonic).toHDPrivateKey();

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
        let masterKey = new Mnemonic(mnemonic).toHDPrivateKey();

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

    let network = await this.db.GetValue("network");

    if (!network) {
      await this.db.SetValue("network", this.network);
    } else {
      this.network = network;
    }

    this.mvk = await this.GetMasterViewKey();

    this.synced = {};
    this.firstSync = false;
    this.creationTip = undefined;

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

    if (this.newWallet && this.type === "navcash") {
      let pool =
        this.network == "mainnet"
          ? "NfLgDYL4C3KKXDS8tLRAFM7spvLykV8v9A"
          : "n4hyNjvNXF1qHf8P4oQbuvVAG8ZkNViJSs";
      await this.AddStakingAddress(pool, undefined, false);
      await this.db.AddLabel(pool, "NavCash Pool");
    }

    this.poolFilled = true;

    this.mnemonic = "";
    this.spendingPassword = "";

    if (this.zapwallettxes) {
      await this.db.ZapWalletTxes();
    }

    this.emit("loaded");
  }

  async xNavFillKeyPool(spendingPassword) {
    let mk = await this.GetMasterKey("xNavSpend", spendingPassword);

    if (!mk) return;

    while ((await this.GetPoolSize(AddressTypes.XNAV)) < 10) {
      await this.xNavCreateSubaddress(spendingPassword);
    }
  }

  async NavFillKeyPool(spendingPassword) {
    if (this.type === "next") return;

    let mk = await this.GetMasterKey("nav", spendingPassword);

    if (!mk) return;

    while ((await this.GetPoolSize(AddressTypes.NAV)) < 10) {
      await this.NavCreateAddress(spendingPassword);
    }
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
      ? await this.db.GetNavAddress(address)
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

    let pubK = await this.db.GetValue("masterPubKey");

    if (!pubK) return undefined;

    if (
      bitcore.HDPrivateKey(privK).hdPublicKey.toString() !==
      bitcore.HDPublicKey(pubK).toString()
    )
      return undefined;

    return privK;
  }

  async GetMasterSpendKey(key) {
    if (!this.db) return undefined;

    let privK = await this.db.GetMasterKey("xNavSpend", key);

    if (!privK) return undefined;

    let pubK = await this.db.GetValue("masterSpendPubKey");

    if (!pubK) return undefined;

    if (
      !blsct.mcl
        .deserializeHexStrToG1(pubK)
        .isEqual(
          blsct.mcl.mul(blsct.G(), blsct.mcl.deserializeHexStrToFr(privK))
        )
    )
      return undefined;

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

  async SetTip(height) {
    this.lastBlock = height;
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

  async GetScriptHashes(stakingAddress = undefined) {
    let ret = [];

    let addresses = await this.db.GetNavAddresses();

    for (let i in addresses) {
      if (!stakingAddress) {
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
      ret.push(addresses[i].stakingAddress);
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

  async Connect() {
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

    try {
      await this.client.connect("navcoin-js", "1.5");
      this.connected = true;

      let tip = (await this.client.blockchain_headers_subscribe()).height;
      await this.SetTip(tip);

      if (this.newWallet && !this.creationTip) {
        this.creationTip = tip;
        await this.db.SetValue("creationTip", tip);
      }

      this.client.subscribe.on(
        "blockchain.headers.subscribe",
        async (event) => {
          await self.SetTip(event[0].height);
        }
      );
    } catch (e) {
      this.connected = false;
      this.emit("connection_failed");
      console.error(
        `error connecting to electrum ${
          this.electrumNodes[this.electrumNodeIndex].host
        }:${this.electrumNodes[this.electrumNodeIndex].port}: ${e}`
      );
      return await this.ManageElectrumError(e);
    }

    this.emit(
      "connected",
      this.electrumNodes[this.electrumNodeIndex].host +
        ":" +
        this.electrumNodes[this.electrumNodeIndex].port
    );

    let self = this;

    await this.Sync();

    try {
      this.client.subscribe.on(
        "blockchain.scripthash.subscribe",
        async (event) => {
          await self.ReceivedScriptHashStatus(event[0], event[1]);
        }
      );
    } catch (e) {
      console.error(`error electrum: ${e}`);
      await this.ManageElectrumError(e);
      return false;
    }
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
    let scriptHashes = await this.GetScriptHashes(staking);

    if (!this.alreadyQueued && !staking) {
      let pending = await this.db.GetPendingTxs();

      for (let j in pending) {
        await this.QueueTxKeys(pending[j].tx_hash, pending[j].height, true);
      }

      this.Log(`Queuing ${pending.length} pending transactions`);
      this.alreadyQueued = true;
    }

    for (let i in scriptHashes) {
      let s = scriptHashes[i];

      try {
        this.synced[s] = false;
        let currentStatus = await this.client.blockchain_scripthash_subscribe(
          s
        );
        await this.ReceivedScriptHashStatus(s, currentStatus);
      } catch (e) {
        console.log("ReceivedScriptHashStatus", e);
        await this.ManageElectrumError(e);
        return await this.Sync(staking);
      }
    }

    if (!staking) {
      let stakingAddresses = await this.GetStakingAddresses();

      for (let k in stakingAddresses) {
        let address = stakingAddresses[k];
        await this.Sync(address);
      }
    }
  }

  async ManageElectrumError(e) {
    if (
      e === "Error: close connect" ||
      e === "Error: connection not established" ||
      e ===
        "Error: failed to connect to electrum server: [Error: websocket connection closed: code: [1006], reason: [connection failed]]"
    ) {
      this.connected = false;
      this.electrumNodeIndex =
        (this.electrumNodeIndex + 1) % this.electrumNodes.length;
      this.emit("connection_failed");
      this.client.close();
      sleep(1);
      this.Log(`Reconnecting to electrum node ${this.electrumNodeIndex}`);
      await this.Connect();
    }

    if (e === "server busy - request timed out") {
      sleep(5);
    }
  }

  Disconnect() {
    if (this.client) this.client.close();
    this.connected = false;

    delete this.client;
  }

  async ReceivedScriptHashStatus(s, status) {
    let prevStatus = await this.GetStatusHashForScriptHash(s);

    if (status && status !== prevStatus) {
      await this.db.SetStatusForScriptHash(s, status);

      this.Log(`Received new status ${status} for ${s}. Syncing.`);

      this.queue.add(this, this.SyncScriptHash, [s], true, !this.firstSync);
    }
  }

  async SyncScriptHash(scripthash) {
    let currentHistory = [];
    let prevMaxHeight = -10;
    let lb = this.lastBlock + 0;

    let historyRange = {};

    while (true) {
      try {
        currentHistory = await this.db.GetScriptHashHistory(scripthash);
      } catch (e) {
        this.Log(`error getting history from db: ${e}`);
      }

      let currentLastHeight = this.creationTip ? this.creationTip : 0;

      for (let i in currentHistory) {
        if (currentHistory[i].height > currentLastHeight)
          currentLastHeight = currentHistory[i].height;
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
          fetched: false,
        });

        let hash = newHistory.history[j].tx_hash;
        let height = newHistory.history[j].height;
      }

      await this.db.BulkRawInsertHistory(toAddBulk);

      toAddBulk = [];

      for (var i in toAddBulk) {
        await this.QueueTxKeys(toAddBulk[i].tx_hash, toAddBulk[i].height, true);

        if (j % 100 == 0) this.queue.emitProgress();
      }

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

    this.synced[scripthash] = true;

    for (let i in this.synced) {
      this.firstSync &= this.synced[i];
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

  async GetUtxos(type = OutputTypes.NAV | OutputTypes.STAKED) {
    let utxos = await this.db.GetUtxos();

    let tip = await this.GetTip();
    let ret = [];

    for (let u in utxos) {
      let utxo = utxos[u];

      if (!(utxo.type & type)) continue;

      let outpoint = utxo.id.split(":");

      let tx = await this.db.GetTx(outpoint[0]);

      let pending = false;

      if ((tx.pos < 2 && tip - tx.height < 120) || tx.height <= 0)
        pending = true;

      if (!pending) {
        let out = bitcore.Transaction.Output.fromBufferReader(
          new bitcore.encoding.BufferReader(new Buffer(utxo.out, "hex"))
        );
        let item = { txid: outpoint[0], vout: outpoint[1], output: out };

        if (out.isCt()) {
          let hashid = new Buffer(blsct.GetHashId(out, this.mvk)).toString(
            "hex"
          );
          let value = await this.db.GetKey(hashid);

          item.accIndex = value;
        }

        ret.push(item);
      }
    }

    return ret;
  }

  async GetBalance(address) {
    if (address instanceof bitcore.Address)
      return await this.GetBalance(address.hashBuffer);

    if (
      typeof address === "string" &&
      bitcore.Address.isValid(address, this.network, "pubkey")
    )
      return await this.GetBalance(bitcore.Address(address));

    if (typeof address === "object") address = address.toString("hex");

    let utxos = await this.db.GetUtxos();

    let navConfirmed = bitcore.crypto.BN.Zero;
    let xNavConfirmed = bitcore.crypto.BN.Zero;
    let coldConfirmed = bitcore.crypto.BN.Zero;
    let votingConfirmed = bitcore.crypto.BN.Zero;
    let navPending = bitcore.crypto.BN.Zero;
    let xNavPending = bitcore.crypto.BN.Zero;
    let coldPending = bitcore.crypto.BN.Zero;
    let votingPending = bitcore.crypto.BN.Zero;

    let tip = await this.GetTip();

    for (let u in utxos) {
      let utxo = utxos[u];
      let prevHash = utxo.id.split(":")[0];

      let tx = await this.db.GetTx(prevHash);

      if (!tx) continue;

      let pending = false;

      if (
        (tx.pos < 2 && tip - tx.height < 120) ||
        tx.height <= 0 ||
        !tx.height ||
        !tx.pos
      )
        pending = true;

      if (
        utxo.type & OutputTypes.XNAV &&
        (!address || utxo.hashId == address)
      ) {
        if (pending)
          xNavPending = xNavPending.add(new bitcore.crypto.BN(utxo.amount));
        else
          xNavConfirmed = xNavConfirmed.add(new bitcore.crypto.BN(utxo.amount));
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

    return {
      nav: {
        confirmed: navConfirmed.toNumber(),
        pending: navPending.toNumber(),
      },
      xnav: {
        confirmed: xNavConfirmed.toNumber(),
        pending: xNavPending.toNumber(),
      },
      staked: {
        confirmed: coldConfirmed.toNumber(),
        pending: coldPending.toNumber(),
      },
      voting: {
        confirmed: votingConfirmed.toNumber(),
        pending: votingPending.toNumber(),
      },
    };
  }

  async AddOutput(outpoint, out) {
    let amount = out.isCt() ? out.amount : out.satoshis;
    let label = out.isCt() ? out.memo : out.script.toAddress(this.network);
    let isCold =
      out.script.isColdStakingOutP2PKH() || out.script.isColdStakingV2Out();

    let type = 0x0;

    if (out.isCt()) type |= OutputTypes.XNAV;
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

      if (out.isCt()) {
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

      if (!out.isCt()) {
        await this.db.UseNavAddress(
          out.script.toAddress(this.network).toString()
        );
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
    if (prev && prev.spentIn && spentIn) {
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
        tx_ = await this.client.blockchain_transaction_get(hash, false);
      } catch (e) {
        this.Log(`error getting tx ${hash}: ${e}`);
        await this.ManageElectrumError(e);
        sleep(1);
        return await this.GetTx(hash, inMine);
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

    let mine = false;
    let memos = { in: [], out: [] };

    let deltaNav = 0;
    let deltaXNav = 0;
    let deltaCold = 0;

    if (requestInputs) {
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

        if (prevOut.isCt()) {
          let hid = blsct.GetHashId(prevOut, this.mvk);
          if (hid) {
            let hashId = new Buffer(hid).toString("hex");
            if (await this.db.GetKey(hashId)) {
              if (blsct.RecoverBLSCTOutput(prevOut, this.mvk)) {
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
                deltaXNav -= prevOut.amount;
                memos.in.push(prevOut.memo);
              }
            }
          }
        } else if (
          prevOut.script.isPublicKeyHashOut() ||
          prevOut.script.isPublicKeyOut()
        ) {
          let hashId = new Buffer(
            prevOut.script.isPublicKeyOut()
              ? ripemd160(sha256(prevOut.script.getPublicKey()))
              : prevOut.script.getPublicKeyHash()
          ).toString("hex");

          if (await this.db.GetKey(hashId)) {
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
          let hashId = new Buffer(prevOut.script.getPublicKeyHash()).toString(
            "hex"
          );

          if (await this.db.GetKey(hashId)) {
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

        if (out.isCt()) {
          let hid = blsct.GetHashId(out, this.mvk);
          if (hid) {
            let hashId = new Buffer(hid).toString("hex");
            if (await this.db.GetKey(hashId)) {
              if (blsct.RecoverBLSCTOutput(out, this.mvk)) {
                mine = true;
                let newOutput = await this.AddOutput(
                  `${tx.txid}:${i}`,
                  out,
                  tx.height
                );
                if (newOutput) mustNotify = true;
                deltaXNav += out.amount;
                memos.out.push(out.memo);
              }
            }
          }
        } else if (
          out.script.isPublicKeyHashOut() ||
          out.script.isPublicKeyOut()
        ) {
          let hashId = new Buffer(
            out.script.isPublicKeyOut()
              ? ripemd160(sha256(out.script.getPublicKey()))
              : out.script.getPublicKeyHash()
          ).toString("hex");
          if (await this.db.GetKey(hashId)) {
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
          let hashId = new Buffer(out.script.getPublicKeyHash()).toString(
            "hex"
          );

          if (await this.db.GetKey(hashId)) {
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
      }

      if (mustNotify && mine) {
        if (deltaXNav != 0) {
          this.emit("new_tx", {
            txid: tx.txid,
            amount: deltaXNav,
            type: "xnav",
            confirmed: tx.height > -0,
            height: tx.height,
            pos: tx.pos,
            timestamp: tx.tx.time,
            memos: memos,
          });
          await this.db.AddWalletTx(
            tx.txid,
            "xnav",
            deltaXNav,
            tx.height > 0,
            tx.height,
            tx.pos,
            tx.tx.time,
            memos
          );
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
          });
          await this.db.AddWalletTx(
            tx.txid,
            "nav",
            deltaNav,
            tx.height > 0,
            tx.height,
            tx.pos,
            tx.tx.time
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
          });
          await this.db.AddWalletTx(
            tx.txid,
            "cold_staking",
            deltaCold,
            tx.height > 0,
            tx.height,
            tx.pos,
            tx.tx.time
          );
        }
      }
    }

    await this.db.MarkAsFetched(hash);

    return tx;
  }

  async AddStakingAddress(pk, pk2, sync = false) {
    if (
      pk instanceof bitcore.Address ||
      (typeof pk === "string" && !bitcore.util.js.isHexa(pk))
    )
      return await this.AddStakingAddress(
        bitcore.Address(pk).toObject().hash,
        pk2,
        sync
      );

    if (
      pk2 instanceof bitcore.Address ||
      (typeof pk2 === "string" && !bitcore.util.js.isHexa(pk2))
    )
      return await this.AddStakingAddress(
        pk,
        bitcore.Address(pk2).toObject().hash,
        sync
      );

    if (pk instanceof Buffer)
      return await this.AddStakingAddress(pk.toString("hex"), pk2, sync);

    if (pk2 instanceof Buffer)
      return await this.AddStakingAddress(pk, pk2.toString("hex"), sync);

    let strAddress = bitcore
      .Address(new Buffer(pk, "hex"))
      .toString(this.network);

    let isInDb = await this.db.GetStakingAddress(strAddress);

    if (!isInDb) {
      try {
        await this.db.AddStakingAddress(strAddress, pk);

        this.Log(`New staking address: ${strAddress}`);

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

        if (await this.db.GetKey(hashId)) {
          return true;
        }
      } else if (script.isColdStakingOutP2PKH()) {
        let hashId = new Buffer(script.getPublicKeyHash()).toString("hex");

        if (await this.db.GetKey(hashId)) {
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
          (await this.db.GetKey(hashId)) ||
          (await this.db.GetKey(hashIdVoting))
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
        if (hashId && (await this.db.GetKey(hashId))) {
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

  async xNavCreateTransaction(
    dest,
    amount,
    memo,
    spendingPassword,
    subtractFee = true
  ) {
    if (amount <= 0) throw new TypeError("Amount must be greater than 0");

    let mvk = this.mvk;
    let msk = await this.GetMasterSpendKey(spendingPassword);

    if (!(msk && mvk)) return;

    let utx = await this.GetUtxos(OutputTypes.XNAV);
    let utxos = [];

    for (const out_i in utx) {
      let out = utx[out_i];

      if (!out.output.isCt()) continue;

      utxos.push(out);
    }

    if (!utxos.length) throw new Error("No available xNAV outputs");

    let tx = blsct.CreateTransaction(
      utxos,
      dest,
      amount,
      memo,
      mvk,
      msk,
      subtractFee
    );

    if (await this.GetMasterKey("nav", spendingPassword)) {
      await this.xNavFillKeyPool(spendingPassword);
      await this.NavFillKeyPool(spendingPassword);
    }

    return { tx: [tx.toString()], fee: tx.feeAmount };
  }

  async SendTransaction(txs) {
    if (_.isArray(txs)) {
      let ret = [];

      for (const i in txs) {
        let tx = txs[i];
        try {
          let hash = await this.client.blockchain_transaction_broadcast(tx);
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
          hashes: [await this.client.blockchain_transaction_broadcast(txs)],
          error: undefined,
        };
      } catch (e) {
        console.error(`error sending tx: ${e}`);
        await this.ManageElectrumError(e);
        return { hashes: [], error: e };
      }
    }
  }

  async NavCreateTransaction(
    dest,
    amount,
    memo,
    spendingPassword,
    subtractFee = true,
    fee = 100000,
    ret = { fee: 0, tx: [] },
    selectxnav = false,
    type = OutputTypes.NAV | OutputTypes.STAKED
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
        ret,
        selectxnav,
        type
      );

    let msk = await this.GetMasterKey("xNavSpend", spendingPassword);

    if (!msk) return;

    let utxos = await this.GetUtxos(type);

    let tx = bitcore.Transaction();
    let addedInputs = 0;
    let privateKeys = [];
    let gammaIns = new blsct.mcl.Fr();

    for (let u in utxos) {
      let out = utxos[u];

      if (out.output.isCt())
        throw new TypeError("NavSend can only spend nav outputs");

      let prevtx = await this.GetTx(out.txid);

      if (prevtx.tx.version & 0x20 && !selectxnav) continue;

      // noinspection JSBitwiseOperatorUsage
      if (!(prevtx.tx.version & 0x20) && selectxnav) continue;

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
          ret,
          true
        );
        amount = addedInputs;
      }
    }

    if (dest.isXnav()) {
      if (amount >= (subtractFee ? fee : 0)) {
        let out = blsct.CreateBLSCTOutput(
          dest,
          amount - (subtractFee ? fee : 0),
          memo
        );
        tx.addOutput(out);
        blsct.SigBalance(tx, blsct.mcl.sub(gammaIns, out.gamma));
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
    }

    if (addedInputs - (amount + (subtractFee ? 0 : fee)) > 0) {
      tx.to(
        (await this.NavReceivingAddresses())[0].address,
        addedInputs - (amount + (subtractFee ? 0 : fee))
      );
    }

    tx.settime(Math.floor(Date.now() / 1000)).sign(privateKeys);

    if (tx.inputs.length > 0) {
      ret.fee += fee;
      ret.tx.push(tx.toString());
    }

    if (await this.GetMasterKey("nav", spendingPassword)) {
      await this.xNavFillKeyPool(spendingPassword);
      await this.NavFillKeyPool(spendingPassword);
    }

    return ret;
  }

  async GetPrivateKey(hashId, key) {
    let ret = await this.db.GetKey(hashId, key);

    if (!ret) return;

    return ret.substr(0, 4) == "xprv"
      ? bitcore.HDPrivateKey(ret).privateKey
      : bitcore.PrivateKey(ret);
  }
}

module.exports.WalletFile = WalletFile;

module.exports.Init = async () => {
  await blsct.Init();
};

module.exports.xNavBootstrap = {
  mainnet: require("./xnav_bootstrap"),
  testnet: require("./xnav_bootstrap_testnet"),
};

module.exports.OutputTypes = OutputTypes;
module.exports.AddressTypes = AddressTypes;
