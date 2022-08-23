import * as events from "events";
import { default as AddressTypes } from "../utils/address_types.js";
import * as crypto from "crypto";

import Dexie from "dexie";
import {
  applyEncryptionMiddleware,
  NON_INDEXED_FIELDS,
} from "@aguycalled/dexie-encrypted";

const algorithm = "aes-256-cbc";

export default class Db extends events.EventEmitter {
  constructor() {
    super();

    this.keys = {};
  }

  async Open(filename, secret, indexedDB, IDBKeyRange) {
    let key = new Buffer(
      crypto
        .createHash("sha256")
        .update(String(secret))
        .digest("hex")
        .substr(0, 64),
      "hex"
    );

    try {
      Dexie.dependencies.indexedDB = indexedDB || window.indexedDB;
      Dexie.dependencies.IDBKeyRange = IDBKeyRange || window.IDBKeyRange;

      this.db = new Dexie(filename, {
        indexedDB: indexedDB || window.indexedDB,
        IDBKeyRange: IDBKeyRange || window.IDBKeyRange,
      });

      this.dbTx = new Dexie("___tx___", {
        indexedDB: indexedDB || window.indexedDB,
        IDBKeyRange: IDBKeyRange || window.IDBKeyRange,
      });

      this.open = true;

      let self = this;

      applyEncryptionMiddleware(
        this.db,
        key,
        {
          keys: NON_INDEXED_FIELDS,
          walletTxs: NON_INDEXED_FIELDS,
          outPoints: NON_INDEXED_FIELDS,
          scriptHistories: NON_INDEXED_FIELDS,
          settings: NON_INDEXED_FIELDS,
          encryptedSettings: NON_INDEXED_FIELDS,
          statuses: NON_INDEXED_FIELDS,
          stakingAddresses: NON_INDEXED_FIELDS,
          labels: NON_INDEXED_FIELDS,
          names: NON_INDEXED_FIELDS,
          tokens: NON_INDEXED_FIELDS,
          nfts: NON_INDEXED_FIELDS,
        },
        async (db) => {
          self.emit("db_load_error", "Wrong key");
          self.open = false;
          throw new Error("Wrong key");
        }
      );

      this.db.version(7).stores({
        keys: "&hash, type, address, used, change",
        walletTxs: "&id, hash, amount, type, confirmed, height, pos, timestamp",
        outPoints: "&id, spentIn, amount, label, type",
        scriptHistories: "&id, scriptHash, tx_hash, height, fetched",
        settings: "&key",
        encryptedSettings: "&key",
        statuses: "&scriptHash",
        stakingAddresses: "&id, [address+addressVoting]",
        labels: "&address, name",
        names: "&name",
        tokens: "&id",
        nfts: "&id",
        consensus: "&id",
      });

      this.dbTx.version(2).stores({
        txs: "&hash",
        txKeys: "&hash",
        candidates: "&input, network",
      });

      this.db.on("versionchange", function (event) {
        self.db.close();
      });

      let keysArray = await this.db.keys.toArray();

      for (let key of keysArray) {
        this.keys[key.hash] = true;
      }

      this.emit("db_open");
    } catch (e) {
      console.log("Open error", e);
      this.open = false;
      this.emit("db_load_error", e);
    }
  }

  static SetBackend(indexedDB, IDBKeyRange) {
    Dexie.dependencies.indexedDB = indexedDB;
    Dexie.dependencies.IDBKeyRange = IDBKeyRange;
  }

  Close() {
    if (this.db) this.db.close();
    if (this.dbTx) this.dbTx.close();
    delete this.db;
    delete this.dbTx;

    this.emit("db_closed");
  }

  Encrypt(plain, key) {
    const iv = crypto.randomBytes(16);
    const aes = crypto.createCipheriv(algorithm, key, iv);
    let ciphertext = aes.update(plain);
    ciphertext = Buffer.concat([iv, ciphertext, aes.final()]);
    return ciphertext.toString("base64");
  }

  static async ListWallets() {
    return (await Dexie.getDatabaseNames()).filter(
      (e) => e != "localforage" && e != "___tx___"
    );
  }

  static async RemoveWallet(filename) {
    try {
      await Dexie.delete(filename);
      return true;
    } catch (e) {
      console.log(e);
      return false;
    }
  }

  async GetPoolSize(type, change) {
    if (!this.db) return;

    return await this.db.keys
      .where(
        change
          ? { type: type, used: 0, change: change }
          : { type: type, used: 0 }
      )
      .count()
      .catch((e) => {
        console.error("GetPoolSize error: " + e.message);
      });
  }

  async GetMasterKey(key, password) {
    if (!this.db) return;

    let dbFind = await this.db.encryptedSettings
      .get({
        key: "masterKey_" + key,
      })
      .catch((e) => {
        console.error("GetMasterKey error: " + e.message);
      });

    if (!dbFind) return undefined;

    password = this.HashPassword(password);

    let ret = dbFind.value;

    try {
      const ciphertextBytes = Buffer.from(ret, "base64");
      const iv = ciphertextBytes.slice(0, 16);
      const data = ciphertextBytes.slice(16);
      const aes = crypto.createDecipheriv(algorithm, password, iv);
      let plaintextBytes = Buffer.from(aes.update(data));
      plaintextBytes = Buffer.concat([plaintextBytes, aes.final()]);
      ret = plaintextBytes.toString();
    } catch (e) {
      return undefined;
    }

    return ret;
  }

  async AddMasterKey(type, value, password) {
    if (!this.db) return;

    password = this.HashPassword(password);
    value = this.Encrypt(value, password);

    try {
      await this.db.encryptedSettings
        .put({
          key: "masterKey_" + type,
          value: value,
        })
        .catch((e) => {
          console.error("AddMasterKey error: " + e.message);
        });
      return true;
    } catch (e) {
      return false;
    }
  }

  async UpdateCounter(index, value) {
    if (!this.db) return;

    await this.db.settings
      .put({ key: "counter_" + index, value: value })
      .catch((e) => {
        console.error("UpdateCounter error: " + e.message);
      });
  }

  async GetCounter(index) {
    if (!this.db) return;

    let ret = await this.db.settings.get("counter_" + index).catch((e) => {
      console.error("GetCounter error: " + e.message);
    });

    if (ret) return ret.value;

    return undefined;
  }

  HashPassword(password) {
    password = password || "masterkey navcoinjs";
    password = crypto
      .createHash("sha256")
      .update(String(password))
      .digest("base64")
      .substr(0, 32);
    return password;
  }

  async AddKey(hashId, value, type, address, used, change, path, password) {
    if (!this.db) return;

    if (type != AddressTypes.XNAV) {
      password = this.HashPassword(password);
      value = this.Encrypt(value, password);
    }

    try {
      await this.db.keys.add({
        hash: hashId,
        value: value,
        type: type,
        address: address,
        used: 0,
        change: change,
        path: path,
      });
    } catch (e) {
      //console.error("AddKey error: " + e.message);
      return false;
    }
    this.keys[hashId] = true;
  }

  async HaveKey(key) {
    return this.keys[key];
  }

  async GetKey(key, password) {
    if (!this.db) return;

    let dbFind = await this.db.keys.get({ hash: key }).catch((e) => {
      console.error("GetKey error: " + e.message);
    });

    if (!dbFind) return undefined;
    password = this.HashPassword(password);

    let ret = dbFind.value;

    if (dbFind.type != AddressTypes.XNAV) {
      try {
        const ciphertextBytes = Buffer.from(ret, "base64");
        const iv = ciphertextBytes.slice(0, 16);
        const data = ciphertextBytes.slice(16);
        const aes = crypto.createDecipheriv(algorithm, password, iv);
        let plaintextBytes = Buffer.from(aes.update(data));
        plaintextBytes = Buffer.concat([plaintextBytes, aes.final()]);
        ret = plaintextBytes.toString();
      } catch (e) {
        return ret;
      }
    }

    return ret;
  }

  async SetValue(key, value) {
    if (!this.db) return;

    await this.db.settings
      .put({
        key: key,
        value: value,
      })
      .catch((e) => {
        console.error("SetValue error: " + e.message);
      });
  }

  async GetValue(key) {
    if (!this.db) return;

    let ret = await this.db.settings.get(key).catch((e) => {
      console.error("GetValue error: " + e.message);
    });

    if (ret) return ret.value;

    return undefined;
  }

  async GetNavAddresses() {
    if (!this.db) return [];

    return await this.db.keys
      .where({ type: AddressTypes.NAV })
      .toArray()
      .catch((e) => {
        console.error("GetNavAddresses error: " + e.message);
      });
  }

  async GetStakingAddresses() {
    if (!this.db) return [];

    return await this.db.stakingAddresses.toArray().catch((e) => {
      console.error("GetStakingAddresses error: " + e.message);
    });
  }

  async AddStakingAddress(address, address2, hash, pk2) {
    if (!this.db) return;

    await this.db.stakingAddresses
      .put({
        id: address + "_" + address2,
        address: address,
        addressVoting: address2,
        hash: hash,
        hashVoting: pk2,
      })
      .catch((e) => {
        console.error("AddStakingAddress error: " + e.message);
      });
  }

  async GetStakingAddress(address, address2) {
    if (!this.db) return;

    return await this.db.stakingAddresses
      .get(address + "_" + address2)
      .catch((e) => {
        console.error("GetStakingAddress error: " + e.message);
      });
  }

  async GetStatusForScriptHash(s) {
    if (!this.db) return;

    let ret = await this.db.statuses.get(s).catch((e) => {
      console.error("GetStatusForScriptHash error: " + e.message);
    });

    return ret ? ret.status : undefined;
  }

  async SetStatusForScriptHash(s, st) {
    if (!this.db) return;

    await this.db.statuses.put({ scriptHash: s, status: st }).catch((e) => {
      console.error("SetStatusForScriptHash error: " + e.message);
    });
  }

  async BulkRawInsert(documents) {
    if (!this.dbTx) return;
    const chunkSize = 50;
    for (let i = 0; i < documents.length; i += chunkSize) {
      const chunk = documents.slice(i, i + chunkSize);
      await this.dbTx.txKeys.bulkPut(chunk).catch(console.log);
    }
  }

  async BulkRawInsertHistory(documents) {
    if (!this.db) return;
    const chunkSize = 50;
    for (let i = 0; i < documents.length; i += chunkSize) {
      const chunk = documents.slice(i, i + chunkSize);
      await this.db.scriptHistories.bulkPut(chunk).catch(console.log);
    }
  }

  async ZapWalletTxes() {
    if (!this.db) return;

    let types = [
      "statuses",
      "scriptHistories",
      "outPoints",
      "walletTxs",
      "names",
    ];

    for (var i in types) {
      let type = types[i];
      await this.db[type].clear().catch((e) => {
        console.error("ZapWalletTxes error: " + e.message);
      });
    }
  }

  async GetXNavReceivingAddresses(all) {
    if (!this.db) return [];

    let ret = await this.db.keys
      .where({ type: AddressTypes.XNAV })
      .toArray()
      .catch((e) => {
        console.error("GetXNavReceivingAddresses error: " + e.message);
      });

    ret.sort((a, b) => {
      if (a.value[0] == b.value[0]) {
        return a.value[1] - b.value[1];
      }
      return a.value[0] - b.value[0];
    });

    return ret;
  }

  async GetNavReceivingAddresses(all) {
    if (!this.db) return [];

    return await this.db.keys
      .where({ type: AddressTypes.NAV })
      .toArray()
      .catch((e) => {
        console.error("GetNavReceivingAddresses error: " + e.message);
      });
  }

  async GetNavAddress(address) {
    if (!this.db) return;

    let ret = await this.db.keys
      .where({ address: address })
      .toArray()
      .catch((e) => {
        console.error("GetNavAddress error: " + e.message);
      });

    return ret[0];
  }

  async GetPendingTxs(downloaded = 0) {
    if (!this.db) return [];

    return await this.db.scriptHistories
      .where({ fetched: downloaded })
      .toArray()
      .catch((e) => {
        console.error("GetPendingTxs error: " + e.message);
      });
  }

  async CleanScriptHashHistory(scriptHash, lowerLimit, upperLimit) {
    if (!this.db) return;

    await this.db.scriptHistories
      .where("height")
      .aboveOrEqual(upperLimit)
      .or("height")
      .belowOrEqual(lowerLimit)
      .filter((e) => e.scriptHash == scriptHash)
      .delete()
      .catch((e) => {
        console.error("CleanScriptHashHistory error: " + e.message);
      });
  }

  async AddScriptHashHistory(scriptHash, hash, height, fetched) {
    if (!this.db) return;

    await this.db.scriptHistories
      .put({
        id: scriptHash + "_" + hash,
        scriptHash: scriptHash,
        tx_hash: hash,
        height: height,
        fetched: fetched ? 1 : 0,
      })
      .catch((e) => {
        console.error("AddScriptHashHistory error: " + e.message);
      });
  }

  async AddLabel(address, name) {
    if (!this.db) return;

    await this.db.labels.put({ address: address, name: name }).catch((e) => {
      console.error("AddLabel error: " + e.message);
    });
  }

  async AddName(name, height, data = {}) {
    if (!this.db) return;

    await this.db.names
      .put({ name: name, height: height, data: data })
      .catch((e) => {
        console.error("AddName error: " + e.message);
      });
  }

  async GetName(name) {
    if (!this.db) return;

    try {
      return await this.db.names.get(name).catch((e) => {
        console.error("GetName error: " + e.message);
      });
    } catch (e) {
      return undefined;
    }
  }

  async AddTokenInfo(id, name, code, supply, version, key) {
    if (!this.db) return;

    await this.db.tokens
      .put({
        id: id,
        name: name,
        code: code,
        supply: supply,
        version: version,
        key: key,
      })
      .catch((e) => {
        console.error("AddTokenInfo error: " + e.message);
      });
  }

  async GetTokenInfo(id) {
    if (!this.db) return;

    try {
      return await this.db.tokens.get({ id }).catch((e) => {
        console.error("GetTokenInfo error: " + e.message);
      });
    } catch (e) {
      return undefined;
    }
  }

  async AddNftInfo(id, nftid, metadata) {
    if (!this.db) return;

    await this.db.nfts
      .put({ id: id + "-" + nftid, metadata: metadata })
      .catch((e) => {
        console.error("AddNftInfo error: " + e.message);
      });
  }

  async GetNftInfo(id, nftid) {
    if (!this.db) return;

    try {
      return await this.db.nfts.get({ id: id + "-" + nftid }).catch((e) => {
        console.error("GetNftInfo error: " + e.message);
      });
    } catch (e) {
      return undefined;
    }
  }

  async GetMyNames() {
    if (!this.db) return;

    try {
      return await this.db.names.toArray().catch((e) => {
        console.error("GetMyNames error: " + e.message);
      });
    } catch (e) {
      return [];
    }
  }

  async GetMyTokens() {
    if (!this.db) return;

    try {
      return await this.db.tokens.toArray().catch((e) => {
        console.error("GetMyTokens error: " + e.message);
      });
    } catch (e) {
      return [];
    }
  }

  async GetLabel(address) {
    if (!this.db) return;

    let label = await this.db.labels.get(address).catch((e) => {
      console.error("GetLabel error: " + e.message);
    });

    return label ? label : address;
  }

  async GetScriptHashHistory(scriptHash) {
    if (!this.db) return [];

    try {
      return await this.db.scriptHistories
        .where({ scriptHash: scriptHash })
        .toArray()
        .catch((e) => {
          console.error("GetScriptHashHistory error: " + e.message);
        });
    } catch (e) {
      return [];
    }
  }

  async MarkAsFetched(hash) {
    if (!this.db) return;

    try {
      await this.db.scriptHistories
        .where({ tx_hash: hash })
        .modify({ fetched: 1 })
        .catch((e) => {
          console.error("MarkAsFetched error: " + e.message);
        });
    } catch (e) {
      return [];
    }
  }

  async GetWalletHistory() {
    if (!this.db) return [];

    let history = await this.db.walletTxs.toArray().catch((e) => {
      console.error("GetWalletHistory error: " + e.message);
    });

    let confirmed = history.filter((e) => e.height > 0);
    let unconfirmed = history.filter((e) => !e.confirmed || e.height <= 0);

    let ret = unconfirmed.concat(confirmed.reverse());

    ret.sort((a, b) => {
      if (a.height == b.height) {
        if (a.pos == b.pos) return a.amount > 0 && b.amount < 0 ? -1 : 1;
        else if (a.timestamp == b.timestamp) return a.pos - b.pos;
        else return b.timestamp - a.timestamp;
      }
      return b.height - a.height;
    });

    return ret;
  }

  async AddWalletTx(
    hash,
    type,
    amount,
    confirmed,
    height,
    pos,
    timestamp,
    memos,
    strdzeel,
    addresses_in,
    addresses_out,
    name,
    code,
    tokenId,
    tokenNftId
  ) {
    if (!this.db) return;

    await this.db.walletTxs
      .put({
        id: hash + "_" + type,
        hash: hash,
        amount: amount,
        type: type,
        confirmed: confirmed ? 1 : 0,
        height: height,
        pos: pos,
        timestamp: timestamp,
        memos: memos,
        strdzeel: strdzeel,
        addresses_in: addresses_in,
        addresses_out: addresses_out,
        token_name: name,
        token_code: code,
        token_id: tokenId,
        nft_id: tokenNftId,
      })
      .catch((e) => {
        console.error("AddWalletTx error: " + e.message);
      });
  }

  async GetUtxos(forBalance = false) {
    if (!this.db) return [];

    let ret = await this.db.outPoints.where({ spentIn: "" });

    if (forBalance) ret.or({ spentIn: "0:0" });

    return ret.toArray().catch((e) => {
      console.error("GetUtxos error: " + e.message);
    });
  }

  async GetCandidates(network) {
    if (!this.dbTx) return;

    return await this.dbTx.candidates
      .where({ network: network })
      .toArray()
      .catch((e) => {
        console.error("GetCandidates error: " + e.message);
      });
  }

  async GetTxs() {
    if (!this.dbTx) return;

    return await this.dbTx.txs.toArray().catch((e) => {
      console.error("GetTxs error: " + e.message);
    });
  }

  async GetTx(hash) {
    if (!this.dbTx) return;

    return await this.dbTx.txs.get(hash).catch((e) => {
      console.error("GetTx error: " + e.message);
    });
  }

  async AddUtxo(
    outPoint,
    out,
    spentIn,
    amount,
    label,
    type,
    spendingPk = "",
    stakingPk = "",
    votingPk = "",
    hashId = ""
  ) {
    if (!this.db) return;

    await this.db.outPoints.add({
      id: outPoint,
      out: out,
      spentIn: spentIn,
      amount: amount,
      label: label,
      type: type,
      spendingPk: spendingPk,
      stakingPk: stakingPk,
      votingPk: votingPk,
      hashId: hashId,
    });
  }

  async GetUtxo(outPoint) {
    if (!this.db) return {};

    return await this.db.outPoints.get(outPoint).catch((e) => {
      console.error("GetUtxo error: " + e.message);
    });
  }

  async SpendUtxo(outPoint, spentIn) {
    if (!this.db) return;

    try {
      await this.db.outPoints
        .where({ id: outPoint })
        .modify({ spentIn: spentIn })
        .catch((e) => {
          console.error("SpendUtxo error: " + e.message);
        });
    } catch (e) {
      console.log("SpendUtxo", e);
    }
  }

  async SetTxHeight(hash, height, pos) {
    if (!this.db) return;

    try {
      await this.dbTx.txs
        .where({ hash: hash })
        .modify({ height: height, pos: pos })
        .catch((e) => {
          console.error("SetTxHeight error: " + e.message);
        });
    } catch (e) {
      console.log("SetTxHeight", e);
    }
  }

  async UseNavAddress(address) {
    if (!this.db) return;

    try {
      await this.db.keys
        .where({ address: address })
        .modify({ used: 1 })
        .catch((e) => {
          console.error("UseNavAddress error: " + e.message);
        });
    } catch (e) {
      console.log("usenav", e);
    }
  }

  async UseXNavAddress(hashId) {
    if (!this.db) return;

    try {
      await this.db.keys
        .where({ hash: hashId })
        .modify({ used: 1 })
        .catch((e) => {
          console.error("UseXNavAddress error: " + e.message);
        });
    } catch (e) {
      console.log("usexnav", e);
    }
  }

  async AddTx(tx) {
    if (!this.dbTx) return;

    tx.hash = tx.txid;
    delete tx.tx;
    try {
      await this.dbTx.txs.add(tx).catch((e) => {
        console.error("AddTx error: " + e.message);
      });
      return true;
    } catch (e) {
      return false;
    }
  }

  async AddTxKeys(tx) {
    if (!this.dbTx) return;

    tx.hash = tx.txidkeys;
    try {
      await this.dbTx.txKeys.put(tx).catch((e) => {
        console.error("AddTxKeys error: " + e.message);
      });
      return true;
    } catch (e) {
      return false;
    }
  }

  async AddTxCandidate(candidate, network) {
    if (!this.dbTx) return;

    try {
      await this.dbTx.candidates
        .put({
          network: network,
          tx: candidate.tx.toString(),
          fee: candidate.fee,
          input:
            candidate.tx.inputs[0].prevTxId.toString("hex") +
            ":" +
            candidate.tx.inputs[0].outputIndex,
        })
        .catch((e) => {
          console.error("AddTxCandidate error: " + e.message);
        });
      return true;
    } catch (e) {
      return false;
    }
  }

  async RemoveTxCandidate(input) {
    if (!this.dbTx) return;

    await this.dbTx.candidates
      .where({ input: input })
      .delete()
      .catch((e) => {
        console.error("RemoveTxCandidate error: " + e.message);
      });
  }

  async GetTxKeys(hash) {
    if (!this.dbTx) return;

    return await this.dbTx.txKeys.get(hash).catch((e) => {
      console.error("GetTxKeys error: " + e.message);
    });
  }

  async GetAllTxKeys() {
    if (!this.dbTx) return;

    return await this.dbTx.txKeys.toArray().catch((e) => {
      console.error("GetAllTxKeys error: " + e.message);
    });
  }

  async WriteConsensusParameters(parameters) {
    if (!this.db) return;

    for (let id in parameters) {
      await this.db.consensus.put(parameters[id]).catch((e) => {
        console.error("WriteConsensusParameters error: " + e.message);
      });
    }

    return true;
  }

  async GetConsensusParameters() {
    if (!this.db) return;

    return await this.db.consensus.toArray().catch((e) => {
      console.error("GetConsensusParameters error: " + e.message);
    });
  }
}

export const ListWallets = Db.ListWallets;
export const RemoveWallet = Db.RemoveWallet;
export const SetBackend = Db.SetBackend;
