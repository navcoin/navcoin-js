import { default as bitcore } from "@aguycalled/bitcore-lib";
import { StakingAddress } from "./staking_address.js";
import { Logger } from "./logger.js";
const blsct = bitcore.Transaction.Blsct;
import { GetInfo } from "./get_info.js";
import {getMasterViewKey} from './key_request.js'

export class TxProcessor {

  constructor(options) {
    this.client = options.client;
    this.db = options.db
    this.network = options.network;
    this.error = options.error;
    this.AddOutput = options.addOutput;
    this.DeriveSpendingKeyFromStringHash = options.deriveSpendingKeyFromStringHash;
    this.spendingPassword = options.spendingPassword;
    this.log = options.log;
    this.Log = new Logger(this.log);
    this.getInfo = new GetInfo(this.client, this.db);
    this.stakingAddress = new StakingAddress({ db: options.db, network: options.network, sync: options.sync });
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
            await this.stakingAddress.AddStakingAddress(stakingPk, undefined, true);
          } else if (script.isColdStakingV2Out()) {
            let stakingPk = script.getStakingPublicKeyHash();
            let votingPk = script.getVotingPublicKeyHash();
            await this.stakingAddress.AddStakingAddress(stakingPk, votingPk, true);
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
            await this.stakingAddress.AddStakingAddress(stakingPk, undefined, true);
          } else if (script.isColdStakingV2Out()) {
            let stakingPk = script.getStakingPublicKeyHash();
            let votingPk = script.getVotingPublicKeyHash();
            await this.stakingAddress.AddStakingAddress(stakingPk, votingPk, true);
          }

          return true;
        }
      }
    } else if (input.spendingKey && input.outputKey) {
      this.mvk = getMasterViewKey(this.db);
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
        await this.error.ManageElectrumError(e);
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
      } catch (e) { }
    }

    let mustNotify = false;

    if (tx.height != prevHeight) {
      if (tx.height) await this.db.SetTxHeight(hash, tx.height, tx.pos);
      mustNotify = true;
    }

    console.log("GETTX FUNC RESULT...", tx);

    if (!requestInputs) return tx;

    await this.ValidateTx(tx, mustNotify);

    await this.db.MarkAsFetched(hash);

    return tx;
  }

  async Spend(outPoint, spentIn) {
    let prev = await this.db.GetUtxo(outPoint);
    if (prev && prev.spentIn && spentIn && prev.spentIn == spentIn) {
      return false;
    }
    await this.db.SpendUtxo(outPoint, spentIn);
    return true;
  }

  async validateTransactionInputs(tx) {

    let memosIn = [];
    let deltaNavInput = 0;
    let deltaXNavInput = {};
    let deltaColdInput = 0;
    let addressesIn = { spending: [], staking: [] };
    let mustNotifyIn = false;
    let inputIsMine = false;
    this.mvk = getMasterViewKey(this.db);



    for (let i in tx.tx.inputs) {
      let input = tx.tx.inputs[i].toObject();

      let { prevTxId, outputIndex } = input
      if (
        prevTxId ==
        "0000000000000000000000000000000000000000000000000000000000000000"
      )
        continue;

      let prevTx = (
        await this.GetTx(prevTxId, undefined, undefined, false)
      ).tx;

      let { outputs } = prevTx;
      let prevOut = outputs[outputIndex];

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
              inputIsMine = true;
              let newOutput = await this.AddOutput(
                `${prevTxId}:${outputIndex}`,
                prevOut,
                prevTx.height
              );
              let newSpend = await this.Spend(
                `${prevTxId}:${outputIndex}`,
                `${tx.txid}:${i}`
              );


              if (newSpend || newOutput) mustNotifyIn = true;
              if (
                !deltaXNavInput[
                prevOut.tokenId.toString("hex") + ":" + prevOut.tokenNftId
                ]
              )
                deltaXNavInput[
                  prevOut.tokenId.toString("hex") + ":" + prevOut.tokenNftId
                ] = 0;

              deltaXNavInput[
                prevOut.tokenId.toString("hex") + ":" + prevOut.tokenNftId
              ] -= prevOut.amount ? prevOut.amount : prevOut.satoshis;

              this.Log.Message(`prevOut.memo  : ${prevOut.memo}`);

              memosIn.push(prevOut.memo);
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
          inputIsMine = true;
          let newOutput = await this.AddOutput(
            `${prevTxId}:${outputIndex}`,
            prevOut,
            prevTx.height
          );
          let newSpend = await this.Spend(
            `${prevTxId}:${outputIndex}`,
            `${tx.txid}:${i}`
          );
          if (newSpend || newOutput) mustNotifyIn = true;
          deltaNavInput -= prevOut.satoshis;
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
          inputIsMine = true;
          let newOutput = await this.AddOutput(
            `${prevTxId}:${outputIndex}`,
            prevOut,
            prevTx.height
          );
          let newSpend = await this.Spend(
            `${prevTxId}:${outputIndex}`,
            `${tx.txid}:${i}`
          );
          if (newSpend || newOutput) mustNotifyIn = true;
          deltaColdInput -= prevOut.satoshis;
        }
      }
    }
    return {
      deltaNavInput,
      deltaColdInput,
      deltaXNavInput,
      addressesIn,
      memosIn,
      mustNotifyIn,
    }

  }

  async validateTransactionOutputs(tx) {

    let outputIsMine = false;
    let mustNotifyOut = false;
    let memosOut = [];
    let deltaNavOutput = 0;
    let deltaXNavOutput = {};
    let deltaColdOutput = 0;
    let addressesOut = { spending: [], staking: [] };

    console.log(`validateTransactionOutputs ${this.mvk}`)

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
              outputIsMine = true;
              let newOutput = await this.AddOutput(
                `${tx.txid}:${i}`,
                out,
                tx.height
              );
              if (newOutput) mustNotifyOut = true;
              if (
                !deltaXNavOutput[out.tokenId.toString("hex") + ":" + out.tokenNftId]
              )
                deltaXNavOutput[
                  out.tokenId.toString("hex") + ":" + out.tokenNftId
                ] = 0;
              deltaXNavOutput[out.tokenId.toString("hex") + ":" + out.tokenNftId] +=
                out.amount ? out.amount : out.satoshis;
              memosOut.push(out.memo);
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
            outputIsMine = true;
            let newOutput = await this.AddOutput(
              `${tx.txid}:${i}`,
              out,
              tx.height
            );
            if (newOutput) mustNotifyOut = true;
            if (!deltaXNavOutput[out.tokenId.toString("hex") + ":" + out.tokenNftId])
              deltaXNavOutput[out.tokenId.toString("hex") + ":" + out.tokenNftId] = 0;
            deltaXNavOutput[out.tokenId.toString("hex") + ":" + out.tokenNftId] +=
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
          outputIsMine = true;
          let newOutput = await this.AddOutput(
            `${tx.txid}:${i}`,
            out,
            tx.height
          );
          if (newOutput) mustNotifyOut = true;
          deltaNavOutput += out.satoshis;
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
          outputIsMine = true;
          let newOutput = await this.AddOutput(
            `${tx.txid}:${i}`,
            out,
            tx.height
          );
          if (newOutput) mustNotifyOut = true;
          deltaColdOutput += out.satoshis;
        }
      }

      if (out.vData[0] == 7 || out.vData[0] == 8) {
        try {
          let name = out.vData.slice(5, 5 + out.vData[4]).toString();
          if (await isMyName(this.db, name)) {
            let data = await this.ResolveName(name);
            await addName(this.db, this.emit, name, undefined, data);
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
            try {
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
            } catch (e) {
              console.log(e.message);
            }
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
          let decrypted = decrypt(
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
            await addName(this.db, this.emit, decryptedName.toString(), tx.height);
          }
        } catch (e) { }
      }
    }

    return {
      deltaColdOutput,
      deltaNavOutput,
      deltaXNavOutput,
      outputIsMine,
      memosOut,
      mustNotifyOut
    }
  }

  async ValidateTx(tx, mustNotify = true) {

    let { addressesIn, deltaNavInput, deltaXNavInput, deltaColdInput, inputIsMine, memosIn, mustNotifyIn, } = await this.validateTransactionInputs(tx);
    let { addressesOut, deltaNavOutput, deltaXNavOutput, deltaColdOutput, outputIsMine, memosOut, mustNotifyOut } = await this.validateTransactionOutputs(tx);
    let deltaXNav = { ...deltaXNavInput, ...deltaXNavOutput };
    let deltaNav = deltaNavInput += deltaNavOutput;
    let deltaCold = deltaColdInput += deltaColdOutput
    let mine = inputIsMine ? inputIsMine : outputIsMine;
    let memos = { in: memosIn, out: memosOut };
    mustNotify = mustNotifyIn ? mustNotifyIn : mustNotifyOut;


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
            ? await this.getInfo.GetTokenInfo(token)
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


}