import { Logger } from "./logger.js";
import { getTip } from "./get_tip.js";
import { default as bitcore } from "@aguycalled/bitcore-lib";
import { GetInfo } from "./get_info.js";
import { default as OutputTypes } from "./utils/output_types.js";

export class AssetBalance {

    constructor(options) {

        this.client = options.client;
        this.db = options.db;
        this.log = options.log;
        this.Log = new Logger(this.log);
        this.getInfo = new GetInfo(this.client, this.db);

    }

    async GetBalance(address) {
        if (address instanceof bitcore.Address)
            return await this.GetBalance(address.hashBuffer);

        if (typeof address === "string" && !bitcore.util.js.isHexa(address))
            return await this.GetBalance(bitcore.Address(address));

        if (typeof address === "object") address = address.toString("hex");

        let utxos = await this.db.GetUtxos(true);


        let navConfirmed = bitcore.crypto.BN.Zero;

        this.Log.Message(`navConfirmed init  ${navConfirmed}`);

        let xNavConfirmed = bitcore.crypto.BN.Zero;
        let tokConfirmed = {};
        let coldConfirmed = bitcore.crypto.BN.Zero;
        let votingConfirmed = bitcore.crypto.BN.Zero;
        let navPending = bitcore.crypto.BN.Zero;
        let xNavPending = bitcore.crypto.BN.Zero;
        let tokPending = {};
        let coldPending = bitcore.crypto.BN.Zero;
        let votingPending = bitcore.crypto.BN.Zero;

        let tip = await getTip(this.db);

        for (let u in utxos) {
            this.Log.Message(`utxos... ${utxos[u]}`);

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

                    let info = await this.getInfo.GetTokenInfo(tokenId);
                    ret.tokens[tokenId].name = info.name;
                    ret.tokens[tokenId].code = info.code;
                    ret.tokens[tokenId].supply = info.supply;
                }
                ret.tokens[tokenId].confirmed = tokConfirmed[i];
            } else {
                if (!ret.nfts[tokenId]) {
                    ret.nfts[tokenId] = {};

                    let info = await this.getInfo.GetTokenInfo(tokenId);
                    ret.nfts[tokenId].name = info.name;
                    ret.nfts[tokenId].scheme = info.code;
                    ret.nfts[tokenId].supply = info.supply;
                    ret.nfts[tokenId].confirmed = {};
                    ret.nfts[tokenId].pending = {};
                }
                let nftInfo = await this.getInfo.GetNftInfo(tokenId, tokenNftId);

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

                    let info = await this.getInfo.GetTokenInfo(tokenId);
                    ret.tokens[tokenId].name = info.name;
                    ret.tokens[tokenId].code = info.code;
                    ret.tokens[tokenId].supply = info.supply;
                }
                ret.tokens[tokenId].pending = tokPending[i];
            } else {
                if (!ret.nfts[tokenId]) {
                    ret.nfts[tokenId] = {};

                    let info = await this.getInfo.GetTokenInfo(tokenId);
                    ret.nfts[tokenId].name = info.name;
                    ret.nfts[tokenId].scheme = info.code;
                    ret.nfts[tokenId].supply = info.supply;
                    ret.nfts[tokenId].pending = {};
                    ret.nfts[tokenId].confirmed = {};
                }
                let nftInfo = await this.getInfo.GetNftInfo(tokenId, tokenNftId);

                if (nftInfo)
                    ret.nfts[tokenId].pending[tokenNftId] = nftInfo[0]
                        ? nftInfo[0].metadata
                        : "";
            }
        }

        return ret;
    }
}