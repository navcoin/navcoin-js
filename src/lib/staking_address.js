import { default as bitcore } from "@aguycalled/bitcore-lib";

export class StakingAddress {

    constructor(options) {
        this.db = options.db;
        this.Sync = options.sync;
        this.network = options.network;
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
            this.Log.Message(`New staking address: ${strAddress} ${strAddress2}`);
    
            if (sync) await this.Sync(strAddress);
          } catch (e) {
            //console.log(e)
          }
        }
      }
}