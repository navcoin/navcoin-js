import { Logger } from "./logger";

export class GetAddress {

    constructor(options) {
        this.db = options.db;
        this.client = options.client;
        this.Log = new Logger(options.log);
        this.assetBalance = options.assetBalance 
    }

    async xNavReceivingAddresses(all = true) {
        return await this.db.GetXNavReceivingAddresses(all);
    }

    async NavReceivingAddresses(all = true) {
        return await this.db.GetNavReceivingAddresses(all);
    }

    async GetStakingAddresses() {
        let ret = [];

        let addresses = await this.db.GetStakingAddresses();

        for (let i in addresses) {
            ret.push(addresses[i].address);
        }

        return ret;
    }

    async GetAllAddresses() {
        let ret = { spending: { public: {}, private: {} }, staking: {} };

        let receiving = await this.db.GetNavReceivingAddresses(true);

        for (let i in receiving) {
            let address = receiving[i];
            ret.spending.public[address.address] = {
                balances: await this.assetBalance.GetBalance(address.address),
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
                balances: await this.assetBalance.GetBalance(address.hash),
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
                staking: (await this.assetBalance.GetBalance(address.address)).staked,
            };

            let label = await this.db.GetLabel(address.address);

            if (label != address.address) ret.staking[address.address].label = label;
        }

        return ret;
    }

}