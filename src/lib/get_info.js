
export class GetInfo {

    constructor(client, db) {
        this.client = client
        this.db = db;
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
}