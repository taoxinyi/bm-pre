const mcl = require('mcl-wasm');

class PRE {
    /**
     * Setup by g,h and curve to create G1 and G2, return the generators
     * @param {string} g - the generator of G1, either be string or hex string(dumped by PRE)
     * @param {string} h - the generator of G2, either be string or hex string(dumped by PRE)
     * @param {number} curve - the curve type
     * @param {boolean} fromHex - whether return g and h in hex string or Object
     * @param {boolean} returnHex - whether return g and h in hex string
     * @returns {Promise<Object>} - {g,h}
     */
    static async init({g, h, curve = mcl.BLS12_381, fromHex = false, returnHex = false}) {
        await mcl.init(curve);
        const gPoint = fromHex ? mcl.deserializeHexStrToG1(g) : mcl.hashAndMapToG1(g);
        const hPoint = fromHex ? mcl.deserializeHexStrToG2(h) : mcl.hashAndMapToG2(h);
        if (returnHex) {
            return {g: PRE.dump(gPoint), h: PRE.dump(hPoint)}
        }
        return {g: gPoint, h: hPoint}
    }

    /**
     * Generate the key pair for the delegtor
     * @param {string|mcl.G1} g - the hex string or G1 of g
     * @param returnHex - whether return key pair in hex string or Object
     * @returns {{sk: string|mcl.Fr, pk: string|mcl.G1}}
     */
    static keyGenInG1({g}, {returnHex = false} = {}) {

        const sk = PRE.randomInFr();
        const pk = PRE.getPkFromG1(sk, g, {returnHex: returnHex});
        return {
            sk: returnHex ? PRE.dump(sk) : sk,
            pk: pk
        }
    }

    /**
     * Generate the key pair for the delegatee
     * @param {string|mcl.G2} h - the hex string or G2 of h
     * @param returnHex - whether return key pair in hex string or Object
     * @returns {{sk: string|mcl.Fr, pk: string|mcl.G2}}
     */
    static keyGenInG2({h}, {returnHex = false} = {}) {
        const sk = PRE.randomInFr();
        const pk = PRE.getPkFromG2(sk, h, {returnHex: returnHex});
        return {
            sk: returnHex ? PRE.dump(sk) : sk,
            pk: pk
        }
    }

    /**
     * Get the delegator's public key from secret key
     * @param {string|mcl.Fr} ska - the hex string or Fr of ska
     * @param {string|mcl.G1} g - the hex string or G1 of g
     * @param returnHex - whether return public key in hex string or Object
     * @returns {string|mcl.G1}
     */
    static getPkFromG1(ska, g, {returnHex = false} = {}) {
        const point = typeof(ska) === "string" ? mcl.deserializeHexStrToFr(ska) : ska;
        const gPoint = typeof(g) === "string" ? mcl.deserializeHexStrToG1(g) : g;
        const pka = mcl.mul(gPoint, point);
        return returnHex ? PRE.dump(pka) : pka;
    }

    /**
     * Get the delegator's public key from secret key
     * @param {string|mcl.Fr} skb - the hex string or Fr of skb
     * @param {string|mcl.G2} h - the hex string or G2 of h
     * @param returnHex - whether return public key in hex string or Object
     * @returns {string|mcl.G2}
     */
    static getPkFromG2(skb, h, {returnHex = false} = {}) {
        const point = typeof(skb) === "string" ? mcl.deserializeHexStrToFr(skb) : skb;
        const hPoint = typeof(h) === "string" ? mcl.deserializeHexStrToG2(h) : h;
        const pka = mcl.mul(hPoint, point);
        return returnHex ? PRE.dump(pka) : pka;
    }

    /**
     * Encryption from delegator's public key
     * @param {string} plain - must be valid hex string form from PRE.dump
     * @param {string|mcl.G1} pk - the hex string or G1 of pk
     * @param {string|mcl.G1} g - the hex string or G1 of g
     * @param {string|mcl.G2} h - the hex string or G2 of h
     * @param returnHex - whether return encrypted in hex string or Object
     * @returns {Array} - [gak,mzk]
     */
    static enc(plain, pk, {g, h}, {returnHex = false} = {}) {
        const gPoint = typeof(g) === "string" ? mcl.deserializeHexStrToG1(g) : g;
        const hPoint = typeof(h) === "string" ? mcl.deserializeHexStrToG2(h) : h;
        const pkPoint = typeof(pk) === "string" ? mcl.deserializeHexStrToG1(pk) : pk;
        const m = mcl.deserializeHexStrToFr(plain);
        const k = PRE.randomInFr();


        const gak = mcl.mul(pkPoint, k);
        const Z = mcl.pairing(gPoint, hPoint);

        const mzk = mcl.add(m, mcl.hashToFr(mcl.pow(Z, k).serialize()));
        return returnHex ? [PRE.dump(gak), PRE.dump(mzk)] : [gak, mzk]

    }

    /**
     * Decryption from delegator's secret key
     * @param {Array} encrypted - the encrypted part, either hex string or object
     * @param {string|mcl.Fr} sk - the hex string or Fr of sk
     * @param {string|mcl.G2} h - the hex string or G2 of h
     * @returns {string} the original hex string
     */
    static dec(encrypted, sk, {h}) {
        const [gak, mzk] = encrypted;
        const gakPoint = typeof(gak) === "string" ? mcl.deserializeHexStrToG1(gak) : gak;
        const mzkPoint = typeof(mzk) === "string" ? mcl.deserializeHexStrToFr(mzk) : mzk;
        const hPoint = typeof(h) === "string" ? mcl.deserializeHexStrToG2(h) : h;
        const skPoint = typeof(sk) === "string" ? mcl.deserializeHexStrToFr(sk) : sk;
        const eah = mcl.pairing(gakPoint, hPoint);
        const eahInvSk = mcl.pow(eah, mcl.inv(skPoint));
        const decrypted = mcl.sub(mzkPoint, mcl.hashToFr(eahInvSk.serialize()));
        return PRE.dump(decrypted)
    }

    /**
     * Generate reKey from delegator's secret key and delegatee's public key
     * @param {string|mcl.Fr} ska - the hex string or Fr of ska
     * @param {string|mcl.G1} pkb - the hex string or G2 of pkb
     * @param returnHex - whether return reKey in hex string or Object
     * @returns {string|mcl.G2}
     */
    static rekeyGen(ska, pkb, {returnHex = false} = {}) {
        const skaPoint = typeof(ska) === "string" ? mcl.deserializeHexStrToFr(ska) : ska;
        const pkbPoint = typeof(pkb) === "string" ? mcl.deserializeHexStrToG2(pkb) : pkb;
        const reKey = mcl.mul(pkbPoint, mcl.inv(skaPoint));
        return returnHex ? PRE.dump(reKey) : reKey
    }

    /**
     * ReEncryption from encrypted and reKey
     * @param {Array} encrypted - the encrypted part
     * @param reKey - the hex string or G2 of pkb
     * @param returnHex - whether return reEncrypted in hex string or Object
     * @returns {Array}
     */
    static reEnc(encrypted, reKey, {returnHex = false} = {}) {
        let [gak, mzk] = encrypted;
        const gakPoint = typeof(gak) === "string" ? mcl.deserializeHexStrToG1(gak) : gak;
        const reKeyPoint = typeof(reKey) === "string" ? mcl.deserializeHexStrToG2(reKey) : reKey;
        let Zbk = mcl.pairing(gakPoint, reKeyPoint);
        if (returnHex)
            Zbk = PRE.dump(Zbk);
        if (typeof (mzk) === "string" && !returnHex)
            mzk = mcl.deserializeHexStrToFr(mzk);
        if (typeof (mzk) !== "string" && returnHex)
            mzk = PRE.dump(mzk);

        return [Zbk, mzk]
    }

    /**
     * ReDecryption from reEncrypted and delegatee's secret key
     * @param {Array} reEncrypted - the reEncrypted part
     * @param {string|mcl.Fr} sk - the hex string or Fr of sk
     * @returns {string} the original hex string
     */
    static reDec(reEncrypted, sk) {
        let [Zbk, mzk] = reEncrypted;
        const skPoint = typeof(sk) === "string" ? mcl.deserializeHexStrToFr(sk) : sk;
        const ZbkPoint = typeof(Zbk) === "string" ? mcl.deserializeHexStrToGT(Zbk) : Zbk;
        const mzkPoint = typeof(mzk) === "string" ? mcl.deserializeHexStrToFr(mzk) : mzk;

        const ZbkInvB = mcl.pow(ZbkPoint, mcl.inv(skPoint));
        const reDecrypted = mcl.sub(mzkPoint, mcl.hashToFr(ZbkInvB.serialize()));
        return PRE.dump(reDecrypted)

    }

    /**
     * delegator sign on hash and return hex string of signature
     * @param {string} msgHash
     * @param {string|mcl.Fr} sk - the hex string or Fr of sk
     * @returns {string}
     */
    static sign(msgHash, sk) {
        const skPoint = typeof(sk) === "string" ? mcl.deserializeHexStrToFr(sk) : sk;
        const msgPoint = mcl.hashAndMapToG2(msgHash);
        const sig = mcl.mul(msgPoint, skPoint);
        return PRE.dump(sig)
    }

    /**
     *
     * verify the delegator's signature
     * @param {string} msgHash
     * @param {string} signature - delegator's signature in hex string
     * @param {string|mcl.G1} pk - delegator's public key
     * @param {string|mcl.G1} g - the hex string or G1 of g
     * @returns {boolean}
     */
    static verify(msgHash, signature, pk, {g}) {
        const pkPoint = typeof(pk) === "string" ? mcl.deserializeHexStrToG1(pk) : pk;
        const msgPoint = mcl.hashAndMapToG2(msgHash);
        const sig = mcl.deserializeHexStrToG2(signature);
        const lhs = mcl.pairing(g, sig);
        const rhs = mcl.pairing(pkPoint, msgPoint);
        return lhs.isEqual(rhs)
    }

    /**
     * Generate random hex string in Fr, normally used to generate symmetric key
     * @returns {string}
     */
    static randomGen() {
        return PRE.dump(PRE.randomInFr());

    }

    /**
     * Generate random element in Fr
     * @returns {mcl.Fr} the random element in Fr
     */
    static randomInFr() {
        const p = new mcl.Fr();
        p.setByCSPRNG();
        return p

    }

    /**
     * dump point/element to hex string
     * @param {object} obj
     * @returns {string}
     */
    static dump(obj) {
        return obj.serializeToHexStr()
    }
}
module.exports = PRE;

