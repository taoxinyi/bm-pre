const PRE = require('./pre.js');
PRE.init({g: "The generator for G1", h: "The generator for G2", returnHex: false}).then(params => {
    const plain = PRE.randomGen();

    const A = PRE.keyGenInG1(params, {returnHex: true});
    const B = PRE.keyGenInG2(params, {returnHex: true});

    const encrypted = PRE.enc(plain, A.pk, params, {returnHex: true});
    const decrypted = PRE.dec(encrypted, A.sk, params);

    const reKey = PRE.rekeyGen(A.sk, B.pk, {returnHex: true});

    const reEncypted = PRE.reEnc(encrypted, reKey, {returnHex: true});
    const reDecrypted = PRE.reDec(reEncypted, B.sk);

    const crypto = require('crypto');
    const msg = "1111";
    const hash = crypto.createHash('sha256');
    hash.update(msg);
    const msgHash = hash.digest('hex');

    const sig = PRE.sign(msgHash, A.sk);
    const C = PRE.keyGenInG1(params, {returnHex: false});

    console.log("plain\n", plain);
    console.log("A's key pair\n", A);
    console.log("B's key pair\n", B);
    console.log("encrypted\n", encrypted);
    console.log("decrypted\n", decrypted);
    console.log("reKey\n", reKey);
    console.log("reEncypted\n", reEncypted);
    console.log("reDecrypted\n", reDecrypted);
    console.log("plain==decrypted==reDecrypted:", plain === decrypted && plain === reDecrypted);
    console.log("A's signature", sig);
    console.log("verify A's signature by A's pk:", PRE.verify(msgHash, sig, A.pk, params));
    console.log("verify A's signature by C's pk:", PRE.verify(msgHash, sig, C.pk, params))

}).catch(err => {
    console.log(err)
});