# bm-pre
A Proxy Re-Encryption library using Bilinear Map. It contains basic functions like encryption, decryption, re-encryption, re-decryption, sign and verify.
## Usage
### Setup
Set the generators of `G1` and `G2`. It must pefrom at first.
```javascript
const PRE = require('bm-pre');
PRE.init({g: "this is g", h: "that is h", returnHex: true}).then(params => {
    console.log(params)
    //...
});
```
### Generate Random Element in Fr
PRE is supposed to encrypt symmetric key.

It's recommended to get the key from a random element in Fr and convert it to hex string instead of generating a random key and mapping it to Fr.
```javascript
const plain = PRE.randomGen();
```
### Generate Key Pairs
Generate key pairs of Delegator(A) and Delegatee(B).
```javascript
const A = PRE.keyGenInG1(params, {returnHex: true});
const B = PRE.keyGenInG2(params, {returnHex: true});
```
You can get public key from existing secret key using `getPkFromG1` and `getPkFromG1`.
### Encryption & Decryption
A can of course encrypt and decrypt.
```javascript
const encrypted = PRE.enc(plain, A.pk, params, {returnHex: true});
const decrypted = PRE.dec(encrypted, A.sk, params);
console.log(plain === decrypted)
```
### Generate Re-Encryption Key
A can generate `reKey` with A's secret key and B's public key.
```javascript
const reKey = PRE.rekeyGen(A.sk, B.pk, {returnHex: true});
```
### Re-Encryption & Re-Decryption
Anyone can convert `encrypted` with `reKey`into ciphertext that can be decrypted by B.
```javascript
const reEncypted = PRE.reEnc(encrypted, reKey, {returnHex: true});
const reDecrypted = PRE.reDec(reEncypted, B.sk);
console.log(plain === reDecrypted)
```
### Sign and Verify
> Right now only signature by delegator is implemented, delegatee can have key pair with delegator's format (in G1) as well.

```javascript
//create hash for msg
const crypto = require('crypto');
const msg = "1111";
const hash = crypto.createHash('sha256');
hash.update(msg);
const msgHash = hash.digest('hex');
//sign hash and verify
const sig = PRE.sign(msgHash, A.sk);
const C = PRE.keyGenInG1(params, {returnHex: false});
console.log("A's signature", sig);
console.log("verify A's signature by A's pk:", PRE.verify(msgHash, sig, A.pk, params));
console.log("verify A's signature by C's pk:", PRE.verify(msgHash, sig, C.pk, params))
```
## Tips
Almost every input parameters can either be hex `string` or `Object` in group. It'll automatically check the type and convert it to `Object` during caculation if necessary.
## Algrithom
- **Setup**

  $g$ and $h$ are the generators of $G_1$ and $G_2$

  $Z=e(g,h)$

  $e:G_1 \times G_2 \to G_T$

- **Key Generation**

  $sk_A \in F_r$, $pk_A=g^{sk_A} \in G_1$

  $sk_B \in F_r$, ​$pk_B=h^{sk_B} \in G_2$

- **Encryption**
  $$
  C_1=((pk_A)^k,mZ^k)
  $$

- **Decryption**

  $$
  \frac{\beta}{e(\alpha,h)^{\frac{1}{sk_A}}}=\frac{me(g,h)^k}{e((pk_A)^k,h)^{\frac{1}{sk_A}}}=\frac{me(g,h)^k}{e((g^{sk_A})^k,h)^{\frac{1}{sk_A}}}=m
  $$

- **Re-Encryption Key Generation**

  $$
  rk_{A \to B}=(pk_B)^{\frac{1}{sk_A}}
  $$

- **Re-Encryption**

  From $C_I=(\alpha,\beta)$

  Caculate $\alpha{'}=e(\alpha,rk_{P \to D})$

  Output $C_2=(\alpha ^{'},\beta)$

- **Re-Decryption**

  $$
  \frac{\beta}{(\alpha^{'})^{\frac{1}{sk_B}}}=\frac{me(g,h)^k}{e(\alpha,rk_{P \to D}))^{\frac{1}{sk_B}}}=\frac{me(g,h)^k}{e((pk_A)^k,(pk_B)^{\frac{1}{sk_A}})^{\frac{1}{sk_B}}}=\frac{me(g,h)^k}{e((g^{sk_A})^k,(h^{sk_B})^{\frac{1}{sk_A}})^{\frac{1}{sk_B}}}=m
  $$

- **Sign**

  $$
  S=H^{sk_A}
  $$

- **Verify**

  $$
  e(g,S)=e(g,H^{sk_A})=e(g^{sk_A},H)=e(pk_A,H)
  $$
