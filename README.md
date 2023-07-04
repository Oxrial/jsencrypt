## Introductio

A forked from [jsencrypt](https://www.npmjs.com/package/jsencrypt) and [jsencrypt-ext](https://www.npmjs.com/package/jsencrypt-ext)，support for privateKey encrypt，publicKey decrypt and long plaintext.

## PrivateKey encrypt and PublicKey decrypt

```
const encrypt = new JSEncrypt()
encrypt.setPrivateKey(privateKey)
const encrypted = encrypt.encrypt("test", { by: "PrivateKey", encoding: "UTF8" })
console.log("私钥加密 encrypted:", encrypted)

const dencrypt = new JSEncrypt()
dencrypt.setPublicKey(publicKey)
const dencrypted = dencrypt.decrypt(encrypted as string, { by: "PublicKey" })
console.log("公钥解密 dencrypted:", dencrypted)
```

### 扩充 API

| function(args)        | options: IEncryptEncodingOptions = <br/> { encoding?: "ASCII" \|"UTF8"; by?: "PrivateKey" \|"PublicKey"; } | desc              |
| --------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------- |
| encrypt(str, options) | default = { encoding: "_UTF8_", by: "_PublicKey_" }                                                        | 公钥(d)/私钥 加密 |
| decrypt(str, options) | default = { by: "_PrivateKey_" }                                                                           | 私钥(d)/公钥 解密 |

## Long Plaintext

```
const encrypt = new JSEncrypt()
encrypt.setPublicKey(publicKey)
const longMessage = JSON.stringify(
  Array.from(new Array(100))
    .fill("壹贰叁肆伍陆柒捌玖拾佰仟")
    .map((i, index) => ({ name: `${index}${i}` }))
)
const encrypted = encrypt.encryptExt(longMessage)
console.log("公钥加密 encrypted:", encrypted)

const dencrypt = new JSEncrypt()
dencrypt.setPrivateKey(privateKey)
const dencrypted = dencrypt.decryptExt(encrypted as string)
console.log("私钥解密 dencrypted:", dencrypted)
```

### 扩充 API

| function(args)           | options: IEncryptEncodingOptions = <br/> { encoding?: "ASCII" \|"UTF8"; by?: "PrivateKey" \|"PublicKey"; } | description       |
| ------------------------ | ---------------------------------------------------------------------------------------------------------- | ----------------- |
| encryptOxr(str, options) | default = { encoding: "_UTF8_", by: "_PublicKey_" }                                                        | 公钥(d)/私钥 加密 |
| decryptOxr(str, options) | default = { by: "_PrivateKey_" }                                                                           | 私钥(d)/公钥 解密 |
