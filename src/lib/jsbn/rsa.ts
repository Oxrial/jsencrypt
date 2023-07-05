// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object

import { BigInteger, nbi, parseBigInt } from "./jsbn";
import { SecureRandom } from "./rng";

// function linebrk(s,n) {
//   var ret = "";
//   var i = 0;
//   while(i + n < s.length) {
//     ret += s.substring(i,i+n) + "\n";
//     i += n;
//   }
//   return ret + s.substring(i,s.length);
// }

// function byte2Hex(b) {
//   if(b < 0x10)
//     return "0" + b.toString(16);
//   else
//     return b.toString(16);
// }

/**
 * 22和11是根据PKCS#1填充规范中定义的填充长度计算得出的。PKCS#1是一种公钥密码学的标准，定义了在RSA加密中进行填充的方式。
 * 在pkcs1pad1方法中，22是根据填充规范计算得出的固定填充长度。填充的方式是在原始字符串前面添加"0001"、一定数量的字节"ff"，再添加一个字节的"00"。所以，填充后的字符串长度为原始字符串长度加上22个字节。
 * 在pkcs1pad2方法中，11是根据填充规范计算得出的随机填充长度。填充的方式与pkcs1pad1类似，但是在填充的过程中还会添加一些随机的非零字节，以增加填充的随机性。所以，填充后的字符串长度为原始字符串长度加上11个字节。
 */
function pkcs1pad1(s: string, n: number) {
    if (n < s.length + 22) {
        console.error("Message too long for RSA");
        return null;
    }
    const len = n - s.length - 6;
    let filler = "";
    for (let f = 0; f < len; f += 2) {
        filler += "ff";
    }
    const m = "0001" + filler + "00" + s;
    return parseBigInt(m, 16);
}

let nTemp = 0;
// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s: string, n: number) {
    if (n < s.length + 11) {
        // TODO: fix for utf-8

        console.error("Message too long for RSA");
        return null;
    }
    nTemp = n;
    const ba = stringToUtf8(s);
    // 直接将原文进行运算
    ba[--nTemp] = 0;
    const rng = new SecureRandom();
    const x = [];
    while (nTemp > 2) {
        // random non-zero pad
        x[0] = 0;
        while (x[0] == 0) {
            rng.nextBytes(x);
        }
        ba[--nTemp] = x[0];
    }
    ba[--nTemp] = 2;
    ba[--nTemp] = 0;

    nTemp = 0;
    return new BigInteger(ba);
}

// 私钥加密固定填充
function pkcs1pad3(s: string, n: number, encoding: string) {
    if (n < s.length + 11) {
        // TODO: fix for utf-8
        console.error("Message too long for RSA");
        return null;
    }
    switch (encoding) {
        case "ASCII":
            s = asciiToHex(s);
            break;
        default:
            s = stringToUtf8Hex(s);
            break;
    }
    var len = n - s.length - 6;
    var filter = "";
    for (var f = 0; f < len; f += 2) {
        filter += "ff";
    }

    nTemp = 0;
    // 0x01为私钥加密，0x02为公钥加密
    // 填充起始标志是以ASCII字符串的形式表示，不是直接使用十六进制表示
    var m = "0001" + filter + "00" + s;
    return parseBigInt(m, 16);
}
// function stringToUtf8(s, n) {}
function stringToUtf8Hex(s: string) {
    nTemp = s.length * 4;
    const ba = stringToUtf8(s);

    let utf8Hex = "";
    for (let j = nTemp; j < s.length * 4; j++) {
        utf8Hex += ("00" + ba[j].toString(16)).slice(-2);
    }
    return utf8Hex;
}
/**
 * 将string转为UTF8字节数组
 * @param s
 * @param n UTF-8编码中，一个字符可能占用1到4个字节
 *             确保输出的十六进制字符串的长度不会超过预设的最大值可取最大值s.length*4
 * @returns
 */
function stringToUtf8(s: string) {
    const ba = [];
    let i = s.length - 1;
    while (i >= 0 && nTemp > 0) {
        const c = s.charCodeAt(i--);
        if (c < 128) {
            // encode using utf-8
            ba[--nTemp] = c;
        } else if (c > 127 && c < 2048) {
            ba[--nTemp] = (c & 63) | 128;
            ba[--nTemp] = (c >> 6) | 192;
        } else {
            ba[--nTemp] = (c & 63) | 128;
            ba[--nTemp] = ((c >> 6) & 63) | 128;
            ba[--nTemp] = (c >> 12) | 224;
        }
    }
    return ba;
}
function asciiToHex(s: string) {
    let hex = "";
    for (let i = 0; i < s.length; i++) {
        let charCode = s.charCodeAt(i).toString(16);
        hex += ("00" + charCode).slice(-2);
    }
    return hex;
}
// "empty" RSA key constructor
export class RSAKey {
    constructor() {
        this.n = null;
        this.e = 0;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.coeff = null;
    }

    //#region PROTECTED
    // protected
    // RSAKey.prototype.doPublic = RSADoPublic;
    // Perform raw public operation on "x": return x^e (mod n)
    public doPublic(x: BigInteger) {
        return x.modPowInt(this.e, this.n);
    }

    // RSAKey.prototype.doPrivate = RSADoPrivate;
    // Perform raw private operation on "x": return x^d (mod n)
    public doPrivate(x: BigInteger) {
        if (this.p == null || this.q == null) {
            return x.modPow(this.d, this.n);
        }

        // TODO: re-calculate any missing CRT params
        let xp = x.mod(this.p).modPow(this.dmp1, this.p);
        const xq = x.mod(this.q).modPow(this.dmq1, this.q);

        while (xp.compareTo(xq) < 0) {
            xp = xp.add(this.p);
        }
        return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
    }

    //#endregion PROTECTED

    //#region PUBLIC

    // RSAKey.prototype.setPublic = RSASetPublic;
    // Set the public key fields N and e from hex strings
    public setPublic(N: string, E: string) {
        if (N != null && E != null && N.length > 0 && E.length > 0) {
            this.n = parseBigInt(N, 16);
            this.e = parseInt(E, 16);
        } else {
            console.error("Invalid RSA public key");
        }
    }

    // RSAKey.prototype.encrypt = RSAEncrypt;
    // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
    public encrypt(text: string) {
        const maxLength = (this.n.bitLength() + 7) >> 3;
        const m = pkcs1pad2(text, maxLength);

        if (m == null) {
            return null;
        }
        const c = this.doPublic(m);
        if (c == null) {
            return null;
        }

        let h = c.toString(16);
        let length = h.length;

        // fix zero before result
        for (let i = 0; i < maxLength * 2 - length; i++) {
            h = "0" + h;
        }

        return h;
    }

    // 使用私钥加密，解密时需对应公钥解密
    public encryptByPrivateKey(text: string, encoding: string) {
        var maxLength = this.n.bitLength() / 4;
        var m = pkcs1pad3(text, maxLength, encoding);
        if (m == null) {
            return null;
        }
        var c = this.doPrivate(m);
        if (c == null) {
            return null;
        }
        var h = c.toString(16);
        var length = h.length;
        if ((length & 1) == 0) {
            return h;
        } else {
            return "0" + h;
        }
    }

    // RSAKey.prototype.setPrivate = RSASetPrivate;
    // Set the private key fields N, e, and d from hex strings
    public setPrivate(N: string, E: string, D: string) {
        if (N != null && E != null && N.length > 0 && E.length > 0) {
            this.n = parseBigInt(N, 16);
            this.e = parseInt(E, 16);
            this.d = parseBigInt(D, 16);
        } else {
            console.error("Invalid RSA private key");
        }
    }

    // RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
    // Set the private key fields N, e, d and CRT params from hex strings
    public setPrivateEx(
        N: string,
        E: string,
        D: string,
        P: string,
        Q: string,
        DP: string,
        DQ: string,
        C: string,
    ) {
        if (N != null && E != null && N.length > 0 && E.length > 0) {
            this.n = parseBigInt(N, 16);
            this.e = parseInt(E, 16);
            this.d = parseBigInt(D, 16);
            this.p = parseBigInt(P, 16);
            this.q = parseBigInt(Q, 16);
            this.dmp1 = parseBigInt(DP, 16);
            this.dmq1 = parseBigInt(DQ, 16);
            this.coeff = parseBigInt(C, 16);
        } else {
            console.error("Invalid RSA private key");
        }
    }

    // RSAKey.prototype.generate = RSAGenerate;
    // Generate a new random private key B bits long, using public expt E
    public generate(B: number, E: string) {
        const rng = new SecureRandom();
        const qs = B >> 1;
        this.e = parseInt(E, 16);
        const ee = new BigInteger(E, 16);
        for (;;) {
            for (;;) {
                this.p = new BigInteger(B - qs, 1, rng);
                if (
                    this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) ==
                        0 &&
                    this.p.isProbablePrime(10)
                ) {
                    break;
                }
            }
            for (;;) {
                this.q = new BigInteger(qs, 1, rng);
                if (
                    this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) ==
                        0 &&
                    this.q.isProbablePrime(10)
                ) {
                    break;
                }
            }
            if (this.p.compareTo(this.q) <= 0) {
                const t = this.p;
                this.p = this.q;
                this.q = t;
            }
            const p1 = this.p.subtract(BigInteger.ONE);
            const q1 = this.q.subtract(BigInteger.ONE);
            const phi = p1.multiply(q1);
            if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
                this.n = this.p.multiply(this.q);
                this.d = ee.modInverse(phi);
                this.dmp1 = this.d.mod(p1);
                this.dmq1 = this.d.mod(q1);
                this.coeff = this.q.modInverse(this.p);
                break;
            }
        }
    }

    // RSAKey.prototype.decrypt = RSADecrypt;
    // Return the PKCS#1 RSA decryption of "ctext".
    // "ctext" is an even-length hex string and the output is a plain string.
    public decrypt(ctext: string) {
        const c = parseBigInt(ctext, 16);
        const m = this.doPrivate(c);
        if (m == null) {
            return null;
        }
        return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
    }
    // 使用公钥解密，需对应私钥加密
    public decryptByPublicKey(ctext: string) {
        const c = parseBigInt(ctext, 16);
        const m = this.doPublic(c);
        if (m == null) {
            return null;
        }
        return pkcs1unpad3(m);
    }

    // Generate a new random private key B bits long, using public expt E
    public generateAsync(B: number, E: string, callback: () => void) {
        const rng = new SecureRandom();
        const qs = B >> 1;
        this.e = parseInt(E, 16);
        const ee = new BigInteger(E, 16);
        const rsa = this;
        // These functions have non-descript names because they were originally for(;;) loops.
        // I don't know about cryptography to give them better names than loop1-4.
        const loop1 = function () {
            const loop4 = function () {
                if (rsa.p.compareTo(rsa.q) <= 0) {
                    const t = rsa.p;
                    rsa.p = rsa.q;
                    rsa.q = t;
                }
                const p1 = rsa.p.subtract(BigInteger.ONE);
                const q1 = rsa.q.subtract(BigInteger.ONE);
                const phi = p1.multiply(q1);
                if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
                    rsa.n = rsa.p.multiply(rsa.q);
                    rsa.d = ee.modInverse(phi);
                    rsa.dmp1 = rsa.d.mod(p1);
                    rsa.dmq1 = rsa.d.mod(q1);
                    rsa.coeff = rsa.q.modInverse(rsa.p);
                    setTimeout(function () {
                        callback();
                    }, 0); // escape
                } else {
                    setTimeout(loop1, 0);
                }
            };
            const loop3 = function () {
                rsa.q = nbi();
                rsa.q.fromNumberAsync(qs, 1, rng, function () {
                    rsa.q.subtract(BigInteger.ONE).gcda(ee, function (r) {
                        if (
                            r.compareTo(BigInteger.ONE) == 0 &&
                            rsa.q.isProbablePrime(10)
                        ) {
                            setTimeout(loop4, 0);
                        } else {
                            setTimeout(loop3, 0);
                        }
                    });
                });
            };
            const loop2 = function () {
                rsa.p = nbi();
                rsa.p.fromNumberAsync(B - qs, 1, rng, function () {
                    rsa.p.subtract(BigInteger.ONE).gcda(ee, function (r) {
                        if (
                            r.compareTo(BigInteger.ONE) == 0 &&
                            rsa.p.isProbablePrime(10)
                        ) {
                            setTimeout(loop3, 0);
                        } else {
                            setTimeout(loop2, 0);
                        }
                    });
                });
            };
            setTimeout(loop2, 0);
        };
        setTimeout(loop1, 0);
    }

    public sign(
        text: string,
        digestMethod: (str: string) => string,
        digestName: string,
    ): string {
        const header = getDigestHeader(digestName);
        const digest = header + digestMethod(text).toString();
        const m = pkcs1pad1(digest, this.n.bitLength() / 4);
        if (m == null) {
            return null;
        }
        const c = this.doPrivate(m);
        if (c == null) {
            return null;
        }
        const h = c.toString(16);
        if ((h.length & 1) == 0) {
            return h;
        } else {
            return "0" + h;
        }
    }

    public verify(
        text: string,
        signature: string,
        digestMethod: (str: string) => string,
    ): boolean {
        const c = parseBigInt(signature, 16);
        const m = this.doPublic(c);
        if (m == null) {
            return null;
        }
        const unpadded = m.toString(16).replace(/^1f+00/, "");
        const digest = removeDigestHeader(unpadded);
        return digest == digestMethod(text).toString();
    }

    //#endregion PUBLIC

    protected n: BigInteger;
    protected e: number;
    protected d: BigInteger;
    protected p: BigInteger;
    protected q: BigInteger;
    protected dmp1: BigInteger;
    protected dmq1: BigInteger;
    protected coeff: BigInteger;
}

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
function pkcs1unpad2(d: BigInteger, n: number): string {
    const b = d.toByteArray();
    let i = 0;
    while (i < b.length && b[i] == 0) {
        ++i;
    }
    /**
     * 检查解密后的字节数组  b  是否符合 PKCS#1 v1.5 的填充规范。
     * 如果条件  (b.length - i != n - 1 || b[i] != 2)  不满足，
     * 即数组  b  的长度减去当前索引  i  不等于  n - 1
     * 或者数组  b  在当前索引  i  处的元素不等于  2 ，
     * 则函数返回  null
     */
    if (b.length - i != n - 1 || b[i] != 2) {
        return null;
    }
    ++i;
    while (b[i] != 0) {
        if (++i >= b.length) {
            return null;
        }
    }
    let ret = "";
    while (++i < b.length) {
        const c = b[i] & 255;
        if (c < 128) {
            // utf-8 decode
            ret += String.fromCharCode(c);
        } else if (c > 191 && c < 224) {
            ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
            ++i;
        } else {
            ret += String.fromCharCode(
                ((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63),
            );
            i += 2;
        }
    }
    return ret;
}

// 使用公钥解密，需对应私钥加密
function pkcs1unpad3(d: BigInteger): string {
    const b = d.toByteArray();
    let i = 0;
    while (i < b.length && b[i] == 0) {
        ++i;
    }
    // if (b.length - i != n - 1 || b[i] != 2) {
    //     return null;
    // }
    ++i;
    while (b[i] != 0) {
        if (++i >= b.length) {
            return null;
        }
    }
    let ret = "";
    while (++i < b.length) {
        const c = b[i] & 255;
        if (c < 128) {
            // utf-8 decode
            ret += String.fromCharCode(c);
        } else if (c > 191 && c < 224) {
            ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
            ++i;
        } else {
            ret += String.fromCharCode(
                ((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63),
            );
            i += 2;
        }
    }
    return ret;
}
// https://tools.ietf.org/html/rfc3447#page-43
const DIGEST_HEADERS: { [name: string]: string } = {
    md2: "3020300c06082a864886f70d020205000410",
    md5: "3020300c06082a864886f70d020505000410",
    sha1: "3021300906052b0e03021a05000414",
    sha224: "302d300d06096086480165030402040500041c",
    sha256: "3031300d060960864801650304020105000420",
    sha384: "3041300d060960864801650304020205000430",
    sha512: "3051300d060960864801650304020305000440",
    ripemd160: "3021300906052b2403020105000414",
};

function getDigestHeader(name: string): string {
    return DIGEST_HEADERS[name] || "";
}

function removeDigestHeader(str: string): string {
    for (const name in DIGEST_HEADERS) {
        if (DIGEST_HEADERS.hasOwnProperty(name)) {
            const header = DIGEST_HEADERS[name];
            const len = header.length;
            if (str.substr(0, len) == header) {
                return str.substr(len);
            }
        }
    }
    return str;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
// function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
// }

// public

// RSAKey.prototype.encrypt_b64 = RSAEncryptB64;
