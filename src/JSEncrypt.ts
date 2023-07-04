import { b64tohex, hex2b64 } from "./lib/jsbn/base64";
import { JSEncryptRSAKey } from "./JSEncryptRSAKey";
const version =
    typeof process !== "undefined" ? process.env?.npm_package_version : undefined;

export interface IJSEncryptOptions {
    default_key_size?: string;
    default_public_exponent?: string;
    log?: boolean;
}
export type IEncryptEncodingOptions = {
    encoding?: "ASCII" | "UTF8";
    by?: "PrivateKey" | "PublicKey";
};

/**
 *
 * @param {Object} [options = {}] - An object to customize JSEncrypt behaviour
 * possible parameters are:
 * - default_key_size        {number}  default: 1024 the key size in bit
 * - default_public_exponent {string}  default: '010001' the hexadecimal representation of the public exponent
 * - log                     {boolean} default: false whether log warn/error or not
 * @constructor
 */
export class JSEncrypt {
    constructor(options: IJSEncryptOptions = {}) {
        options = options || {};
        this.default_key_size = options.default_key_size
            ? parseInt(options.default_key_size, 10)
            : 1024;
        this.default_public_exponent = options.default_public_exponent || "010001"; // 65537 default openssl public exponent for rsa key type
        this.log = options.log || false;
        // The private and public key.
        this.key = null;
    }

    private default_key_size: number;
    private default_public_exponent: string;
    private log: boolean;
    private key: JSEncryptRSAKey;
    public static version: string = version;

    /**
     * Method to set the rsa key parameter (one method is enough to set both the public
     * and the private key, since the private key contains the public key paramenters)
     * Log a warning if logs are enabled
     * @param {Object|string} key the pem encoded string or an object (with or without header/footer)
     * @public
     */
    public setKey(key: string) {
        if (this.log && this.key) {
            console.warn("A key was already set, overriding existing.");
        }
        this.key = new JSEncryptRSAKey(key);
    }

    /**
     * Proxy method for setKey, for api compatibility
     * @see setKey
     * @public
     */
    public setPrivateKey(privkey: string) {
        // Create the key.
        this.setKey(privkey);
    }

    /**
     * Proxy method for setKey, for api compatibility
     * @see setKey
     * @public
     */
    public setPublicKey(pubkey: string) {
        // Sets the public key.
        this.setKey(pubkey);
    }

    doDecrypt(hexText: string, options: IEncryptEncodingOptions) {
        let decrypted = "";
        switch (options.by) {
            case "PublicKey":
                decrypted = this.getKey().decryptByPublicKey(hexText);
                break;
            default:
                decrypted = this.getKey().decrypt(hexText);
                break;
        }
        return decrypted;
    }
    /**
     * Proxy method for RSAKey object's decrypt, decrypt the string using the private
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str base64 encoded crypted string to decrypt
     * @return {string} the decrypted string
     * @public
     */
    public decrypt(str: string, options: IEncryptEncodingOptions = {}) {
        options.by = options.by || "PrivateKey";
        // Return the decrypted string.
        try {
            const hexText = b64tohex(str);
            return this.doDecrypt(hexText, options);
        } catch (ex) {
            return false;
        }
    }

    /**
     * support for long plaintext
     * @param cipherText
     * @param options
     * @returns
     */
    public decryptOxr(cipherText: string, options: IEncryptEncodingOptions = {}) {
        try {
            const hexText = b64tohex(cipherText);
            // @ts-ignore
            const maxLength = this.getKey().n.bitLength() / 4;

            if (hexText.length <= maxLength) {
                return this.doDecrypt(hexText, options);
            } else {
                // long cipher text decrypt
                const arr = hexText.match(new RegExp(".{1," + maxLength + "}", "g"))!;
                const plainText = arr.reduce((acc, cur) => {
                    return acc + this.doDecrypt(cur, options);
                }, "");

                return plainText;
            }
        } catch (error) {
            return false;
        }
    }

    doEncrypt(str: string, options: IEncryptEncodingOptions) {
        let encrypted = "";
        switch (options.by) {
            case "PrivateKey":
                encrypted = this.getKey().encryptByPrivateKey(str, options.encoding);
                break;
            default:
                encrypted = this.getKey().encrypt(str);
                break;
        }
        return encrypted;
    }
    /**
     * Proxy method for RSAKey object's encrypt, encrypt the string using the public
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str the string to encrypt
     * @return {string} the encrypted string encoded in base64
     * @public
     */
    public encrypt(str: string, options: IEncryptEncodingOptions = {}) {
        options.by = options.by || "PublicKey";
        options.encoding = options.encoding || "UTF8";
        // Return the encrypted string.
        try {
            return hex2b64(this.doEncrypt(str, options));
        } catch (ex) {
            return false;
        }
    }
    /**
     * support for long plaintext
     * @param str
     * @param options
     * @returns
     */
    public encryptOxr(str: string, options: IEncryptEncodingOptions = {}) {
        try {
            // @ts-ignore
            const maxByteLength = ((this.getKey().n.bitLength() + 7) >> 3) - 11;
            let i = 0;
            const byteArr = [];
            while (i <= str.length - 1) {
                const c = str.charCodeAt(i);
                if (c < 128) {
                    byteArr.push(str[i]);
                } else if (c > 127 && c < 2048) {
                    byteArr.push(null, str[i]);
                } else {
                    byteArr.push(null, null, str[i]);
                }
                i++;
            }

            if (byteArr.length <= maxByteLength) {
                return this.encrypt(str, options);
            } else {
                // long plain text encrypt
                let cipherStrSum = "";
                while (byteArr.length > 0) {
                    let offset = maxByteLength;
                    while (byteArr[offset - 1] === null) {
                        offset = offset - 1;
                    }
                    const text = byteArr
                        .slice(0, offset)
                        .filter((i) => i !== null)
                        .join("");
                    cipherStrSum += this.doEncrypt(text, options);
                    byteArr.splice(0, offset);
                }
                return hex2b64(cipherStrSum);
            }
        } catch (error) {
            return false;
        }
    }
    /**
     * Proxy method for RSAKey object's sign.
     * @param {string} str the string to sign
     * @param {function} digestMethod hash method
     * @param {string} digestName the name of the hash algorithm
     * @return {string} the signature encoded in base64
     * @public
     */
    public sign(
        str: string,
        digestMethod: (str: string) => string,
        digestName: string,
    ): string | false {
        // return the RSA signature of 'str' in 'hex' format.
        try {
            return hex2b64(this.getKey().sign(str, digestMethod, digestName));
        } catch (ex) {
            return false;
        }
    }

    /**
     * Proxy method for RSAKey object's verify.
     * @param {string} str the string to verify
     * @param {string} signature the signature encoded in base64 to compare the string to
     * @param {function} digestMethod hash method
     * @return {boolean} whether the data and signature match
     * @public
     */
    public verify(
        str: string,
        signature: string,
        digestMethod: (str: string) => string,
    ): boolean {
        // Return the decrypted 'digest' of the signature.
        try {
            return this.getKey().verify(str, b64tohex(signature), digestMethod);
        } catch (ex) {
            return false;
        }
    }

    /**
     * Getter for the current JSEncryptRSAKey object. If it doesn't exists a new object
     * will be created and returned
     * @param {callback} [cb] the callback to be called if we want the key to be generated
     * in an async fashion
     * @returns {JSEncryptRSAKey} the JSEncryptRSAKey object
     * @public
     */
    public getKey(cb?: () => void) {
        // Only create new if it does not exist.
        if (!this.key) {
            // Get a new private key.
            this.key = new JSEncryptRSAKey();
            if (cb && {}.toString.call(cb) === "[object Function]") {
                this.key.generateAsync(
                    this.default_key_size,
                    this.default_public_exponent,
                    cb,
                );
                return;
            }
            // Generate the key.
            this.key.generate(this.default_key_size, this.default_public_exponent);
        }
        return this.key;
    }

    /**
     * Returns the pem encoded representation of the private key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the private key WITH header and footer
     * @public
     */
    public getPrivateKey() {
        // Return the private representation of this key.
        return this.getKey().getPrivateKey();
    }

    /**
     * Returns the pem encoded representation of the private key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the private key WITHOUT header and footer
     * @public
     */
    public getPrivateKeyB64() {
        // Return the private representation of this key.
        return this.getKey().getPrivateBaseKeyB64();
    }

    /**
     * Returns the pem encoded representation of the public key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the public key WITH header and footer
     * @public
     */
    public getPublicKey() {
        // Return the private representation of this key.
        return this.getKey().getPublicKey();
    }

    /**
     * Returns the pem encoded representation of the public key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the public key WITHOUT header and footer
     * @public
     */
    public getPublicKeyB64() {
        // Return the private representation of this key.
        return this.getKey().getPublicBaseKeyB64();
    }
}
