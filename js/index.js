/**
 * https://cryptojs.gitbook.io/docs/
 */

import CryptoJS from "crypto-js";

const key = CryptoJS.enc.Base64.parse("lSWRdevYaeTjNdqbOYhOUybKaZjR+kaw0P12r1FHYG4=");
const iv = CryptoJS.enc.Base64.parse("Mtza6wKU7GQAAAAAnvQ+uA==");

function AesEncrypt(data) {
    let encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: iv,
        mode: CryptoJS.mode.CTR,
        padding: CryptoJS.pad.NoPadding
    });
    return encrypted.ciphertext;
}

// function AesDecrypt(data) {
//     let decrypted = CryptoJS.AES.decrypt(data, key, {
//         iv: iv,
//         mode: CryptoJS.mode.CTR,
//         padding: CryptoJS.pad.NoPadding
//     });
//     console.log(decrypted.toString(CryptoJS.enc.Utf8))
// }

async function main() {
    let encrypt = AesEncrypt("15651859999")
    // console.log(encrypt)
    console.log(CryptoJS.enc.Base64.stringify(encrypt))

    let decrypt = AesEncrypt(encrypt)
    // console.log(decrypt)
    console.log(CryptoJS.enc.Utf8.stringify(decrypt))
}

main();