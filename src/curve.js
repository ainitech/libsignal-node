const curveJs = require('../build/curve25519.js');
const nodeCrypto = require('crypto');
// from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js

console.log("✅ Módulo curve25519.js carregado:", Object.keys(curveJs));


// Função para aguardar o carregamento do módulo
async function ensureModuleLoaded() {
    while (!curveJs) {
        console.log("⏳ Aguardando curve25519.js carregar...");
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
}




const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);
  
const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    } else {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}

exports.generateKeyPair = function() {
    if(typeof nodeCrypto.generateKeyPairSync === 'function') {
        const {publicKey: publicDerBytes, privateKey: privateDerBytes} = nodeCrypto.generateKeyPairSync(
            'x25519',
            {
                publicKeyEncoding: { format: 'der', type: 'spki' },
                privateKeyEncoding: { format: 'der', type: 'pkcs8' }
            }
        );
        // 33 bytes
        // first byte = 5 (version byte)
        const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length-1, PUBLIC_KEY_DER_PREFIX.length + 32);
        pubKey[0] = 5;
    
        const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);
    
        return {
            pubKey,
            privKey
        };
    } else {
        const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
        return {
            privKey: Buffer.from(keyPair.private),
            pubKey: Buffer.from(keyPair.public),
        };
    }
};

exports.calculateAgreement = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }

    if(typeof nodeCrypto.diffieHellman === 'function') {
        const nodePrivateKey = nodeCrypto.createPrivateKey({
            key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = nodeCrypto.createPublicKey({
            key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
            format: 'der',
            type: 'spki'
        });
        
        return nodeCrypto.diffieHellman({
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey,
        });
    } else {
        const secret = curveJs.sharedKey(privKey, pubKey);
        return Buffer.from(secret);
    }
};

exports.calculateSignature = async function (privKey, message) {
    await ensureModuleLoaded();

    if (!curveJs._curve25519_sign) {
        throw new Error("❌ Função _curve25519_sign não encontrada no módulo curve25519.js");
    }

    if (!privKey) {
        throw new Error("❌ Erro: `privKey` está indefinido em calculateSignature.");
    }
    if (!message) {
        throw new Error("❌ Erro: `message` está indefinido em calculateSignature.");
    }

    // Chamada da função diretamente
    return Buffer.from(curveJs._curve25519_sign(privKey, message));
};


exports.verifySignature = async function (pubKey, msg, sig) {
    await ensureModuleLoaded(); // Garante que curve25519.js está carregado

    if (!curveJs._curve25519_verify) {
        throw new Error("❌ Função _curve25519_verify não encontrada no módulo curve25519.js");
    }

    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }

    return curveJs._curve25519_verify(pubKey, msg, sig);
};


