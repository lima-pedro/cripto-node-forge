const forge = require('node-forge');

// Criando um novo par de chaves RSA (2048 bits)
const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });

// Convertendo as chaves públicas e privadas para strings no formato PEM
const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

console.log('Chave Pública:');
console.log(publicKeyPem);

console.log('Chave Privada:');
console.log(privateKeyPem);