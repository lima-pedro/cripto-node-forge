import "./App.css";
import { useState } from "react";
import forge from "node-forge";
import CryptoJS from "crypto-js";

const publicKeyPEM = ``;
const privateKeyPEM = ``;
const secret =
  "";

const payloadString =
  '';

const publicKey = forge.pki.publicKeyFromPem(publicKeyPEM);
const privateKey = forge.pki.privateKeyFromPem(privateKeyPEM);

function App() {
  const [data, setData] = useState();
  const [dataDec, setDataDec] = useState();
  const [hmacHashEnc, setHmacHashEnc] = useState();
  const [hmacHashDec, setHmacHashDec] = useState();
  const [hmacValidate, setHmacValidate] = useState();
  const [validate, setValidate] = useState(false);

  const rawPayload = {
    tsISO: new Date().toISOString(),
    data,
  };

  const createHmac = (dataEncrypted) => {
    const hmac = forge.hmac.create();
    hmac.start("sha256", secret);
    hmac.update(dataEncrypted);
    const hmacNodeForge = hmac.digest().toHex();
    return hmacNodeForge;
  };

  const encryptRSA = (data) => {
    const encrypted = publicKey.encrypt(data, "RSA-OAEP");
    return forge.util.encode64(encrypted);
  };

  const decryptRSA = (encryptedData) => {
    const encryptedBytes = forge.util.decode64(encryptedData);
    const decrypted = privateKey.decrypt(encryptedBytes, "RSA-OAEP");
    return decrypted;
  };

  // O PARAMETRO DATA TEM QUE SER STRING
  const encryptAES = (data) => {
    const key = CryptoJS.enc.Hex.parse(secret.substring(0, 32));
    const iv = CryptoJS.enc.Hex.parse(secret.substring(32, 48));

    const encrypted = CryptoJS.AES.encrypt(data, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    return encrypted;
  };

  const decryptAES = (data) => {
    const key = CryptoJS.enc.Hex.parse(secret.substring(0, 32));
    const iv = CryptoJS.enc.Hex.parse(secret.substring(32, 48));

    const decrypted = CryptoJS.AES.decrypt(data, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    return decrypted.toString(CryptoJS.enc.Utf8);
  };

  const handleDecrypt = () => {
    const [payloadEncryptedRECEIVED, encryptedHMACrsa] = dataDec.split("|");
    
    const decryptPayload = decryptAES(payloadEncryptedRECEIVED);

    if (decryptPayload !== JSON.stringify(rawPayload.data)) {
      setValidate(false);
      setHmacValidate('PAYLOAD DIFERENTES');
      setHmacHashDec('');
      return;
    }

    // HMAC ORIGINAL CRIADO COM PAYLOAD CRIPTOGRAFADO
    const decryptedHmac = decryptRSA(encryptedHMACrsa);

    // AQUI O RAW PAYLOAD SERIA O EVENT BODY
    const payloadString = JSON.stringify(rawPayload.data);
    const payloadEncrypted = encryptAES(payloadString);
    const hmacNodeForge = createHmac(payloadEncrypted);

    if (hmacNodeForge !== decryptedHmac) {
      setValidate(false);
      setHmacValidate('HMACS DIFERENTES');
      setHmacHashDec('');
      return;
    }
    
    setHmacValidate(hmacNodeForge);
    setHmacHashDec(decryptedHmac);
    setValidate(true);
  };

  const handleEncrypt = () => {
    // ENVIAR AQUI O X-TS-ISO, TEM QUE TER NO MÁXIMO 1 MIN
    const payloadString = JSON.stringify(rawPayload.data);
    const payloadEncrypted = encryptAES(payloadString);

    // USA O PAYLOAD ENCRIPTADO PARA CRIAÇÃO DO HMAC
    const hmacNodeForge = createHmac(payloadEncrypted);

    const encryptedHMACrsa = encryptRSA(hmacNodeForge);

    // HMAC HASH QUE DEVE SER UTILIZADO PARA ENVIO AO BACKEND
    setHmacHashEnc(`${payloadEncrypted}|${encryptedHMACrsa}`);

    // handleDecrypt(encryptedHMACrsa);
  };

  return (
    <div className="App">
      <header className="App-header">
        <div>
          <input
            type="text"
            name="text"
            id="text"
            onChange={(e) => setData(e.target.value)}
          />
          <button onClick={handleEncrypt}>
            Encrypt
          </button>
        </div>

        <div id="box">
          <span id="hash">HMAC HASH: {hmacHashEnc}</span>
        </div>

        <div>
          <input
            type="desc"
            name="desc"
            id="desc"
            onChange={(evt) => {
              console.log('E', evt)
              setDataDec(evt.target.value)
            }}
          />
          <button onClick={handleDecrypt}>
            Decrypt
          </button>
        </div>

        <div id="box">
          <div>
            <span id="hash">HMAC DEC: {hmacHashDec}</span>
          </div>
          <div>
            <span id="hash">HMAC DO BODY: {hmacValidate}</span>
          </div>
          <div>
            {console.log('VALIDATE', validate)}
            <span id="hash">IS VALID: {!validate ? 'FALSE' : 'TRUE'}</span>
          </div>
        </div>
      </header>
    </div>
  );
}

export default App;
