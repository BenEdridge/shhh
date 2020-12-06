const ENC_ALGORITHM = 'AES-GCM';
const KEY_DER_ALGORITHM = 'PBKDF2';
const KEY_DER_HASH = 'SHA-256';
const TAG_LENGTH = 128;
const ITERATIONS = 10000;
const EXTRACT_KEY = false;
const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 12;

async function encrypt(data, iv) {

  // import our key and convert into CryptoKey
  const keyArray = fromDecString(AES_KEY);
  const key = await importAESKey(keyArray);

  // txt -> ArrayBuffer
  let dataToEncrypt = new TextEncoder().encode(data);
  return crypto.subtle.encrypt(
    {
      name: ENC_ALGORITHM,
      iv,
      tagLength: TAG_LENGTH,
    },
    key,
    dataToEncrypt
  ).then(arrayBuffer => {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
  }).catch(e => {
    throw Error('Failed to encrypt:' + e);
  });
}

async function decrypt(data, iv) {

  // import our key and convert into CryptoKey
  const keyArray = fromDecString(AES_KEY);
  const key = await importAESKey(keyArray);

  // base64 -> ArrayBuffer
  const dataToDecrypt = base64ToArrayBuffer(data);
  return crypto.subtle.decrypt(
    {
      name: ENC_ALGORITHM,
      iv,
      tagLength: TAG_LENGTH,
    },
    key,
    dataToDecrypt
  ).then(arrayBuffer => {
    return new TextDecoder().decode(arrayBuffer)
  }).catch(e => {
    throw Error('Failed to decrypt:' + e);
  });
}

async function encryptUsingPassword(password, data, iv, salt) {
  const keyMaterial = await passwordToKeyMaterial(password);
  const key = await deriveKeyFromKeyMaterial(keyMaterial, salt);
  return encrypt(data, iv, key)
};

async function decryptUsingPassword(password, data, iv, salt) {
  const keyMaterial = await passwordToKeyMaterial(password);
  const key = await deriveKeyFromKeyMaterial(keyMaterial, salt);
  return decrypt(data, iv, key);
};

async function deriveKeyFromKeyMaterial(keyMaterial, salt){
  return crypto.subtle.deriveKey(
    {
      name: KEY_DER_ALGORITHM,
      salt,
      iterations: ITERATIONS,
      hash: { name: KEY_DER_HASH },
    },
    keyMaterial,
    {
      name: ENC_ALGORITHM,
      length: 256,
    },
    EXTRACT_KEY,
    ["encrypt", "decrypt"]
  );
};

async function passwordToKeyMaterial(password){
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    KEY_DER_ALGORITHM,
    EXTRACT_KEY,
    ["deriveKey"]
  );
};

async function importAESKey(raw) {
  return crypto.subtle.importKey(
    "raw", raw, { name: ENC_ALGORITHM }, EXTRACT_KEY, ["encrypt", "decrypt"]
  );
};

function base64ToArrayBuffer(data) {
  const characters = atob(data);
  let array = new Uint8Array(characters.length);
  for (var i = 0; i < characters.length; i++) {
    array[i] = characters.charCodeAt(i);
  }
  return new Uint8Array(array);
};

const dec2hex = dec => dec < 10 ? '0' + String(dec) : dec.toString(16);

const fromHexString = hexString => new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const fromDecString = decStringArray => new Uint8Array(decStringArray.split(',').map(byte => parseInt(byte, 16)));

function generateRandomHexStringArray(bytes) {
  let array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array, dec2hex).join('');
};

async function setRandomValues(array){
  await crypto.getRandomValues(array);
};

export {
  IV_LENGTH_BYTES,
  SALT_LENGTH_BYTES,
  encrypt,
  decrypt,
  generateRandomHexStringArray,
  setRandomValues,
  encryptUsingPassword,
  decryptUsingPassword,
  dec2hex,
  fromHexString
}