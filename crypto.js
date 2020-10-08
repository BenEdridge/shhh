async function encrypt(data, iv, key) {
  // txt -> ArrayBuffer
  let dataToEncrypt = new TextEncoder().encode(data);
  return crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 32,
    },
    key,
    dataToEncrypt
  ).then(arrayBuffer => {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
  }).catch(e => {
    throw Error('Failed to encrypt:' + e);
  });
}

async function decrypt(data, iv, key) {
  // base64 -> ArrayBuffer
  const dataToDecrypt = base64ToArrayBuffer(data);
  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 32,
    },
    key,
    dataToDecrypt
  ).then(arrayBuffer => {
    return new TextDecoder().decode(arrayBuffer)
  }).catch(e => {
    throw Error('Failed to decrypt:' + e);
  });
}

async function encryptFromPassword(password, data, iv, salt) {
  const keyMaterial = await passwordToKeyMaterial(password);
  const key = await deriveKeyFromKeyMaterial(keyMaterial, salt, 10000);
  return encrypt(data, iv, key)
};

async function decryptFromPassword(password, data, iv, salt) {
  const keyMaterial = await passwordToKeyMaterial(password);
  const key = await deriveKeyFromKeyMaterial(keyMaterial, salt, 10000);
  return decrypt(data, iv, key);
};

async function deriveKeyFromKeyMaterial(keyMaterial, salt, iterations){
  return crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt,
      iterations,
      hash: { name: "SHA-256" },
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
};

async function passwordToKeyMaterial(password){
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
};

async function importAESKey(raw) {
  return crypto.subtle.importKey(
    "raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
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

function generateRandom(n) {
  let array = new Uint8Array(n);
  crypto.getRandomValues(array);
  return Array.from(array, dec2hex).join('');
};

export {
  encrypt,
  decrypt,
  generateRandom,
  importAESKey,
  encryptFromPassword,
  decryptFromPassword,
  dec2hex,
  fromDecString,
  fromHexString
}