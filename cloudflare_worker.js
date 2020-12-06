// https://developers.cloudflare.com/workers/examples/cache-api
// https://blog.cloudflare.com/introducing-the-workers-cache-api-giving-you-control-over-how-your-content-is-cached/
// https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
// https://support.cloudflare.com/hc/en-us/articles/200172516-Understanding-Cloudflare-s-CDN

import * as cryptoHelper from './crypto.js';
import * as html from './html.js';

const RANDOM_URL_BYTE_LENGTH = 32;

addEventListener("fetch", event => {
  const { request } = event;
  const { url } = request;

  if (request.method === "GET") {
    if (url.includes("/reveal")) {
      return event.respondWith(handleRevealRequest(request))
    } else {
      return event.respondWith(rawHtmlResponse(html.buildMainPage()));
    }

  } else if (request.method === "POST" && url.includes("/share")) {
    return event.respondWith(handleShareRequest(event));
  } else if (request.method === "POST" && url.includes("/reveal")) {
    return event.respondWith(handleRevealRequest(request));
  }
});

function rawHtmlResponse(html) {
  const init = {
    headers: {
      "content-type": "text/html;charset=UTF-8",
      "x-xss-protection": "1; mode=block",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      // "content-security-policy": "default-src 'self'; style-src 'sha256-qaE5Qu2z+oPb8isnPXAK1xgiVQ36UNiNIdcPzcgYVTg=';"
    },
  };
  return new Response(html, init);
}

async function readRequestBody(request) {
  const { headers } = request;
  const contentType = headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    return JSON.stringify(await request.json());
  }
  else if (contentType.includes("application/text")) {
    return await request.text();
  }
  else if (contentType.includes("text/html")) {
    return await request.text();
  }
  else if (contentType.includes("form")) {
    const formData = await request.formData()
    const body = {};
    for (const entry of formData.entries()) {
      body[entry[0]] = entry[1]
    }
    return JSON.stringify(body);
  }
  else {
    const myBlob = await request.blob();
    const objectURL = URL.createObjectURL(myBlob);
    return objectURL;
  }
}

async function handleShareRequest(event) {

  const { request } = event;

  const reqBody = await readRequestBody(request);
  const reqBodyObj = JSON.parse(reqBody);

  let iv = new Uint8Array(12);
  await cryptoHelper.setRandomValues(iv);
  const hexStringIv = Array.from(iv, cryptoHelper.dec2hex).join('');

  let salt = new Uint8Array(16);
  await cryptoHelper.setRandomValues(salt);
  let hexStringSalt;

  const secureRandomStorageKey = cryptoHelper.generateRandomHexStringArray(RANDOM_URL_BYTE_LENGTH);

  if (reqBodyObj.expiry > 86401 && !reqBodyObj.secret) {
    return new Response('Invalid Request');
  }

  let encryptedData;

  // device pbkdf2 key instead and use password for encryption
  if (reqBodyObj.password === '') {
    encryptedData = await cryptoHelper.encrypt(reqBodyObj.secret, iv);
  } else {
    encryptedData = await cryptoHelper.encryptUsingPassword(reqBodyObj.password, reqBodyObj.secret, iv, salt);
    hexStringSalt = Array.from(salt, cryptoHelper.dec2hex).join('');
  }
  const respData = JSON.stringify({
    secret: encryptedData,
  });

  // Store the fetched response as cacheKey
  // Use waitUntil so computational expensive tasks don"t delay the response
  await SHHH.put(secureRandomStorageKey, respData, {
    expirationTtl: reqBodyObj.expiry,
    metadata: { hexStringIv, hexStringSalt, deleteOnRead: reqBodyObj.delete },
  });

  return rawHtmlResponse(html.buildSharePage(secureRandomStorageKey));
}

async function handleRevealRequest(request) {

  const revealURL = new URL(request.url);
  const pathSplit = revealURL.pathname.split('/');
  const secureKey = pathSplit[2];

  let { value, metadata } = await SHHH.getWithMetadata(secureKey, 'json');

  if (value === null || metadata === null || !value.secret) {
    return new Response(`URL is invalid or secret has expired`);
  }

  let decryptedData;
  const ivArray = cryptoHelper.fromHexString(metadata.hexStringIv);

  // prompt for password
  if (metadata.hexStringSalt && request.method === 'GET') {
    return rawHtmlResponse(html.buildRevealPage());
  }
  // standard AES encryption 
  else {
    try {
      //path contains salt eg. password derived key
      if (metadata.hexStringSalt && request.method === "POST") {

        const reqBody = await readRequestBody(request);
        const reqBodyObj = JSON.parse(reqBody);
        const saltArray = cryptoHelper.fromHexString(metadata.hexStringSalt);
        decryptedData = await cryptoHelper.decryptUsingPassword(reqBodyObj.password, value.secret, ivArray, saltArray);
      }
      // standard decryption using static AES key 
      else {
        decryptedData = await cryptoHelper.decrypt(value.secret, ivArray);
      }

      if (metadata.deleteOnRead === 'true') { await SHHH.delete(secureKey); }
      return new Response(decryptedData);

    } catch (e) {
      return new Response(e);
    }
  }
};