// https://developers.cloudflare.com/workers/examples/cache-api
// https://blog.cloudflare.com/introducing-the-workers-cache-api-giving-you-control-over-how-your-content-is-cached/
// https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
// https://support.cloudflare.com/hc/en-us/articles/200172516-Understanding-Cloudflare-s-CDN

import * as cryptoHelper from './crypto.js';
import * as html from './html.js';
import pkg from './package.json';

addEventListener("fetch", event => {
  const { request } = event;
  const { url } = request;

  if (request.method === "GET") {
    if (url.includes("/reveal")) {
      return event.respondWith(handleRevealRequest(request))
    } else {
      return event.respondWith(rawHtmlResponse(html.buildMainPage(pkg.version)))
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
  const cacheUrl = new URL(request.url);

  const reqBody = await readRequestBody(request);
  const reqBodyObj = JSON.parse(reqBody);

  const deleteOnRead = true;

  let iv = new Uint8Array(12);
  await crypto.getRandomValues(iv);
  const hexStringIv = Array.from(iv, cryptoHelper.dec2hex).join('');

  let salt = new Uint8Array(16);
  await crypto.getRandomValues(salt);
  const hexStringSalt = Array.from(salt, cryptoHelper.dec2hex).join('');

  let randomisedCacheUrl;

  if (reqBodyObj.password === '') {
    randomisedCacheUrl = `${cacheUrl.protocol}//${cacheUrl.host}/reveal/${cryptoHelper.generateRandom(16)}/${hexStringIv}`;
  } else {
    //requires salt for pbkdf2
    randomisedCacheUrl = `${cacheUrl.protocol}//${cacheUrl.host}/reveal/${cryptoHelper.generateRandom(16)}/${hexStringIv}/${hexStringSalt}`;
  }

  const keyArray = cryptoHelper.fromDecString(AES_KEY);
  const aesKey = await cryptoHelper.importAESKey(keyArray);

  if (reqBodyObj.expiry > 86401 && !reqBodyObj.secret) {
    return new Response('Invalid Request');
  }

  let encryptedData;

  // device pbkdf2 key instead and use password for encryption
  if (reqBodyObj.password === '') {
    encryptedData = await cryptoHelper.encrypt(reqBodyObj.secret, iv, aesKey);
  } else {
    encryptedData = await cryptoHelper.encryptFromPassword(reqBodyObj.password, reqBodyObj.secret, iv, salt);
  }
  const respData = JSON.stringify({
    secret: encryptedData,
  });

  const meta = JSON.stringify({hexStringIv, hexStringSalt, deleteOnRead });

  // Store the fetched response as cacheKey
  // Use waitUntil so computational expensive tasks don"t delay the response
  await SHHH.put(randomisedCacheUrl, respData, { 
    expirationTtl: reqBodyObj.expiry,
    metadata: meta
  });

  return rawHtmlResponse(html.buildSharePage(randomisedCacheUrl));
}

async function handleRevealRequest(request) {

  const revealURL = new URL(request.url);
  let response = await SHHH.get(revealURL, 'json');

  if (response === null || !response.secret) {
    return new Response(`URL is invalid or secret has expired`);
  } else {

    let decryptedData;

    const pathSplit = revealURL.pathname.split('/');
    const ivArray = cryptoHelper.fromHexString(pathSplit[3]);

    // Prompt for PW
    if (pathSplit[4] && request.method === "GET") {
      return rawHtmlResponse(html.buildRevealPage());
    } else {

      try {
        //path contains salt eg. password derived key
        if (pathSplit[4] && request.method === "POST") {

          const reqBody = await readRequestBody(request);
          const reqBodyObj = JSON.parse(reqBody);

          const saltArray = cryptoHelper.fromHexString(pathSplit[4]);
          decryptedData = await cryptoHelper.decryptFromPassword(reqBodyObj.password, response.secret, ivArray, saltArray);

          // if (metadata.deleteOnRead) {
          //   await NAMESPACE.delete(revealURL);
          // }
          return new Response(decryptedData);

        } else {
          const key = cryptoHelper.fromDecString(AES_KEY);
          const aesKey = await cryptoHelper.importAESKey(key);
          decryptedData = await cryptoHelper.decrypt(response.secret, ivArray, aesKey);

          // Prevent multiple reads (Could possibly configure this to n reads)
          // if (metadata.deleteOnRead) {
          //   await NAMESPACE.delete(revealURL);
          // }

          return new Response(decryptedData);
        }

      } catch (e) {
        return new Response(e);
      }
    }
  }
};