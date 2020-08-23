// https://developers.cloudflare.com/workers/examples/cache-api
// https://blog.cloudflare.com/introducing-the-workers-cache-api-giving-you-control-over-how-your-content-is-cached/
// https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode

let cache = caches.default;

function rawHtmlResponse(html) {
  const init = {
    headers: {
      "content-type": "text/html;charset=UTF-8",
    },
  }
  return new Response(html, init)
}

async function readRequestBody(request) {
  const { headers } = request
  const contentType = headers.get("content-type") || ""

  if (contentType.includes("application/json")) {
    return JSON.stringify(await request.json())
  }
  else if (contentType.includes("application/text")) {
    return await request.text()
  }
  else if (contentType.includes("text/html")) {
    return await request.text()
  }
  else if (contentType.includes("form")) {
    const formData = await request.formData()
    const body = {}
    for (const entry of formData.entries()) {
      body[entry[0]] = entry[1]
    }
    return JSON.stringify(body)
  }
  else {
    const myBlob = await request.blob()
    const objectURL = URL.createObjectURL(myBlob)
    return objectURL
  }
}

const passwordPrompt = `
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script>
function init(){
    let password = prompt("Please enter decryption password.");
    if(password){
        let form = document.getElementById("form");
        form.action = window.location.href;
        document.getElementById("password").value = password;
        form.submit();
    } else {
        document.getElementById("message").innerHTML = "Did Not Decrypt Secret";
    }
}
window.onload = function() {
    init();
};
</script>
</head>
<body>
<p id="message"></p>
<form style="display: none" action="" method="POST" id="form">
  <input type="hidden" id="password" name="password" value=""/>
</form>
</body>
</html>
`;

const revealForm = `
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>

textarea {
  width: 100%;
  resize: vertical;
  padding: 12px;
  border: 1px solid #ccc;
  border-radius: 4px;
  box-sizing: border-box;
  margin-top: 6px;
  margin-bottom: 16px;
}

.radios {
  padding: 12px;
  border: 1px solid #ccc;
  border-radius: 4px;
  box-sizing: border-box;
  margin-top: 6px;
  margin-bottom: 16px;
  width: fit-content;
}

input[type="radio"] {
  width: 10px;
  border: 1px solid #ccc;
  border-radius: 2px;
  box-sizing: border-box;
  margin-top: 10px;
}

input {
  width: 100%;
  padding: 12px;
  border: 1px solid #ccc;
  border-radius: 4px;
  box-sizing: border-box;
  margin-top: 6px;
  margin-bottom: 16px;
}

input[type=submit] {
  background-color: #4CAF50;
  color: white;
  font-size: 16px;
}
.container {
  background-color: #f1f1f1;
  padding: 20px;
}

</style>
</head>
<body>

<div class="container">

<h3>Secret Sharing</h3>

  <form action="share" method="POST">
    <label for="secret">Secret</label>
    
    <textarea id="secret" name="secret" rows="5" spellcheck="false" required></textarea>
    
    <label for="password">Encryption Password</label>
    <input type="password" id="password" name="password">
    
    <label for="radios">Expiry</label>
	  <div class="radios">

      <input id="radio1" type="radio" name="expiry" value="120" checked>
      <label for="radio1">2 Minutes</label><br>

      <input id="radio2" type="radio" name="expiry" value="900">
      <label for="radio2">15 Minutes</label><br>

      <input id="radio3" type="radio" name="expiry" value="86400">
      <label for="radio3">24 Hours</label><br>
    </div>
    <input type="submit" value="Share">
  </form>
</div>
</body>
</html>
`;

function dec2hex(dec) {
  return dec < 10 ? '0' + String(dec) : dec.toString(16)
}

const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const fromDecString = decStringArray =>
  new Uint8Array(decStringArray.split(',').map(byte => parseInt(byte, 16)));

function generateRandom(n) {
  let array = new Uint8Array(n);
  crypto.getRandomValues(array);
  return Array.from(array, dec2hex).join('');
}

async function handleShareRequest(event) {

  const { request } = event;
  const cacheUrl = new URL(request.url);

  const reqBody = await readRequestBody(request);
  const reqBodyObj = JSON.parse(reqBody);

  let iv = new Uint8Array(12);
  await crypto.getRandomValues(iv);
  const hexStringIv = Array.from(iv, dec2hex).join('');

  let salt = new Uint8Array(16);
  await crypto.getRandomValues(salt);
  const hexStringSalt = Array.from(salt, dec2hex).join('');

  let randomisedCacheUrl;

  if (reqBodyObj.password === '') {
    randomisedCacheUrl = `${cacheUrl.protocol}//${cacheUrl.host}/reveal/${generateRandom(16)}/${hexStringIv}`;
  } else {
    //requires salt for pbkdf2
    randomisedCacheUrl = `${cacheUrl.protocol}//${cacheUrl.host}/reveal/${generateRandom(16)}/${hexStringIv}/${hexStringSalt}`;
  }

  const keyArray = fromDecString(AES_KEY);
  const aesKey = await importAESKey(keyArray);

  if (reqBodyObj.expiry > 86401 && !reqBodyObj.secret) {
    return new Response('Invalid Request');
  }

  let response = await cache.match(randomisedCacheUrl)

  if (!response) {

    let encryptedData;

    // device pbkdf2 key instead and use password for encryption
    if (reqBodyObj.password === '') {
      encryptedData = await encrypt(reqBodyObj.secret, iv, aesKey);
    } else {
      encryptedData = await encryptFromPassword(reqBodyObj.password, reqBodyObj.secret, iv, salt);
    }
    const respData = JSON.stringify({
      secret: encryptedData,
    });

    response = new Response(respData);

    // Cache API respects Cache-Control headers. Setting max-age to 10
    // will limit the response to be in cache for 10 seconds max
    response.headers.append("Cache-Control", `max-age=${reqBody.expiry}`)

    // Store the fetched response as cacheKey
    // Use waitUntil so computational expensive tasks don"t delay the response
    event.waitUntil(cache.put(randomisedCacheUrl, response.clone()))

    const shareHtml = `
    <!DOCTYPE html>
    <html>
    <head>
    <style>

    input {
      width: 100%;
      padding: 12px;
      border: 1px solid #ccc;
      border-radius: 4px;
      box-sizing: border-box;
      margin-top: 6px;
      margin-bottom: 16px;
    }
    
    button {
      background-color: #4CAF50;
      color: white;
      font-size: 16px;
      width: 100%;
      padding: 12px;
      border: 1px solid #ccc;
      border-radius: 4px;
      box-sizing: border-box;
      margin-top: 6px;
      margin-bottom: 16px;
    }
    .container {
      background-color: #f1f1f1;
      padding: 20px;
    }
    
    </style>
    </head>
    <body class="container">
    <div>
    <input id="url" value="${randomisedCacheUrl}" size="128" readonly/>
    </div>
    <button onclick="clipboard()">Copy</button>
    <script>
    function clipboard() {
      var copyText = document.getElementById("url");
      copyText.select();
      copyText.setSelectionRange(0, 99999)
      document.execCommand("copy");
      alert("Copied URL");
    }
    </script>
    </body>
    </html>
    `;
    return rawHtmlResponse(shareHtml);

  } else {
    return new Response('This secret is stored please use the /reveal endpoint to consume it');
  }
}

async function handleRevealRequest(request) {

  const revealURL = new URL(request.url);
  let response = await cache.match(revealURL);

  if (!response) {
    return new Response('URL is invalid or secret has expired from cache');
  } else {

    let decryptedData;

    const pathSplit = revealURL.pathname.split('/');
    const ivArray = fromHexString(pathSplit[3]);

    // Prompt for PW
    if (pathSplit[4] && request.method === "GET") {
      return rawHtmlResponse(passwordPrompt);
    } else {

      try {
        //path contains salt eg. password derived key
        if (pathSplit[4] && request.method === "POST") {

          const reqBody = await readRequestBody(request);
          const reqBodyObj = JSON.parse(reqBody);

          const saltArray = fromHexString(pathSplit[4]);
          const toDecrypt = await response.json();
          decryptedData = await decryptFromPassword(reqBodyObj.password, toDecrypt.secret, ivArray, saltArray);

          // Prevent multiple reads (Could possibly configure this to n reads)
          cache.delete(cacheUrl);
          return new Response(decryptedData);

        } else {
          const key = fromDecString(AES_KEY);
          const aesKey = await importAESKey(key);
          const toDecrypt = await response.json();
          decryptedData = await decrypt(toDecrypt.secret, ivArray, aesKey);

          // Prevent multiple reads (Could possibly configure this to n reads)
          cache.delete(cacheUrl);
          return new Response(decryptedData);
        }

      } catch (e) {
        return new Response('Revealing Secret Failed');
      }
    }
  }
};

addEventListener("fetch", event => {
  const { request } = event
  const { url } = request

  if (request.method === "GET") {
    if (url.includes("/reveal")) {
      return event.respondWith(handleRevealRequest(request))
    } else {
      return event.respondWith(rawHtmlResponse(revealForm))
    }

  } else if (request.method === "POST" && url.includes("/share")) {
    return event.respondWith(handleShareRequest(event));
  } else if (request.method === "POST" && url.includes("/reveal")) {
    return event.respondWith(handleRevealRequest(request));
  }
});

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
}

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

async function decryptFromPassword(password, data, iv, salt) {
  const keyMaterial = await passwordToKeyMaterial(password);
  const key = await deriveKeyFromKeyMaterial(keyMaterial, salt, 10000);
  return decrypt(data, iv, key);
}

async function importAESKey(raw) {
  return crypto.subtle.importKey(
    "raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );
}

function base64ToArrayBuffer(data) {
  const characters = atob(data);
  let array = new Uint8Array(characters.length);
  for (var i = 0; i < characters.length; i++) {
    array[i] = characters.charCodeAt(i);
  }
  return new Uint8Array(array);
}