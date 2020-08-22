// https://developers.cloudflare.com/workers/examples/cache-api
//https://blog.cloudflare.com/introducing-the-workers-cache-api-giving-you-control-over-how-your-content-is-cached/

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

const someForm = `
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
    
    <textarea id="secret" name="secret" rows="5" required></textarea>
    
    <label for="password">Password</label>
    <input type="password" id="password" name="password">
    
    <label for="radios">Expiry</label>
	  <div class="radios">

      <input id=120 type="radio" name="expiry" value="120">
      <label for="120">2 Minutes</label><br>

      <input id=900 type="radio" name="expiry" value="900">
      <label for="120">15 Minutes</label><br>

      <input id=86400 type="radio" name="expiry" value="86400">
      <label for="120">24 Hours</label><br>
    </div>
    <input type="submit" value="Share">
  </form>
</div>
</body>
</html>
`;

function dec2hex (dec) {
  return dec < 10
    ? '0' + String(dec)
    : dec.toString(16)
}

function generateRandom(){
  let array = new Uint32Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, dec2hex).join('');
}

async function handleShareRequest(event) {

  const { request } = event;

  const cacheUrl = new URL(request.url)
  const randomisedCacheUrl = `https://polished-term-6b3e.boost.workers.dev/reveal/${generateRandom()}`;

  const reqBody = await readRequestBody(request);

  if(reqBody.expiry > 86401 && !reqBody.secret){
    return new Response('Invalid Request');
  }

  let response = await cache.match(randomisedCacheUrl)

  if (!response) {

    response = new Response(reqBody);

    // Cache API respects Cache-Control headers. Setting max-age to 10
    // will limit the response to be in cache for 10 seconds max
    response.headers.append("Cache-Control", `max-age=${reqBody.expiry}`)

    // Store the fetched response as cacheKey
    // Use waitUntil so computational expensive tasks don"t delay the response
    event.waitUntil(cache.put(randomisedCacheUrl, response.clone()))

    const shareHtml =`
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

  const cacheUrl = new URL(request.url);
  let response = await cache.match(cacheUrl);

  if (!response) {
    return new Response('URL is invalid or secret has expired from cache');
  } else {
    let jsonBody = await response.json();

    // Prevent multiple reads (Could possibly configure this to n reads)
    cache.delete(cacheUrl);

    return new Response(jsonBody.secret);
  }
};

addEventListener("fetch", event => {
  const { request } = event
  const { url } = request

  if (request.method === "GET") {
    if(url.includes("/reveal")){
      return event.respondWith(handleRevealRequest(request))
    } else {
      return event.respondWith(rawHtmlResponse(someForm))
    }

  } else if (request.method === "POST" && url.includes("/share")) {
    return event.respondWith(handleShareRequest(event));
  }
});