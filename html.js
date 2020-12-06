import pkg from './package.json';

const buildHTML = (style, script, body) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>${style || ''}</style>
    <script>${script}</script>
    </head>
    <body>${body}
    
    <footer>
    <p hidden>${pkg.name}:${pkg.version}</p>
    </footer>
    </body>
    </html>
  `;
};

const buildMainPage = () => {

  const mainPageStyle = `
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

    input[type="checkbox"] {
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

    footer {
      font-size: 9px;
    }

    .container {
      background-color: #f1f1f1;
      padding: 20px;
    }
  `;

  const mainHtml = `
    <div class="container">

    <h3>Secret Sharing</h3>

      <form action="share" method="POST">
        <label for="secret">Secret</label>
        
        <textarea id="secret" name="secret" rows="5" spellcheck="false" required></textarea>
        
        <label for="password">Encryption Password</label>
        <input type="password" id="password" name="password" pattern=".{8,}" minlength="8" title="8 characters minimum">
        
        <label for="radios">Expiry</label>
        <div class="radios">

          <input id="radio1" type="radio" name="expiry" value="120" checked>
          <label for="radio1">2 Minutes</label><br>

          <input id="radio2" type="radio" name="expiry" value="900">
          <label for="radio2">15 Minutes</label><br>

          <input id="radio3" type="radio" name="expiry" value="86400">
          <label for="radio3">24 Hours</label><br>

          <input id="tickbox" type="checkbox" name="delete" checked="checked">
          <label for="tickbox">Delete after read</label><br>

        </div>
        <input type="submit" value="Share">
      </form>
    </div>
  `;

  return buildHTML(mainPageStyle, '', mainHtml);
};

const buildSharePage = (secureRandomStorageKey) => {

  const shareHtmlStyle = `
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
  `;

  const shareHtmlBody = `
    <body class="container">
    <div>
    <input id="url" value="https://shhh.benedridge.com/reveal/${secureRandomStorageKey}" size="128" readonly/>
    </div>
    <button onclick="clipboard()">Copy</button>
    <script>
    function clipboard() {
      var copyText = document.getElementById("url");
      copyText.select();
      copyText.setSelectionRange(0, 99999);
      document.execCommand("copy");
      alert("Copied URL");
    }
    </script>
  `;

  return buildHTML(shareHtmlStyle, '', shareHtmlBody);
};

const buildRevealPage = () => {

  const passwordPromptScript = `
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
  `;

  const passwordPromptHtml = `
    <p id="message"></p>
    <form style="display: none" action="" method="POST" id="form">
      <input type="hidden" id="password" name="password" value=""/>
    </form>
  `;

  return buildHTML('', passwordPromptScript, passwordPromptHtml);
};

export {
  buildMainPage,
  buildSharePage,
  buildRevealPage
};