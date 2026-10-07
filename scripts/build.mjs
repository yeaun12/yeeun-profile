import fs from 'node:fs/promises';
await fs.mkdir('public/vendor',{recursive:true});
await fs.copyFile('node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js','public/vendor/webauthn.js');
let source=await fs.readFile('public/index.html','utf8');
if(!source.includes('id="vault-title"')){
 source=source.replace('</head>','<link rel="stylesheet" href="/private.css"></head>');
 source=source.replace('<footer class="footer">',(await fs.readFile('public/private-section.html','utf8'))+'<footer class="footer">');
 source=source.replace('</body>','<script src="/vendor/webauthn.js"></script><script type="module" src="/private.js"></script></body>');
 await fs.writeFile('public/index.html',source);
}
