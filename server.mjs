import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import handler from './lib/app.mjs';
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'};
http.createServer(async(req,res)=>{if(req.url.startsWith('/api/'))return handler(req,res);try{const pathname=new URL(req.url,'http://localhost').pathname;const file=path.resolve('public',pathname==='/'?'index.html':'.'+pathname);if(!file.startsWith(path.resolve('public')+path.sep))throw Error();res.setHeader('Content-Type',types[path.extname(file)]||'application/octet-stream');res.setHeader('X-Content-Type-Options','nosniff');res.end(await fs.readFile(file));}catch{res.statusCode=404;res.end('Not found');}}).listen(process.env.PORT||3000,()=>console.log('http://localhost:'+(process.env.PORT||3000)));
