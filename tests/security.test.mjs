import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {chromium} from '@playwright/test';
import chromiumBinary from '@sparticuz/chromium';
import {createClient} from '@libsql/client';
test('실제 WebAuthn 가상 인증기로 등록·서명·격리·삭제·세션 검사',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'t08-'));const dburl='file:'+path.join(dir,'test.db');
 const server=spawn(process.execPath,['server.mjs'],{env:{...process.env,TURSO_DATABASE_URL:dburl,TURSO_AUTH_TOKEN:'',APP_ORIGIN:'http://localhost:3000',RP_ID:'localhost'},stdio:'pipe'});
 let stderr='';server.stderr.on('data',d=>stderr+=d);const records=[];
 let browser;
 try{
 await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('exit',()=>reject(Error(stderr)));});
 browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH||await chromiumBinary.executablePath(),args:chromiumBinary.args.filter(a=>a!=="--disable-web-security")});
 const context=await browser.newContext();const page=await context.newPage();const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 const add=()=>cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const keyA=await add();await page.goto('http://localhost:3000');
 async function request(route,method='GET',body){const r=await page.evaluate(async({route,method,body})=>{const r=await fetch('/api'+route,{method,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});return {status:r.status,body:await r.json()};},{route,method,body});records.push({route,method,request:body||{},...r});return r;}
 const expectStatus=(r,status)=>assert.equal(r.status,status,JSON.stringify(r));
 const original=await fs.readFile('public/index.html','utf8');assert.ok(original.includes('관심 분야'));assert.ok(!original.includes('가상 기록 1.'));
 expectStatus(await request('/notes'),401);await page.screenshot({path:'evidence/virtual-public-locked.png',fullPage:true});
 const cancelled=await request('/register/options','POST',{username:'cancelled',name:'취소',storage:'기기 자체'});expectStatus(cancelled,200);expectStatus(await request('/register/cancel','POST',{ceremonyId:cancelled.body.ceremonyId}),200);
 const db=createClient({url:dburl});assert.equal(Number((await db.execute("SELECT COUNT(*) AS n FROM users WHERE username='cancelled'")).rows[0].n),0);
 async function register(username,name){const opt=await request('/register/options','POST',{username,name,storage:'기기 자체'});expectStatus(opt,200);const response=await page.evaluate(o=>SimpleWebAuthnBrowser.startRegistration({optionsJSON:o}),opt.body.options);const verify=await request('/register/verify','POST',{ceremonyId:opt.body.ceremonyId,response});expectStatus(verify,200);return {id:response.id,opt};}
 async function login(username,override={},tamper=false){const opt=await request('/login/options','POST',{username});expectStatus(opt,200);let response=await page.evaluate(o=>SimpleWebAuthnBrowser.startAuthentication({optionsJSON:o}),{...opt.body.options,...override});if(tamper){const bytes=Buffer.from(response.response.signature,'base64url');bytes[bytes.length-1]^=1;response.response.signature=bytes.toString('base64url');}const payload={ceremonyId:opt.body.ceremonyId,response};return {r:await request('/login/verify','POST',payload),payload,opt};}
 const a=await register('account-a','첫 번째 키');const am=(await request('/me')).body;const an=(await request('/notes')).body;assert.equal(an.count,3);
 const first=(await cdp.send('WebAuthn.getCredentials',{authenticatorId:keyA.authenticatorId})).credentials[0];
 await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:keyA.authenticatorId});const keyA2=await add();const a2=await register('account-a','두 번째 키');assert.notEqual(a.opt.body.options.challenge,a2.opt.body.options.challenge);assert.equal((await request('/passkeys')).body.passkeys.length,2);await page.reload();await page.waitForSelector('#vault-keys article:nth-child(2)');await page.locator('#vault-keys').screenshot({path:'evidence/virtual-two-passkeys.png'});
 expectStatus(await request('/logout','POST',{}),200);const good=await login('account-a');expectStatus(good.r,200);expectStatus(await request('/login/verify','POST',good.payload),400);
 const bad=await login('account-a',{},true);expectStatus(bad.r,400);assert.notEqual(good.opt.body.options.challenge,bad.opt.body.options.challenge);
 const beforeDelete=await context.cookies();const oldCookie=beforeDelete.find(c=>c.name==='t08_session').value;expectStatus(await request('/logout','POST',{}),200);
 const oldRes=await fetch('http://localhost:3000/api/notes',{headers:{Cookie:'t08_session='+oldCookie}});assert.equal(oldRes.status,401);records.push({route:'/notes',method:'GET',request:{Cookie:'t08_session=[가림]'},status:oldRes.status,body:await oldRes.json(),test:'로그아웃 전 세션 재요청'});
 await context.addCookies([{name:'t08_session',value:oldCookie,url:'http://localhost:3000'}]);expectStatus(await request('/notes'),401);await context.clearCookies();
 const good2=await login('account-a');expectStatus(good2.r,200);expectStatus(await request('/passkeys/'+encodeURIComponent(a.id),'DELETE'),200);assert.equal((await request('/passkeys')).body.passkeys.length,1);expectStatus(await request('/passkeys/'+encodeURIComponent(a2.id),'DELETE'),409);
 expectStatus(await request('/logout','POST',{}),200);expectStatus((await login('account-a')).r,200);
 // Restore the deleted real credential inside the virtual authenticator to sign a fresh challenge.
 globalThis.a2Credential=(await cdp.send('WebAuthn.getCredentials',{authenticatorId:keyA2.authenticatorId})).credentials[0];await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:keyA2.authenticatorId});const oldKey=await add();await cdp.send('WebAuthn.addCredential',{authenticatorId:oldKey.authenticatorId,credential:first});expectStatus((await login('account-a',{allowCredentials:[{id:a.id,type:'public-key',transports:['internal']}]})).r,400);
 await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:oldKey.authenticatorId});
 expectStatus(await request('/logout','POST',{}),200);
 const keyB=await add();const b=await register('account-b','B 키');const bm=(await request('/me')).body,bn=(await request('/notes')).body;assert.equal(bn.count,3);assert.notEqual(an.notes[0].body,bn.notes[0].body);
 expectStatus(await request('/notes/'+an.notes[0].id),403);const forgedB=await request('/notes/query','POST',{userId:am.userId,owner_id:am.userId});assert.equal(forgedB.body.owner,bm.userId);assert.equal(forgedB.body.notes.length,3);
 expectStatus(await request('/passkeys/'+a2.id,'DELETE'),403);
 expectStatus(await request('/logout','POST',{}),200);
 const credsB=(await cdp.send('WebAuthn.getCredentials',{authenticatorId:keyB.authenticatorId})).credentials;await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:keyB.authenticatorId});const kAr=await add();
 const savedA=(await db.execute({sql:'SELECT id FROM credentials WHERE id=?',args:[a2.id]})).rows[0];assert.ok(savedA);
 // A2 is available from its original CDP snapshot saved before removal below.
 // Use first A (deleted) only for a foreign-account credential refusal; then restore A2 for valid A login.
 await cdp.send('WebAuthn.addCredential',{authenticatorId:kAr.authenticatorId,credential:globalThis.a2Credential});
 const wrong=await login('account-b',{allowCredentials:[{id:a2.id,type:'public-key',transports:['internal']}]});expectStatus(wrong.r,400);
 expectStatus((await login('account-a')).r,200);expectStatus(await request('/notes/'+bn.notes[0].id),403);
 const forgedA=await request('/notes?userId='+bm.userId);assert.equal(forgedA.body.owner,am.userId);assert.equal(forgedA.body.count,3);
 assert.equal(Number((await db.execute({sql:'SELECT COUNT(*) AS n FROM notes WHERE user_id=?',args:[bm.userId]})).rows[0].n),bn.count);assert.equal(Number((await db.execute({sql:'SELECT COUNT(*) AS n FROM notes WHERE user_id=?',args:[am.userId]})).rows[0].n),an.count);
 const csrf=await fetch('http://localhost:3000/api/logout',{method:'POST',headers:{Origin:'https://evil.invalid','Content-Type':'application/json'},body:'{}'});assert.equal(csrf.status,403);
 await page.reload();await page.waitForSelector('#vault-open:not([hidden])');await page.screenshot({path:'evidence/virtual-authenticator-screen.png',fullPage:true});
 await fs.writeFile('evidence/automated-requests.json',JSON.stringify({environment:'Chromium CDP 가상 인증기. 실제 기기 검사는 별도 필요.',passed:true,checks:['공개 원문 유지','미인증 401','취소 미저장','등록 질문 차이','공개키 저장','두 키 등록','서명 성공·실패','로그인 질문 차이','질문 재사용 거절','로그아웃 기존 세션 401','삭제 뒤 남은 키 로그인','삭제 키 거절','마지막 키 보호','두 계정 서로 다른 가상 자료','양방향 자료 조회 403','양방향 계정 변조 무시','자료 건수 불변','다른 계정 키 삭제 거절','다른 계정 패스키 거절','다른 Origin 거절'],records},null,2));db.close();
 }finally{if(browser)await browser.close();server.kill();await fs.rm(dir,{recursive:true,force:true});}
});
