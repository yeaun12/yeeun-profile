import crypto from 'node:crypto';
import {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {db,init,sql} from './db.mjs';
export const origin=process.env.APP_ORIGIN||'http://localhost:3000';
export const rpID=process.env.RP_ID||new URL(origin).hostname;
const secure=origin.startsWith('https:');
const random=()=>crypto.randomBytes(32).toString('base64url');
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
const cookie=(key,value,age)=>`${key}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${secure?'; Secure':''}`;
class HTTPError extends Error {constructor(status,message){super(message);this.status=status;}}
const fail=(status,msg)=>{throw new HTTPError(status,msg)};
const parseCookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').filter(x=>x.includes('=')).map(x=>{const i=x.indexOf('=');return [x.slice(0,i).trim(),x.slice(i+1)]}));
const clean=(v,max=80)=>typeof v==='string'&&v.length<=max?v.trim():'';
async function audit(user,action,status,detail){if(user)await sql('INSERT INTO audit(user_id,at,action,status,detail) VALUES(?,?,?,?,?)',[user,Date.now(),action,status,JSON.stringify(detail)]);}
async function session(req){const c=parseCookies(req),t=c.t08_session;if(!t)return null;return (await sql('SELECT s.*,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=? AND s.expires_at>?',[hash(t),Date.now()])).rows[0]||null;}
async function must(req){const s=await session(req);if(!s)fail(401,'패스키 로그인이 필요합니다.');return s;}
async function issueSession(res,user,key){const token=random();await sql('INSERT INTO sessions(hash,user_id,credential_id,expires_at) VALUES(?,?,?,?)',[hash(token),user,key,Date.now()+3600000]);res.setHeader('Set-Cookie',cookie('t08_session',token,3600));}
async function challenge(req,res,kind,value,payload){let binding=parseCookies(req).t08_binding;if(!binding||!/^[\w-]{43}$/.test(binding)){binding=random();res.setHeader('Set-Cookie',cookie('t08_binding',binding,600));}const id=random();await sql('DELETE FROM challenges WHERE expires_at<?',[Date.now()]);await sql('INSERT INTO challenges(id,binding,kind,value,payload,expires_at) VALUES(?,?,?,?,?,?)',[id,hash(binding),kind,value,JSON.stringify(payload),Date.now()+120000]);return id;}
async function consume(req,id,kind){const binding=parseCookies(req).t08_binding;if(!binding)fail(400,'질문이 만료되었거나 이미 사용되었습니다.');const row=(await sql('DELETE FROM challenges WHERE id=? AND binding=? AND kind=? AND expires_at>? RETURNING *',[clean(id),hash(binding),kind,Date.now()])).rows[0];if(!row)fail(400,'질문이 만료되었거나 이미 사용되었습니다.');return {...row,payload:JSON.parse(row.payload)};}
async function body(req){if(req.body&&typeof req.body==='object')return req.body;if(typeof req.body==='string'){try{return JSON.parse(req.body)}catch{fail(400,'올바른 JSON을 보내세요.')}}let text='';for await(const c of req){text+=c;if(Buffer.byteLength(text)>65536)fail(413,'요청이 너무 큽니다.');}try{return text?JSON.parse(text):{}}catch{fail(400,'올바른 JSON을 보내세요.')}}
function send(res,status,value){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(value));}
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 let actor=null;
 try{
 await init();const url=new URL(req.url,origin),route=url.pathname.replace(/^\/api/,'');const method=req.method;
 if(method!=='GET'&&req.headers.origin!==origin)fail(403,'허용되지 않은 출처의 요청입니다.');
 const b=method==='GET'?{}:await body(req);
 if(route==='/register/options'&&method==='POST'){
 const s=await session(req);const username=s?.username||clean(b.username,32);
 if(!/^[a-zA-Z0-9_-]{3,32}$/.test(username))fail(400,'계정 이름은 영문·숫자·밑줄·하이픈 3~32자로 입력하세요.');
 if(!s&&(await sql('SELECT id FROM users WHERE username=?',[username])).rows.length)fail(409,'이미 등록된 계정입니다. 기존 패스키로 로그인하세요.');
 const name=clean(b.name),storage=clean(b.storage);
 if(!name||!['구글 비밀번호 관리자','기기 자체','보안 키','기타 비밀번호 관리자'].includes(storage))fail(400,'패스키 이름과 저장 위치를 선택하세요.');
 const uid=s?.user_id||crypto.randomUUID();const keys=(await sql('SELECT id,transports FROM credentials WHERE user_id=?',[uid])).rows;
 const options=await generateRegistrationOptions({rpName:'예은의 비공개 기록',rpID,userName:username,userID:new TextEncoder().encode(uid),attestationType:'none',supportedAlgorithmIDs:[-7,-257],excludeCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)})),authenticatorSelection:{residentKey:'required',userVerification:'required'}});
 const ceremonyId=await challenge(req,res,'register',options.challenge,{uid,username,name,storage,existing:!!s});
 return send(res,200,{options,ceremonyId});}
 if(route==='/register/verify'&&method==='POST'){
 const c=await consume(req,b.ceremonyId,'register'),p=c.payload;actor=p.uid;
 if(p.existing){const s=await must(req);if(s.user_id!==p.uid)fail(403,'등록 계정이 일치하지 않습니다.');}
 let result;try{result=await verifyRegistrationResponse({response:b.response,expectedChallenge:c.value,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true});}catch{await audit(actor,'register',400,{reason:'verification_failed'});fail(400,'패스키 등록 검증에 실패했습니다.');}
 if(!result.verified)fail(400,'패스키 등록 검증에 실패했습니다.');
 const k=result.registrationInfo.credential;const statements=[];
 if(!p.existing){statements.push({sql:'INSERT INTO users(id,username,created_at) VALUES(?,?,?)',args:[p.uid,p.username,Date.now()]});for(let i=1;i<=3;i++)statements.push({sql:'INSERT INTO notes(id,user_id,title,body) VALUES(?,?,?,?)',args:[crypto.randomUUID(),p.uid,['프로젝트 메모','지원 준비 목록','학습 회고'][i-1],`${p.username}의 가상 기록 ${i}. 과제 확인용으로 만든 내용입니다.`]});}
 statements.push({sql:'INSERT INTO credentials(id,user_id,public_key,counter,transports,name,storage,created_at) VALUES(?,?,?,?,?,?,?,?)',args:[k.id,p.uid,Buffer.from(k.publicKey).toString('base64url'),k.counter,JSON.stringify(k.transports||[]),p.name,p.storage,Date.now()]});
 await db.batch(statements,'write');await issueSession(res,p.uid,k.id);await audit(actor,'register',200,{credentialId:k.id,publicKey:Buffer.from(k.publicKey).toString('base64url'),storage:p.storage});return send(res,200,{ok:true,publicKey:Buffer.from(k.publicKey).toString('base64url'),note:'COSE 공개키입니다. 개인키와 비밀번호는 서버에 저장하지 않습니다.'});}
 if(route==='/register/cancel'&&method==='POST'){await sql('DELETE FROM challenges WHERE id=? AND binding=? AND kind=?',[clean(b.ceremonyId),hash(parseCookies(req).t08_binding||''),'register']);return send(res,200,{ok:true,saved:false});}
 if(route==='/login/options'&&method==='POST'){
 const username=clean(b.username,32);const user=(await sql('SELECT id FROM users WHERE username=?',[username])).rows[0];if(!user)fail(400,'등록된 패스키로 로그인할 수 없습니다.');
 const keys=(await sql('SELECT id,transports FROM credentials WHERE user_id=?',[user.id])).rows;if(!keys.length)fail(400,'등록된 패스키가 없습니다.');
 const options=await generateAuthenticationOptions({rpID,userVerification:'required',allowCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});const ceremonyId=await challenge(req,res,'login',options.challenge,{uid:user.id});return send(res,200,{options,ceremonyId});}
 if(route==='/login/verify'&&method==='POST'){
 const c=await consume(req,b.ceremonyId,'login');actor=c.payload.uid;
 const k=(await sql('SELECT * FROM credentials WHERE id=? AND user_id=?',[clean(b.response?.id,1024),actor])).rows[0];if(!k){await audit(actor,'login',400,{reason:'credential_missing'});fail(400,'등록된 패스키로 로그인할 수 없습니다.');}
 let result;try{result=await verifyAuthenticationResponse({response:b.response,expectedChallenge:c.value,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true,credential:{id:k.id,publicKey:new Uint8Array(Buffer.from(k.public_key,'base64url')),counter:Number(k.counter),transports:JSON.parse(k.transports)}});}catch{await audit(actor,'login',400,{reason:'signature_failed'});fail(400,'패스키 서명 검증에 실패했습니다.');}
 if(!result.verified)fail(400,'패스키 서명 검증에 실패했습니다.');await sql('UPDATE credentials SET counter=? WHERE id=?',[result.authenticationInfo.newCounter,k.id]);await issueSession(res,actor,k.id);await audit(actor,'login',200,{credentialId:k.id});return send(res,200,{ok:true});}
 if(route==='/logout'&&method==='POST'){const t=parseCookies(req).t08_session;if(t)await sql('DELETE FROM sessions WHERE hash=?',[hash(t)]);res.setHeader('Set-Cookie',cookie('t08_session','',0));return send(res,200,{ok:true});}
 if(route==='/me'&&method==='GET'){const s=await must(req);return send(res,200,{username:s.username,userId:s.user_id,session:'HttpOnly 세션 쿠키, 서버에는 SHA-256 해시만 저장, 1시간 만료'});}
 const s=await must(req);actor=s.user_id;
 if(route==='/notes'&&method==='GET'){const rows=(await sql('SELECT id,title,body FROM notes WHERE user_id=? ORDER BY id',[actor])).rows;return send(res,200,{notes:rows,count:rows.length,owner:actor});}
 if(route.startsWith('/notes/')&&method==='GET'){const n=(await sql('SELECT id,title,body FROM notes WHERE id=? AND user_id=?',[decodeURIComponent(route.slice(7)),actor])).rows[0];if(!n){await audit(actor,'foreign_note',403,{noteId:route.slice(7)});fail(403,'이 자료에 접근할 권한이 없습니다.');}return send(res,200,{note:n});}
 if(route==='/notes/query'&&method==='POST'){return send(res,200,{notes:(await sql('SELECT id,title,body FROM notes WHERE user_id=?',[actor])).rows,owner:actor});}
 if(route==='/passkeys'&&method==='GET'){return send(res,200,{passkeys:(await sql('SELECT id,name,storage,created_at,public_key FROM credentials WHERE user_id=? ORDER BY created_at',[actor])).rows,lastKeyPolicy:'마지막 패스키는 삭제할 수 없습니다. 모든 기기·저장소를 잃으면 복구할 수 없으며 비밀번호 우회 복구는 제공하지 않습니다.'});}
 if(route.startsWith('/passkeys/')&&method==='DELETE'){
 const id=decodeURIComponent(route.slice(10));const result=await sql('DELETE FROM credentials WHERE id=? AND user_id=? AND (SELECT COUNT(*) FROM credentials WHERE user_id=?)>1 RETURNING id',[id,actor,actor]);
 if(!result.rows.length){const own=(await sql('SELECT id FROM credentials WHERE id=? AND user_id=?',[id,actor])).rows.length;fail(own?409:403,own?'마지막 패스키는 삭제할 수 없습니다. 먼저 다른 패스키를 등록하세요.':'이 패스키를 삭제할 권한이 없습니다.');}
 await sql('DELETE FROM sessions WHERE credential_id=?',[id]);await audit(actor,'delete_passkey',200,{credentialId:id});return send(res,200,{ok:true});}
 if(route==='/evidence'&&method==='GET'){return send(res,200,{audit:(await sql('SELECT at,action,status,detail FROM audit WHERE user_id=? ORDER BY id',[actor])).rows});}
 fail(404,'없는 경로입니다.');
 }catch(e){if(!(e instanceof HTTPError))console.error('API error:',e.code||e.name);return send(res,e.status||500,{error:e.status?e.message:'서버 처리에 실패했습니다. 설정과 연결 상태를 확인하세요.'});}
}
