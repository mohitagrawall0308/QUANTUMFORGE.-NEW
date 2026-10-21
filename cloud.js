/* QuantumForge cloud bridge
 * - Talks to Supabase through its REST API (no SDK needed).
 * - End-to-end encryption: every message gets a fresh AES-256-GCM key; that key is
 *   wrapped with the recipient's RSA-OAEP public key (and the sender's, so the sender
 *   can re-read their Sent items). The cloud only ever stores ciphertext.
 * - Each account has an RSA keypair. The public half is published to `profiles`;
 *   the private half stays in this browser's IndexedDB as a NON-extractable key.
 * The publishable key below is designed to be public; access is limited by the
 * Row Level Security policies in schema.sql.
 */
(()=>{
 const CFG={
  url:'https://csrsvkgzmpuhkgxnrors.supabase.co',
  key:'sb_publishable_1eV7ITcSIHBB1RoIf3pzPQ_Royci4_K'
 };
 const SESSION='qf-local-session-v1';
 const te=new TextEncoder(),td=new TextDecoder();
 const b64=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s)};
 const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 const S={status:'idle',detail:'',user:null,identity:null,run:0};

 /* ---------- Supabase REST ---------- */
 async function api(path,{method='GET',body,prefer}={}){
  const headers={apikey:CFG.key};
  if(body)headers['Content-Type']='application/json';
  if(prefer)headers.Prefer=prefer;
  let r;
  try{r=await fetch(CFG.url+'/rest/v1/'+path,{method,headers,body:body?JSON.stringify(body):undefined})}
  catch{const e=new Error('Cannot reach the cloud. Check your internet connection and try again.');e.offline=true;throw e}
  const text=await r.text();let j=null;try{j=text?JSON.parse(text):null}catch{}
  if(!r.ok){
   const e=new Error((j&&j.message)||text||'Cloud error '+r.status);e.status=r.status;e.code=j&&j.code;
   if(r.status===404||e.code==='PGRST205'||e.code==='42P01'){e.setup=true;e.message='The cloud tables are not set up yet. Run schema.sql once in the Supabase SQL editor.'}
   throw e;
  }
  return j;
 }

 /* ---------- Local key storage (IndexedDB, non-extractable private key) ---------- */
 const idb=()=>new Promise((res,rej)=>{const r=indexedDB.open('qf-keys-v1',1);r.onupgradeneeded=()=>r.result.createObjectStore('ids');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)});
 async function idbGet(k){const d=await idb();return new Promise((res,rej)=>{const q=d.transaction('ids').objectStore('ids').get(k);q.onsuccess=()=>res(q.result);q.onerror=()=>rej(q.error)})}
 async function idbPut(k,v){const d=await idb();return new Promise((res,rej)=>{const t=d.transaction('ids','readwrite');t.objectStore('ids').put(v,k);t.oncomplete=()=>res();t.onerror=()=>rej(t.error)})}

 const RSA={name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'};
 async function makeIdentity(){
  const kp=await crypto.subtle.generateKey(RSA,true,['encrypt','decrypt']);
  const pub=await crypto.subtle.exportKey('jwk',kp.publicKey);
  const privJwk=await crypto.subtle.exportKey('jwk',kp.privateKey);
  const priv=await crypto.subtle.importKey('jwk',privJwk,{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
  return {pub:{kty:pub.kty,n:pub.n,e:pub.e,alg:pub.alg},priv,privJwk};
 }
 const importPub=jwk=>crypto.subtle.importKey('jwk',{kty:jwk.kty,n:jwk.n,e:jwk.e,alg:'RSA-OAEP-256',ext:true},{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);

 /* ---------- Directory ---------- */
 const PUBLIC_COLS='username,display_name,public_key';
 const ACCOUNT_COLS=PUBLIC_COLS+',credential_id,credential_public_key,credential_alg,key_backup';
 async function getProfile(key,cols=PUBLIC_COLS){
  const rows=await api('profiles?username=eq.'+encodeURIComponent(key)+'&select='+cols);
  return rows&&rows[0]||null;
 }
 /* Full account row (passkey public key + encrypted key backup) used for sign-in on any device. */
 const getAccount=key=>getProfile(String(key).toLowerCase(),ACCOUNT_COLS);
 async function createAccount(row){await api('profiles',{method:'POST',body:row,prefer:'return=minimal'})}
 const loadIdentity=key=>idbGet(String(key).toLowerCase());
 const saveIdentity=(key,id)=>idbPut(String(key).toLowerCase(),{pub:id.pub,priv:id.priv});
 async function importPrivateJwk(jwk){
  return crypto.subtle.importKey('jwk',jwk,{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
 }
 async function usernameTaken(name){
  try{return !!(await getProfile(String(name).toLowerCase()))}catch{return false}
 }

 function setStatus(status,detail=''){
  S.status=status;S.detail=detail;
  window.dispatchEvent(new CustomEvent('qf-cloud-status',{detail:{status,message:problem()}}));
 }
 function problem(){
  switch(S.status){
   case 'ready':return '';
   case 'idle':case 'connecting':return 'Connecting to the cloud… try again in a moment.';
   case 'conflict':return 'This browser does not hold the encryption key for “'+(S.user||'')+'”. Sign out, then sign in again with your passkey to restore it on this device.';
   default:return S.detail||'The cloud connection failed.';
  }
 }

 /* The passkey sign-in (auth.js) creates or restores the key on this device. Here we only confirm it matches the cloud profile. */
 async function ensureIdentity(){
  const user=localStorage.getItem(SESSION);
  if(!user){S.user=null;S.identity=null;setStatus('idle');return}
  const run=++S.run,key=user.toLowerCase();
  S.user=key;S.identity=null;setStatus('connecting');
  try{
   if(!(window.crypto&&crypto.subtle&&window.indexedDB))throw new Error('This browser lacks the encryption features needed for cloud messages (use HTTPS and a current browser).');
   const id=await idbGet(key),prof=await getProfile(key);
   if(!prof){if(run===S.run)setStatus('error','No cloud account named “'+user+'” exists. Sign out and create the account again.');return}
   if(!id||!prof.public_key||id.pub.n!==prof.public_key.n){if(run===S.run)setStatus('conflict');return}
   if(run!==S.run)return;
   S.identity=id;setStatus('ready');
  }catch(e){
   if(run!==S.run)return;
   setStatus(e.setup?'setup':e.offline?'offline':'error',e.message);
  }
 }

 /* ---------- Send / list / open ---------- */
 async function send(recipientRaw,text){
  if(S.status!=='ready')throw new Error(problem());
  const rkey=String(recipientRaw).trim().toLowerCase();
  const rp=await getProfile(rkey);
  if(!rp)throw new Error('No QuantumForge user named “'+String(recipientRaw).trim()+'” exists in the cloud yet. They need to create an account first.');
  const [rPub,sPub]=await Promise.all([importPub(rp.public_key),importPub(S.identity.pub)]);
  const aes=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt']);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},aes,te.encode(text));
  const raw=await crypto.subtle.exportKey('raw',aes);
  const [kr,ks]=await Promise.all([crypto.subtle.encrypt({name:'RSA-OAEP'},rPub,raw),crypto.subtle.encrypt({name:'RSA-OAEP'},sPub,raw)]);
  const out=await api('messages',{method:'POST',prefer:'return=representation',body:{
   sender:S.user,recipient:rp.username,iv:b64(iv),ciphertext:b64(ct),key_for_recipient:b64(kr),key_for_sender:b64(ks)
  }});
  return {id:out&&out[0]&&out[0].id,recipient:rp.display_name||rp.username};
 }
 async function list(box){
  if(S.status!=='ready')throw new Error(problem());
  const col=box==='sent'?'sender':'recipient';
  return api('messages?'+col+'=eq.'+encodeURIComponent(S.user)+'&select=id,sender,recipient,created_at&order=created_at.desc&limit=100');
 }
 async function open(id){
  if(S.status!=='ready')throw new Error(problem());
  const rows=await api('messages?id=eq.'+encodeURIComponent(id)+'&select=*');
  const m=rows&&rows[0];
  if(!m)throw new Error('That message no longer exists.');
  const wrapped=m.recipient===S.user?m.key_for_recipient:m.sender===S.user?m.key_for_sender:null;
  if(!wrapped)throw new Error('This message is not addressed to you.');
  try{
   const raw=await crypto.subtle.decrypt({name:'RSA-OAEP'},S.identity.priv,unb64(wrapped));
   const aes=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);
   const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(m.iv)},aes,unb64(m.ciphertext));
   return {id:m.id,sender:m.sender,recipient:m.recipient,createdAt:m.created_at,text:td.decode(pt),mine:m.sender===S.user&&m.recipient!==S.user};
  }catch{throw new Error('Could not decrypt this message with the key on this device. It may be damaged, or it was encrypted for a different key.')}
 }

 window.qfCloud={send,list,open,usernameTaken,getAccount,createAccount,makeIdentity,loadIdentity,saveIdentity,importPrivateJwk,retry:ensureIdentity,problem,get status(){return S.status},get user(){return S.user}};
 window.addEventListener('qf-authenticated',ensureIdentity);
})();
