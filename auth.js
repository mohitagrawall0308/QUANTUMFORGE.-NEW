/* QuantumForge passkey sign-in with global (cloud) usernames.
 *  - A username is a row in the cloud `profiles` table, so it works on every device.
 *  - The passkey (Face ID / Touch ID / Windows Hello / fingerprint) is a discoverable credential whose
 *    public key is stored in that row. Sign-in verifies the passkey signature against the cloud key.
 *  - The RSA message key is backed up in the profile, encrypted with the passkey's PRF secret when the
 *    authenticator supports it, otherwise with a recovery password. A new device restores it after sign-in.
 */
(()=>{
 const $=s=>document.querySelector(s),SESSION='qf-local-session-v1';
 const pk=window.qfPk,te=new TextEncoder(),td=new TextDecoder();
 let resolveReady;window.qfAuthReady=new Promise(r=>resolveReady=r);window.qfCsrf='';
 let pending=null; // passkey already created for a registration that still needs a recovery password

 const error=s=>{$('#authError').textContent=s;$('#authError').hidden=false};
 const clearError=()=>{$('#authError').hidden=true};
 const NAME_RE=/^[A-Za-z0-9_.-]{3,32}$/;
 const bytes=n=>crypto.getRandomValues(new Uint8Array(n));
 const prfOut=cred=>{const r=cred.getClientExtensionResults?.().prf;return r&&r.results&&r.results.first?new Uint8Array(r.results.first):null};
 const prfExt={prf:{eval:{first:pk.PRF_SALT}}};

 function show(){
  const u=localStorage.getItem(SESSION);
  $('#authGate').hidden=!!u;document.body.classList.toggle('auth-locked',!u);
  $('#userBadge').textContent=u?'SIGNED IN · '+u:'PASSKEY REQUIRED';$('#logout').hidden=!u;
  if(u){resolveReady(true);window.dispatchEvent(new Event('qf-authenticated'));window.qfLoadAudit?.()}
 }
 function supported(){
  if(!window.PublicKeyCredential||!navigator.credentials||!window.isSecureContext||!window.crypto?.subtle||!window.qfCloud||!pk){
   error('Passkeys need a current browser on HTTPS (or localhost).');return false}
  return true;
 }
 function askRecovery(note){$('#recoveryRow').hidden=false;$('#recoveryNote').textContent=note;$('#recoveryPassword').focus()}
 function friendly(e){
  if(e&&(e.name==='NotAllowedError'||e.name==='AbortError'))return 'Verification was cancelled or timed out. Try again.';
  if(e&&e.name==='InvalidStateError')return 'A passkey for this username already exists on this device. Use “Sign in with passkey”.';
  return (e&&e.message)||'Something went wrong.';
 }
 function busy(btn,on,label){if(on){btn.dataset.old=btn.textContent;btn.disabled=true;btn.textContent=label}else{btn.disabled=false;btn.textContent=btn.dataset.old||btn.textContent}}

 async function secretFor(backupMethod,prf,needPasswordNote){
  if(backupMethod==='prf'){
   if(!prf)throw Error('This passkey cannot unlock your key backup on this device/browser. Try the device or browser where you created the account.');
   return {prf};
  }
  const pw=$('#recoveryPassword').value;
  if(pw.length<12){askRecovery(needPasswordNote);throw Error('Enter your recovery password (at least 12 characters) and tap the button again.')}
  return {password:pw};
 }

 /* ---------- Create a new global username ---------- */
 async function register(){
  clearError();
  const username=$('#authUsername').value.trim(),key=username.toLowerCase();
  if(!NAME_RE.test(username)){error('Use a username with 3–32 letters, numbers, dots, underscores or hyphens.');return}
  if(!supported())return;
  const btn=$('#registerPasskey');busy(btn,true,'Waiting for face / fingerprint…');
  try{
   if(await window.qfCloud.getAccount(key)){pending=null;throw Error('That username is already taken. Choose another, or sign in if it is yours.')}
   if(!pending||pending.key!==key){
    const cred=await navigator.credentials.create({publicKey:{
     challenge:bytes(32),rp:{name:'QuantumForge',id:location.hostname},
     user:{id:te.encode(key),name:username,displayName:username},
     pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
     authenticatorSelection:{userVerification:'required',residentKey:'required'},
     attestation:'none',timeout:60000,extensions:prfExt}});
    if(!cred)throw Error('Passkey setup was cancelled.');
    if(typeof cred.response.getPublicKey!=='function'||!cred.response.getPublicKey())throw Error('This browser cannot export the passkey public key. Update your browser and try again.');
    let prf=prfOut(cred);
    const enabled=!!cred.getClientExtensionResults?.().prf?.enabled;
    if(!prf&&enabled){ // some authenticators only return the PRF secret on a sign-in
     const a=await navigator.credentials.get({publicKey:{challenge:bytes(32),rpId:location.hostname,allowCredentials:[{type:'public-key',id:cred.rawId}],userVerification:'required',timeout:60000,extensions:prfExt}});
     prf=prfOut(a);
    }
    pending={key,username,cred,prf,spki:pk.b64u(cred.response.getPublicKey()),alg:cred.response.getPublicKeyAlgorithm()};
   }
   let secret;
   if(pending.prf)secret={prf:pending.prf};
   else{
    const pw=$('#recoveryPassword').value;
    if(pw.length<12){askRecovery('Your passkey is created, but this device cannot use it to sync your encryption key. Choose a recovery password (12+ characters, keep it safe; it cannot be reset) to restore messages on other devices, then tap Create again.');throw Error('Choose a recovery password to finish creating the account.')}
    secret={password:pw};
   }
   const id=await window.qfCloud.makeIdentity();
   const backup=await pk.wrapPrivateJwk(id.privJwk,secret);
   await window.qfCloud.createAccount({username:key,display_name:pending.username,public_key:id.pub,
    credential_id:pk.b64u(pending.cred.rawId),credential_public_key:pending.spki,credential_alg:pending.alg,key_backup:backup});
   await window.qfCloud.saveIdentity(key,id);
   localStorage.setItem(SESSION,pending.username);pending=null;$('#recoveryPassword').value='';$('#recoveryRow').hidden=true;
   window.qfAudit?.('Account created','success');show();
  }catch(e){
   if(e&&e.status===409)error('That username was just taken by someone else. Choose another.');
   else error(friendly(e));
  }finally{busy(btn,false)}
 }

 /* ---------- Sign in from any device ---------- */
 async function login(){
  clearError();
  if(!supported())return;
  const typed=$('#authUsername').value.trim().toLowerCase(),btn=$('#loginPasskey');
  busy(btn,true,'Waiting for face / fingerprint…');
  try{
   let allow=[];
   if(typed){ // narrow the prompt to this username's passkey when one is typed
    if(!NAME_RE.test(typed))throw Error('Use a username with 3–32 letters, numbers, dots, underscores or hyphens.');
    const a=await window.qfCloud.getAccount(typed);
    if(!a)throw Error('No account with that username exists yet. Create it first.');
    if(a.credential_id)allow=[{type:'public-key',id:pk.unb64u(a.credential_id)}];
   }
   const challenge=bytes(32);
   const cred=await navigator.credentials.get({publicKey:{challenge,rpId:location.hostname,allowCredentials:allow,userVerification:'required',timeout:60000,extensions:prfExt}});
   if(!cred)throw Error('Sign-in was cancelled.');
   const handle=cred.response.userHandle&&cred.response.userHandle.byteLength?td.decode(cred.response.userHandle):typed;
   if(!handle)throw Error('That passkey did not identify an account. Type your username and try again.');
   const key=handle.toLowerCase(),acct=await window.qfCloud.getAccount(key);
   if(!acct)throw Error('No QuantumForge account exists for this passkey.');
   if(!acct.credential_id||!acct.credential_public_key)throw Error('This username was created before passkey sign-in was stored in the cloud. Create a new username.');
   if(pk.b64u(cred.rawId)!==acct.credential_id)throw Error('This passkey does not belong to that account.');
   await pk.verifyAssertion(cred,{challenge,rpId:location.hostname,origin:location.origin,alg:acct.credential_alg,spki:acct.credential_public_key});
   // Make sure this device holds the encryption key; restore it from the cloud backup if not.
   let id=await window.qfCloud.loadIdentity(key);
   if(!id||!acct.public_key||id.pub.n!==acct.public_key.n){
    const b=acct.key_backup;
    if(!b)throw Error('No encryption-key backup exists for this account, so it cannot be used on a new device.');
    const secret=await secretFor(b.method,prfOut(cred),'Enter the recovery password you chose when you created this account to restore your encryption key on this device, then sign in again.');
    const jwk=await pk.unwrapPrivateJwk(b,secret);
    if(jwk.n!==acct.public_key.n)throw Error('The restored key does not match this account.');
    id={pub:acct.public_key,priv:await window.qfCloud.importPrivateJwk(jwk)};
    await window.qfCloud.saveIdentity(key,id);
   }
   localStorage.setItem(SESSION,acct.display_name||key);$('#recoveryPassword').value='';$('#recoveryRow').hidden=true;
   window.qfAudit?.('Passkey sign-in','success');show();
  }catch(e){error(friendly(e))}
  finally{busy(btn,false)}
 }

 $('#registerPasskey').addEventListener('click',register);
 $('#loginPasskey').addEventListener('click',login);
 $('#authUsername').addEventListener('input',()=>{if(pending&&pending.key!==$('#authUsername').value.trim().toLowerCase())pending=null});
 $('#logout').addEventListener('click',()=>{localStorage.removeItem(SESSION);pending=null;show();window.dispatchEvent(new Event('qf-signed-out'))});

 window.qfCurrentUser=()=>localStorage.getItem(SESSION);
 window.qfLoadAudit=()=>{
  const root=$('#auditRows'),status=$('#auditStatus');if(!root||!status)return;
  const a=JSON.parse(localStorage.getItem('qf-local-audit-v1')||'[]').filter(x=>x.actor===window.qfCurrentUser()).slice(-30).reverse();
  root.replaceChildren();status.textContent='Browser-local activity log · '+a.length+' events (not a tamper-proof audit trail)';
  a.forEach(e=>{const row=document.createElement('div');row.className='audit-row';const left=document.createElement('div'),title=document.createElement('strong'),meta=document.createElement('small'),badge=document.createElement('span');title.textContent=e.action;meta.textContent=e.at+' · '+(e.id||'local');badge.className='audit-result';badge.textContent=e.outcome;left.append(title,meta);row.append(left,badge);root.append(row)});
 };
 show();$('#refreshAudit').addEventListener('click',window.qfLoadAudit);
})();
