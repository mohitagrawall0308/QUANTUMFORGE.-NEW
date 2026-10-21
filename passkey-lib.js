/* QuantumForge passkey helpers (pure functions; no DOM). Exposed as window.qfPk. */
(()=>{
 const g=typeof window!=='undefined'?window:globalThis;
 const te=new TextEncoder(),td=new TextDecoder();
 const u8=x=>x instanceof Uint8Array?x:new Uint8Array(x instanceof ArrayBuffer?x:(x.buffer||x));
 const b64u=b=>{let s='';u8(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
 const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((s.length+3)%4)),c=>c.charCodeAt(0));
 const sha256=async d=>new Uint8Array(await crypto.subtle.digest('SHA-256',d));
 const PRF_SALT=te.encode('QuantumForge key backup v1');

 /* ECDSA signatures from authenticators are ASN.1 DER; WebCrypto wants raw r||s. */
 function derToRaw(der,size=32){
  const d=u8(der);let i=0;
  if(d[i++]!==0x30)throw Error('Bad signature');
  let len=d[i++];if(len&0x80)i+=len&0x7f;
  const out=new Uint8Array(size*2);
  for(let part=0;part<2;part++){
   if(d[i++]!==0x02)throw Error('Bad signature');
   let l=d[i++],v=d.slice(i,i+l);i+=l;
   while(v.length>size&&v[0]===0)v=v.slice(1);
   if(v.length>size)throw Error('Bad signature');
   out.set(v,part*size+size-v.length);
  }
  return out;
 }

 /* Verify a WebAuthn assertion against the passkey public key stored in the cloud profile.
    p = {challenge:Uint8Array, rpId, origin, alg:-7|-257, spki:base64url}. Throws on any failure. */
 async function verifyAssertion(cred,p){
  const r=cred.response,cdBytes=u8(r.clientDataJSON),ad=u8(r.authenticatorData);
  const cd=JSON.parse(td.decode(cdBytes));
  if(cd.type!=='webauthn.get')throw Error('Unexpected passkey response type.');
  if(cd.challenge!==b64u(p.challenge))throw Error('Passkey challenge mismatch.');
  if(cd.origin!==p.origin)throw Error('Passkey origin mismatch.');
  const rp=await sha256(te.encode(p.rpId));
  if(ad.length<37||rp.some((v,i)=>v!==ad[i]))throw Error('Passkey was issued for a different site.');
  if(!(ad[32]&0x01)||!(ad[32]&0x04))throw Error('Face, fingerprint or device-PIN verification was not performed.');
  const signed=new Uint8Array(ad.length+32);signed.set(ad);signed.set(await sha256(cdBytes),ad.length);
  const spki=unb64u(p.spki),sig=u8(r.signature);let ok=false;
  if(p.alg===-7){
   const k=await crypto.subtle.importKey('spki',spki,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
   ok=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},k,derToRaw(sig),signed);
  }else if(p.alg===-257){
   const k=await crypto.subtle.importKey('spki',spki,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
   ok=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',k,sig,signed);
  }else throw Error('Unsupported passkey algorithm.');
  if(!ok)throw Error('Passkey signature check failed.');
  return true;
 }

 /* Key backup: the RSA private key (JWK) is encrypted with AES-GCM under a key derived from
    either the passkey's PRF secret (preferred, high entropy) or a recovery password. */
 async function wrapKey(secret,salt){
  if(secret.prf){
   const m=await crypto.subtle.importKey('raw',u8(secret.prf),'HKDF',false,['deriveKey']);
   return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:te.encode('QuantumForge backup v1')},m,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  const m=await crypto.subtle.importKey('raw',te.encode(secret.password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},m,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 }
 async function wrapPrivateJwk(jwk,secret){
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},await wrapKey(secret,salt),te.encode(JSON.stringify(jwk)));
  return {v:1,method:secret.prf?'prf':'password',salt:b64u(salt),iv:b64u(iv),wrapped:b64u(ct)};
 }
 async function unwrapPrivateJwk(b,secret){
  try{
   const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64u(b.iv)},await wrapKey(secret,unb64u(b.salt)),unb64u(b.wrapped));
   return JSON.parse(td.decode(pt));
  }catch{throw Error(secret.prf?'This passkey could not unlock the key backup.':'Recovery password is incorrect.')}
 }
 g.qfPk={b64u,unb64u,sha256,derToRaw,verifyAssertion,wrapPrivateJwk,unwrapPrivateJwk,PRF_SALT};
})();
