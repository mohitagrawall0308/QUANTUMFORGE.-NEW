/* Encrypt dialog + shared modal helpers. Messages are sent through the cloud bridge (cloud.js). */
(()=>{
 const $=s=>document.querySelector(s);let active=null,lastFocus=null;
 const AUDIT='qf-local-audit-v1';
 const read=k=>{try{return JSON.parse(localStorage.getItem(k)||'[]')}catch{return []}};const save=(k,v)=>localStorage.setItem(k,JSON.stringify(v));
 function audit(action,outcome,id=''){const a=read(AUDIT);a.push({actor:window.qfCurrentUser?.()||'',action,outcome,id,at:new Date().toLocaleString()});save(AUDIT,a);window.qfLoadAudit?.()}
 window.qfAudit=audit;
 function open(id,focus){lastFocus=document.activeElement;active=$(id);active.hidden=false;document.body.classList.add('modal-open');if(focus)setTimeout(()=>$(focus).focus(),30)}
 function close(){if(!active)return;if(active.id==='decModal'){$('#decOut').hidden=true;$('#decMsg').textContent='';$('#decErr').hidden=true}active.hidden=true;active=null;document.body.classList.remove('modal-open');lastFocus?.focus?.()}
 window.qfModal={open,close};
 document.addEventListener('keydown',e=>{if(active&&e.key==='Escape')close()});document.querySelectorAll('.modal').forEach(m=>{m.addEventListener('mousedown',e=>{if(e.target===m)close()});m.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',close))});
 $('#openEncrypt').addEventListener('click',()=>open('#encModal','#encRecipient'));
 $('#encMsg').addEventListener('input',()=>{$('#encCount').textContent=$('#encMsg').value.length+' / 5000';$('#encOut').hidden=true});
 function fail(id,msg){$(id).textContent=msg;$(id).hidden=false}
 $('#encGo').addEventListener('click',async()=>{
  const recipient=$('#encRecipient').value.trim(),text=$('#encMsg').value,btn=$('#encGo');
  $('#encErr').hidden=true;
  if(!recipient){fail('#encErr','Enter the username of the person you are sending to.');return}
  if(!text.trim()){fail('#encErr','Enter a message to encrypt.');return}
  if(!window.qfCloud){fail('#encErr','The cloud bridge failed to load. Refresh the page.');return}
  btn.disabled=true;btn.textContent='Encrypting and sending…';
  try{
   const r=await window.qfCloud.send(recipient,text);
   $('#encFp').textContent=r.recipient;$('#encOut').hidden=false;
   $('#encMsg').value='';$('#encCount').textContent='0 / 5000';
   audit('Message sent','success',r.id||'');
   if(typeof setAutoPaused==='function')setAutoPaused(true);
   if(typeof setStatus==='function')setStatus('Message encrypted and delivered to the cloud.');
   window.qfRefreshInbox?.();
  }catch(e){fail('#encErr',e.message||'Could not send message.');audit('Message sent','failed')}
  finally{btn.disabled=false;btn.textContent='Encrypt & send'}
 });
 document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',async()=>{const el=$(b.dataset.copy);try{await navigator.clipboard.writeText(el.value!==undefined?el.value:el.textContent);const old=b.textContent;b.textContent='Copied ✓';setTimeout(()=>b.textContent=old,1400)}catch{el.select?.();fail('#encErr','Clipboard permission was denied. Select and copy the text manually.')}}));
 window.qfLoadAudit?.();
})();
