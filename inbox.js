/* Messages section: shows messages sent to you (Inbox) and by you (Sent) from the cloud. */
(()=>{
 const $=s=>document.querySelector(s),POLL_MS=15000;
 let box='inbox',timer=null,items={inbox:[],sent:[]},loaded=false,lastOpened=null;
 const me=()=>String(window.qfCurrentUser?.()||'').toLowerCase();
 const readKey=()=>'qf-read-v1:'+me();
 const readSet=()=>{try{return new Set(JSON.parse(localStorage.getItem(readKey())||'[]'))}catch{return new Set()}};
 const markRead=id=>{try{const s=readSet();s.add(id);localStorage.setItem(readKey(),JSON.stringify([...s].slice(-500)))}catch{}};
 const unread=()=>{const r=readSet();return items.inbox.filter(m=>!r.has(m.id)).length};

 function setBadges(){
  const n=unread();
  for(const el of [$('#unreadCount'),$('#navUnread')]){if(!el)continue;el.textContent=n>99?'99+':n;el.hidden=!n}
 }
 function setStatus(t){$('#inboxStatus').textContent=t}

 function render(){
  const root=$('#inboxRows'),list=items[box],r=readSet();
  root.replaceChildren();
  if(!loaded)return;
  if(!list.length){
   const d=document.createElement('div');d.className='inbox-empty';
   d.textContent=box==='inbox'?'No messages yet. When someone sends you an encrypted message it will appear here.':'You haven’t sent any messages yet.';
   root.append(d);return;
  }
  list.forEach(m=>{
   const row=document.createElement('button'),dot=document.createElement('i'),who=document.createElement('span'),
    name=document.createElement('strong'),when=document.createElement('small'),lock=document.createElement('span');
   const isNew=box==='inbox'&&!r.has(m.id);
   row.type='button';row.className='inbox-row'+(isNew?' unread':'');
   dot.className='dot';dot.setAttribute('aria-hidden','true');who.className='who';
   name.textContent=(box==='inbox'?'From ':'To ')+(box==='inbox'?m.sender:m.recipient);
   when.textContent=new Date(m.created_at).toLocaleString();
   lock.className='lock';lock.textContent=isNew?'NEW · ENCRYPTED':'ENCRYPTED';
   who.append(name,when);row.append(dot,who,lock);
   row.addEventListener('click',()=>openMessage(m.id));
   root.append(row);
  });
 }

 async function refresh(){
  if(!me()){return}
  const c=window.qfCloud;
  if(!c)return;
  if(c.status!=='ready'){loaded=false;render();setStatus(c.problem());return}
  try{
   const [a,b]=await Promise.all([c.list('inbox'),c.list('sent')]);
   items={inbox:a||[],sent:b||[]};loaded=true;
   const n=unread();
   setStatus('Signed in as '+window.qfCurrentUser()+' · '+items.inbox.length+' received'+(n?' · '+n+' unread':'')+' · synced '+new Date().toLocaleTimeString());
   setBadges();render();
  }catch(e){setStatus(e.message)}
 }

 function startPolling(){stopPolling();timer=setInterval(()=>{if(!document.hidden)refresh()},POLL_MS)}
 function stopPolling(){if(timer){clearInterval(timer);timer=null}}

 function selectTab(which){
  box=which;
  $('#tabInbox').setAttribute('aria-selected',String(which==='inbox'));
  $('#tabSent').setAttribute('aria-selected',String(which==='sent'));
  render();
 }

 async function openMessage(id){
  const q=window.qfModal;if(!q)return;
  $('#decErr').hidden=true;$('#decOut').hidden=true;$('#decReply').hidden=true;
  $('#decIntro').hidden=false;$('#decIntro').textContent='Decrypting on this device…';
  q.open('#decModal');
  try{
   const m=await window.qfCloud.open(id);
   lastOpened=m;
   $('#decIntro').hidden=true;
   $('#decMsg').textContent=m.text;
   $('#decMeta').textContent=(m.mine?'To '+m.recipient:'From '+m.sender)+' · '+new Date(m.createdAt).toLocaleString();
   $('#decReply').hidden=m.sender===me();
   $('#decOut').hidden=false;
   if(m.recipient===me()){markRead(id);setBadges();render()}
   window.qfAudit?.('Message decrypted','success',id);
  }catch(e){
   $('#decIntro').hidden=true;$('#decErr').textContent=e.message;$('#decErr').hidden=false;
   window.qfAudit?.('Message decryption','failed',id);
  }
 }

 $('#tabInbox').addEventListener('click',()=>selectTab('inbox'));
 $('#tabSent').addEventListener('click',()=>selectTab('sent'));
 $('#inboxRefresh').addEventListener('click',async()=>{
  const c=window.qfCloud;
  if(c&&c.status!=='ready'&&c.status!=='connecting'){setStatus('Reconnecting…');await c.retry()}
  refresh();
 });
 $('#decReply').addEventListener('click',()=>{
  if(!lastOpened)return;
  const to=lastOpened.sender;
  window.qfModal.close();
  window.qfModal.open('#encModal','#encMsg');
  $('#encRecipient').value=to;$('#encOut').hidden=true;
 });
 /* The "Messages" button in the top band jumps to this section. */
 $('#openDecrypt').addEventListener('click',()=>{
  const sec=$('#messages');
  sec.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});
  selectTab('inbox');refresh();
 });
 window.qfRefreshInbox=refresh;

 window.addEventListener('qf-cloud-status',e=>{
  if(e.detail.status==='ready'){refresh();startPolling()}
  else{stopPolling();loaded=false;items={inbox:[],sent:[]};setBadges();render();if(me())setStatus(e.detail.message)}
 });
 window.addEventListener('qf-signed-out',()=>{
  stopPolling();loaded=false;items={inbox:[],sent:[]};setBadges();render();setStatus('Sign in to see your messages.');
 });
 document.addEventListener('visibilitychange',()=>{if(!document.hidden&&window.qfCloud?.status==='ready')refresh()});
})();
