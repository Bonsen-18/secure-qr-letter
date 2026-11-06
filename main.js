'use strict';
// No fetch, analytics, cookies or remote calls. Only the URL hash contains ciphertext.
const $ = id => document.getElementById(id);
const encoder = new TextEncoder(); const decoder = new TextDecoder('utf-8', {fatal:true});
const ITERATIONS = 600000;
let generatedLink = '';
let loadedPayload = null;

function bytesToBase64url(bytes) {
  let s=''; for (let i=0;i<bytes.length;i+=8192) s += String.fromCharCode(...bytes.subarray(i,i+8192));
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function base64urlToBytes(s) {
  if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length > 6000) throw Error('密文格式无效或过长。');
  const raw = atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4));
  return Uint8Array.from(raw, c=>c.charCodeAt(0));
}
function makePayload(bytes) { return bytesToBase64url(bytes); }
async function getKey(pass, salt, usage) {
  const base = await crypto.subtle.importKey('raw',encoder.encode(pass),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:ITERATIONS,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,[usage]);
}
async function encrypt(message, pass) {
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await getKey(pass,salt,'encrypt');
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,tagLength:128},key,encoder.encode(message)));
  const out=new Uint8Array(1+16+12+ciphertext.length);
  out[0]=1;out.set(salt,1);out.set(iv,17);out.set(ciphertext,29);
  return makePayload(out);
}
async function decrypt(payload,pass) {
  const data=base64urlToBytes(payload);
  if(data.length < 46 || data[0]!==1) throw Error('二维码中的密文版本不兼容或内容损坏。');
  const key=await getKey(pass,data.subarray(1,17),'decrypt');
  const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:data.subarray(17,29),tagLength:128},key,data.subarray(29));
  return decoder.decode(bytes);
}
function setStatus(id,msg,isError=false){const el=$(id);el.textContent=msg;el.classList.toggle('error',isError)}
function switchTab(tab){$('write-panel').classList.toggle('hidden',tab!=='write');$('read-panel').classList.toggle('hidden',tab!=='read');$('tab-write').classList.toggle('active',tab==='write');$('tab-read').classList.toggle('active',tab==='read')}
function getUrl() {
  const raw=$('site-url').value.trim();let url;
  try {url=new URL(raw)}catch{throw Error('请填写已经部署的完整 HTTPS 页面地址。')}
  if(url.protocol!=='https:') throw Error('二维码必须使用可供手机访问的 HTTPS 网址（不要使用 file:// 或 localhost）。');
  if(url.username||url.password||url.search||url.hash) throw Error('网址应为纯净的页面地址，不要包含用户名、参数或 #。');
  return url.href;
}
function qrSvg(link) {
  const {QRCode,Level}=window.QRCodeLocal;
  const qr=new QRCode(-1,Level.M);qr.addData(link);qr.make();
  const n=qr.getModuleCount();const margin=4;const size=n+2*margin;
  const paths=[];
  for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(qr.isDark(y,x))paths.push(`M${x+margin},${y+margin}h1v1h-1z`);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size*8}" height="${size*8}" shape-rendering="crispEdges" role="img" aria-label="加密信件二维码"><rect width="${size}" height="${size}" fill="#fff"/><path d="${paths.join('')}" fill="#000"/></svg>`;
}
async function generate() {
  const btn=$('encrypt-btn');$('result').classList.add('hidden');generatedLink='';
  try {
    if(!globalThis.crypto?.subtle || !globalThis.QRCodeLocal) throw Error('当前浏览器不支持安全加密或二维码组件未加载。请使用 HTTPS 访问。');
    const message=$('message').value; const pass=$('password').value;
    if(!message.trim()) throw Error('请先输入信件正文。');
    if(pass.length<12) throw Error('暗号至少需要 12 个字符；推荐使用长随机口令。');
    const baseUrl=getUrl();
    const estimate=baseUrl.length + Math.ceil((encoder.encode(message).length+45)*4/3)+4;
    if(estimate>1700) throw Error(`信件太长：预计二维码约 ${estimate} 字符。建议将正文缩短（尤其是中文）。`);
    btn.disabled=true;setStatus('write-status','正在本地加密……');
    const payload=await encrypt(message,pass);
    const link=baseUrl+'#m='+payload;
    let svg;
    try{svg=qrSvg(link)}catch(e){throw Error('二维码容量超出限制，请缩短信件内容。')}
    generatedLink=link;
    $('qr-frame').innerHTML=svg;
    const mod=(Number(svg.match(/viewBox="0 0 (\d+)/)?.[1])||0)-8;
    $('qr-meta').textContent=`二维码包含 ${link.length} 个字符，${mod} × ${mod} 模块。请打印至少 7–10 厘米见方并实际扫码测试。`;
    $('result').classList.remove('hidden');setStatus('write-status','加密成功。暗号没有写入二维码，也没有上传到服务器。');
  }catch(e){setStatus('write-status',e.message||'生成失败。',true)}finally{btn.disabled=false}
}
function parseCipher(text){
  let s=text.trim();
  if(s.includes('#m=')) s=s.split('#m=')[1];
  else if(s.startsWith('#m='))s=s.slice(3);
  if(s.includes('&') || s.includes('#'))throw Error('密文链接格式不正确。');
  const bytes=base64urlToBytes(s);
  if(bytes.length<46||bytes[0]!==1)throw Error('不是受支持的加密信件。');
  return s;
}
function loadCipher(s){
  try{loadedPayload=parseCipher(s);setStatus('cipher-loaded','已载入加密信件，等待输入暗号。');setStatus('read-status','');$('plaintext-result').classList.add('hidden');$('plaintext').textContent='';return true}
  catch(e){loadedPayload=null;setStatus('cipher-loaded',e.message,true);return false}
}
async function unlock(){
  const btn=$('decrypt-btn');$('plaintext-result').classList.add('hidden');$('plaintext').textContent='';
  if(!loadedPayload) {setStatus('read-status','请先扫描二维码或载入密文。',true);return}
  if(!$('unlock-password').value){setStatus('read-status','请输入暗号。',true);return}
  try{btn.disabled=true;setStatus('read-status','正在你的设备上解密……');const message=await decrypt(loadedPayload,$('unlock-password').value);$('plaintext').textContent=message;$('plaintext-result').classList.remove('hidden');setStatus('read-status','解密成功。信件明文仅在当前页面显示。');$('unlock-password').value=''}
  catch(e){setStatus('read-status',e.name==='OperationError'?'暗号不正确，或二维码内容已损坏。':(e.message||'解密失败。'),true)}
  finally{btn.disabled=false}
}
function downloadBlob(blob,name){const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),2000)}
async function downloadPng(){
  const svg=$('qr-frame').querySelector('svg');if(!svg)return;
  const data=new XMLSerializer().serializeToString(svg);
  const url=URL.createObjectURL(new Blob([data],{type:'image/svg+xml'}));
  try{const img=new Image();await new Promise((resolve,reject)=>{img.onload=resolve;img.onerror=reject;img.src=url});const canvas=document.createElement('canvas');canvas.width=1600;canvas.height=1600;const ctx=canvas.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,1600,1600);ctx.imageSmoothingEnabled=false;ctx.drawImage(img,0,0,1600,1600);const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));if(!blob)throw Error('PNG 生成失败');downloadBlob(blob,'secret-letter-qr.png')}catch(e){setStatus('write-status',e.message,true)}finally{URL.revokeObjectURL(url)}
}
$('tab-write').addEventListener('click',()=>switchTab('write'));
$('tab-read').addEventListener('click',()=>switchTab('read'));
$('message').addEventListener('input',()=>{$('message-counter').textContent=Array.from($('message').value).length+' 字'});
for(const button of document.querySelectorAll('[data-toggle]')) button.addEventListener('click',()=>{const inp=$(button.dataset.toggle);inp.type=inp.type==='password'?'text':'password';button.textContent=inp.type==='password'?'显示':'隐藏'});
$('encrypt-btn').addEventListener('click',generate);
$('decrypt-btn').addEventListener('click',unlock);
$('unlock-password').addEventListener('keydown',e=>{if(e.key==='Enter')unlock()});
$('load-btn').addEventListener('click',()=>loadCipher($('cipher-input').value));
$('clear-btn').addEventListener('click',()=>{$('plaintext').textContent='';$('plaintext-result').classList.add('hidden');setStatus('read-status','当前页面显示的明文已清除。')});
$('copy-link').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(generatedLink);setStatus('write-status','链接已复制。请注意：链接中含有密文，但不含暗号。')}catch{setStatus('write-status','无法复制，请尝试下载二维码。',true)}});
$('print-btn').addEventListener('click',()=>window.print());
$('download-png').addEventListener('click',downloadPng);
if(location.protocol==='https:'){$('site-url').value=location.origin+location.pathname}
if(location.hash.startsWith('#m=')){switchTab('read');loadCipher(location.hash.slice(3));$('payload-entry').classList.add('hidden');}
else if(location.hash){switchTab('read');setStatus('cipher-loaded','链接中的密文标记不正确。',true)}
