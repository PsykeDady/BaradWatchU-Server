// Isolated browser/API fixture; does not authenticate against Google.
// Run after npm run build: node --experimental-websocket dashboard.smoke.mjs
import http from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
const root=resolve('dist/server-dashboard/browser'), profile=await mkdtemp(join(tmpdir(),'bwu-browser-'));
let cookieSeen=false,id='',polls=0;
const server=http.createServer(async(req,res)=>{
 res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
 const send=(data,code=200)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(data));};
 if(req.url==='/api/auth-mode')return send({mode:'LOCAL'});
 if(req.url==='/api/session'){cookieSeen=req.headers.cookie?.includes('__Host-bwu-session=fixture');return send({mode:'LOCAL',operator:{id:'LOCAL',name:'Mario Rossi'},authorized:true,csrf:'csrf'});}
 if(req.url==='/api/identity')return send({id:'SRV-TEST',name:'Company Server',fingerprint:'SHA256:test'});
 if(req.url==='/api/clients')return send([{id:'BWU-TEST',name:'Workstation',endpoint:'127.0.0.1:7443',fingerprint:'SHA256:client'}]);
 if(req.url==='/api/clients/BWU-TEST/requests'){assert.equal(req.headers['x-bwu-csrf'],'csrf');assert.equal(req.headers.origin,`http://localhost:${server.address().port}`);let b='';for await(const c of req)b+=c;id=JSON.parse(b).requestId;return send({requestId:id,state:'PENDING_CONSENT',consentExpiresAtUnixMs:Date.now()+120000,resultAvailable:false},202);}
 if(req.url===`/api/requests/${id}/result`)return send({report:{schemaVersion:'baradwatchu.audit.v1',completedAtUnixMs:Date.now(),initiator:{origin:'REMOTE',operatorDisplayName:'Mario Rossi',serverDisplayName:'Company Server',serverId:'SRV-TEST'},results:[{id:'REQ-001',name:'Security check',status:'PASS',summary:'Fixture audit completed',details:['<script>window.injected=true</script>']}]}});
 if(req.url===`/api/requests/${id}`){polls++;return send({requestId:id,state:polls===1?'RUNNING':'COMPLETED',resultAvailable:polls>1});}
 try{const path=req.url==='/'?'index.html':req.url.slice(1);if(path.includes('..'))throw Error();const b=await readFile(join(root,path));if(path==='index.html')res.setHeader('Set-Cookie','__Host-bwu-session=fixture; Path=/; Secure; HttpOnly; SameSite=Lax');res.setHeader('Content-Type',({'.js':'text/javascript','.css':'text/css','.html':'text/html'})[extname(path)]||'application/octet-stream');res.end(b);}catch{res.writeHead(404);res.end();}
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const chrome=spawn(process.env.CHROME||'google-chrome-stable',['--headless=new','--no-first-run','--no-default-browser-check','--disable-gpu','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});
let ws;
try{
 let port;const end=Date.now()+20000;
 while(Date.now()<end){try{port=(await readFile(join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break;}catch{await new Promise(r=>setTimeout(r,100));}}
 assert.ok(port,'Chrome debugging port');const tabs=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
 ws=new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);await new Promise(r=>ws.addEventListener('open',r,{once:true}));
 let seq=0;const pending=new Map(),errors=[];ws.addEventListener('message',({data})=>{const m=JSON.parse(data);if(m.id){pending.get(m.id)?.(m);pending.delete(m.id);}if(m.method==='Runtime.exceptionThrown')errors.push(m.params);});
 const call=(method,params={})=>new Promise((ok,no)=>{const id=++seq;pending.set(id,m=>m.error?no(m.error):ok(m.result));ws.send(JSON.stringify({id,method,params}));});
 const evaluate=async(expression)=>(await call('Runtime.evaluate',{expression,returnByValue:true})).result.value;
 const wait=async(expression)=>{const end=Date.now()+20000;while(Date.now()<end){if(await evaluate(expression))return;await new Promise(r=>setTimeout(r,100));}throw Error('Timed out: '+expression);};
 await call('Runtime.enable');await call('Page.enable');await call('Page.navigate',{url:`http://localhost:${server.address().port}/`});
 await wait("document.body.innerText.includes('Workstation')");assert.ok(cookieSeen,'Secure cookie sent on HTTP localhost');assert.equal(await evaluate('document.cookie.includes("bwu-session")'),false,'HttpOnly cookie hidden');assert.ok(await evaluate("document.body.innerText.includes('display name is descriptive, not an authenticated OS user')"));assert.equal(await evaluate("document.body.innerText.includes('Continue with Google')"),false,'LOCAL mode has no Google login');
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent==='Request audit').click()");
 for(const text of ['Waiting for consent','Audit running','Fixture audit completed'])await wait(`document.body.innerText.includes('${text}')`);
 assert.ok(await evaluate("document.body.innerText.includes('Requested by Mario Rossi through Company Server')"));assert.equal(await evaluate('window.injected===true'),false);assert.equal(errors.length,0,JSON.stringify(errors));
 const screenshot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});await writeFile('/tmp/bwu-server-dashboard-smoke.png',Buffer.from(screenshot.data,'base64'));
 console.log('PASS: LOCAL session/fleet/pending/running/result, requester, CSRF, XSS escaping, Secure+HttpOnly localhost cookie, no Google login. Fixture API only. Screenshot: /tmp/bwu-server-dashboard-smoke.png');
}finally{ws?.close();chrome.kill('SIGTERM');if(chrome.exitCode===null)await new Promise(r=>chrome.once('exit',r));await new Promise(r=>server.close(r));await rm(profile,{recursive:true,force:true});}
