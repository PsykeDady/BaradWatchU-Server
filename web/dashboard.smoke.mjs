// Isolated browser/API fixture; does not authenticate against Google.
// Run after npm run build: node --experimental-websocket dashboard.smoke.mjs
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
const LAUNCH_TOKEN='f'.repeat(64);
const root=resolve('dist/server-dashboard/browser'), profile=await mkdtemp(join(tmpdir(),'bwu-browser-'));
let cookieSeen=false,id='',polls=0,language='english',definitions=[],savedReport=null;
const server=http.createServer(async(req,res)=>{
 res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
 const send=(data,code=200)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(data));};
 if(req.url==='/api/messages'||req.url==='/api/configuration/language'){
  if(req.method==='PUT'){assert.equal(req.headers['x-bwu-csrf'],'csrf');let b='';for await(const c of req)b+=c;language=JSON.parse(b).language;}
  const locale=language==='italian'?'it_IT':'en_EN';
  return send({language,effectiveLanguage:locale,messages:JSON.parse(readFileSync(new URL(`../crates/messages/locales/${locale}.json`,import.meta.url),'utf8')).messages});
 }
 if(req.url==='/api/expected-manifest')return send(null);
 if(req.url==='/api/report-theme')return send({selectedThemeId:'default',themes:[{id:'default',name:'BaradWatchU'}]});
 if(req.url==='/api/requirement-definitions'){
  if(req.method==='POST'){assert.equal(req.headers['x-bwu-csrf'],'csrf');let b='';for await(const c of req)b+=c;const definition=JSON.parse(b);definitions=[definition];return send(definition);}
  return send(definitions);
 }
 if(req.url==='/api/requirements')return send([]);
 if(req.url==='/api/history/usage')return send({audits:savedReport?1:0,files:savedReport?1:0,bytes:savedReport?100:0});
 if(req.url==='/api/history'){
  if(req.method==='DELETE'){assert.equal(req.headers['x-bwu-csrf'],'csrf');savedReport=null;return send({removedAudits:1});}
  return send(savedReport?[{id,clientId:'BWU-TEST',clientName:'Workstation',fingerprint:'SHA256:client',completedAtUnixMs:savedReport.completedAtUnixMs,files:1,bytes:100}]:[]);
 }
 if(id && req.url===`/api/history/${id}`){
  if(req.method==='DELETE'){assert.equal(req.headers['x-bwu-csrf'],'csrf');savedReport=null;return send({removedAudits:1});}
  return send({report:savedReport,serverRequirementComparison:{source:'fixture',items:[]}});
 }
 if(req.url==='/api/auth-mode')return send({mode:'LOCAL'});
 if(req.url==='/auth/logout'&&req.method==='POST'){assert.equal(req.headers['x-bwu-csrf'],'csrf');return send({ok:true});}
 if(req.url==='/api/session'){if(req.headers['x-baradwatchu-token']!==LAUNCH_TOKEN){res.writeHead(401,{'content-type':'application/json'});return res.end(JSON.stringify({error:'LOCAL_TOKEN_REQUIRED'}));}cookieSeen=req.headers.cookie?.includes('__Host-bwu-session=fixture');return send({mode:'LOCAL',operator:{id:'LOCAL',name:'Mario Rossi'},authorized:true,csrf:'csrf'});}
 if(req.url==='/api/identity')return send({id:'SRV-TEST',name:'Company Server',fingerprint:'SHA256:test'});
 if(req.url==='/api/clients')return send([{id:'BWU-TEST',name:'Workstation',endpoint:'127.0.0.1:7443',fingerprint:'SHA256:client'}]);
 if(req.url==='/api/clients/BWU-TEST/requests'){assert.equal(req.headers['x-bwu-csrf'],'csrf');assert.equal(req.headers.origin,`http://localhost:${server.address().port}`);let b='';for await(const c of req)b+=c;id=JSON.parse(b).requestId;return send({requestId:id,state:'PENDING_CONSENT',consentExpiresAtUnixMs:Date.now()+120000,resultAvailable:false},202);}
 if(req.url===`/api/requests/${id}/result`) {savedReport={schemaVersion:'baradwatchu.audit.v1',completedAtUnixMs:Date.now(),initiator:{origin:'REMOTE',operatorDisplayName:'Mario Rossi',serverDisplayName:'Company Server',serverId:'SRV-TEST'},client:{version:'0.0.1',sha256:'a'.repeat(64)},installation:{status:'VERIFIED',platform:'Linux-x86_64',manifestSha256:'b'.repeat(64),verifiedFiles:1,files:[{requirementId:'REQ-001',path:'catalog/checks/REQ-001/check.sh',expectedSha256:'c'.repeat(64),actualSha256:'c'.repeat(64),state:'VERIFIED'}]},extensions:{providers:[{requirementId:'REQ-001',providerId:'fixture',name:'Fixture provider',origin:'BUILTIN',required:true,status:'PASS',summary:'Provider passed',details:['Provider evidence']}],disabledRequirements:[{id:'REQ-002',priority:'LOW',reason:'Not in scope',author:'Operator',expiresAtUnixMs:Date.now()+86400000}]},results:[{id:'REQ-001',name:'Security check',description:'Checks the workstation baseline.',priority:'HIGH',status:'PASS',complianceStatus:'PASS',summary:'Fixture audit completed',details:['<script>window.injected=true</script>'],provenance:{toolId:'security-check',toolVersion:1,origin:'BUILTIN',toolPath:'catalog/checks/REQ-001/check.sh',expectedSha256:'d'.repeat(64),actualSha256:'d'.repeat(64),integrityStatus:'VERIFIED',integrityScope:'FILE',isOverride:false}}]};return send({report:savedReport});}
 if(req.url===`/api/requests/${id}`){polls++;return send({requestId:id,state:polls===1?'RUNNING':'COMPLETED',resultAvailable:polls>1});}
 try{const path=(new URL(req.url,'http://fixture').pathname==='/'?'index.html':new URL(req.url,'http://fixture').pathname.slice(1));if(path.includes('..'))throw Error();const b=await readFile(join(root,path));if(path==='index.html')res.setHeader('Set-Cookie','__Host-bwu-session=fixture; Path=/; Secure; HttpOnly; SameSite=Lax');res.setHeader('Content-Type',({'.js':'text/javascript','.css':'text/css','.html':'text/html'})[extname(path)]||'application/octet-stream');res.end(b);}catch{res.writeHead(404);res.end();}
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
 const wait=async(expression)=>{const end=Date.now()+20000;while(Date.now()<end){if(await evaluate(expression))return;await new Promise(r=>setTimeout(r,100));}throw Error('Timed out: '+expression+'; body='+await evaluate('document.body.innerText'));};
 await call('Runtime.enable');await call('Page.enable');await call('Page.navigate',{url:`http://localhost:${server.address().port}/?k=${LAUNCH_TOKEN}`});
 await wait("document.body.innerText.includes('Workstation')");assert.equal(await evaluate('location.search'),'','launch token removed from the address bar');assert.equal(await evaluate("sessionStorage.getItem('bwu-launch-token')"),LAUNCH_TOKEN,'launch token kept per tab like the Client');assert.ok(cookieSeen,'Secure cookie sent on HTTP localhost');assert.equal(await evaluate('document.cookie.includes("bwu-session")'),false,'HttpOnly cookie hidden');assert.equal(await evaluate("document.body.innerText.includes('Continue with Google')"),false,'LOCAL mode has no Google login');
 assert.equal(await evaluate("getComputedStyle(document.querySelector('.brand-mark')).fontSize"),'0px','Client logo hides the B text');
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Settings').click()");
 await wait("document.body.innerText.includes('Server identity')");
 assert.ok(await evaluate("document.body.innerText.includes('loopback access does not authenticate')"));
 await evaluate("(()=>{const s=[...document.querySelectorAll('select')].find(s=>[...s.options].some(o=>o.value==='italian'));s.value='italian';s.dispatchEvent(new Event('change'));})()");
 await wait("document.documentElement.lang==='it' && document.body.innerText.includes('Identità Server')");
 assert.equal(language,'italian','language saved through shared API');
 await evaluate("(()=>{const input=[...document.querySelectorAll('textarea')].find(t=>t.value.includes('baradwatchu.custom-checks.v1'));const config=JSON.parse(input.value);config.name='Fixture requirement';config.expectedSha256='a'.repeat(64);input.value=JSON.stringify(config);input.dispatchEvent(new Event('input'));[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Salva definizione').click();})()");
 await wait("document.body.innerText.includes('CUSTOM-001 · Fixture requirement')");
 assert.equal(definitions[0].priority,'HIGH');assert.equal(definitions[0].toolPath,'./check.sh');

 await evaluate("(()=>{const s=[...document.querySelectorAll('select')].find(s=>[...s.options].some(o=>o.value==='english'));s.value='english';s.dispatchEvent(new Event('change'));})()");
 await wait("document.documentElement.lang==='en' && document.body.innerText.includes('Server identity')");

 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Fleet management').click()");
 await wait("document.body.innerText.includes('Request audit')");
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Request audit').click()");
 for(const text of ['Waiting for consent','Audit running','Fixture audit completed'])await wait(`document.body.innerText.includes('${text}')`);
 assert.ok(await evaluate("document.body.innerText.includes('Requested by Mario Rossi')"));
 for(const text of ['Client version 0.0.1','Installation integrity','Checks the workstation baseline.','Execution provenance','Providers','Not in scope'])await wait(`document.body.innerText.includes('${text}')`);
 await evaluate("[...document.querySelectorAll('summary')].find(s=>s.textContent.trim()==='Providers').click()");await wait("document.body.innerText.includes('Fixture provider')");
 await evaluate("document.querySelector('.report-counts button[data-status=FAIL]').click()");assert.equal(await evaluate("document.body.innerText.includes('Checks the workstation baseline.')"),false,'status counter filters findings');await evaluate("document.querySelector('.report-counts button:not([data-status])').click()");assert.equal(await evaluate("document.body.innerText.includes('Checks the workstation baseline.')"),true,'All results clears the filter');
 await evaluate("(()=>{const i=document.querySelector('.report-counts input.search');i.value='no-such-requirement';i.dispatchEvent(new Event('input'));})()");await wait("document.body.innerText.includes('No results match these filters.')");await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Show all').click()");await wait("document.body.innerText.includes('Checks the workstation baseline.')");
 assert.equal(await evaluate("document.body.innerText.includes('1 Pass')"),true,'result summary counts include audit statuses');
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='End session').click()");await wait("document.body.innerText.includes('Local session ended')");await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='New local session').click()");await wait("document.body.innerText.includes('Mario Rossi · LOCAL')");assert.equal(await evaluate('window.injected===true'),false);assert.equal(errors.length,0,JSON.stringify(errors));
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='History').click()");
 await wait("document.body.innerText.includes('Open report')");
 await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Open report').click()");
 await wait("document.body.innerText.includes('Fixture audit completed')");
 assert.ok(await evaluate("document.querySelector('a[href*=\"/api/history/\"][href$=\"/pdf\"]')!==null"),'PDF uses persisted history');
 await evaluate("window.confirm=()=>true;[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Clear history').click()");
 await wait("document.body.innerText.includes('No received reports saved.')");
 assert.equal(savedReport,null);
 const screenshot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});await writeFile('/tmp/bwu-server-dashboard-smoke.png',Buffer.from(screenshot.data,'base64'));
 console.log('PASS: LOCAL session/fleet/pending/running/result, requester, CSRF, XSS escaping, Secure+HttpOnly localhost cookie, no Google login. Fixture API only. Screenshot: /tmp/bwu-server-dashboard-smoke.png');
}finally{ws?.close();chrome.kill('SIGTERM');if(chrome.exitCode===null)await new Promise(r=>chrome.once('exit',r));await new Promise(r=>server.close(r));await rm(profile,{recursive:true,force:true});}
