import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { bootstrapApplication } from '@angular/platform-browser';
import { APP_VERSION } from './app-version';

interface Operator { id: string; issuer?: string; sub?: string; name: string; email?: string; }
interface Session { mode: 'LOCAL'|'OIDC'; operator: Operator; authorized: boolean; csrf: string; }
interface Client { id: string; name: string; endpoint: string; fingerprint: string; }
interface Identity { id: string; name: string; fingerprint: string; publicKey: string; }
interface RequestStatus { requestId: string; state: string; reason?: string; consentExpiresAtUnixMs?: number; resultAvailable: boolean; }
interface Finding { id: string; name: string; status: string; summary: string; details?: string[]; }
interface Report { schemaVersion: string; completedAtUnixMs: number; results: Finding[]; initiator?: {origin: string; operatorDisplayName?: string; serverId?: string; serverDisplayName?: string}; }

@Component({
  selector: 'bwu-root', standalone: true, imports: [CommonModule], styleUrl: './styles.css',
  template: `<main>
    <header><div><p class="eyebrow">SERVER · {{ version }}</p><h1>BaradWatchU</h1><p>Remote workstation audits · explicit local consent</p></div>
      <div *ngIf="session"><strong>{{session.operator.name}}</strong><p *ngIf="session.mode==='OIDC'">{{session.operator.email}}</p><p *ngIf="session.mode==='LOCAL'" class="hint">LOCAL loopback mode · this display name is descriptive, not an authenticated OS user</p><button *ngIf="session.mode==='OIDC'" (click)="logout()" [disabled]="busy">Sign out</button></div>
    </header>
    <p *ngIf="loading" role="status">Loading session…</p>
    <p *ngIf="error" class="error" role="alert">{{error}}</p>
    <section *ngIf="!loading && !session && mode==='OIDC'"><h2>Sign in</h2><p>Use your company Google account. Fleet operations require explicit administrator authorization.</p><a class="button" href="/auth/login">Continue with Google</a></section>
    <section *ngIf="session && !session.authorized"><h2>Authorization required</h2><p>Your Google account is authenticated but is not authorized to manage this fleet. Give the local Server administrator the following subject identifier.</p><dl><dt>Issuer</dt><dd>{{session.operator.issuer}}</dd><dt>Subject</dt><dd><code>{{session.operator.sub}}</code></dd></dl><button (click)="load()">Check authorization again</button></section>
    <ng-container *ngIf="session?.authorized">
      <section><h2>Trusted Clients</h2><p>Pair both identities manually before requesting an audit. Every request needs the workstation user's acceptance within 120 seconds.</p>
        <p *ngIf="!clients.length">No Client registered. Import a verified public identity below.</p>
        <div class="client" *ngFor="let client of clients"><div><h3>{{client.name}}</h3><p><code>{{client.id}}</code> · {{client.endpoint}}</p><small>{{client.fingerprint}}</small></div><div class="actions"><button (click)="start(client)" [disabled]="busy || active || !identity">Request audit</button><button class="secondary" (click)="remove(client)" [disabled]="busy || active">Remove trust</button></div></div>
      </section>
      <section *ngIf="requestId"><h2>Audit request · {{selectedName}}</h2><p><code>{{requestId}}</code></p><p role="status" class="status">{{stateLabel}}</p><p *ngIf="status?.reason">{{status?.reason}}</p><p *ngIf="status?.state==='PENDING_CONSENT'">Waiting for explicit acceptance on the workstation. {{remaining}} seconds remaining.</p><p *ngIf="status?.state==='RUNNING'">Consent accepted. The Client is running its audit.</p><p *ngIf="status?.state==='COMPLETED'">Results remain available from the Client for one hour after completion, unless its service restarts.</p><div class="actions"><button *ngIf="requestId" (click)="refreshRequest()" [disabled]="busy">Refresh status / result</button><button *ngIf="retryCreate" (click)="sendRequest()" [disabled]="busy">Retry same request</button><button *ngIf="report" (click)="download(report,'audit-'+requestId+'.json')">Download JSON</button></div></section>
      <section *ngIf="report"><h2>Audit result</h2><p>{{report.completedAtUnixMs | date:'medium'}} · {{report.initiator?.origin || 'Origin unavailable'}}</p><p *ngIf="report.initiator?.origin==='REMOTE'">Requested by {{report.initiator?.operatorDisplayName || 'Unknown operator'}} through {{report.initiator?.serverDisplayName}} ({{report.initiator?.serverId}})</p><p class="hint">Results describe the Client's observations at audit time.</p><article *ngFor="let row of report.results" class="finding"><div class="finding-title"><h3>{{row.id}} · {{row.name}}</h3><strong [attr.data-status]="row.status">{{row.status}}</strong></div><p>{{row.summary}}</p><details *ngIf="row.details?.length"><summary>Evidence</summary><p class="evidence" *ngFor="let detail of row.details">{{detail}}</p></details></article><details><summary>Complete report JSON</summary><pre>{{report | json}}</pre></details></section>
      <section><h2>Server identity</h2><ng-container *ngIf="identity; else missingIdentity"><p>{{identity.name}} · <code>{{identity.id}}</code></p><p class="fingerprint">{{identity.fingerprint}}</p><button (click)="download(identity,'baradwatchu-server-identity.json')">Export public identity</button><p>Import this public file on the Client and independently compare its fingerprint.</p></ng-container><ng-template #missingIdentity><p>Generate the identity explicitly before pairing. The private key stays on this Server.</p><label>Server display name<input #serverName maxlength="128" placeholder="Company Server"></label><button (click)="generate(serverName.value)" [disabled]="busy">Generate identity</button></ng-template></section>
      <section><h2>Register a trusted Client</h2><p>Paste the Client's exported public identity. Compare its fingerprint with the Client through a trusted channel.</p><label>Public identity JSON<textarea #identityJson rows="6" spellcheck="false"></textarea></label><div class="fields"><label>Display name<input #clientName maxlength="128"></label><label>IP address and port<input #endpoint placeholder="192.0.2.10:7443"></label></div><label>Independently verified fingerprint<input #fingerprint placeholder="SHA256:…" spellcheck="false"></label><button (click)="importClient(identityJson.value,clientName.value,endpoint.value,fingerprint.value)" [disabled]="busy || !identity">Confirm fingerprint and register</button></section>
    </ng-container>
  </main>`
})
class AppComponent implements OnInit, OnDestroy {
  readonly version=APP_VERSION;
  session:Session|null=null;mode:'LOCAL'|'OIDC'|null=null;clients:Client[]=[];identity:Identity|null=null;loading=true;busy=false;error='';
  requestId='';selectedId='';selectedName='';status:RequestStatus|null=null;report:Report|null=null;retryCreate=false;
  private timer:ReturnType<typeof setTimeout>|undefined;
  get active():boolean{return this.status?.state==='PENDING_CONSENT'||this.status?.state==='RUNNING';}
  get remaining():number{return Math.max(0,Math.ceil(((this.status?.consentExpiresAtUnixMs || 0)-Date.now())/1000));}
  get stateLabel():string{return ({PENDING_CONSENT:'Waiting for consent',RUNNING:'Audit running',COMPLETED:'Audit completed',BUSY:'Client busy — no request queued',UNAVAILABLE:'Client unavailable',REJECTED:'Request rejected by the workstation user',EXPIRED:'Consent expired — audit not executed',FAILED:'Audit request failed'} as Record<string,string>)[this.status?.state || ''] || 'Request delivery is not confirmed';}
  ngOnInit():void{void this.load();}
  ngOnDestroy():void{clearTimeout(this.timer);}
  private async api<T>(path:string,method='GET',body?:unknown):Promise<T>{
    const headers:Record<string,string>={};if(method!=='GET'){headers['X-BWU-CSRF']=this.session?.csrf || '';headers['Content-Type']='application/json';}
    const response=await fetch(path,{method,headers,credentials:'same-origin',body:body===undefined?undefined:JSON.stringify(body)});
    let value:any;try{value=await response.json();}catch{throw new Error('Server returned an invalid response. Check Server configuration.');}
    if(!response.ok && !value.state){if(response.status===401)this.session=null;const messages:Record<string,string>={RESULT_EXPIRED:'The Client no longer holds this result (one-hour lifetime or service restart). The local Client history is preserved.',CLIENT_UNREACHABLE:'Cannot reach the Client at its registered address.',TLS_OR_CONNECTION_FAILED:'Connection or mutual TLS verification failed. Check both manually paired identities and the Client endpoint.',REQUEST_NOT_FOUND:'Request unavailable on this Server. It may have restarted or the request record expired.',ADMIN_NOT_AUTHORIZED:'This operator is not authorized to manage the fleet.',INVALID_REQUEST:'The Client rejected the request. Upgrade the Client service and agent to the requester-metadata protocol.'};throw new Error(messages[value.error] || value.error || 'Server request failed');}return value as T;
  }
  async load():Promise<void>{this.error='';this.loading=true;try{this.mode=(await this.api<{mode:'LOCAL'|'OIDC'}>('/api/auth-mode')).mode;this.session=await this.api<Session>('/api/session');if(this.session.authorized){await this.loadFleet();const saved=sessionStorage.getItem('bwu-request');if(saved){const r=JSON.parse(saved);if(r.operatorId===this.session.operator.id){this.requestId=r.id;this.selectedId=r.client;this.selectedName=r.name;await this.refreshRequest();}}}}catch(e){const message=e instanceof Error?e.message:String(e);if(!['LOGIN_REQUIRED','SESSION_EXPIRED'].includes(message))this.error=message;}finally{this.loading=false;}}
  async loadFleet():Promise<void>{[this.clients,this.identity]=await Promise.all([this.api<Client[]>('/api/clients'),this.api<Identity|null>('/api/identity')]);}
  async logout():Promise<void>{await this.action(async()=>{await this.api('/auth/logout','POST',{});clearTimeout(this.timer);sessionStorage.removeItem('bwu-request');this.session=null;this.report=null;this.status=null;this.requestId='';});}
  async generate(name:string):Promise<void>{if(!name.trim()||!confirm('Generate a new Server identity?'))return;await this.action(async()=>{this.identity=await this.api<Identity>('/api/identity/generate','POST',{name,confirm:true});});}
  async importClient(content:string,name:string,endpoint:string,confirmFingerprint:string):Promise<void>{await this.action(async()=>{const identity=JSON.parse(content);await this.api('/api/clients','POST',{identity,name,endpoint,confirmFingerprint});await this.loadFleet();});}
  async remove(client:Client):Promise<void>{if(!confirm('Remove trust for '+client.name+'?'))return;await this.action(async()=>{await this.api('/api/clients/'+client.id,'DELETE');await this.loadFleet();});}
  async start(client:Client):Promise<void>{clearTimeout(this.timer);this.requestId=crypto.randomUUID();this.selectedId=client.id;this.selectedName=client.name;this.status=null;this.report=null;sessionStorage.setItem('bwu-request',JSON.stringify({id:this.requestId,client:client.id,name:client.name,operatorId:this.session?.operator.id}));await this.sendRequest();}
  async sendRequest():Promise<void>{this.retryCreate=true;await this.action(async()=>{this.status=await this.api<RequestStatus>('/api/clients/'+this.selectedId+'/requests','POST',{requestId:this.requestId});this.retryCreate=['BUSY','UNAVAILABLE'].includes(this.status.state);await this.afterStatus();});}
  async refreshRequest():Promise<void>{clearTimeout(this.timer);await this.action(async()=>{this.status=await this.api<RequestStatus>('/api/requests/'+this.requestId);await this.afterStatus();});}
  private async afterStatus():Promise<void>{clearTimeout(this.timer);if(this.status?.state==='COMPLETED'){const result=await this.api<{report:Report}>('/api/requests/'+this.requestId+'/result');this.report=result.report;}else if(this.active){this.timer=setTimeout(()=>void this.refreshRequest(),3000);}}
  private async action(fn:()=>Promise<void>):Promise<void>{this.busy=true;this.error='';try{await fn();}catch(e){this.error=e instanceof Error?e.message:String(e);}finally{this.busy=false;}}
  download(value:unknown,name:string):void{const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
}
bootstrapApplication(AppComponent).catch((error:unknown)=>console.error(error));
