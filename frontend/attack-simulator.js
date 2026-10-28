function esc(v){return String(v??'--').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function pretty(v){return JSON.stringify(v,null,2);}
async function api(url,opts){const r=await fetch(url,opts);let d={};try{d=await r.json();}catch(_e){}if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);return d;}
function badge(v){const s=String(v||'').toLowerCase();const ok=['success','precondition_confirmed','lateral_movement_confirmed','confirmed'].includes(s);const bad=['failed','error','timeout','target_unreachable'].includes(s);return `<span class="badge ${ok?'badge-ok':bad?'badge-danger':'badge-muted'}">${esc(v||'--')}</span>`;}
let catalogById={};
let editingCampaignId=null;
function providerOfTask(r){const m=r.metadata||{};return m.provider||((r.task_key||'').startsWith('MAGI-M-ATK-')?'metasploit':'magi_native');}
function providerLabel(p){return p==='metasploit'?'Metasploit':'MAGI Native';}
function switchAttackView(view){
  document.querySelectorAll('[data-attack-view]').forEach(el=>{el.style.display=(el.dataset.attackView===view)?'':'none';});
  document.querySelectorAll('.attack-nav-item').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
  if(view==='history') loadHistory();
  if(view==='campaign') loadCampaigns();
  if(view==='correlation') loadCorrelationTargets();
  if(view==='attackpath') loadAttackPaths();
}
async function loadProviderStatus(){
  const el=document.getElementById('metasploitProviderStatus'); if(!el)return;
  try{
    const d=await api('/api/attack-simulator/providers'),m=(d.providers||{}).metasploit||{};
    el.textContent=m.available?`AVAILABLE${m.version?' · '+m.version:''}`:'NOT INSTALLED';
    el.title=m.path||m.message||'';
  }catch(e){el.textContent='UNKNOWN';el.title=e.message;}
}
async function loadSummary(){const d=await api('/api/attack-simulator/summary');document.getElementById('attackSimulationCount').textContent=d.simulations??0;}
async function loadCredentials(){try{const d=await api('/api/actions/credentials');const all=d.credentials||[];const windows=all.filter(c=>['windows','wmi','winrm'].includes(String(c.type||c.credential_type||'').toLowerCase()));const ssh=all.filter(c=>['ssh','linux'].includes(String(c.type||c.credential_type||'').toLowerCase()));const snmp=all.filter(c=>['snmp','snmp_v2c','snmpv2c'].includes(String(c.type||c.credential_type||'').toLowerCase()));const opts=(rows,empty)=>`<option value="">${empty}</option>`+rows.map(c=>`<option value="${esc(c.id)}">${esc(c.name)} — ${esc(c.type||c.credential_type||'credential')} — ${esc(c.domain?c.domain+'\\':'')}${esc(c.username||'')}</option>`).join('');document.getElementById('attackCredential').innerHTML=opts(all,'Nenhuma / não necessária');const cw=document.getElementById('campaignCredential');if(cw)cw.innerHTML=windows.map(c=>`<option value="${esc(c.id)}">${esc(c.name)} — ${esc(c.type||c.credential_type||'credential')} — ${esc(c.domain?c.domain+'\\':'')}${esc(c.username||'')}</option>`).join('');const cn=document.getElementById('campaignSnmpCredential');if(cn)cn.innerHTML=opts(snmp,'Sem community SNMP');}catch(_e){}}
let attackCatalogRows=[];
let attackCatalogPage=1;
let attackCatalogPageSize=25;
let attackCatalogRequest=0;
// MAGI 6.1.1: small local SVG glyphs; no external assets or brand assumptions.
const magiGlyphs={
  monitor:'<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  network:'<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-5h14v5"/>',
  server:'<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01M11 7h7M11 17h7"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c-5 5-5 13 0 18M12 3c5 5 5 13 0 18"/>',
  shield:'<path d="M12 2 4 5v6c0 5 3.5 8.5 8 11 4.5-2.5 8-6 8-11V5z"/><path d="m9 12 2 2 4-4"/>'
};
function magiIcon(name){return `<svg class="magi-context-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${magiGlyphs[name]||magiGlyphs.shield}</svg>`;}
function attackGlyph(r){const c=String(r.category||'').toLowerCase(), k=String(r.task_key||'').toLowerCase(), n=String(r.name||'').toLowerCase();if(c.includes('application')||/http|web|url/.test(n))return 'globe';if(/ldap|ldaps|sql|database/.test(n))return 'server';if(/kerberos|active directory|windows|endpoint/.test(c+' '+n)&&!/reachability|protocol|tcp/.test(n))return 'monitor';if(/network|reachability|tcp|snmp|ssh|rdp|winrm/.test(c+' '+n+' '+k))return 'network';return 'shield';}
function addAttackFieldIcons(){const glyphs={attackTarget:'monitor',attackUrl:'globe',attackHostB:'network',attackCredential:'shield',attackCategory:'server',attackSearch:'globe',attackProvider:'server',attackTechniqueParameter:'shield'};Object.entries(glyphs).forEach(([id,glyph])=>{const el=document.getElementById(id);if(!el||el.parentElement?.querySelector('.magi-field-icon'))return;const wrap=document.createElement('span');wrap.className='magi-input-wrap';el.parentNode.insertBefore(wrap,el);wrap.appendChild(el);const i=document.createElement('span');i.className='magi-field-icon';i.innerHTML=magiIcon(glyph);wrap.insertBefore(i,el);});}
function renderAttackCatalog(){
  const table=document.getElementById('attackCatalogTable');if(!table)return;
  const count=attackCatalogRows.length;
  const pages=Math.max(1,Math.ceil(count/attackCatalogPageSize));
  attackCatalogPage=Math.max(1,Math.min(attackCatalogPage,pages));
  const start=(attackCatalogPage-1)*attackCatalogPageSize;
  const rows=attackCatalogRows.slice(start,start+attackCatalogPageSize);
  table.innerHTML=rows.map(r=>{
    const meta=r.metadata||{},provider=providerOfTask(r);
    const providerBadge=provider==='metasploit'?'<span class="badge badge-muted">Metasploit</span>':'<span class="badge badge-ok">MAGI Native</span>';
    const technical=JSON.stringify(r.detection||{},null,2);
    return `<tr><td class="atk-catalog-name"><div class="magi-attack-title"><span class="magi-attack-icon">${magiIcon(attackGlyph(r))}</span><div><strong>${esc(r.name||r.task_key)}</strong><small>${esc(r.description||'Sem descrição disponível')}</small><details class="atk-technical"><summary>Detalhes técnicos</summary><dl><dt>Identificador</dt><dd>${esc(r.task_key)}</dd><dt>Fase</dt><dd>${esc(meta.attack_phase||'Não informada')}</dd><dt>Requer credencial</dt><dd>${meta.credential_required?'Sim':'Não'}</dd></dl><pre>${esc(technical)}</pre></details></div></div></td><td>${providerBadge}</td><td>${esc(r.category)}</td><td>${badge(r.impact)}</td><td class="atk-catalog-actions"><button class="btn primary btn-sm atk-run" data-id="${esc(r.id)}">Executar</button></td></tr>`;
  }).join('')||'<tr><td colspan="5">Nenhuma simulação encontrada para os filtros atuais.</td></tr>';
  const info=document.getElementById('attackCatalogPaginationInfo');
  if(info)info.textContent=count?`Exibindo ${start+1}–${Math.min(start+attackCatalogPageSize,count)} de ${count} simulações`:'Nenhuma simulação';
  const page=document.getElementById('attackCatalogPageLabel');if(page)page.textContent=`Página ${attackCatalogPage} de ${pages}`;
  const prev=document.getElementById('attackCatalogPrev');if(prev)prev.disabled=attackCatalogPage<=1;
  const next=document.getElementById('attackCatalogNext');if(next)next.disabled=attackCatalogPage>=pages;
  table.querySelectorAll('.atk-run').forEach(b=>b.addEventListener('click',()=>runAttack(b.dataset.id,false)));
}
async function loadCatalog(){
  const request=++attackCatalogRequest;
  const url=new URL('/api/attack-simulator/catalog',location.origin);
  const q=document.getElementById('attackSearch').value.trim();
  const c=document.getElementById('attackCategory').value;
  const provider=document.getElementById('attackProvider')?.value||'';
  if(q)url.searchParams.set('search',q);
  if(c)url.searchParams.set('category',c);
  try{
    const d=await api(url);
    if(request!==attackCatalogRequest)return;
    let rows=d.simulations||[];
    if(provider)rows=rows.filter(r=>providerOfTask(r)===provider);
    catalogById={};rows.forEach(r=>catalogById[String(r.id)]=r);
    attackCatalogRows=rows;
    attackCatalogPage=1;
    renderAttackCatalog();
  }catch(e){
    if(request!==attackCatalogRequest)return;
    document.getElementById('attackCatalogTable').innerHTML=`<tr><td colspan="5">Falha ao carregar catálogo: ${esc(e.message)}</td></tr>`;
  }
}

function executionPayload(id){
  const task=catalogById[String(id)]||{},meta=task.metadata||{};
  const isApplication=String(task.category||'').toLowerCase()==='application';
  const p={
    target:isApplication?document.getElementById('attackUrl').value.trim():document.getElementById('attackTarget').value.trim(),
    host_b:document.getElementById('attackHostB').value.trim(),
    credential_id:document.getElementById('attackCredential').value||null,
    technique_parameter:document.getElementById('attackTechniqueParameter')?.value.trim()||null,
    max_hops:Number(document.getElementById('attackMaxHops').value||3),
    max_branches_per_host:Number(document.getElementById('attackMaxBranches').value||3),
    max_total_hosts:Number(document.getElementById('attackMaxHosts').value||15),
    max_job_duration_minutes:Number(document.getElementById('attackMaxMinutes').value||30),
    allowed_networks:document.getElementById('attackAllowedNetworks').value.split(',').map(x=>x.trim()).filter(Boolean)
  };
  if(meta.secondary_target_required&&!p.host_b)throw new Error('Host B / Destination é obrigatório para esta simulação.');
  if(meta.credential_required&&!p.credential_id)throw new Error('Credential Profile é obrigatório para esta simulação.');
  return p;
}
async function runAttack(id,plan){const out=document.getElementById('attackResult');const task=catalogById[String(id)]||{};let body;try{body=executionPayload(id);}catch(e){out.textContent=e.message;return;}if(!body.target){out.textContent=String(task.category||'').toLowerCase()==='application'?'Application URL obrigatória.':'Host A / Target obrigatório.';return;}if(!plan&&!confirm(`Executar simulação controlada em ${body.target}${body.host_b?' → '+body.host_b:''}?`))return;out.textContent=plan?'Planejando...':'Enviando ao Runner...';try{const d=await api(`/api/attack-simulator/simulations/${id}/${plan?'plan':'execute'}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});out.textContent=pretty(d);if(!plan)setTimeout(loadHistory,1200);}catch(e){out.textContent=e.message;}}
let activeHistoryLog=null;
let activeHistoryLogTab='summary';

function historyLogSummary(d){
  const e=d.execution||{};
  return [
    `Execution: ${e.id??'--'}`,
    `Technique: ${e.task_key||'--'}${e.task_name?' — '+e.task_name:''}`,
    `Provider: ${providerLabel(e.provider)}`,
    `Target: ${e.target||'--'}`,
    `Status: ${e.status||'--'}`,
    `Finding: ${e.finding_status||'--'}`,
    `Runner: ${e.runner_id||'--'}`,
    `Runner Job: ${e.runner_job_id||'--'}`,
    `Started: ${e.started_at||'--'}`,
    `Finished: ${e.finished_at||'--'}`,
    '',
    e.finding_message||''
  ].join('\n');
}

function renderHistoryLog(){
  if(!activeHistoryLog)return;
  const content=document.getElementById('attackHistoryLogContent');
  const d=activeHistoryLog;
  if(activeHistoryLogTab==='stdout') content.textContent=d.stdout||'(sem stdout)';
  else if(activeHistoryLogTab==='stderr') content.textContent=d.stderr||'(sem stderr)';
  else if(activeHistoryLogTab==='evidence') content.textContent=pretty(d.evidence||{});
  else content.textContent=historyLogSummary(d);
  document.querySelectorAll('.history-log-tab').forEach(b=>b.classList.toggle('active',b.dataset.logTab===activeHistoryLogTab));
}

async function openHistoryLog(id){
  const panel=document.getElementById('attackHistoryLogPanel'),content=document.getElementById('attackHistoryLogContent');
  panel.style.display='';
  content.textContent='Carregando log persistido...';
  try{
    activeHistoryLog=await api(`/api/attack-simulator/history/${id}/log`);
    activeHistoryLogTab='summary';
    const e=activeHistoryLog.execution||{};
    document.getElementById('attackHistoryLogTitle').textContent=`Log — ${e.task_key||'Execução'}`;
    document.getElementById('attackHistoryLogSubtitle').textContent=`Runner Job ${e.runner_job_id||'--'} · ${e.target||'--'}`;
    renderHistoryLog();
    panel.scrollIntoView({behavior:'smooth',block:'start'});
  }catch(e){content.textContent=e.message;}
}

async function loadHistory(){
  const d=await api('/api/attack-simulator/history?limit=100'),rows=d.executions||[];
  document.getElementById('attackHistoryTable').innerHTML=rows.map(r=>{
    const e=r.evidence||{},meta=e.metadata||{},result=meta.attack_result||e.attack_result||r.finding_status;
    const provider=meta.provider||e.provider||((r.task_key||'').startsWith('MAGI-M-ATK-')?'metasploit':'magi_native');
    const normalized=meta.normalized_evidence||e.normalized_evidence||{};
    const detail=Object.keys(normalized).length?`<br><small>${esc(JSON.stringify(normalized))}</small>`:'';
    return `<tr><td>${esc(r.id)}</td><td><strong>${esc(r.task_key)}</strong><br><small>${esc(r.task_name)}</small></td><td>${esc(providerLabel(provider))}</td><td>${esc(r.category)}</td><td>${esc(r.target)}${e.secondary_target?' → '+esc(e.secondary_target):''}</td><td>${badge(r.status)}<br><small>Runner ${esc(r.runner_id||'--')} / Job ${esc(r.runner_job_id||'--')}</small></td><td>${badge(result)}<br><small>${esc(r.finding_message||'')}</small>${detail}</td><td>${esc(r.created_at)}</td><td><button class="btn secondary btn-sm atk-history-log" data-id="${esc(r.id)}">Log</button></td></tr>`;
  }).join('')||'<tr><td colspan="9">Nenhuma execução.</td></tr>';
  document.querySelectorAll('.atk-history-log').forEach(b=>b.onclick=()=>openHistoryLog(b.dataset.id));
}
async function syncCatalog(){const out=document.getElementById('attackResult');out.textContent='Sincronizando catálogo...';try{out.textContent=pretty(await api('/api/attack-simulator/sync',{method:'POST'}));await Promise.all([loadSummary(),loadCatalog()]);}catch(e){out.textContent=e.message;}}
function updateAttackTargetFields(){
  // Both are intentionally visible: the catalog can show multiple categories at once.
  // executionPayload chooses URL only for Application techniques.
  const urlField=document.getElementById('attackUrlField');
  const targetField=document.getElementById('attackTargetField');
  if(urlField)urlField.style.display='';
  if(targetField)targetField.style.display='';
}

document.addEventListener('DOMContentLoaded',()=>{
  buildHeader('attack');addAttackFieldIcons();loadSummary();loadCredentials();loadCatalog();loadHistory();loadProviderStatus();updateAttackTargetFields();
  document.getElementById('attackSearch').addEventListener('input',loadCatalog);
  document.getElementById('attackCategory').addEventListener('change',()=>{loadCatalog();updateAttackTargetFields();});
  document.getElementById('attackProvider')?.addEventListener('change',loadCatalog);
  document.getElementById('attackCatalogPrev')?.addEventListener('click',()=>{attackCatalogPage--;renderAttackCatalog();});
  document.getElementById('attackCatalogNext')?.addEventListener('click',()=>{attackCatalogPage++;renderAttackCatalog();});
  document.getElementById('attackCatalogPageSize')?.addEventListener('change',e=>{attackCatalogPageSize=Number(e.target.value)||25;attackCatalogPage=1;renderAttackCatalog();});
  document.getElementById('refreshAttackHistory').onclick=loadHistory;
  document.querySelectorAll('.attack-nav-item').forEach(b=>b.onclick=()=>switchAttackView(b.dataset.view));
  document.querySelectorAll('.history-log-tab').forEach(b=>b.onclick=()=>{activeHistoryLogTab=b.dataset.logTab;renderHistoryLog();});
  const closeLog=document.getElementById('closeAttackHistoryLog');if(closeLog)closeLog.onclick=()=>{document.getElementById('attackHistoryLogPanel').style.display='none';};
  switchAttackView('attack');
});

function copyCredentialsToCampaign(){}
function dtLocal(v){if(!v)return '--';try{return new Date(v).toLocaleString();}catch(_e){return v;}}
let campaignListRows=[];
let activeCampaignId=null;
function campaignRoute(id){return '#campaign/'+encodeURIComponent(id);}
function closeCampaignPage(){activeCampaignId=null;const list=document.querySelector('#campaignPanel .magi-campaign-section');const create=document.querySelector('#campaignPanel .magi-campaign-create-section');if(list)list.classList.remove('magi-campaign-list-hidden');if(create)create.classList.remove('magi-campaign-list-hidden');const detail=document.getElementById('campaignDetail');if(detail){detail.innerHTML='';detail.classList.remove('magi-campaign-standalone');}if(location.hash.startsWith('#campaign/'))history.pushState(null,'','#campaign');}
function openCampaignPage(id){activeCampaignId=id;const list=document.querySelector('#campaignPanel .magi-campaign-section');const create=document.querySelector('#campaignPanel .magi-campaign-create-section');if(list)list.classList.add('magi-campaign-list-hidden');if(create)create.classList.add('magi-campaign-list-hidden');const detail=document.getElementById('campaignDetail');detail.classList.add('magi-campaign-standalone');document.getElementById('campaignPanel').appendChild(detail);if(location.hash!==campaignRoute(id))history.pushState(null,'',campaignRoute(id));}

let campaignPage=1;
let campaignPageSize=25;
function renderCampaignList(){
  const rows=campaignListRows;const totalPages=Math.max(1,Math.ceil(rows.length/campaignPageSize));campaignPage=Math.min(Math.max(1,campaignPage),totalPages);
  const count=document.getElementById('campaignListCount');if(count)count.textContent=rows.length+' Campaign'+(rows.length===1?'':'s');
  const tbody=document.getElementById('campaignTable');if(!tbody)return;
  tbody.innerHTML=rows.slice((campaignPage-1)*campaignPageSize,campaignPage*campaignPageSize).map(c=>{
    const st=c.execution_stats||{},scope=(c.scope_cidrs||[]).join(', '),id=esc(c.campaign_uuid),status=String(c.execution_status||c.status||'').toLowerCase();
    const completed=['completed','cancelled','finished','ended'].includes(status),paused=status.includes('paus'),running=['running','active','monitoring','in_progress'].some(x=>status.includes(x));
    return `<tr><td><button class="magi-camp-name camp-view" data-id="${id}" type="button">${esc(c.name)}</button><br><small>${esc(c.campaign_uuid)}</small></td><td>${esc(scope)}</td><td>${badge(c.execution_status||c.status)}<br><small>Execução #${esc(c.execution_number||1)}</small></td><td>${esc(dtLocal(c.scheduled_start||c.start_at))}<br><small>até ${esc(dtLocal(c.scheduled_end||c.end_at))}</small></td><td>${esc(st.discovered||0)} hosts · ${esc(st.accessed||0)} acessos<br><small>${esc(st.confirmed||0)} caminhos</small></td><td>${esc(dtLocal(c.next_cycle_at))}</td><td><div class="magi-camp-actions"><button class="btn primary btn-sm camp-view" data-id="${id}">Detalhes</button> <button class="btn secondary btn-sm camp-monitor" data-id="${id}">Monitoring</button> ${!completed&&!paused?`<button class="btn secondary btn-sm camp-pause" data-id="${id}">Pausar</button>`:''}${!completed&&paused?`<button class="btn primary btn-sm camp-resume" data-id="${id}">Retomar</button>`:''}<details class="magi-camp-more"><summary aria-label="Mais ações">•••</summary><div class="magi-camp-menu"><button class="camp-edit" data-id="${id}">Ajustar</button><button class="camp-next" data-id="${id}">Próximo ciclo agora</button>${completed?`<button class="camp-new-execution" data-id="${id}">Nova execução</button>`:''}<button class="camp-finish" data-id="${id}">Encerrar Campaign</button><button class="camp-delete" data-id="${id}">Excluir</button></div></details></div></td></tr>`;
  }).join('')||'<tr><td colspan="7">Nenhuma Campaign.</td></tr>';
  const pageInfo=document.getElementById('campaignPageInfo');if(pageInfo)pageInfo.textContent=`Página ${campaignPage} de ${totalPages}`;
  const prev=document.getElementById('campaignPagePrev'),next=document.getElementById('campaignPageNext');if(prev)prev.disabled=campaignPage<=1;if(next)next.disabled=campaignPage>=totalPages;
  for(const [cls,fn] of [['camp-view',viewCampaign],['camp-monitor',monitorCampaign],['camp-edit',editCampaign],['camp-next',nextCampaignCycle],['camp-pause',id=>campaignAction(id,'pause')],['camp-resume',id=>campaignAction(id,'resume')],['camp-new-execution',newCampaignExecution],['camp-finish',finishCampaign],['camp-delete',deleteCampaign]]){
    tbody.querySelectorAll('.'+cls).forEach(el=>el.onclick=()=>fn(el.dataset.id));
  }
}
async function loadCampaigns(){
  try{const d=await api('/api/attack-simulator/campaigns');campaignListRows=d.campaigns||[];renderCampaignList();}
  catch(e){document.getElementById('campaignResult').textContent=e.message;}
}

let dhcpIntegrations=[];
async function loadDhcpIntegrationsForCampaign(){try{const d=await api('/api/settings');dhcpIntegrations=d?.integrations?.dhcp||[];const el=document.getElementById('campaignDhcpIntegration');if(el)el.innerHTML='<option value="">Selecione um DHCP configurado</option>'+dhcpIntegrations.filter(x=>x.enabled!==false).map(x=>`<option value="${esc(x.id)}">${esc(x.name)} — ${esc(x.server)}</option>`).join('');}catch(_e){}}
function selectedDhcpIntegration(){const id=document.getElementById('campaignDhcpIntegration')?.value;return dhcpIntegrations.find(x=>String(x.id)===String(id));}

async function createCampaign(){
  const out=document.getElementById('campaignResult');
  const seeds=['campaignSeed1','campaignSeed2','campaignSeed3'].map(id=>document.getElementById(id).value.trim()).filter(Boolean);
  const scopes=document.getElementById('campaignScope').value.split(',').map(x=>x.trim()).filter(Boolean);
  const body={name:document.getElementById('campaignName').value.trim(),scope_cidrs:scopes,initial_seeds:seeds,windows_credential_ids:Array.from(document.getElementById('campaignCredential').selectedOptions).map(o=>Number(o.value)).filter(Boolean),snmp_credential_id:document.getElementById('campaignSnmpCredential').value||null,dhcp_enabled:!!document.getElementById('campaignDhcpEnabled')?.checked,dhcp_integration_id:document.getElementById('campaignDhcpIntegration')?.value||null,dhcp_server:selectedDhcpIntegration()?.server||null,dhcp_credential_id:selectedDhcpIntegration()?.credential_id||null,enabled_vectors:['winrm','smb','snmp_v2c'].filter(v=>document.getElementById('vec_'+v)?.checked),snmp_topology_enabled:!!document.getElementById('campaignSnmpTopology')?.checked,create_benign_evidence:!!document.getElementById('campaignEvidence')?.checked,start_at:document.getElementById('campaignStart').value,end_at:document.getElementById('campaignEnd').value,daily_start:document.getElementById('campaignDailyStart').value,daily_end:document.getElementById('campaignDailyEnd').value,cycle_interval_minutes:15,cycle_timeout_minutes:15,recurrence_days:document.getElementById('campaignRecurrence').value||null,max_seeds_per_cycle:3,branch_policy:[10,5,3,0],max_paths_per_cycle:60,max_outstanding_jobs:5,snapshot_retention:10};
  if(!body.name||!scopes.length||!seeds.length||!body.start_at||!body.end_at){out.textContent='Nome, scope, ao menos um Host A, início e término são obrigatórios.';return;}if(!body.windows_credential_ids.length&&!body.snmp_credential_id&&!body.dhcp_enabled){out.textContent='Selecione ao menos uma credencial Windows/SNMP ou habilite Windows DHCP.';return;}if(body.dhcp_enabled&&!body.dhcp_integration_id){out.textContent='Selecione uma integração DHCP configurada.';return;}if(!body.enabled_vectors.length){out.textContent='Selecione ao menos um vetor.';return;}
  const editing=!!editingCampaignId;
  if(!confirm(`${editing?'Ajustar':'Criar'} Campaign ${body.name} para ${scopes.join(', ')}?${editing?' O histórico será preservado.':''}`))return;
  out.textContent=editing?'Ajustando Campaign...':'Criando Campaign...';
  try{
    const url=editing?`/api/attack-simulator/campaigns/${editingCampaignId}`:'/api/attack-simulator/campaigns';
    const d=await api(url,{method:editing?'PATCH':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    out.textContent=pretty(d);editingCampaignId=null;const btn=document.getElementById('createCampaign');if(btn)btn.textContent='Criar Campaign';await loadCampaigns();
  }catch(e){out.textContent=e.message;}
}

async function editCampaign(id){
  try{
    const d=await api(`/api/attack-simulator/campaigns/${id}`),c=d.campaign||{};
    editingCampaignId=id;
    document.getElementById('campaignName').value=c.name||'';
    document.getElementById('campaignScope').value=(c.scope_cidrs||[]).join(', ');
    const seeds=c.initial_seeds||[];['campaignSeed1','campaignSeed2','campaignSeed3'].forEach((x,i)=>document.getElementById(x).value=seeds[i]||'');
    Array.from(document.getElementById('campaignCredential').options).forEach(o=>o.selected=(c.windows_credential_ids||[c.credential_id]).map(Number).includes(Number(o.value)));
    document.getElementById('campaignSnmpCredential').value=c.snmp_credential_id||'';if(document.getElementById('campaignDhcpEnabled'))document.getElementById('campaignDhcpEnabled').checked=!!c.dhcp_enabled;const di=document.getElementById('campaignDhcpIntegration');if(di){const hit=dhcpIntegrations.find(x=>x.server===c.dhcp_server&&Number(x.credential_id)===Number(c.dhcp_credential_id));di.value=hit?.id||'';}
    ['winrm','smb','snmp_v2c'].forEach(v=>{const el=document.getElementById('vec_'+v);if(el)el.checked=(c.enabled_vectors||[]).includes(v);});
    if(document.getElementById('campaignEvidence'))document.getElementById('campaignEvidence').checked=!!c.create_benign_evidence; if(document.getElementById('campaignSnmpTopology'))document.getElementById('campaignSnmpTopology').checked=c.snmp_topology_enabled!==false;
    const localInput=v=>v?String(v).slice(0,16):'';
    document.getElementById('campaignStart').value=localInput(c.start_at);
    document.getElementById('campaignEnd').value=localInput(c.end_at);
    document.getElementById('campaignDailyStart').value=String(c.daily_start||'08:00').slice(0,5);
    document.getElementById('campaignDailyEnd').value=String(c.daily_end||'18:00').slice(0,5);
    document.getElementById('campaignRecurrence').value=c.recurrence_days||'';
    document.getElementById('createCampaign').textContent='Salvar ajustes';setCampaignCreatorOpen(true);
    document.getElementById('campaignResult').textContent='Editando Campaign existente. Histórico, assets e paths serão preservados.';
  }catch(e){document.getElementById('campaignResult').textContent=e.message;}
}
async function nextCampaignCycle(id){
  if(!confirm('Encerrar o trabalho pendente do ciclo atual e iniciar o próximo ciclo agora?'))return;
  try{const d=await api(`/api/attack-simulator/campaigns/${id}/next-cycle`,{method:'POST'});document.getElementById('campaignResult').textContent=pretty(d);await loadCampaigns();await viewCampaign(id);}catch(e){document.getElementById('campaignResult').textContent=e.message;}
}
async function deleteCampaign(id){
  if(!confirm('Excluir esta Campaign? Jobs pendentes serão cancelados. O histórico bruto já concluído do Runner não será alterado.'))return;
  try{const d=await api(`/api/attack-simulator/campaigns/${id}`,{method:'DELETE'});document.getElementById('campaignResult').textContent=pretty(d);if(editingCampaignId===id){editingCampaignId=null;document.getElementById('createCampaign').textContent='Criar Campaign';}await loadCampaigns();}catch(e){document.getElementById('campaignResult').textContent=e.message;}
}

async function campaignAction(id,action){try{await api(`/api/attack-simulator/campaigns/${id}/${action}`,{method:'POST'});await loadCampaigns();await viewCampaign(id);}catch(e){document.getElementById('campaignResult').textContent=e.message;}}
let selectedCampaignTab='summary';
function campaignCoverageData(c){
  const leases=Array.isArray(c.dhcp_leases)?c.dhcp_leases:[],cov=Array.isArray(c.coverage)?c.coverage:[];
  const reference=new Set(leases.map(x=>x.ip_address).filter(Boolean));
  const covered=new Set(cov.filter(x=>x.reached&&reference.has(x.ip_address)).map(x=>x.ip_address));
  const outside=new Set(cov.filter(x=>x.reached&&x.ip_address&&!reference.has(x.ip_address)).map(x=>x.ip_address));
  return {reference,covered,outside,pct:reference.size?Math.round(100*covered.size/reference.size):null};
}
function campaignGauge(data){
  if(data.pct===null)return '<div class="magi-coverage-unavailable">Cobertura indisponível<br><small>Sem referência DHCP nesta execução.</small></div>';
  return `<div class="magi-coverage-gauge" role="img" aria-label="Cobertura DHCP ${data.pct}%"><svg viewBox="0 0 200 120" aria-hidden="true"><path d="M25 103 A75 75 0 0 1 175 103" pathLength="100" class="magi-gauge-track"/><path d="M25 103 A75 75 0 0 1 175 103" pathLength="100" class="magi-gauge-fill" style="stroke-dasharray:${data.pct} 100"/><text x="100" y="94" text-anchor="middle" class="magi-gauge-value">${data.pct}%</text></svg></div>`;
}
async function viewCampaign(id){
  try{
    const d=await api(`/api/attack-simulator/campaigns/${id}`),c=d.campaign||{},ex=(c.executions||[])[0]||{};
    const data=campaignCoverageData(c),stats=ex.stats||c.execution_stats||{};
    const detail=document.getElementById('campaignDetail');
    openCampaignPage(id);
    detail.innerHTML=`<div class="magi-camp-detail-header"><div><h3>${esc(c.name||'Campaign')}</h3><small>${esc((c.scope_cidrs||[]).join(', '))} · Execução #${esc(ex.execution_number||c.execution_number||'--')}</small></div><button type="button" class="btn secondary btn-sm" id="closeCampaignDetails">Fechar detalhes</button></div>
      <div class="magi-camp-detail-grid"><div class="magi-camp-stat"><small>Hosts descobertos</small><strong>${esc(stats.discovered??stats.hosts_known??(c.assets||[]).length??0)}</strong></div><div class="magi-camp-stat"><small>Acessos confirmados</small><strong>${esc(stats.accessed??stats.access_confirmed??0)}</strong></div><div class="magi-camp-stat"><small>Ciclos executados</small><strong>${esc(stats.cycles??(c.cycles||[]).length)}</strong></div><div class="magi-camp-stat magi-camp-stat-coverage"><div><small>Cobertura DHCP</small><strong>${data.pct===null?'Indisponível':data.pct+'%'}</strong><small>${data.covered.size} / ${data.reference.size} IPs da referência</small></div>${campaignGauge(data)}</div></div>
      <p class="magi-camp-footnote">Cobertura = IPs únicos da referência DHCP alcançados pela Campaign. Alcance não comprova autenticação.</p>
      <div class="ap-tabs magi-camp-tabs" role="tablist" aria-label="Detalhes da Campaign">${[['summary','Overview'],['path','Attack Path'],['network','Rede'],['coverage','Cobertura'],['evidence','Evidências'],['cycles','Ciclos'],['history','Histórico']].map(([key,label])=>`<button type="button" class="btn secondary btn-sm ap-tab" role="tab" data-tab="${key}">${label}</button>`).join('')}</div>
      <div id="attackPathPanel" class="ap-panel">Carregando resultados...</div>`;
    document.getElementById('closeCampaignDetails').onclick=closeCampaignPage;
    detail.querySelectorAll('.ap-tab').forEach(btn=>btn.onclick=()=>activateCampaignTab(id,btn.dataset.tab,c));
    await activateCampaignTab(id,'summary',c);
    detail.scrollIntoView({behavior:'smooth',block:'start'});
  }catch(e){document.getElementById('campaignResult').textContent=e.message;}
}
async function activateCampaignTab(id,tab,c){
  selectedCampaignTab=tab;
  document.querySelectorAll('#campaignDetail .ap-tab').forEach(b=>{const active=b.dataset.tab===tab;b.classList.toggle('primary',active);b.classList.toggle('secondary',!active);b.setAttribute('aria-selected',String(active));});
  await renderCampaignTab(id,tab,c);
}

function campaignEvidenceFailure(e){const value=[e.result,e.reason,e.status,e.error,e.error_code,e.evidence?.status,e.evidence?.reason].filter(x=>x!==undefined&&x!==null).map(x=>typeof x==='object'?JSON.stringify(x):String(x)).join(' ').toLowerCase();return /discovery_not_confirmed|not.confirmed|no icmp echo reply|timeout|timed.out|connection.refused|auth.failed|access.denied|unreachable|failed|error/.test(value);}
function campaignEvidenceLabel(e){if(e.kind==='DISCOVERY')return campaignEvidenceFailure(e)?'✕ DESCOBERTA NÃO CONFIRMADA':'DESCOBERTA REGISTRADA';return attackKindLabel(e.kind);}
function campaignEvidenceClass(e){if(e.kind==='DISCOVERY')return campaignEvidenceFailure(e)?'ap-badge-danger':'ap-badge-neutral';return attackKindClass(e.kind);}
function campaignFailureHint(e){const msg=[e.reason,e.result,e.error,e.error_code].filter(Boolean).map(x=>typeof x==='object'?JSON.stringify(x):String(x)).join(' ');if(/no icmp echo reply/i.test(msg))return 'ICMP sem resposta. Isso não comprova que o host está desligado; SMB, WinRM e autenticação exigem testes independentes.';if(/timeout|timed.out/i.test(msg))return 'Tempo limite excedido. A causa exata depende dos registros do Runner e da conectividade.';if(/connection refused/i.test(msg))return 'Conexão recusada pelo destino ou por um intermediário.';if(/auth|access denied|logon failure/i.test(msg))return 'Falha de autenticação ou autorização informada pelo teste.';return campaignEvidenceFailure(e)?'A tentativa não foi confirmada. Consulte o motivo e os dados técnicos registrados.':'Não há falha específica registrada neste evento.';}
function attackKindLabel(k){return ({ACCESS:'✓ ACCESS CONFIRMED',SNMP:'✓ SNMP DISCOVERY CONFIRMED',AUTHENTICATION_FAILED:'✕ AUTHENTICATION FAILED',TRANSPORT_FAILED:'✕ TRANSPORT FAILED',SERVICE_UNAVAILABLE:'✕ SERVICE UNAVAILABLE',BARRIER:'✕ BARRIER',DISCOVERY:'✓ DISCOVERY CONFIRMED'})[k]||k;}
function attackKindClass(k){return ['ACCESS','DISCOVERY','SNMP'].includes(k)?'ap-badge-success':['AUTHENTICATION_FAILED','TRANSPORT_FAILED','SERVICE_UNAVAILABLE','BARRIER'].includes(k)?'ap-badge-danger':'ap-badge-neutral';}
async function renderCampaignTab(id,tab,cached){
  const panel=document.getElementById('attackPathPanel'); if(!panel)return;
  try{
    if(tab==='cycles'){
      const cycles=cached.cycles||[];
      panel.innerHTML=`<h4>Ciclos da Campaign</h4><div class="magi-camp-records">${cycles.map((x,i)=>`<div class="ap-panel"><strong>Ciclo ${esc(x.cycle_number??x.number??i+1)}</strong><br><small>${esc(dtLocal(x.started_at||x.start_at||x.created_at))} · ${esc(x.status||'--')}</small><details><summary>Dados técnicos</summary><pre>${esc(pretty(x))}</pre></details></div>`).join('')||'<p>Nenhum ciclo registrado.</p>'}</div>`;return;
    }
    if(tab==='history'){
      const runs=cached.executions||[];
      panel.innerHTML=`<h4>Histórico de execuções</h4><p>Execuções disponíveis para esta Campaign, sem mesclar evidências de outras campanhas.</p><div class="magi-camp-records">${runs.map((x,i)=>`<div class="ap-panel"><strong>Execução #${esc(x.execution_number??i+1)}</strong> · ${esc(x.status||x.execution_status||'--')}<br><small>Início: ${esc(dtLocal(x.started_at||x.start_at||x.created_at))} · Fim: ${esc(dtLocal(x.finished_at||x.ended_at))}</small><details><summary>Detalhes registrados</summary><pre>${esc(pretty(x.stats||x))}</pre></details></div>`).join('')||'<p>Nenhuma execução registrada.</p>'}</div>`;return;
    }
    const d=await api(`/api/attack-simulator/campaigns/${id}/attack-path`),a=d.attack_path||{},sum=a.summary||{},edges=a.edges||[];
    if(tab==='summary'){
      panel.innerHTML=`<h4>Resumo da Campaign</h4><div class="ap-kpis">
        <div><small>IPs avaliados</small><br><strong>${esc(sum.ips_evaluated||0)}</strong></div>
        <div><small>Hosts conhecidos</small><br><strong>${esc(sum.hosts_known||0)}</strong></div>
        <div><small>Acessos confirmados</small><br><strong>${esc(sum.access_confirmed||0)}</strong></div>
        <div><small>Maior hop</small><br><strong>${esc(sum.max_hop||0)}</strong></div>
        <div><small>SNMP</small><br><strong>${esc(sum.snmp_discovered||0)}</strong></div>
        <div><small>Barreiras</small><br><strong>${esc(sum.barriers||0)}</strong></div>
        <div><small>Cycles</small><br><strong>${esc(sum.cycles||0)}</strong></div></div>
        <p><strong>Acessos por protocolo:</strong> ${esc(pretty(sum.confirmed_by_protocol||{}))}</p>
        <p><strong>Encerramento/estado:</strong> ${esc(sum.stop_reason||'--')}</p>`;return;
    }
    if(tab==='network'){
      const snmp=(a.evidence||[]).filter(e=>e.kind==='SNMP'||(e.evidence||{}).snmp_confirmed);
      const neighbors=[];snmp.forEach(e=>((e.evidence||{}).snmp_neighbors||[]).forEach(n=>neighbors.push({device:e.target,protocol:n.protocol,neighbor:n.neighbor_name})));
      panel.innerHTML=`<h4>Network Intelligence</h4><p>SNMP é tratado como descoberta de topologia, não como lateral movement.</p><div class="ap-kpis"><div><small>Dispositivos SNMP</small><br><strong>${snmp.length}</strong></div><div><small>Neighbors LLDP/CDP</small><br><strong>${neighbors.length}</strong></div></div><div class="ap-evidence">${neighbors.map(n=>`<div class="ap-panel"><strong>${esc(n.device)} → ${esc(n.neighbor)}</strong><br><small>${esc(String(n.protocol||'').toUpperCase())}</small></div>`).join('')||'<p>Nenhum neighbor LLDP/CDP retornado pelos dispositivos SNMP desta execução.</p>'}</div>`;return;
    }
    if(tab==='coverage'){
      const cov=cached.coverage||[],leases=cached.dhcp_leases||[],known=cov.length,reached=cov.filter(x=>x.reached).length,evaluated=cov.filter(x=>x.evaluated).length,notReached=cov.filter(x=>!x.reached).length,pending=cov.filter(x=>!x.evaluated).length,pct=known?((evaluated/known)*100).toFixed(1):'Indisponível';const cd=campaignCoverageData(cached),dhcpFound=cd.covered.size,dhcpPct=cd.pct===null?'Indisponível':cd.pct.toFixed(1)+'%',outsideDhcp=cd.outside.size;
      panel.innerHTML=`<h4>Campaign Coverage Intelligence</h4><p>Coverage considera ativos conhecidos por Campaign e Windows DHCP. DHCP lease não significa host online.</p><div class="ap-kpis"><div><small>Known assets</small><br><strong>${known}</strong></div><div><small>Reached</small><br><strong>${reached}</strong></div><div><small>Evaluated</small><br><strong>${evaluated}</strong></div><div><small>Not reached</small><br><strong>${notReached}</strong></div><div><small>Pending</small><br><strong>${pending}</strong></div><div><small>Known-asset coverage</small><br><strong>${pct}%</strong></div></div><div class="ap-kpis"><div><small>DHCP entregou</small><br><strong>${cd.reference.size} IPs</strong></div><div><small>Campaign encontrou desses</small><br><strong>${dhcpFound} / ${cd.reference.size}</strong></div><div><small>DHCP coverage</small><br><strong>${dhcpPct}</strong></div><div><small>Encontrados fora do DHCP</small><br><strong>${outsideDhcp}</strong></div></div><p><strong>Snapshot DHCP:</strong> leases capturadas no início desta execução; alterações posteriores não mudam retroativamente este denominador.</p><div class="ap-evidence">${cov.map(x=>`<div class="ap-panel"><strong>${esc(x.hostname||x.ip_address)}</strong> — ${esc(x.ip_address)}<br><small>Sources: ${esc((x.sources||[]).join(', '))} | State: ${esc(x.state)} | Reached: ${x.reached?'yes':'no'} | Evaluated: ${x.evaluated?'yes':'no'}</small></div>`).join('')||'<p>Coverage ainda não possui observações.</p>'}</div>`;return;
    }
    if(tab==='evidence'){
      const records=a.evidence||[];
      const observed=new Set(records.map(e=>String(e.target||'').trim()).filter(Boolean));
      const missed=(cached.coverage||[]).filter(x=>!x.reached&&!observed.has(String(x.ip_address||'').trim()));
      panel.innerHTML=`<h4>Diagnóstico e evidências por host</h4><p>Somente testes registrados são classificados. Ausência de ICMP não equivale a host offline; protocolos não executados permanecem sem resultado.</p><div class="ap-evidence">${records.map(e=>`<div class="ap-panel"><span class="ap-badge ${campaignEvidenceClass(e)}">${esc(campaignEvidenceLabel(e))}</span> <strong>${esc(e.origin||'Runner')} → ${esc(e.target||'Destino não informado')}</strong><br><small><strong>Protocolo:</strong> ${esc(e.protocol||'Não informado')} | <strong>Ciclo:</strong> ${esc(e.cycle_id??'Não informado')} | <strong>Runner Job:</strong> ${esc(e.runner_job_id??'Não informado')} | <strong>Hop:</strong> ${esc(e.hop??'--')}</small><p><strong>Diagnóstico:</strong> ${esc(campaignFailureHint(e))}</p>${e.reason?`<p><strong>Motivo original:</strong> ${esc(e.reason)}</p>`:''}${e.result?`<details><summary>Resultado técnico do Runner</summary><pre>${esc(typeof e.result==='object'?pretty(e.result):String(e.result))}</pre></details>`:''}</div>`).join('')}${missed.map(x=>`<div class="ap-panel"><span class="ap-badge ap-badge-neutral">SEM ALCANCE CONFIRMADO</span> <strong>${esc(x.hostname||x.ip_address||'Host')}</strong> — ${esc(x.ip_address||'--')}<p>Ativo conhecido por ${esc((x.sources||[]).join(', ')||'inventário')}, mas não alcançado. Não há evidência de falha específica neste conjunto de resultados.</p><small>ICMP / SMB / WinRM / autenticação: sem resultados individuais disponíveis.</small></div>`).join('')}${!records.length&&!missed.length?'<p>Nenhuma evidência de execução disponível.</p>':''}</div>`;return;
    }
    const visible=edges.filter(e=>['ACCESS','SNMP','AUTHENTICATION_FAILED','TRANSPORT_FAILED','SERVICE_UNAVAILABLE','BARRIER'].includes(e.kind));
    panel.innerHTML=`<h4>Attack Path — somente esta Campaign / Execution #${esc(a.execution_number||'--')}</h4>
      <p>O grafo abaixo não mistura resultados de outras Campaigns. Falhas relevantes são exibidas como barreiras.</p>
      <div class="ap-graph"><div class="ap-row"><span class="ap-node">MAGI Runner</span></div>
      ${visible.map(e=>`<div class="ap-row"><span class="ap-node">${esc(e.origin)}</span><span class="ap-edge">── ${esc(e.protocol||e.relation_type||'path')} / ${esc(attackKindLabel(e.kind))} ──►</span><span class="ap-node">${esc(e.target)}</span>${e.reason?`<span><strong>Motivo:</strong> ${esc(e.reason)}</span>`:''}</div>`).join('')||'<p>Nenhum path relevante consolidado ainda.</p>'}</div>
      <div class="ap-kpis"><div><small>Acessos</small><br><strong>${esc(sum.access_confirmed||0)}</strong></div><div><small>Maior hop</small><br><strong>${esc(sum.max_hop||0)}</strong></div><div><small>Barreiras</small><br><strong>${esc(sum.barriers||0)}</strong></div></div>`;
  }catch(e){panel.textContent=e.message;}
}

window.addEventListener('load',()=>{setTimeout(()=>{copyCredentialsToCampaign();loadDhcpIntegrationsForCampaign();loadCampaigns().then(()=>{const match=location.hash.match(/^#campaign\/(.+)$/);if(match)viewCampaign(decodeURIComponent(match[1]));});const rc=document.getElementById('refreshCampaigns'),cc=document.getElementById('createCampaign');if(rc)rc.onclick=loadCampaigns;if(cc)cc.onclick=createCampaign;document.getElementById('campaignPageSize')?.addEventListener('change',e=>{campaignPageSize=Number(e.target.value)||25;campaignPage=1;renderCampaignList();});document.getElementById('campaignPagePrev')?.addEventListener('click',()=>{campaignPage--;renderCampaignList();});document.getElementById('campaignPageNext')?.addEventListener('click',()=>{campaignPage++;renderCampaignList();});},250);});

let correlationPlan=[];
async function loadCorrelationTargets(){
  const d=await api('/api/attack-simulator/correlation/targets');
  const el=document.getElementById('correlationTarget'); if(!el)return;
  const cur=el.value; el.innerHTML='<option value="">Selecione um ativo</option>'+(d.items||[]).map(x=>`<option value="${esc(x.target_uuid)}">${esc(x.asset_type==='Web'?'WEB':'HOST')} · ${esc(x.name)} — ${esc(x.address||x.ip_address)} — ${esc(x.asset_type||'Asset')}</option>`).join('');
  if(cur)el.value=cur;
}
async function loadCorrelationPlan(){
  const id=document.getElementById('correlationTarget')?.value; if(!id)return;
  const d=await api(`/api/attack-simulator/correlation/${id}/plan`); correlationPlan=d.simulations||[];
  document.getElementById('correlationAssetSummary').textContent=`${d.target.name} · ${d.target.ip_address} · ${d.target.asset_type||'Asset'} · ${d.total} simulações correlacionadas`;
  document.getElementById('correlationTable').innerHTML=correlationPlan.map(x=>`<tr><td><input class="corr-check" type="checkbox" value="${esc(x.technique_key)}" checked></td><td><strong>${esc(x.technique_key)}</strong><br><small>${esc(x.attack_name||'')}</small></td><td>${badge(x.impact)}</td><td>${esc(x.credential_requirement==='REQUIRED'?'Obrigatória':x.credential_requirement==='OPTIONAL'?'Opcional':'Não necessária')}</td><td>${esc(x.remote_evidence==='SUPPORTED'?'Remota suportada':'Log MAGI')}</td><td>${esc(x.state||'AVAILABLE')}</td><td>${Number(x.confidence||0)}%</td><td><small>${esc((x.reason?.checks||[]).filter(c=>c.matched).map(c=>`${c.type}:${Array.isArray(c.value)?c.value.join(','):c.value}`).join(' · ')||'Correlação do ativo')}</small></td></tr>`).join('')||'<tr><td colspan="8">Nenhuma simulação aplicável.</td></tr>';
  document.getElementById('correlationAll').checked=correlationPlan.length>0;
}
async function executeCorrelation(){
  const id=document.getElementById('correlationTarget').value; const techniques=[...document.querySelectorAll('.corr-check:checked')].map(x=>x.value); const out=document.getElementById('correlationResult');
  if(!id||!techniques.length){out.textContent='Selecione um ativo e ao menos uma técnica.';return;} if(!confirm(`Executar ${techniques.length} simulações correlacionadas?`))return;
  out.textContent='Criando execuções individuais...'; try{const d=await api(`/api/attack-simulator/correlation/${id}/execute`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({techniques,create_benign_evidence:!!document.getElementById('correlationEvidence')?.checked})});out.textContent=pretty(d);setTimeout(loadHistory,1200);}catch(e){out.textContent=e.message;}
}
document.addEventListener('DOMContentLoaded',()=>{loadCorrelationTargets();const t=document.getElementById('correlationTarget');if(t)t.onchange=loadCorrelationPlan;const r=document.getElementById('refreshCorrelation');if(r)r.onclick=async()=>{await loadCorrelationTargets();if(t.value)await loadCorrelationPlan()};const a=document.getElementById('correlationAll');if(a)a.onchange=()=>document.querySelectorAll('.corr-check').forEach(x=>x.checked=a.checked);const e=document.getElementById('executeCorrelation');if(e)e.onclick=executeCorrelation;});

async function loadAttackPaths(){
  const body=document.getElementById('attackPathRuns'); if(!body)return;
  try{const d=await api('/api/attack-simulator/attack-paths'); const rows=d.items||[];
    body.innerHTML=rows.map(x=>`<tr><td><strong>${esc(x.path_uuid)}</strong></td><td>${esc((x.metadata||{}).campaign_name||(x.metadata||{}).source||'manual')}</td><td>${badge(x.status)}</td><td>${esc(x.created_at||'--')}</td><td><button class="btn secondary btn-sm" onclick="viewAttackPath('${esc(x.path_uuid)}')">Ver telemetria</button></td></tr>`).join('')||'<tr><td colspan="5">Nenhum Attack Path registrado.</td></tr>';
  }catch(e){body.innerHTML=`<tr><td colspan="5">${esc(e.message)}</td></tr>`;}
}
async function viewAttackPath(id){
  const out=document.getElementById('attackPathTelemetry');
  try{const d=await api(`/api/attack-simulator/attack-paths/${id}`),edges=d.edges||[],events=d.telemetry||[];
    out.innerHTML=`<strong>${esc(id)}</strong><br><br><strong>Edges</strong><br>${edges.map(e=>`${esc(e.origin_address)} → ${esc(e.target_address)} · ${esc(e.protocol||'--')} · ${esc(e.state)}`).join('<br>')||'Nenhum edge.'}<br><br><strong>Path Telemetry</strong><br>${events.map(e=>`#${esc(e.sequence_no)} · hop ${esc(e.hop)} · ${esc(e.node_address)} · ${esc(e.event_type)} · ${esc(e.transport)}${e.relay_depth?`(${esc(e.relay_depth)})`:''}`).join('<br>')||'Nenhum sinal recebido.'}`;
  }catch(e){out.textContent=e.message;}
}
window.viewAttackPath=viewAttackPath;
document.addEventListener('DOMContentLoaded',()=>{const b=document.getElementById('refreshAttackPaths');if(b)b.onclick=loadAttackPaths;});

async function finishCampaign(id){
  if(!confirm('Encerrar esta Campaign agora? Os resultados coletados serão preservados, mas os IPs não avaliados permanecerão inconclusivos.'))return;
  try{await api(`/api/attack-simulator/campaigns/${encodeURIComponent(id)}/finish`,{method:'POST'});
    await loadCampaigns();await viewCampaign(id);
    const d=await api(`/api/attack-simulator/campaigns/${encodeURIComponent(id)}/baselines`);
    document.getElementById('campaignResult').textContent=pretty({message:'Campaign encerrada; baseline preservado',baselines:d.baselines});
  }catch(e){document.getElementById('campaignResult').textContent=e.message;}
}

async function newCampaignExecution(id){
  if(!confirm('Iniciar nova execução desta Campaign? O histórico e os baselines anteriores serão preservados.'))return;
  try{
    const d=await api(`/api/attack-simulator/campaigns/${encodeURIComponent(id)}/new-execution`,{method:'POST'});
    await loadCampaigns();await viewCampaign(id);
    document.getElementById('campaignResult').textContent=`Nova execução #${d.execution_number} agendada. Aguardando Runner disponível.`;
  }catch(e){document.getElementById('campaignResult').textContent=e.message;}
}

// 5.9: lightweight, opt-in monitoring. No authenticated probes.
async function monitorCampaign(id){
 const out=document.getElementById('campaignResult');
 try{
   const url=`/api/security-monitoring/campaigns/${encodeURIComponent(id)}`;
   const d=await api(url);
   const lines=(d.events||[]).slice(0,15).map(e=>`${e.created_at||''} · ${e.ip_address} · ${e.event_type}`);
   const alertLines=(d.alerts||[]).slice(0,10).map(a=>`#${a.id} · ${a.severity} · ${a.status} · ${a.ip_address} · ${a.event_type}`);
   out.textContent=`Alertas (últimos 10):\n${alertLines.join('\n')||'Nenhum'}\n\nMonitoring: ${d.enabled?'ATIVO':'DESATIVADO'}\nIntervalo: 60 min · Light · Sem autenticação · 2 confirmações\nExecuções: ${(d.runs||[]).length} (últimas 20)\nEventos:\n${lines.join('\n')||'Nenhum evento confirmado'}`;
   const openAlerts=(d.alerts||[]).filter(a=>a.status==='open');
   if(openAlerts.length && confirm(`Há ${openAlerts.length} alertas abertos. Gerenciar um alerta agora?`)){
     const selected=prompt('ID do alerta aberto (consulte a lista acima):');
     const alert=openAlerts.find(a=>String(a.id)===String(selected));
     if(!alert){out.textContent='ID de alerta aberto inválido.\n'+out.textContent;return;}
     const action=confirm('OK = Reconhecer alerta; Cancelar = Encerrar alerta')?'acknowledge':'close';
     await api(`${url}/alerts/${alert.id}/${action}`,{method:'POST'});
     out.textContent=`Alerta #${alert.id}: ${action==='acknowledge'?'reconhecido':'encerrado'}.\n`+out.textContent;
     return;
   }
   if(d.enabled && confirm('Executar Verificar agora?\nOK = iniciar verificação manual.\nCancelar = continuar para as opções do Monitoring.')){
     const manual=await api(`${url}/verify-now`,{method:'POST'});
     out.textContent=`${manual.message}\n`+out.textContent;
     return;
   }
   if(confirm(`${d.enabled?'Desativar':'Ativar'} Monitoring para esta Campaign?\nA cada 60 minutos o Runner verificará somente os hosts conhecidos do último baseline, sem credenciais.`)){
     const next=await api(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:!d.enabled})});
     out.textContent=`Monitoring ${next.enabled?'ativado':'desativado'}.\n`+out.textContent;
   }
 }catch(e){out.textContent='Monitoring: '+e.message;}
}

// MAGI 6.2.0 — Existing campaigns first; creator is secondary and collapsible.
function setCampaignCreatorOpen(open){
  const creator=document.getElementById('campaignCreator');
  if(!creator)return;
  creator.hidden=!open;
  ['openCampaignCreator','toggleCampaignCreator'].forEach(id=>{
    const b=document.getElementById(id);if(b)b.setAttribute('aria-expanded',String(open));
  });
  if(open){document.querySelector('.magi-campaign-create-section')?.scrollIntoView({behavior:'smooth',block:'start'});}
}
window.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('openCampaignCreator')?.addEventListener('click',()=>setCampaignCreatorOpen(true));
  document.getElementById('toggleCampaignCreator')?.addEventListener('click',()=>setCampaignCreatorOpen(!!document.getElementById('campaignCreator')?.hidden));
});
