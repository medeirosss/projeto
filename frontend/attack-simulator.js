function esc(v){return String(v??'--').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function pretty(v){return JSON.stringify(v,null,2);}
async function api(url,opts){const r=await fetch(url,opts);let d={};try{d=await r.json();}catch(_e){}if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);return d;}
function badge(v){const s=String(v||'').toLowerCase();const ok=['success','precondition_confirmed','lateral_movement_confirmed','confirmed'].includes(s);const bad=['failed','error','timeout','target_unreachable'].includes(s);return `<span class="badge ${ok?'badge-ok':bad?'badge-danger':'badge-muted'}">${esc(v||'--')}</span>`;}
let catalogById={};
let editingCampaignId=null;
async function loadSummary(){const d=await api('/api/attack-simulator/summary');document.getElementById('attackSimulationCount').textContent=d.simulations??0;}
async function loadCredentials(){try{const d=await api('/api/actions/credentials');const all=d.credentials||[];const windows=all.filter(c=>['windows','wmi','winrm'].includes(String(c.type||c.credential_type||'').toLowerCase()));const ssh=all.filter(c=>['ssh','linux'].includes(String(c.type||c.credential_type||'').toLowerCase()));const snmp=all.filter(c=>['snmp','snmp_v2c','snmpv2c'].includes(String(c.type||c.credential_type||'').toLowerCase()));const opts=(rows,empty)=>`<option value="">${empty}</option>`+rows.map(c=>`<option value="${esc(c.id)}">${esc(c.name)} — ${esc(c.domain?c.domain+'\\':'')}${esc(c.username||c.type||'')}</option>`).join('');document.getElementById('attackCredential').innerHTML=opts(windows,'Nenhuma / não necessária');const cw=document.getElementById('campaignCredential');if(cw)cw.innerHTML=opts(windows,'Sem credencial Windows');const cs=document.getElementById('campaignSshCredential');if(cs)cs.innerHTML=opts(ssh,'Sem credencial SSH');const cn=document.getElementById('campaignSnmpCredential');if(cn)cn.innerHTML=opts(snmp,'Sem community SNMP');}catch(_e){}}
async function loadCatalog(){const url=new URL('/api/attack-simulator/catalog',location.origin);const q=document.getElementById('attackSearch').value.trim();const c=document.getElementById('attackCategory').value;if(q)url.searchParams.set('search',q);if(c)url.searchParams.set('category',c);const d=await api(url);const rows=d.simulations||[];catalogById={};rows.forEach(r=>catalogById[String(r.id)]=r);document.getElementById('attackCatalogTable').innerHTML=rows.map(r=>{const req=(r.metadata||{}).credential_required?' <span class="badge badge-muted">Credential</span>':'';return `<tr><td><strong>${esc(r.task_key)} - ${esc(r.name)}</strong>${req}<br><small>${esc(r.description)}</small></td><td>${esc(r.category)}</td><td>${esc((r.metadata||{}).attack_phase)}</td><td>${badge(r.impact)}</td><td><code>${esc(JSON.stringify(r.detection||{}))}</code></td><td><button class="btn secondary btn-sm atk-plan" data-id="${r.id}">Planejar</button> <button class="btn primary btn-sm atk-run" data-id="${r.id}">Executar</button></td></tr>`}).join('')||'<tr><td colspan="6">Nenhuma simulação.</td></tr>';document.querySelectorAll('.atk-plan').forEach(b=>b.onclick=()=>runAttack(b.dataset.id,true));document.querySelectorAll('.atk-run').forEach(b=>b.onclick=()=>runAttack(b.dataset.id,false));}
function executionPayload(id){const task=catalogById[String(id)]||{},meta=task.metadata||{};const p={target:document.getElementById('attackTarget').value.trim(),host_b:document.getElementById('attackHostB').value.trim(),credential_id:document.getElementById('attackCredential').value||null,max_hops:Number(document.getElementById('attackMaxHops').value||3),max_branches_per_host:Number(document.getElementById('attackMaxBranches').value||3),max_total_hosts:Number(document.getElementById('attackMaxHosts').value||15),max_job_duration_minutes:Number(document.getElementById('attackMaxMinutes').value||30),allowed_networks:document.getElementById('attackAllowedNetworks').value.split(',').map(x=>x.trim()).filter(Boolean)};if(meta.secondary_target_required&&!p.host_b)throw new Error('Host B / Destination é obrigatório para esta simulação.');if(meta.credential_required&&!p.credential_id)throw new Error('Credential Profile é obrigatório para esta simulação.');return p;}
async function runAttack(id,plan){const out=document.getElementById('attackResult');let body;try{body=executionPayload(id);}catch(e){out.textContent=e.message;return;}if(!body.target){out.textContent='Host A / Target obrigatório.';return;}if(!plan&&!confirm(`Executar simulação controlada em ${body.target}${body.host_b?' → '+body.host_b:''}?`))return;out.textContent=plan?'Planejando...':'Enviando ao Runner...';try{const d=await api(`/api/attack-simulator/simulations/${id}/${plan?'plan':'execute'}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});out.textContent=pretty(d);if(!plan)setTimeout(loadHistory,1200);}catch(e){out.textContent=e.message;}}
async function loadHistory(){const d=await api('/api/attack-simulator/history?limit=100');const rows=d.executions||[];document.getElementById('attackHistoryTable').innerHTML=rows.map(r=>{const e=r.evidence||{};const result=e.attack_result||r.finding_status;return `<tr><td>${esc(r.id)}</td><td><strong>${esc(r.task_key)}</strong><br><small>${esc(r.task_name)}</small></td><td>${esc(r.category)}</td><td>${esc(r.target)}${e.secondary_target?' → '+esc(e.secondary_target):''}</td><td>${badge(r.status)}<br><small>teste/job</small></td><td>${badge(result)}<br><small>${esc(r.finding_message||'')}</small></td><td>${esc(r.created_at)}</td></tr>`}).join('')||'<tr><td colspan="7">Nenhuma execução.</td></tr>';}
async function syncCatalog(){const out=document.getElementById('attackResult');out.textContent='Sincronizando catálogo...';try{out.textContent=pretty(await api('/api/attack-simulator/sync',{method:'POST'}));await Promise.all([loadSummary(),loadCatalog()]);}catch(e){out.textContent=e.message;}}
document.addEventListener('DOMContentLoaded',()=>{buildHeader('attack');loadSummary();loadCredentials();loadCatalog();loadHistory();document.getElementById('attackSearch').addEventListener('input',loadCatalog);document.getElementById('attackCategory').addEventListener('change',loadCatalog);document.getElementById('refreshAttackHistory').onclick=loadHistory;document.getElementById('syncAttackCatalog').onclick=syncCatalog;});

function copyCredentialsToCampaign(){}
function dtLocal(v){if(!v)return '--';try{return new Date(v).toLocaleString();}catch(_e){return v;}}
async function loadCampaigns(){
  try{
    const d=await api('/api/attack-simulator/campaigns');const rows=d.campaigns||[];
    document.getElementById('campaignTable').innerHTML=rows.map(c=>{const st=c.execution_stats||{};const scope=(c.scope_cidrs||[]).join(', ');return `<tr><td><strong>${esc(c.name)}</strong><br><small>${esc(c.campaign_uuid)}</small></td><td>${esc(scope)}</td><td>${badge(c.execution_status||c.status)}<br><small>#${esc(c.execution_number||1)}</small></td><td>${esc(dtLocal(c.scheduled_start||c.start_at))}<br>→ ${esc(dtLocal(c.scheduled_end||c.end_at))}<br><small>${esc(c.daily_start)}–${esc(c.daily_end)}</small></td><td>${esc(st.discovered||0)} hosts<br>${esc(st.accessed||0)} acessados<br>${esc(st.confirmed||0)} paths</td><td>${esc(dtLocal(c.next_cycle_at))}</td><td><button class="btn secondary btn-sm camp-view" data-id="${esc(c.campaign_uuid)}">Ver</button> <button class="btn secondary btn-sm camp-edit" data-id="${esc(c.campaign_uuid)}">Ajustar</button> <button class="btn primary btn-sm camp-next" data-id="${esc(c.campaign_uuid)}">Próximo ciclo agora</button> <button class="btn secondary btn-sm camp-pause" data-id="${esc(c.campaign_uuid)}">Pausar</button> <button class="btn primary btn-sm camp-resume" data-id="${esc(c.campaign_uuid)}">Retomar</button> <button class="btn danger btn-sm camp-delete" data-id="${esc(c.campaign_uuid)}">Excluir</button></td></tr>`}).join('')||'<tr><td colspan="7">Nenhuma Campaign.</td></tr>';
    document.querySelectorAll('.camp-view').forEach(b=>b.onclick=()=>viewCampaign(b.dataset.id));
    document.querySelectorAll('.camp-edit').forEach(b=>b.onclick=()=>editCampaign(b.dataset.id));
    document.querySelectorAll('.camp-next').forEach(b=>b.onclick=()=>nextCampaignCycle(b.dataset.id));
    document.querySelectorAll('.camp-pause').forEach(b=>b.onclick=()=>campaignAction(b.dataset.id,'pause'));
    document.querySelectorAll('.camp-resume').forEach(b=>b.onclick=()=>campaignAction(b.dataset.id,'resume'));
    document.querySelectorAll('.camp-delete').forEach(b=>b.onclick=()=>deleteCampaign(b.dataset.id));
  }catch(e){document.getElementById('campaignResult').textContent=e.message;}
}
async function createCampaign(){
  const out=document.getElementById('campaignResult');
  const seeds=['campaignSeed1','campaignSeed2','campaignSeed3'].map(id=>document.getElementById(id).value.trim()).filter(Boolean);
  const scopes=document.getElementById('campaignScope').value.split(',').map(x=>x.trim()).filter(Boolean);
  const body={name:document.getElementById('campaignName').value.trim(),scope_cidrs:scopes,initial_seeds:seeds,credential_id:document.getElementById('campaignCredential').value||null,ssh_credential_id:document.getElementById('campaignSshCredential').value||null,snmp_credential_id:document.getElementById('campaignSnmpCredential').value||null,enabled_vectors:['winrm','smb','ssh','snmp_v2c'].filter(v=>document.getElementById('vec_'+v)?.checked),create_benign_evidence:!!document.getElementById('campaignEvidence')?.checked,start_at:document.getElementById('campaignStart').value,end_at:document.getElementById('campaignEnd').value,daily_start:document.getElementById('campaignDailyStart').value,daily_end:document.getElementById('campaignDailyEnd').value,cycle_interval_minutes:15,cycle_timeout_minutes:15,recurrence_days:document.getElementById('campaignRecurrence').value||null,max_seeds_per_cycle:3,branch_policy:[10,5,3,0],max_paths_per_cycle:60,max_outstanding_jobs:5,snapshot_retention:10};
  if(!body.name||!scopes.length||!seeds.length||!body.start_at||!body.end_at){out.textContent='Nome, scope, ao menos um Host A, início e término são obrigatórios.';return;}if(!body.credential_id&&!body.ssh_credential_id&&!body.snmp_credential_id){out.textContent='Selecione ao menos uma credencial Windows, SSH ou SNMP.';return;}if(!body.enabled_vectors.length){out.textContent='Selecione ao menos um vetor.';return;}
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
    document.getElementById('campaignCredential').value=c.credential_id||'';
    document.getElementById('campaignSshCredential').value=c.ssh_credential_id||'';
    document.getElementById('campaignSnmpCredential').value=c.snmp_credential_id||'';
    ['winrm','smb','ssh','snmp_v2c'].forEach(v=>{const el=document.getElementById('vec_'+v);if(el)el.checked=(c.enabled_vectors||[]).includes(v);});
    if(document.getElementById('campaignEvidence'))document.getElementById('campaignEvidence').checked=!!c.create_benign_evidence;
    const localInput=v=>v?String(v).slice(0,16):'';
    document.getElementById('campaignStart').value=localInput(c.start_at);
    document.getElementById('campaignEnd').value=localInput(c.end_at);
    document.getElementById('campaignDailyStart').value=String(c.daily_start||'08:00').slice(0,5);
    document.getElementById('campaignDailyEnd').value=String(c.daily_end||'18:00').slice(0,5);
    document.getElementById('campaignRecurrence').value=c.recurrence_days||'';
    document.getElementById('createCampaign').textContent='Salvar ajustes';
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
async function viewCampaign(id){
  try{
    const d=await api(`/api/attack-simulator/campaigns/${id}`),c=d.campaign||{},ex=(c.executions||[])[0]||{},st=ex.stats||{},paths=c.paths||[],assets=c.assets||[];
    document.getElementById('campaignDetail').innerHTML=`<h3>${esc(c.name)} — Execution #${esc(ex.execution_number||'--')}</h3>
      <div class="ap-tabs"><button class="btn secondary btn-sm ap-tab" data-tab="summary">Resumo</button><button class="btn primary btn-sm ap-tab" data-tab="path">Attack Path</button><button class="btn secondary btn-sm ap-tab" data-tab="evidence">Evidências</button><button class="btn secondary btn-sm ap-tab" data-tab="cycles">Ciclos</button></div>
      <div id="attackPathPanel" class="ap-panel">Carregando Attack Path...</div>`;
    document.querySelectorAll('.ap-tab').forEach(b=>b.onclick=()=>renderCampaignTab(id,b.dataset.tab,c));
    await renderCampaignTab(id,'path',c);
  }catch(e){document.getElementById('campaignResult').textContent=e.message;}
}
function attackKindLabel(k){return ({ACCESS:'✓ ACCESS CONFIRMED',SNMP:'● SNMP / DISCOVERY ONLY',AUTHENTICATION_FAILED:'! AUTHENTICATION FAILED',TRANSPORT_FAILED:'! TRANSPORT FAILED',SERVICE_UNAVAILABLE:'! SERVICE UNAVAILABLE',BARRIER:'! BARRIER',DISCOVERY:'● DISCOVERY'})[k]||k;}
async function renderCampaignTab(id,tab,cached){
  const panel=document.getElementById('attackPathPanel'); if(!panel)return;
  try{
    if(tab==='cycles'){panel.innerHTML=`<h4>Ciclos</h4><pre>${esc(pretty((cached.cycles||[])))}</pre>`;return;}
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
    if(tab==='evidence'){
      panel.innerHTML=`<h4>Evidências rastreáveis</h4><div class="ap-evidence">${(a.evidence||[]).map(e=>`<div class="ap-panel"><span class="ap-badge">${esc(attackKindLabel(e.kind))}</span> <strong>${esc(e.origin)} → ${esc(e.target||'--')}</strong><br><small>Protocol: ${esc(e.protocol||'--')} | Hop: ${esc(e.hop??'--')} | Cycle: ${esc(e.cycle_id||'--')} | Runner Job: ${esc(e.runner_job_id||'--')}</small>${e.result?`<pre>${esc(String(e.result))}</pre>`:''}</div>`).join('')||'<p>Sem evidências nesta execução.</p>'}</div>`;return;
    }
    const visible=edges.filter(e=>['ACCESS','SNMP','AUTHENTICATION_FAILED','TRANSPORT_FAILED','SERVICE_UNAVAILABLE','BARRIER'].includes(e.kind));
    panel.innerHTML=`<h4>Attack Path — somente esta Campaign / Execution #${esc(a.execution_number||'--')}</h4>
      <p>O grafo abaixo não mistura resultados de outras Campaigns. Falhas relevantes são exibidas como barreiras.</p>
      <div class="ap-graph"><div class="ap-row"><span class="ap-node">MAGI Runner</span></div>
      ${visible.map(e=>`<div class="ap-row"><span class="ap-node">${esc(e.origin)}</span><span class="ap-edge">── ${esc(e.protocol||e.relation_type||'path')} / ${esc(attackKindLabel(e.kind))} ──►</span><span class="ap-node">${esc(e.target)}</span></div>`).join('')||'<p>Nenhum path relevante consolidado ainda.</p>'}</div>
      <div class="ap-kpis"><div><small>Acessos</small><br><strong>${esc(sum.access_confirmed||0)}</strong></div><div><small>Maior hop</small><br><strong>${esc(sum.max_hop||0)}</strong></div><div><small>Barreiras</small><br><strong>${esc(sum.barriers||0)}</strong></div></div>`;
  }catch(e){panel.textContent=e.message;}
}

window.addEventListener('load',()=>{setTimeout(()=>{copyCredentialsToCampaign();loadCampaigns();const rc=document.getElementById('refreshCampaigns'),cc=document.getElementById('createCampaign');if(rc)rc.onclick=loadCampaigns;if(cc)cc.onclick=createCampaign;},250);});
