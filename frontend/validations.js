let selectedTechniqueId = null;

function safeText(value){ return value === null || value === undefined || value === '' ? '--' : String(value); }
function asList(value){ return Array.isArray(value) ? value : []; }
function jsonPretty(value){ try { return JSON.stringify(value, null, 2); } catch(_e){ return String(value); } }
function riskBadge(risk){
  const r = String(risk || 'medium').toLowerCase();
  return `<span class="badge risk-${r}">${r.toUpperCase()}</span>`;
}
function boolBadge(value, yes='Sim', no='Não'){
  return value ? `<span class="badge badge-ok">${yes}</span>` : `<span class="badge badge-muted">${no}</span>`;
}

function escapeHtml(value){
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function canExecuteLab(row){
  // Regra de produto: somente bloqueia se o teste estiver desabilitado ou não aprovado pelo admin.
  return !!row.enabled && !!row.approved_for_execution && !!row.approved_for_lab;
}

function renderExecutionEvidence(row){
  const evidence = row.evidence || {};
  const payload = row.payload || {};
  const command = evidence.command || row.command_preview || payload.command_preview || '';
  const stdout = row.stdout || evidence.stdout || '';
  const stderr = row.stderr || evidence.stderr || '';
  const exitCode = row.exit_code ?? evidence.exit_code ?? '';
  const executedReal = row.executed_real_test === true || evidence.executed_real_test === true;
  if(!command && !stdout && !stderr && exitCode === '') return '';
  return `
    <details class="atomic-evidence">
      <summary>Evidência</summary>
      <div><strong>Execução real:</strong> ${executedReal ? 'SIM' : 'NÃO'}</div>
      <div><strong>Exit code:</strong> ${safeText(exitCode)}</div>
      <div><strong>Comando:</strong></div>
      <pre>${escapeHtml(command)}</pre>
      <div><strong>STDOUT:</strong></div>
      <pre>${escapeHtml(stdout)}</pre>
      <div><strong>STDERR:</strong></div>
      <pre>${escapeHtml(stderr)}</pre>
    </details>`;
}

function formatDateTime(value){
  if(!value) return '--';
  try{ return new Date(value).toLocaleString('pt-BR'); }catch(_e){ return String(value); }
}

function formatDuration(seconds){
  if(seconds === null || seconds === undefined || seconds === '') return '--';
  const n = Number(seconds);
  if(Number.isNaN(n)) return '--';
  if(n < 60) return `${n}s`;
  const minutes = Math.floor(n / 60);
  const rest = n % 60;
  return `${minutes}m ${rest}s`;
}

function statusBadge(status){
  const st = String(status || 'unknown').toLowerCase();
  const cls = ['success'].includes(st) ? 'badge-ok' : ['failed','error','timeout','blocked','target_unreachable'].includes(st) ? 'badge-danger' : 'badge-muted';
  return `<span class="badge ${cls}">${escapeHtml(st)}</span>`;
}

async function fetchJson(url, options){
  const res = await fetch(url, options || {});
  const data = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data.detail ? jsonPretty(data.detail) : `HTTP ${res.status}`);
  return data;
}

async function loadAtomicSummary(){
  const data = await fetchJson('/api/validations/atomic/summary');
  const summary = data.summary || {};
  document.getElementById('atomicTechniquesCount').textContent = summary.techniques_count || 0;
  document.getElementById('atomicTestsCount').textContent = summary.tests_count || 0;
  document.getElementById('atomicApprovedCount').textContent = summary.approved_count || 0;
  document.getElementById('atomicDependenciesCount').textContent = summary.dependencies_count || 0;
  if(data.last_import){
    document.getElementById('atomicImportResult').textContent = jsonPretty(data.last_import);
  }
}

async function loadAtomicTechniques(){
  const search = document.getElementById('atomicSearch').value.trim();
  const url = new URL('/api/validations/atomic/techniques', window.location.origin);
  if(search) url.searchParams.set('search', search);
  url.searchParams.set('limit', '300');
  const data = await fetchJson(url.toString());
  const tbody = document.getElementById('atomicTechniquesTable');
  const rows = data.techniques || [];
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="6">Nenhuma técnica importada.</td></tr>'; return; }
  tbody.innerHTML = rows.map(row => `
    <tr data-technique="${safeText(row.technique_id)}">
      <td><button class="btn secondary btn-sm atomic-select" data-technique="${safeText(row.technique_id)}">${safeText(row.technique_id)}</button></td>
      <td>${safeText(row.display_name)}</td>
      <td>${safeText(row.attack_tactic)}</td>
      <td>${row.atomic_tests_count || 0}</td>
      <td>${asList(row.platforms).join(', ') || '--'}</td>
      <td>${asList(row.executors).join(', ') || '--'}</td>
    </tr>`).join('');
  document.querySelectorAll('.atomic-select').forEach(btn => btn.addEventListener('click', () => selectTechnique(btn.dataset.technique)));
}

async function selectTechnique(techniqueId){
  selectedTechniqueId = techniqueId;
  document.getElementById('atomicSelectedTitle').textContent = `Técnica selecionada: ${techniqueId}`;
  const url = new URL('/api/validations/atomic/tests', window.location.origin);
  url.searchParams.set('technique_id', techniqueId);
  url.searchParams.set('limit', '200');
  const data = await fetchJson(url.toString());
  const rows = data.tests || [];
  const tbody = document.getElementById('atomicTestsTable');
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="9">Nenhuma tarefa encontrada.</td></tr>'; return; }
  tbody.innerHTML = rows.map(row => `
    <tr>
      <td><strong>#${safeText(row.atomic_test_number || row.id)} - ${safeText(row.atomic_name)}</strong><br><small>${safeText(row.description).slice(0, 160)}</small></td>
      <td>${asList(row.supported_platforms).join(', ') || '--'}</td>
      <td>${safeText(row.executor_name)}</td>
      <td>${boolBadge(row.executor_elevation_required)}</td>
      <td>${row.has_dependencies ? `Sim (${row.dependency_count || 0})` : 'Não'}</td>
      <td>${riskBadge(row.risk_level)}</td>
      <td>${boolBadge(row.safe_for_production, 'Produção', 'Controlado')}</td>
      <td>${boolBadge(row.requires_reboot, 'Reboot', 'Não')}</td>
      <td class="action-cell"><button class="btn primary btn-sm execute-task" data-id="${row.id}">Executar</button></td>
    </tr>`).join('');
  document.querySelectorAll('.execute-task').forEach(btn => btn.addEventListener('click', () => executeTask(btn.dataset.id)));
}


async function loadAtomicCredentials(){
  const select=document.getElementById('atomicCredentialId');
  if(!select) return;
  try{
    const data=await fetchJson('/api/actions/credentials');
    const rows=(data.credentials||[]).filter(c=>['windows','winrm','wmi'].includes(String(c.type||c.credential_type||'').toLowerCase()) && c.has_password);
    select.innerHTML='<option value="">Selecione uma credencial</option>'+rows.map(c=>{
      const identity=[c.domain,c.username].filter(Boolean).join('\\\\') || c.username || '--';
      return `<option value="${escapeHtml(String(c.id))}">${escapeHtml(c.name||'Credencial')} — ${escapeHtml(identity)} (${escapeHtml(c.type||c.credential_type||'windows')})</option>`;
    }).join('');
    if(rows.length===1) select.value=String(rows[0].id);
    if(!rows.length) select.innerHTML='<option value="">Nenhuma credencial Windows/WinRM disponível</option>';
  }catch(e){
    select.innerHTML='<option value="">Erro ao carregar credenciais</option>';
  }
}

async function executeTask(testId){
  const result = document.getElementById('atomicExecutionResult');
  const targetHost = document.getElementById('atomicTargetHost').value.trim();
  const credentialId = document.getElementById('atomicCredentialId')?.value || '';
  if(!targetHost){
    result.textContent = 'Target não preenchido. Informe um IP ou hostname antes de executar.';
    alert('Target não preenchido.');
    document.getElementById('atomicTargetHost').focus();
    return;
  }
  if(targetHost.includes(',') || targetHost.includes('/') || targetHost.includes(' ')){
    result.textContent = 'Target inválido. Informe um único IP ou hostname.';
    alert('Target inválido.');
    return;
  }
  if(!credentialId){
    result.textContent = 'Selecione uma credencial Windows/WinRM para execução remota.';
    alert('Credencial obrigatória para Atomic remoto.');
    return;
  }
  if(!confirm(`Executar a tarefa remotamente no target ${targetHost}?`)) return;
  result.textContent = `Enviando tarefa ${testId} para o Runner online...`;
  try{
    const data = await fetchJson(`/api/validations/atomic/tests/${testId}/execute-lab`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({target_host: targetHost, credential_id: credentialId, requested_by:'ui'})
    });
    result.textContent = jsonPretty(data);
  }catch(err){ result.textContent = err.message; }
}

function buildHistoryUrl(){
  const url = new URL('/api/repositories/executions', window.location.origin);
  url.searchParams.set('limit', '100');
  const fields = [
    ['historySearch', 'search'],
    ['historyTechnique', 'technique_id'],
    ['historyRunner', 'runner_id'],
    ['historyStatus', 'status'],
    ['historyRequestedBy', 'requested_by'],
    ['historyDateFrom', 'date_from'],
    ['historyDateTo', 'date_to'],
    ['historySource', 'source'],
  ];
  fields.forEach(([id, param]) => {
    const el = document.getElementById(id);
    const value = el ? el.value.trim() : '';
    if(value) url.searchParams.set(param, value);
  });
  return url;
}

function findingBadge(row){
  const finding=String(row.finding_status||'').toLowerCase();
  if(row.source==='atomic'){
    if(finding==='confirmed') return '<span class="badge badge-ok">CONFIRMADO</span>';
    if(finding==='target_unreachable') return '<span class="badge badge-danger">TARGET INACESSÍVEL</span>';
    if(finding==='authentication_failed') return '<span class="badge badge-danger">FALHA DE AUTENTICAÇÃO</span>';
    if(finding==='remote_transport_error') return '<span class="badge badge-danger">FALHA WINRM</span>';
    if(finding==='dependency_missing') return '<span class="badge badge-danger">DEPENDÊNCIA AUSENTE</span>';
    if(finding==='runner_dependency_error') return '<span class="badge badge-danger">RUNNER SEM DEPENDÊNCIA</span>';
    if(finding==='prevented') return '<span class="badge badge-ok">PREVENIDO / INTERROMPIDO</span>';
    if(finding==='not_confirmed') return '<span class="badge badge-danger">NÃO CONFIRMADO</span>';
    if(finding==='executed_unverified') return '<span class="badge badge-muted">EXECUTADO / NÃO VERIFICADO</span>';
    if(finding==='error') return '<span class="badge badge-danger">ERRO</span>';
    return row.executed_real_test ? '<span class="badge badge-muted">EXECUTADO / NÃO VERIFICADO</span>' : '<span class="badge badge-muted">PENDENTE</span>';
  }
  if(finding==='not_evaluated') return '<span class="badge badge-muted">NÃO AVALIADO / TARGET INACESSÍVEL</span>';
  if(finding==='detected') return '<span class="badge badge-danger">DETECTADO</span>';
  if(finding==='not_detected') return '<span class="badge badge-ok">NÃO DETECTADO</span>';
  if(finding==='error') return '<span class="badge badge-danger">ERRO</span>';
  return '<span class="badge badge-muted">PENDENTE</span>';
}

async function loadAtomicExecutions(){
  const data = await fetchJson(buildHistoryUrl().toString());
  const tbody = document.getElementById('atomicExecutionsTable');
  const rows = data.executions || [];
  const meta = document.getElementById('atomicHistoryMeta');
  if(meta) meta.textContent = `Histórico unificado: ${data.total || rows.length || 0} registro(s). Exibindo ${rows.length}.`;
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="12">Nenhuma execução encontrada para os filtros atuais.</td></tr>'; return; }
  tbody.innerHTML = rows.map(row => {
    const technique = row.source === 'atomic'
      ? `${safeText(row.technique_id)} #${safeText(row.atomic_test_number)}`
      : safeText(row.task_key);
    const sourceLabel = row.source === 'atomic' ? 'Atomic Red Team' : 'MAGI';
    return `<tr>
      <td><strong>${safeText(row.id)}</strong><br><small>${safeText(row.execution_uuid)}</small></td>
      <td><span class="badge ${row.source==='magi'?'badge-ok':'badge-muted'}">${escapeHtml(sourceLabel)}</span></td>
      <td>${escapeHtml(technique)}</td>
      <td><strong>${escapeHtml(row.task_name||'--')}</strong><br><small>${escapeHtml(row.executor||'--')}</small></td>
      <td>${safeText(row.runner_id)}${row.runner_job_id ? `<br><small>Job ${safeText(row.runner_job_id)}</small>` : ''}</td>
      <td>${safeText(row.target)}</td>
      <td>${statusBadge(row.status)}${row.error ? `<br><small>${escapeHtml(row.error)}</small>` : ''}</td>
      <td>${findingBadge(row)}${row.finding_message ? `<br><small>${escapeHtml(row.finding_message)}</small>` : ''}</td>
      <td>${formatDuration(row.duration_seconds)}</td>
      <td>${safeText(row.requested_by)}${row.approved_by ? `<br><small>Aprovado por ${safeText(row.approved_by)}</small>` : ''}</td>
      <td>${formatDateTime(row.created_at)}</td>
      <td class="action-cell"><button class="btn secondary btn-sm execution-detail" data-source="${row.source}" data-id="${row.id}">Detalhes</button></td>
    </tr>`;
  }).join('');
  document.querySelectorAll('.execution-detail').forEach(btn => btn.addEventListener('click', () => showExecutionDetail(btn.dataset.source, btn.dataset.id)));
}

async function showExecutionDetail(source, executionId){
  const result = document.getElementById('historyExecutionResult') || document.getElementById('atomicExecutionResult');
  result.textContent = `Carregando detalhes da execução ${executionId}...`;
  try{
    const data = await fetchJson(`/api/repositories/executions/${encodeURIComponent(source)}/${executionId}`);
    const row = data.execution || {};
    result.textContent = jsonPretty({
      source: row.source_label || row.source,
      id: row.id,
      execution_uuid: row.execution_uuid,
      technique_or_check: row.source === 'atomic' ? `${row.technique_id || '--'} #${row.atomic_test_number || '--'}` : row.task_key,
      task_name: row.task_name,
      executor: row.executor,
      status: row.status,
      finding_status: row.finding_status,
      finding_message: row.finding_message,
      runner_id: row.runner_id,
      runner_job_id: row.runner_job_id,
      target: row.target,
      requested_by: row.requested_by,
      approved_by: row.approved_by,
      created_at: row.created_at,
      started_at: row.started_at,
      finished_at: row.finished_at,
      duration_seconds: row.duration_seconds,
      executed_real_test: row.executed_real_test,
      confirmation_status: row.finding_status,
      confirmation_message: row.finding_message,
      execution_scope: row.evidence?.execution_scope || row.evidence?.metadata?.execution_scope || null,
      requested_target: row.evidence?.requested_target || row.evidence?.metadata?.requested_target || row.target,
      evidence: row.evidence,
      remediation: row.remediation,
      error: row.error,
      raw: row.raw
    });
  }catch(err){ result.textContent = err.message; }
}


async function importAtomicCatalog(){
  const sourcePath = document.getElementById('atomicSourcePath').value.trim();
  const payload = sourcePath ? {source_path: sourcePath} : {};
  document.getElementById('atomicImportResult').textContent = 'Importando catálogo...';
  try{
    const data = await fetchJson('/api/validations/atomic/import', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
    });
    document.getElementById('atomicImportResult').textContent = jsonPretty(data);
    await loadAtomicSummary();
    await loadAtomicTechniques();
  }catch(err){
    document.getElementById('atomicImportResult').textContent = err.message;
  }
}


async function loadRepositories(){
  const data=await fetchJson('/api/repositories/summary'); const summary=data.summary||{};
  document.getElementById('repoCount').textContent=summary.repositories||0; document.getElementById('repoAvailable').textContent=summary.available_repositories||0; document.getElementById('repoTasks').textContent=summary.tasks||0; document.getElementById('repoEnabledTasks').textContent=summary.enabled_tasks||0;
  const tbody=document.getElementById('repositoriesTable'); const rows=data.repositories||[];
  tbody.innerHTML=rows.map(r=>{const lifecycle=(r.metadata||{}).lifecycle; const state=lifecycle==='frozen'?'<span class="badge badge-muted">Congelado / pós-ataque</span>':(r.available?'<span class="badge badge-ok">Disponível</span>':'<span class="badge badge-muted">Preparado</span>'); return `<tr><td><strong>${escapeHtml(r.name)}</strong><br><small>${escapeHtml(r.repository_key)}</small></td><td>${escapeHtml(r.provider)}</td><td>${state}</td><td>${r.task_count||0}</td><td>${escapeHtml(r.description||'--')}</td></tr>`;}).join('')||'<tr><td colspan="5">Nenhum repositório.</td></tr>';
}
async function loadMagiChecks(){
  const search=document.getElementById('magiCheckSearch')?.value.trim()||''; const url=new URL('/api/repositories/tasks',window.location.origin); url.searchParams.set('repository_key',document.getElementById('validationRepository')?.value||'magi'); if(search)url.searchParams.set('search',search);
  const data=await fetchJson(url); const tbody=document.getElementById('magiChecksTable'); const rows=data.tasks||[];
  tbody.innerHTML=rows.map(r=>`<tr><td><strong>${escapeHtml(r.task_key)} - ${escapeHtml(r.name)}</strong><br><small>${escapeHtml(r.description||'')}</small></td><td>${escapeHtml(r.category||'--')}</td><td>${escapeHtml(r.platform||'--')}</td><td>${riskBadge(r.impact)}</td><td><code>${escapeHtml(JSON.stringify(r.detection||{}))}</code></td><td>${escapeHtml(r.remediation||'--')}</td><td class="action-cell"><button class="btn secondary btn-sm magi-plan" data-id="${r.id}">Planejar</button> <button class="btn primary btn-sm magi-execute" data-id="${r.id}">Executar</button></td></tr>`).join('')||'<tr><td colspan="7">Nenhum check.</td></tr>';
  document.querySelectorAll('.magi-plan').forEach(b=>b.addEventListener('click',()=>runMagiCheck(b.dataset.id,true))); document.querySelectorAll('.magi-execute').forEach(b=>b.addEventListener('click',()=>runMagiCheck(b.dataset.id,false)));
}
async function runMagiCheck(id,planOnly){
  const target=document.getElementById('magiCheckTarget').value.trim(), out=document.getElementById('magiCheckResult'); if(!target){out.textContent='Target obrigatório.';return;}
  if(!planOnly&&!confirm(`Executar check defensivo em ${target}?`))return; out.textContent=planOnly?'Montando plano...':'Enviando ao Runner...';
  try{const data=await fetchJson(`/api/repositories/tasks/${id}/${planOnly?'plan':'execute'}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});out.textContent=jsonPretty(data);}catch(e){out.textContent=e.message;}
}
async function syncRepositories(){const out=document.getElementById('magiCheckResult');out.textContent='Sincronizando...';try{const d=await fetchJson('/api/repositories/sync',{method:'POST'});out.textContent=jsonPretty(d);await loadRepositories();await loadMagiChecks();}catch(e){out.textContent=e.message;}}

function showValidationSection(key){
  const tasks = document.getElementById('tasksSection');
  const history = document.getElementById('historySection');
  const repositories = document.getElementById('repositoriesSection');
  if(tasks) tasks.hidden = key !== 'tasks';
  if(history) history.hidden = key !== 'history';
  if(repositories) repositories.hidden = key !== 'repositories';
  if(key === 'history') loadAtomicExecutions().catch(()=>{});
  if(key === 'tasks') loadMagiChecks().catch(()=>{});
  if(key === 'repositories') loadRepositories().catch(()=>{});
}

function bindValidationsUi(){
  buildHeader('validations');
  initializeBranding();
  renderModuleSidebar('validationsSidebar', [{title:'Validação', items:[{key:'tasks', label:'Tarefas'},{key:'repositories', label:'Repositórios'},{key:'history', label:'Histórico'}]}], showValidationSection);
  document.getElementById('repositoriesSyncBtn')?.addEventListener('click', syncRepositories);
  document.getElementById('magiCheckSearch')?.addEventListener('input', ()=>{clearTimeout(window.__magiCheckTimer);window.__magiCheckTimer=setTimeout(loadMagiChecks,250);});
  document.getElementById('validationRepository')?.addEventListener('change', loadMagiChecks);
  document.getElementById('atomicImportBtn')?.addEventListener('click', importAtomicCatalog);
  document.getElementById('atomicRefreshBtn')?.addEventListener('click', async ()=>{ await loadAtomicSummary(); await loadAtomicTechniques(); if(selectedTechniqueId) await selectTechnique(selectedTechniqueId); });
  document.getElementById('atomicExecutionsRefreshBtn')?.addEventListener('click', loadAtomicExecutions);
  ['historySearch','historyTechnique','historyRunner','historyStatus','historyRequestedBy','historyDateFrom','historyDateTo','historySource'].forEach(id => {
    const el = document.getElementById(id); if(!el) return;
    el.addEventListener('input', ()=>{ clearTimeout(window.__atomicHistoryTimer); window.__atomicHistoryTimer = setTimeout(loadAtomicExecutions, 350); });
    el.addEventListener('change', loadAtomicExecutions);
  });
  document.getElementById('historyClearBtn')?.addEventListener('click', ()=>{ ['historySearch','historyTechnique','historyRunner','historyStatus','historyRequestedBy','historyDateFrom','historyDateTo','historySource'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; }); loadAtomicExecutions(); });
  document.getElementById('atomicSearch')?.addEventListener('input', ()=>{ clearTimeout(window.__atomicSearchTimer); window.__atomicSearchTimer = setTimeout(loadAtomicTechniques, 250); });
  showValidationSection('tasks');
  loadMagiChecks().catch(()=>{});
}
document.addEventListener('DOMContentLoaded', bindValidationsUi);
