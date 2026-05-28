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
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="10">Nenhum teste encontrado.</td></tr>'; return; }
  tbody.innerHTML = rows.map(row => `
    <tr>
      <td><strong>#${safeText(row.atomic_test_number || row.id)} - ${safeText(row.atomic_name)}</strong><br><small>${safeText(row.description).slice(0, 160)}</small></td>
      <td>${asList(row.supported_platforms).join(', ') || '--'}</td>
      <td>${safeText(row.executor_name)}</td>
      <td>${boolBadge(row.executor_elevation_required)}</td>
      <td>${row.has_dependencies ? `Sim (${row.dependency_count || 0})` : 'Não'}</td>
      <td>${riskBadge(row.risk_level)}</td>
      <td>${boolBadge(row.approved_for_execution || row.approved_for_lab, 'Aprovado', 'Pendente')}</td>
      <td>${boolBadge(row.safe_for_production, 'Safe', 'Lab')}</td>
      <td>${boolBadge(row.requires_reboot, 'Reboot', 'Não')}</td>
      <td class="action-cell">
        <button class="btn secondary btn-sm approve-test" data-id="${row.id}">Aprovar</button>
        <button class="btn primary btn-sm prepare-test" data-id="${row.id}">Preparar</button>
      </td>
    </tr>`).join('');
  document.querySelectorAll('.approve-test').forEach(btn => btn.addEventListener('click', () => approveAtomicTest(btn.dataset.id)));
  document.querySelectorAll('.prepare-test').forEach(btn => btn.addEventListener('click', () => prepareAtomicExecution(btn.dataset.id)));
}

async function approveAtomicTest(testId){
  const result = document.getElementById('atomicExecutionResult');
  result.textContent = `Aprovando teste ${testId}...`;
  try{
    const data = await fetchJson(`/api/validations/atomic/tests/${testId}/approve`, {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({approved: true})
    });
    result.textContent = jsonPretty(data);
    await loadAtomicSummary();
    if(selectedTechniqueId) await selectTechnique(selectedTechniqueId);
  }catch(err){ result.textContent = err.message; }
}

async function prepareAtomicExecution(testId){
  const result = document.getElementById('atomicExecutionResult');
  const runnerId = document.getElementById('atomicRunnerId').value.trim();
  const targetHost = document.getElementById('atomicTargetHost').value.trim();
  result.textContent = `Preparando preview do teste ${testId}...`;
  try{
    const data = await fetchJson(`/api/validations/atomic/tests/${testId}/prepare-execution`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({runner_id: runnerId || null, target_host: targetHost || null, requested_by: 'ui'})
    });
    result.textContent = jsonPretty(data);
    await loadAtomicExecutions();
  }catch(err){ result.textContent = err.message; }
}

async function loadAtomicExecutions(){
  const data = await fetchJson('/api/validations/atomic/executions?limit=20');
  const tbody = document.getElementById('atomicExecutionsTable');
  const rows = data.executions || [];
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="8">Nenhum preview criado.</td></tr>'; return; }
  tbody.innerHTML = rows.map(row => `
    <tr>
      <td>${row.id}</td>
      <td>${safeText(row.technique_id)} #${safeText(row.atomic_test_number)}</td>
      <td>${safeText(row.atomic_name)}</td>
      <td>${safeText(row.runner_id)}</td>
      <td>${safeText(row.target_host)}</td>
      <td>${safeText(row.status)}${row.block_reason ? `<br><small>${safeText(row.block_reason)}</small>` : ''}${row.error_message ? `<br><small>${safeText(row.error_message)}</small>` : ''}</td>
      <td><code>${safeText(row.command_preview)}</code></td>
      <td>${row.status === 'pending_review' ? `<button class="btn primary btn-sm dispatch-execution" data-id="${row.id}">Enviar ao Runner</button>` : safeText(row.runner_job_id)}</td>
    </tr>`).join('');
  document.querySelectorAll('.dispatch-execution').forEach(btn => btn.addEventListener('click', () => dispatchAtomicExecution(btn.dataset.id)));
}

async function dispatchAtomicExecution(executionId){
  const result = document.getElementById('atomicExecutionResult');
  const runnerId = document.getElementById('atomicRunnerId').value.trim();
  if(!runnerId){ result.textContent = 'Informe o Runner ID antes de enviar o job.'; return; }
  result.textContent = `Enviando execução ${executionId} ao Runner ${runnerId}...`;
  try{
    const data = await fetchJson(`/api/validations/atomic/executions/${executionId}/dispatch`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({runner_id: runnerId, approved_by: 'ui', mode: 'dry_run'})
    });
    result.textContent = jsonPretty(data);
    await loadAtomicExecutions();
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

function bindValidationsUi(){
  buildHeader('validations');
  initializeBranding();
  renderModuleSidebar('validationsSidebar', [{title:'Validações', items:[{key:'atomic', label:'Atomic Red Team'}]}], ()=>{});
  document.getElementById('atomicImportBtn').addEventListener('click', importAtomicCatalog);
  document.getElementById('atomicRefreshBtn').addEventListener('click', async ()=>{ await loadAtomicSummary(); await loadAtomicTechniques(); await loadAtomicExecutions(); if(selectedTechniqueId) await selectTechnique(selectedTechniqueId); });
  document.getElementById('atomicExecutionsRefreshBtn').addEventListener('click', loadAtomicExecutions);
  document.getElementById('atomicSearch').addEventListener('input', ()=>{ clearTimeout(window.__atomicSearchTimer); window.__atomicSearchTimer = setTimeout(loadAtomicTechniques, 250); });
  loadAtomicSummary().catch(()=>{});
  loadAtomicTechniques().catch(()=>{});
  loadAtomicExecutions().catch(()=>{});
}

document.addEventListener('DOMContentLoaded', bindValidationsUi);
