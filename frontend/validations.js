let selectedTechniqueId = null;

function safeText(value){ return value === null || value === undefined || value === '' ? '--' : String(value); }
function asList(value){ return Array.isArray(value) ? value : []; }
function jsonPretty(value){ try { return JSON.stringify(value, null, 2); } catch(_e){ return String(value); } }

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
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="6">Nenhum teste encontrado.</td></tr>'; return; }
  tbody.innerHTML = rows.map(row => `
    <tr>
      <td><strong>${safeText(row.atomic_name)}</strong><br><small>${safeText(row.description).slice(0, 180)}</small></td>
      <td>${asList(row.supported_platforms).join(', ') || '--'}</td>
      <td>${safeText(row.executor_name)}</td>
      <td>${row.executor_elevation_required ? 'Sim' : 'Não'}</td>
      <td>${row.has_dependencies ? `Sim (${row.dependency_count || 0})` : 'Não'}</td>
      <td>${safeText(row.risk_level)}</td>
    </tr>`).join('');
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
  document.getElementById('atomicRefreshBtn').addEventListener('click', async ()=>{ await loadAtomicSummary(); await loadAtomicTechniques(); if(selectedTechniqueId) await selectTechnique(selectedTechniqueId); });
  document.getElementById('atomicSearch').addEventListener('input', ()=>{ clearTimeout(window.__atomicSearchTimer); window.__atomicSearchTimer = setTimeout(loadAtomicTechniques, 250); });
  loadAtomicSummary().catch(()=>{});
  loadAtomicTechniques().catch(()=>{});
}

document.addEventListener('DOMContentLoaded', bindValidationsUi);
