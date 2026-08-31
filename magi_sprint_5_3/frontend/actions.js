let actionModules = null;
let scriptCatalog = [];
let targetCatalog = { machines: [], users: [] };
let credentialCatalog = [];
let alertCatalog = [];
let executionCatalog = [];

function showActionSection(section){
  document.querySelectorAll('.report-content .report-section').forEach(el => el.classList.add('hidden-section'));
  const target = document.getElementById(section);
  if(target) target.classList.remove('hidden-section');
}

function esc(v){return String(v ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');}

async function loadListenerInfo(){
  const res = await fetch('/api/actions/listener-info');
  const data = await res.json();
  const url = `${window.location.origin}${data.path || '/api/actions/inbound-alert'}`;
  const el = document.getElementById('alertListenerBox');
  if(el) el.textContent = `Listener: ${url}`;
}

function metadataText(meta){
  if(!meta) return 'Sem metadados detectados.';
  const req = (meta.required || []).join(', ') || 'nenhuma';
  const opt = (meta.optional || []).join(', ') || 'nenhuma';
  const cred = meta.credential || 'não definida';
  return `Obrigatórias: ${req} | Opcionais: ${opt} | Credencial sugerida: ${cred}`;
}

function updateManualMetadata(){
  const scriptName = document.getElementById('manualScriptSelect')?.value || '';
  const item = scriptCatalog.find(x => x.name === scriptName);
  const box = document.getElementById('manualScriptMetadata');
  if(box) box.textContent = metadataText(item?.metadata);
}

async function loadScripts(){
  const res = await fetch('/api/actions/scripts');
  const data = await res.json();
  scriptCatalog = data.scripts || [];
  const selects = [document.getElementById('manualScriptSelect')].filter(Boolean);
  selects.forEach(select => {
    select.innerHTML = scriptCatalog.length ? scriptCatalog.map(item => `<option value="${item.name}">${item.name}</option>`).join('') : '<option value="">Nenhum script encontrado</option>';
  });
  updateManualMetadata();
  renderScriptsRepo();
  if(alertCatalog.length) renderAlertRows();
}

async function loadCredentials(){
  const res = await fetch('/api/actions/credentials');
  const data = await res.json();
  credentialCatalog = data.credentials || [];
  const select = document.getElementById('manualCredentialSelect');
  if(select){
    select.innerHTML = '<option value="">Sem credencial</option>' + credentialCatalog.map(item => `<option value="${item.name}">${item.name} (${item.username || '--'})</option>`).join('');
  }
  renderCredentialsTable();
  if(alertCatalog.length) renderAlertRows();
}

async function saveCredential(){
  const payload = {
    name: document.getElementById('credName').value.trim(),
    username: document.getElementById('credUsername').value.trim(),
    type: document.getElementById('credType').value,
    password: document.getElementById('credPassword').value,
    description: document.getElementById('credDescription').value.trim(),
    winrm_host: document.getElementById('credWinrmHost')?.value?.trim?.() || '',
    winrm_port: Number(document.getElementById('credWinrmPort')?.value || 5985),
    winrm_use_https: Boolean(document.getElementById('credWinrmHttps')?.checked),
    winrm_transport: document.getElementById('credWinrmTransport')?.value || 'ntlm'
  };
  const res = await fetch('/api/actions/credentials', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  const data = await res.json();
  if(!res.ok){ alert(data.detail || 'Erro ao salvar credencial.'); return; }
  ['credName','credUsername','credPassword','credDescription','credWinrmHost'].forEach(id => document.getElementById(id).value = '');
  await loadCredentials();
}

async function deleteCredential(id){
  if(!confirm('Excluir credencial?')) return;
  const res = await fetch(`/api/actions/credentials/${encodeURIComponent(id)}`, {method:'DELETE'});
  if(!res.ok){ alert('Não foi possível excluir a credencial.'); return; }
  await loadCredentials();
}

function renderCredentialsTable(){
  const tbody = document.getElementById('credentialsTable');
  if(!tbody) return;
  tbody.innerHTML = '';
  if(!credentialCatalog.length){ tbody.innerHTML = '<tr><td colspan="6">Nenhuma credencial cadastrada.</td></tr>'; return; }
  credentialCatalog.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(item.name)}</td><td>${esc(item.username || '--')}</td><td>${esc(item.type || '--')}${item.type === 'winrm' ? '<br><small>' + esc(item.winrm_host || '') + ':' + esc(item.winrm_port || '') + '</small>' : ''}</td><td>${item.has_password ? '********' : '--'}</td><td>${esc(item.description || '--')}</td><td><button class="btn secondary btn-sm" data-id="${esc(item.id)}">Excluir</button></td>`;
    tr.querySelector('button')?.addEventListener('click', () => deleteCredential(item.id));
    tbody.appendChild(tr);
  });
}

async function uploadScript(){
  const input = document.getElementById('scriptUploadInput');
  const file = input.files[0];
  if(!file){ alert('Selecione um script.'); return; }
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch('/api/actions/scripts/upload', {method:'POST', body:formData});
  const data = await res.json();
  if(!res.ok){ alert(data.detail || 'Erro ao enviar script.'); return; }
  input.value = '';
  await loadScripts();
}

async function deleteScript(name){
  if(!confirm(`Excluir o script ${name}?`)) return;
  const res = await fetch(`/api/actions/scripts/${encodeURIComponent(name)}`, {method:'DELETE'});
  if(!res.ok){ alert('Não foi possível excluir o script.'); return; }
  await loadScripts();
}

function renderScriptsRepo(){
  const tbody = document.getElementById('scriptsTable');
  if(!tbody) return;
  tbody.innerHTML = '';
  if(!scriptCatalog.length){ tbody.innerHTML = '<tr><td colspan="6">Nenhum script cadastrado.</td></tr>'; return; }
  scriptCatalog.forEach(item => {
    const meta = item.metadata || {};
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(item.name)}</td><td>${esc(meta.name || item.name)}</td><td>${esc((meta.required || []).join(', ') || '--')}</td><td>${esc((meta.optional || []).join(', ') || '--')}</td><td>${esc(meta.credential || '--')}</td><td><button class="btn secondary btn-sm">Excluir</button></td>`;
    tr.querySelector('button')?.addEventListener('click', () => deleteScript(item.name));
    tbody.appendChild(tr);
  });
}

async function loadTargets(){
  const res = await fetch('/api/actions/targets');
  targetCatalog = await res.json();
  const select = document.getElementById('manualMachineSelect');
  if(!select) return;
  const machines = targetCatalog.machines || [];
  select.innerHTML = '<option value="custom">Customizado / manual</option>' + (machines.length ? machines.map((item, idx) => `<option value="${idx}">${item.hostname} ${item.ip ? `| ${item.ip}` : ''}</option>`).join('') : '');
  applyMachineSelection();
}

function applyMachineSelection(){
  const select = document.getElementById('manualMachineSelect');
  if(!select) return;
  const machines = targetCatalog.machines || [];
  if(select.value === 'custom') return;
  const idx = Number(select.value || 0);
  const item = machines[idx] || {};
  document.getElementById('manualIp').value = item.ip || '';
  document.getElementById('manualUser').value = item.user || '';
  document.getElementById('manualResourceId').value = item.resource_id || '';
  document.getElementById('manualSource').value = item.source || '';
}

function stringifyResult(data){ return JSON.stringify(data, null, 2); }

function parseCustomVariables(raw){
  const text = String(raw || '').trim();
  if(!text) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch(e) {
    const vars = {};
    text.split(/\r?\n/).forEach(line => {
      const clean = line.trim();
      if(!clean || clean.startsWith('#')) return;
      const idx = clean.indexOf('=');
      if(idx > 0){ vars[clean.slice(0, idx).trim()] = clean.slice(idx + 1).trim(); }
    });
    return vars;
  }
}

function buildTargetOptions(selectedIp){
  const machines = targetCatalog.machines || [];
  let html = '<option value="alert">Usar alvo do alerta</option><option value="custom">Customizado / manual</option>';
  html += machines.map((item, idx) => {
    const label = `${item.hostname || 'Sem hostname'} ${item.ip ? '| ' + item.ip : ''}`;
    const selected = selectedIp && item.ip === selectedIp ? ' selected' : '';
    return `<option value="${idx}"${selected}>${esc(label)}</option>`;
  }).join('');
  return html;
}

function getTargetFromSelection(selectValue, customIp, alert){
  const machines = targetCatalog.machines || [];
  const raw = alert.raw_payload || {};
  if(selectValue === 'custom'){
    return { hostname:'', ip: customIp || '', user: alert.username || alert.target_user || '', username: alert.username || alert.target_user || '', resource_id:'', source:'custom' };
  }
  if(selectValue !== 'alert'){
    const item = machines[Number(selectValue || 0)] || {};
    return { hostname:item.hostname || '', ip:item.ip || customIp || '', user:item.user || '', username:item.user || '', resource_id:item.resource_id || '', source:item.source || 'UEM' };
  }
  const ip = customIp || alert.target_ip || alert.source_ip || raw.target_ip || raw.IP || raw.ip || raw.host_ip || '';
  const user = alert.username || alert.target_user || raw.username || raw.target_user || raw.caller_user_sid || '';
  return { hostname: alert.hostname || raw.hostname || '', ip, user, username:user, resource_id:'', source: alert.source_system || raw.source_system || 'alert' };
}

async function executeManual(){
  const selected = document.getElementById('manualMachineSelect').value;
  const machines = targetCatalog.machines || [];
  const item = selected === 'custom' ? {} : (machines[Number(selected || 0)] || {});
  const manualUser = document.getElementById('manualUser').value.trim();
  const payload = {
    script_name: document.getElementById('manualScriptSelect').value,
    credential_name: document.getElementById('manualCredentialSelect').value,
    target: {
      hostname: item.hostname || document.getElementById('manualHostname')?.value?.trim?.() || '',
      ip: document.getElementById('manualIp').value.trim(),
      user: manualUser,
      username: manualUser,
      resource_id: document.getElementById('manualResourceId').value.trim(),
      source: document.getElementById('manualSource').value.trim() || (selected === 'custom' ? 'custom' : item.source || '')
    },
    variables: parseCustomVariables(document.getElementById('manualCustomVariables')?.value || '')
  };
  const res = await fetch('/api/actions/execute/manual', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  const data = await res.json();
  document.getElementById('manualResultBox').textContent = stringifyResult(data);
  await loadExecutions();
}

async function loadAlerts(){
  const res = await fetch('/api/actions/alerts');
  const data = await res.json();
  alertCatalog = data.alerts || [];
  const summary = data.summary || {};
  document.getElementById('alertTotalCount').textContent = summary.total_events || 0;
  document.getElementById('alertMitreCount').textContent = summary.mitre_events || 0;
  document.getElementById('alertCriticalCount').textContent = summary.critical_events || 0;
  renderAlertRows();
}

function getAlertTargetIp(alert){
  const raw = alert.raw_payload || {};
  return alert.target_ip || alert.source_ip || raw.target_ip || raw.IP || raw.ip || raw.host_ip || '';
}

function renderAlertRows(){
  const tbody = document.getElementById('alertRowsTable');
  if(!tbody) return;
  tbody.innerHTML = '';
  if(!alertCatalog.length){ tbody.innerHTML = '<tr><td colspan="12">Nenhum alerta recebido.</td></tr>'; return; }
  const scriptOptions = '<option value="">Selecione</option>' + scriptCatalog.map(item => `<option value="${item.name}">${item.name}</option>`).join('');
  const credentialOptions = '<option value="">Sem credencial</option>' + credentialCatalog.map(item => `<option value="${item.name}">${item.name}</option>`).join('');
  alertCatalog.forEach((alert) => {
    const alertIp = getAlertTargetIp(alert);
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(alert.alert_id || '--')}</td><td>${esc(alert.received_at || alert.date || '--')}</td><td>${esc(alert.event || alert.event_number || '--')}</td><td>${esc(alert.username || alert.target_user || '--')}</td><td>${esc(alert.technique || '--')}</td><td>${esc(alert.tactic || '--')}</td><td>${esc(alert.nist || '--')}</td><td>${esc(alert.severity || '--')}</td><td><select class="table-select alert-script-select">${scriptOptions}</select></td><td><select class="table-select alert-cred-select">${credentialOptions}</select></td><td><select class="table-select alert-target-select">${buildTargetOptions(alertIp)}</select><input class="table-input alert-target-input" value="${esc(alertIp)}" placeholder="IP alvo/custom"></td><td><div class="table-actions"><button class="btn secondary btn-sm alert-payload-btn">Payload</button><button class="btn primary btn-sm alert-execute-btn">Executar</button></div></td>`;
    tr.querySelector('.alert-payload-btn')?.addEventListener('click', ()=> document.getElementById('alertRawBox').textContent = stringifyResult(alert.raw_payload || alert));
    tr.querySelector('.alert-target-select')?.addEventListener('change', () => {
      const target = getTargetFromSelection(tr.querySelector('.alert-target-select').value, '', alert);
      tr.querySelector('.alert-target-input').value = target.ip || '';
    });
    tr.querySelector('.alert-execute-btn')?.addEventListener('click', async ()=> {
      const script_name = tr.querySelector('.alert-script-select').value;
      const credential_name = tr.querySelector('.alert-cred-select').value;
      if(!script_name){ window.alert('Selecione o playbook.'); return; }
      const target_ip = tr.querySelector('.alert-target-input').value.trim();
      const target = getTargetFromSelection(tr.querySelector('.alert-target-select').value, target_ip, alert);
      const payload = { script_name, credential_name, target_ip, target, alert };
      const res = await fetch('/api/actions/execute/alert', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
      const data = await res.json();
      document.getElementById('alertResultBox').textContent = stringifyResult(data);
      await loadAlerts();
      await loadExecutions();
    });
    tbody.appendChild(tr);
  });
}


async function loadExecutions(){
  const tbody = document.getElementById('executionsTable');
  if(!tbody) return;
  const res = await fetch('/api/actions/executions?limit=100');
  const data = await res.json();
  executionCatalog = data.executions || [];
  renderExecutions();
}

function renderExecutions(){
  const tbody = document.getElementById('executionsTable');
  if(!tbody) return;
  tbody.innerHTML = '';
  if(!executionCatalog.length){
    tbody.innerHTML = '<tr><td colspan="8">Nenhuma execução registrada.</td></tr>';
    return;
  }
  executionCatalog.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(item.id || '--')}</td><td>${esc(item.started_at || '--')}</td><td>${esc(item.finished_at || '--')}</td><td>${esc(item.status || '--')}</td><td>${esc(item.playbook_name || item.playbook_id || '--')}</td><td>${esc(item.credential_name || item.credential_id || '--')}</td><td>${esc(item.target || '--')}</td><td>${esc(item.executed_by || '--')}</td>`;
    tr.addEventListener('click', () => {
      const box = document.getElementById('executionDetailBox');
      if(box) box.textContent = stringifyResult(item);
    });
    tbody.appendChild(tr);
  });
}

async function bootActions(){
  buildHeader('actions');
  actionModules = await fetchModuleStatus();
  const groups = [];
  if(actionModules.uem.enabled && actionModules.uem.online){
    groups.push({ title:'UEM', items:[{ key:'installerSection', label:'Instalador' }] });
  }
  if(actionModules.security.enabled){
    groups.push({ title:'Security', items:[{ key:'playbookAlertSection', label:'Executar playbook por alerta' }, { key:'playbookManualSection', label:'Execução manual' }, { key:'executionsHistorySection', label:'Histórico de execuções' }] });
  }
  groups.push({ title:'Gerais', items:[{ key:'credentialsRepoSection', label:'Repositório de credenciais' }, { key:'scriptsRepoSection', label:'Repositório de scripts' }] });
  renderModuleSidebar('actionsSidebar', groups, (key)=> showActionSection(key));
  showActionSection(groups[0].items[0].key);
  await loadListenerInfo();
  await loadScripts();
  await loadTargets();
  await loadCredentials();
  await loadAlerts();
  await loadExecutions();
  document.getElementById('manualMachineSelect')?.addEventListener('change', applyMachineSelection);
  document.getElementById('credWinrmHttps')?.addEventListener('change', (ev)=>{ const port=document.getElementById('credWinrmPort'); if(port) port.value = ev.target.checked ? 5986 : 5985; });
  document.getElementById('manualScriptSelect')?.addEventListener('change', updateManualMetadata);
  document.getElementById('executeManualBtn')?.addEventListener('click', executeManual);
  document.getElementById('saveCredentialBtn')?.addEventListener('click', saveCredential);
  document.getElementById('uploadScriptBtn')?.addEventListener('click', uploadScript);
}

bootActions();
