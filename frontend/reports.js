let activeUsersRows = [];
let scanRows = [];
let compareFiles = [];
let reportModules = null;

function escapeHtml(value){
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function statusIcon(value){ return Number(value) === 1 ? '/assets/pc_green.png' : '/assets/pc_red.png'; }
function statusText(value){ return Number(value) === 1 ? 'Online' : 'Offline'; }

function showSection(section){
  document.querySelectorAll('.report-content .report-section').forEach(el => el.classList.add('hidden-section'));
  const target = document.getElementById(section);
  if(target) target.classList.remove('hidden-section');
}

async function loadSettings(){
  const data = await fetch('/api/settings').then(r=>r.json()).catch(()=> ({}));
  setBrandLogo(data.logo_path || data?.theme?.logo_path);
}

async function loadActiveUsersReport(){
  const res = await fetch('/api/reports/active-users');
  const data = await res.json();
  if(!res.ok){
    document.getElementById('activeUsersTable').innerHTML = `<tr><td colspan="3">${escapeHtml(data.detail || 'Erro ao carregar relatório.')}</td></tr>`;
    return;
  }
  document.getElementById('reportNotice').textContent = data.notice || '-';
  document.getElementById('latestJsonLabel').textContent = data.latest_json || '-';
  activeUsersRows = Array.isArray(data.rows) ? data.rows : [];
  renderActiveUsersTable(activeUsersRows);
}

function renderActiveUsersTable(rows){
  const tbody = document.getElementById('activeUsersTable');
  tbody.innerHTML = '';
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="3">Nenhum registro encontrado.</td></tr>'; return; }
  rows.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(row.name || '--')}</td><td><span class="status-chip"><img src="${statusIcon(row.live_status)}" alt="${statusText(row.live_status)}">${statusText(row.live_status)}</span></td><td>${escapeHtml(row.user || '--')}</td>`;
    tbody.appendChild(tr);
  });
}

function filterActiveUsersTable(){
  const value = document.getElementById('activeUsersSearchInput').value.trim().toUpperCase();
  renderActiveUsersTable(!value ? activeUsersRows : activeUsersRows.filter(row => String(row.name || '').toUpperCase().includes(value)));
}

function createUploadRow(){
  const wrapper = document.createElement('div');
  wrapper.className = 'scan-source-row';
  wrapper.innerHTML = `<input type="file" class="scan-file-input" accept=".csv"><input type="text" class="scan-label-input" placeholder="Nome de identificação do CSV"><button type="button" class="scan-remove-btn">Remover</button>`;
  wrapper.querySelector('.scan-remove-btn').addEventListener('click', ()=> wrapper.remove());
  return wrapper;
}

function createFolderRow(){
  const wrapper = document.createElement('div');
  wrapper.className = 'scan-source-row';
  const select = document.createElement('select');
  select.className = 'scan-folder-select';
  fillCompareFileSelect(select);
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'scan-label-input';
  input.placeholder = 'Nome de identificação do arquivo';
  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'scan-remove-btn';
  removeBtn.textContent = 'Remover';
  removeBtn.addEventListener('click', ()=> wrapper.remove());
  wrapper.appendChild(select); wrapper.appendChild(input); wrapper.appendChild(removeBtn);
  return wrapper;
}

function fillCompareFileSelect(select){
  select.innerHTML = '';
  const firstOption = document.createElement('option');
  firstOption.value = ''; firstOption.textContent = 'Selecione um arquivo';
  select.appendChild(firstOption);
  compareFiles.forEach(file => { const option = document.createElement('option'); option.value = file.file_name; option.textContent = file.file_name; select.appendChild(option); });
}

function ensureDefaultScanRows(){
  const uploadList = document.getElementById('scanUploadList');
  const folderList = document.getElementById('scanFolderList');
  if(!uploadList.children.length){ uploadList.appendChild(createUploadRow()); uploadList.appendChild(createUploadRow()); }
  if(!folderList.children.length){ folderList.appendChild(createFolderRow()); folderList.appendChild(createFolderRow()); }
}

async function loadCompareFolderFiles(){
  const res = await fetch('/api/reports/scans/compare-files');
  const data = await res.json();
  compareFiles = Array.isArray(data.files) ? data.files : [];
  document.querySelectorAll('.scan-folder-select').forEach(select => { const previous = select.value; fillCompareFileSelect(select); select.value = previous; });
}

async function runUploadCompare(){
  const rows = Array.from(document.querySelectorAll('#scanUploadList .scan-source-row'));
  const files = []; const labels = [];
  for(const row of rows){
    const file = row.querySelector('.scan-file-input').files[0];
    const label = row.querySelector('.scan-label-input').value.trim();
    if(!file && !label) continue;
    if(!file){ alert('Selecione o arquivo CSV em todas as linhas preenchidas.'); return; }
    if(!label){ alert('Informe o nome de identificação para todos os CSVs enviados.'); return; }
    files.push(file); labels.push(label);
  }
  if(!files.length){ alert('Selecione pelo menos um CSV para comparar.'); return; }
  const formData = new FormData();
  files.forEach(file => formData.append('files', file));
  labels.forEach(label => formData.append('labels', label));
  const res = await fetch('/api/reports/scans/upload', { method:'POST', body:formData });
  const data = await res.json();
  handleScanCompareResponse(res, data);
}

async function runFolderCompare(){
  const rows = Array.from(document.querySelectorAll('#scanFolderList .scan-source-row'));
  const sources = [];
  for(const row of rows){
    const file_name = row.querySelector('.scan-folder-select').value;
    const label = row.querySelector('.scan-label-input').value.trim();
    if(!file_name && !label) continue;
    if(!file_name){ alert('Selecione os arquivos da pasta compare em todas as linhas preenchidas.'); return; }
    if(!label){ alert('Informe o nome de identificação para todos os arquivos escolhidos.'); return; }
    sources.push({ file_name, label });
  }
  if(!sources.length){ alert('Selecione pelo menos um arquivo da pasta compare.'); return; }
  const res = await fetch('/api/reports/scans/from-folder', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ files: sources }) });
  const data = await res.json();
  handleScanCompareResponse(res, data);
}

function handleScanCompareResponse(res, data){
  if(!res.ok){ document.getElementById('scansSummaryLabel').textContent = data.detail || 'Erro ao executar compare.'; return; }
  scanRows = Array.isArray(data.rows) ? data.rows : [];
  document.getElementById('scansSummaryLabel').textContent = data.summary || 'Compare concluído.';
  renderScanResults(scanRows); filterScanResults();
}

function renderScanResults(rows){
  const tbody = document.getElementById('scanResultsTable');
  tbody.innerHTML = '';
  if(!rows.length){ tbody.innerHTML = '<tr><td colspan="3">Nenhum resultado para exibir.</td></tr>'; return; }
  rows.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(row.hostname || '--')}</td><td>${escapeHtml(Array.isArray(row.present_in) ? row.present_in.join(', ') : '--')}</td><td>${escapeHtml(Array.isArray(row.missing_in) ? row.missing_in.join(', ') : '--')}</td>`;
    tbody.appendChild(tr);
  });
}

function filterScanResults(){
  const value = document.getElementById('scansSearchInput').value.trim().toUpperCase();
  renderScanResults(!value ? scanRows : scanRows.filter(row => String(row.hostname || '').toUpperCase().includes(value)));
}

async function exportScanResults(){
  const res = await fetch('/api/reports/scans/export', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(scanRows) });
  if(!res.ok){ alert('Nenhum arquivo disponível para exportação.'); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'scan_compare_result.csv'; a.click(); URL.revokeObjectURL(url);
}

function bindScanActions(){
  document.getElementById('activeUsersSearchInput').addEventListener('input', filterActiveUsersTable);
  document.getElementById('scansSearchInput').addEventListener('input', filterScanResults);
  document.getElementById('addUploadSourceBtn').addEventListener('click', ()=> document.getElementById('scanUploadList').appendChild(createUploadRow()));
  document.getElementById('addFolderSourceBtn').addEventListener('click', ()=> document.getElementById('scanFolderList').appendChild(createFolderRow()));
  document.getElementById('runUploadCompareBtn').addEventListener('click', runUploadCompare);
  document.getElementById('refreshCompareFilesBtn').addEventListener('click', loadCompareFolderFiles);
  document.getElementById('runFolderCompareBtn').addEventListener('click', runFolderCompare);
  document.getElementById('exportScansBtn').addEventListener('click', exportScanResults);
}

async function bootReports(){
  buildHeader('reports');
  bindThemeToggle();
  await loadSettings();
  reportModules = await fetchModuleStatus();
  const groups = [];
  if(reportModules.uem.enabled && reportModules.uem.online){
    groups.push({ title:'UEM', items:[{ key:'activeUsersSection', label:'Usuários ativos no ambiente' }, { key:'scansSection', label:'Correlação AD x UEM x CSV' }] });
  }
  if(reportModules.security.enabled && reportModules.security.online){
    groups.push({ title:'Security', items:[{ key:'mitreSection', label:'MITRE Map' }, { key:'nistSection', label:'NIST Map' }] });
  }
  if(!groups.length){
    document.getElementById('reportSidebar').innerHTML = '<div class="report-group-title">Nenhum relatório disponível</div>';
    return;
  }
  renderModuleSidebar('reportSidebar', groups, (key)=> showSection(key));
  showSection(groups[0].items[0].key);
  bindScanActions(); ensureDefaultScanRows();
  await loadActiveUsersReport(); await loadCompareFolderFiles(); await loadMitreMap(); await loadNistMap();
}

bootReports();


async function loadMitreMap(){
  const res = await fetch('/api/reports/mitre-map');
  const data = await res.json();
  const tbody = document.getElementById('mitreMapTable');
  if(!tbody) return;
  const rows = data.rows || [];
  tbody.innerHTML = rows.length ? rows.map(row => `<tr><td>${escapeHtml(row.label || '--')}</td><td>${escapeHtml(row.count || 0)}</td></tr>`).join('') : '<tr><td colspan="2">Nenhum alerta mapeado.</td></tr>';
}

async function loadNistMap(){
  const res = await fetch('/api/reports/nist-map');
  const data = await res.json();
  const tbody = document.getElementById('nistMapTable');
  if(!tbody) return;
  const rows = data.rows || [];
  tbody.innerHTML = rows.length ? rows.map(row => `<tr><td>${escapeHtml(row.label || '--')}</td><td>${escapeHtml(row.count || 0)}</td></tr>`).join('') : '<tr><td colspan="2">Nenhum alerta mapeado.</td></tr>';
}
