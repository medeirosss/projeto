let alertsOpen = [];
let alertsResolved = [];

function esc(v){return String(v ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');}

function showAlertSection(section){
  document.querySelectorAll('.report-content .report-section').forEach(el => el.classList.add('hidden-section'));
  const target = document.getElementById(section);
  if(target) target.classList.remove('hidden-section');
}

function statusBadge(alert){
  const status = Number(alert.status || 0);
  const cls = status === 1 ? 'status-badge status-red' : 'status-badge';
  return `<span class="${cls}">${esc(alert.status_label || status)}</span>`;
}

async function loadAlertsPage(){
  const [openRes, resolvedRes] = await Promise.all([fetch('/api/alerts'), fetch('/api/alerts/resolved')]);
  const openData = await openRes.json();
  const resolvedData = await resolvedRes.json();
  alertsOpen = openData.alerts || [];
  alertsResolved = resolvedData.alerts || [];
  const summary = openData.summary || {};
  document.getElementById('alertsTotalCount').textContent = summary.total || 0;
  document.getElementById('alertsNewCount').textContent = summary.new || 0;
  document.getElementById('alertsKnownCount').textContent = summary.known || 0;
  document.getElementById('alertsResolvedCount').textContent = summary.resolved || 0;
  renderOpenAlerts();
  renderResolvedAlerts();
}

function renderOpenAlerts(){
  const tbody = document.getElementById('alertsOpenTable');
  tbody.innerHTML = '';
  if(!alertsOpen.length){ tbody.innerHTML = '<tr><td colspan="9">Nenhum alerta ativo.</td></tr>'; return; }
  alertsOpen.forEach(alert => {
    const tr = document.createElement('tr');
    if(Number(alert.status||0) === 1) tr.classList.add('row-alert-red');
    tr.innerHTML = `<td>${esc(alert.alert_id || '--')}</td><td>${statusBadge(alert)}</td><td>${esc(alert.received_at || '--')}</td><td>${esc(alert.event || '--')}</td><td>${esc(alert.technique || '--')}</td><td>${esc(alert.tactic || '--')}</td><td>${esc(alert.nist || '--')}</td><td>${esc(alert.severity || '--')}</td><td><div class="table-actions"><button class="btn secondary btn-sm btn-payload">Payload</button><button class="btn secondary btn-sm btn-known">Conhecido</button><button class="btn success btn-sm btn-resolve">Finalizar manual</button><a class="btn primary btn-sm" href="/acoes">Abrir em Ações</a></div></td>`;
    tr.querySelector('.btn-payload')?.addEventListener('click', ()=> document.getElementById('alertsPayloadBox').textContent = JSON.stringify(alert.raw_payload || alert, null, 2));
    tr.querySelector('.btn-known')?.addEventListener('click', ()=> setAlertStatus(alert.alert_id, 2, '', 'analyst', 'Alerta conhecido pelo analista.'));
    tr.querySelector('.btn-resolve')?.addEventListener('click', ()=> setAlertStatus(alert.alert_id, 3, 'manual', 'analyst', 'Alerta finalizado manualmente.'));
    tbody.appendChild(tr);
  });
}

function renderResolvedAlerts(){
  const tbody = document.getElementById('alertsResolvedTable');
  tbody.innerHTML = '';
  if(!alertsResolved.length){ tbody.innerHTML = '<tr><td colspan="8">Nenhum alerta resolvido.</td></tr>'; return; }
  alertsResolved.forEach(alert => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(alert.alert_id || '--')}</td><td>${esc(alert.received_at || '--')}</td><td>${esc(alert.resolved_at || '--')}</td><td>${esc(alert.resolution_type || '--')}</td><td>${esc(alert.event || '--')}</td><td>${esc(alert.technique || '--')}</td><td>${esc(alert.nist || '--')}</td><td>${statusBadge(alert)}</td>`;
    tbody.appendChild(tr);
  });
}

async function setAlertStatus(alertId, status, resolution_type, resolved_by, message){
  await fetch(`/api/alerts/${alertId}/status`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({status, resolution_type, resolved_by, message})});
  await loadAlertsPage();
}

async function bootAlerts(){
  buildHeader('alerts');
  const groups = [{ title:'Alertas', items:[{ key:'alertsOpenSection', label:'Alertas recebidos' }, { key:'alertsResolvedSection', label:'Alertas resolvidos' }] }];
  renderModuleSidebar('alertsSidebar', groups, (key)=> showAlertSection(key));
  showAlertSection('alertsOpenSection');
  await loadAlertsPage();
}

bootAlerts();
