let alertsOpen = [];
let alertsResolved = [];
let selectedAlert = null;

function esc(v){return String(v ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');}
function val(v, fallback='--'){ const text = String(v ?? '').trim(); return text && text.toLowerCase() !== 'none' ? text : fallback; }

function showAlertSection(section){
  document.querySelectorAll('.report-content .report-section').forEach(el => el.classList.add('hidden-section'));
  const target = document.getElementById(section);
  if(target) target.classList.remove('hidden-section');
}

function statusBadge(alert){
  const status = Number(alert.status || 0);
  let cls = 'status-badge';
  if(status === 1) cls += ' status-red';
  if(status === 2) cls += ' status-yellow';
  if(status === 3) cls += ' status-green';
  return `<span class="${cls}">${esc(alert.status_label || status)}</span>`;
}

function severityClass(severity){
  const sev = String(severity || '').toLowerCase();
  if(sev.includes('crit')) return 'severity-critical';
  if(sev.includes('alta') || sev.includes('high')) return 'severity-high';
  if(sev.includes('media') || sev.includes('média') || sev.includes('medium')) return 'severity-medium';
  if(sev.includes('baixa') || sev.includes('low')) return 'severity-low';
  return 'severity-neutral';
}

function severityBadge(alert){
  const severity = val(alert.severity, 'Media');
  return `<span class="severity-badge ${severityClass(severity)}">${esc(severity)}</span>`;
}

function getRaw(alert){
  return alert?.raw_payload || alert?.payload || alert || {};
}

function getNested(obj, path){
  try{
    return path.split('.').reduce((acc, key)=> acc && acc[key] !== undefined ? acc[key] : undefined, obj);
  }catch{ return undefined; }
}

function getFromAlert(alert, ...keys){
  const raw = getRaw(alert);
  for(const key of keys){
    const direct = alert?.[key];
    if(val(direct, '') !== '') return direct;
    const normalized = raw?.normalized?.[key];
    if(val(normalized, '') !== '') return normalized;
    const normalizedContext = raw?.normalized?.normalized_context?.[key];
    if(val(normalizedContext, '') !== '') return normalizedContext;
    const original = raw?.original?.[key];
    if(val(original, '') !== '') return original;
    const nestedOriginal = getNested(raw?.original || {}, key);
    if(val(nestedOriginal, '') !== '') return nestedOriginal;
  }
  return '';
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
  if(selectedAlert){
    const fresh = alertsOpen.find(a => a.alert_id === selectedAlert.alert_id) || alertsResolved.find(a => a.alert_id === selectedAlert.alert_id);
    if(fresh) selectAlert(fresh, false); else clearDetail();
  }
}

function renderOpenAlerts(){
  const tbody = document.getElementById('alertsOpenTable');
  tbody.innerHTML = '';
  if(!alertsOpen.length){ tbody.innerHTML = '<tr><td colspan="9">Nenhum alerta ativo.</td></tr>'; clearDetail(); return; }
  alertsOpen.forEach(alert => {
    const tr = document.createElement('tr');
    tr.classList.add('alert-table-row');
    if(selectedAlert?.alert_id === alert.alert_id) tr.classList.add('selected-row');
    if(Number(alert.status||0) === 1) tr.classList.add('row-alert-red');
    const eventTitle = val(alert.display_name || alert.event || alert.event_number);
    const eventSub = [val(alert.username || alert.target_user, ''), val(alert.hostname, ''), val(alert.ip_address || alert.source_ip, '')].filter(Boolean).join(' • ');
    tr.innerHTML = `<td><strong class="alert-id-text">${esc(alert.alert_id || '--')}</strong></td><td>${statusBadge(alert)}</td><td>${esc(alert.received_at || '--')}</td><td><strong>${esc(eventTitle)}</strong><small class="alert-subline">${esc(eventSub || 'Sem contexto adicional')}</small></td><td>${esc(alert.technique || alert.mitre_technique || '--')}</td><td>${esc(alert.tactic || alert.mitre_tactic || '--')}</td><td>${esc(alert.nist || alert.nist_control || '--')}</td><td>${severityBadge(alert)}</td><td><div class="table-actions"><button class="btn primary btn-sm btn-detail">Detalhes</button><button class="btn secondary btn-sm btn-known">Conhecido</button><button class="btn success btn-sm btn-resolve">Finalizar</button></div></td>`;
    tr.querySelector('.btn-detail')?.addEventListener('click', (e)=>{ e.stopPropagation(); selectAlert(alert); });
    tr.querySelector('.btn-known')?.addEventListener('click', (e)=>{ e.stopPropagation(); setAlertStatus(alert.alert_id, 2, '', 'analyst', 'Alerta conhecido pelo analista.'); });
    tr.querySelector('.btn-resolve')?.addEventListener('click', (e)=>{ e.stopPropagation(); setAlertStatus(alert.alert_id, 3, 'manual', 'analyst', 'Alerta finalizado manualmente.'); });
    tr.addEventListener('click', ()=> selectAlert(alert));
    tbody.appendChild(tr);
  });
}

function renderResolvedAlerts(){
  const tbody = document.getElementById('alertsResolvedTable');
  tbody.innerHTML = '';
  if(!alertsResolved.length){ tbody.innerHTML = '<tr><td colspan="8">Nenhum alerta resolvido.</td></tr>'; return; }
  alertsResolved.forEach(alert => {
    const tr = document.createElement('tr');
    tr.classList.add('alert-table-row');
    tr.innerHTML = `<td>${esc(alert.alert_id || '--')}</td><td>${esc(alert.received_at || '--')}</td><td>${esc(alert.resolved_at || '--')}</td><td>${esc(alert.resolution_type || '--')}</td><td>${esc(alert.display_name || alert.event || '--')}</td><td>${esc(alert.technique || alert.mitre_technique || '--')}</td><td>${esc(alert.nist || alert.nist_control || '--')}</td><td>${statusBadge(alert)}</td>`;
    tr.addEventListener('click', ()=> selectAlert(alert));
    tbody.appendChild(tr);
  });
}

function clearDetail(){
  selectedAlert = null;
  document.getElementById('alertDetailEmpty')?.classList.remove('hidden-section');
  document.getElementById('alertDetailContent')?.classList.add('hidden-section');
  const slot = document.getElementById('detailStatusSlot');
  if(slot) slot.innerHTML = '';
}

function selectAlert(alert, rerender=true){
  selectedAlert = alert;
  document.getElementById('alertDetailEmpty')?.classList.add('hidden-section');
  document.getElementById('alertDetailContent')?.classList.remove('hidden-section');

  const title = val(alert.display_name || alert.event || alert.event_number, 'Alerta inbound');
  const source = val(alert.source_system, 'Origem não informada');
  const received = val(alert.received_at, '--');
  const targetUser = val(getFromAlert(alert, 'target_user', 'username', 'account_name'), '--');
  const actor = val(getFromAlert(alert, 'actor_user', 'caller_user_name', 'subject_user', 'SubjectUserName'), '--');
  const host = val(getFromAlert(alert, 'hostname', 'host', 'computer', 'winlog.computer_name'), '--');
  const ip = val(getFromAlert(alert, 'ip_address', 'target_ip', 'source_ip', 'source.ip'), '--');
  const mitre = val(alert.technique || alert.mitre_technique, '--');
  const tactic = val(alert.tactic || alert.mitre_tactic, '--');
  const nist = val(alert.nist || alert.nist_control, '--');
  const recommendation = val(getFromAlert(alert, 'recommendation'), 'Validar o evento com o time responsável e confirmar se a atividade foi autorizada.');
  const severity = val(alert.severity, 'Media');

  document.getElementById('detailStatusSlot').innerHTML = statusBadge(alert);
  document.getElementById('detailTitle').textContent = title;
  document.getElementById('detailSubtitle').textContent = `${source} • Recebido em ${received}`;
  document.getElementById('detailUser').textContent = targetUser;
  document.getElementById('detailActor').textContent = actor;
  document.getElementById('detailHost').textContent = host;
  document.getElementById('detailIp').textContent = ip;
  document.getElementById('detailMitre').textContent = mitre;
  document.getElementById('detailTactic').textContent = tactic;
  document.getElementById('detailNist').textContent = nist;
  document.getElementById('detailRecommendation').textContent = recommendation;
  document.getElementById('detailSeverityBadge').textContent = severity;
  document.getElementById('detailSeverityBadge').className = `severity-badge ${severityClass(severity)}`;
  document.getElementById('detailSourceBadge').textContent = source;
  document.getElementById('detailSeverityIcon').className = `detail-icon ${severityClass(severity)}`;
  document.getElementById('alertsPayloadBox').textContent = JSON.stringify(getRaw(alert), null, 2);

  const known = document.getElementById('detailKnownBtn');
  const resolve = document.getElementById('detailResolveBtn');
  if(known) known.onclick = ()=> setAlertStatus(alert.alert_id, 2, '', 'analyst', 'Alerta conhecido pelo analista.');
  if(resolve) resolve.onclick = ()=> setAlertStatus(alert.alert_id, 3, 'manual', 'analyst', 'Alerta finalizado manualmente.');

  if(rerender) renderOpenAlerts();
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
