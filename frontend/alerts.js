let alertsOpen = [];
let alertsResolved = [];
let selectedAlert = null;
let alertsRefreshTimer = null;
let isLoadingAlerts = false;

function esc(v){return String(v ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');}
function val(v, fallback='--'){
  const text = String(v ?? '').trim();
  if(!text) return fallback;
  const lowered = text.toLowerCase();
  if(['none','null','undefined','-','n/a','na'].includes(lowered)) return fallback;
  return text;
}

function alertIdOf(alert){
  return alert?.alert_id || alert?.alert_uuid || alert?.id || '';
}

function showAlertSection(section){
  document.querySelectorAll('.report-content .report-section').forEach(el => el.classList.add('hidden-section'));
  const target = document.getElementById(section);
  if(target) target.classList.remove('hidden-section');
}

function statusBadge(alert){
  const status = Number(alert.status || 0);
  let cls = 'status-badge';
  let label = alert.status_label || status;

  if(status === 1){ cls += ' status-red'; label = alert.status_label || 'Novo Alarme'; }
  if(status === 2){ cls += ' status-yellow'; label = alert.status_label || 'Conhecido'; }
  if(status === 3){ cls += ' status-green'; label = alert.status_label || 'Finalizado'; }

  return `<span class="${cls}">${esc(label)}</span>`;
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
  }catch{
    return undefined;
  }
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

async function loadAlertsPage(options = {}){
  if(isLoadingAlerts) return;
  isLoadingAlerts = true;

  try{
    const [openRes, resolvedRes] = await Promise.all([
      fetch('/api/alerts', { cache: 'no-store' }),
      fetch('/api/alerts/resolved', { cache: 'no-store' })
    ]);

    if(!openRes.ok) throw new Error(await openRes.text());
    if(!resolvedRes.ok) throw new Error(await resolvedRes.text());

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
      const currentId = alertIdOf(selectedAlert);
      const fresh = alertsOpen.find(a => alertIdOf(a) === currentId) || alertsResolved.find(a => alertIdOf(a) === currentId);
      if(fresh) selectAlert(fresh, false);
      else clearDetail();
    }
  }catch(error){
    console.error('Erro ao carregar alertas:', error);
    if(!options.silent){
      const tbody = document.getElementById('alertsOpenTable');
      if(tbody) tbody.innerHTML = `<tr><td colspan="9">Erro ao carregar alertas.</td></tr>`;
    }
  }finally{
    isLoadingAlerts = false;
  }
}

function renderOpenAlerts(){
  const tbody = document.getElementById('alertsOpenTable');
  if(!tbody) return;

  tbody.innerHTML = '';
  if(!alertsOpen.length){
    tbody.innerHTML = '<tr><td colspan="9">Nenhum alerta ativo.</td></tr>';
    clearDetail();
    return;
  }

  alertsOpen.forEach(alert => {
    const alertId = alertIdOf(alert);
    const tr = document.createElement('tr');
    tr.classList.add('alert-table-row');

    if(alertIdOf(selectedAlert) === alertId) tr.classList.add('selected-row');
    if(Number(alert.status || 0) === 1) tr.classList.add('row-alert-red');

    const eventTitle = val(alert.display_name || alert.event || alert.event_number, 'Inbound Alert');
    const eventSub = [
      val(alert.username || alert.target_user, ''),
      val(alert.hostname, ''),
      val(alert.ip_address || alert.source_ip, '')
    ].filter(Boolean).join(' • ');

    tr.innerHTML = `
      <td><strong class="alert-id-text">${esc(alertId || '--')}</strong></td>
      <td>${statusBadge(alert)}</td>
      <td>${esc(alert.received_at || '--')}</td>
      <td>
        <strong>${esc(eventTitle)}</strong>
        <small class="alert-subline">${esc(eventSub || 'Sem contexto adicional')}</small>
      </td>
      <td>${esc(alert.technique || alert.mitre_technique || '--')}</td>
      <td>${esc(alert.tactic || alert.mitre_tactic || '--')}</td>
      <td>${esc(alert.nist || alert.nist_control || '--')}</td>
      <td>${severityBadge(alert)}</td>
      <td>
        <div class="table-actions">
          <button class="btn primary btn-sm btn-detail" type="button">Detalhes</button>
          <button class="btn secondary btn-sm btn-known" type="button">Conhecido</button>
          <button class="btn success btn-sm btn-resolve" type="button">Finalizar</button>
        </div>
      </td>`;

    tr.querySelector('.btn-detail')?.addEventListener('click', (e) => {
      e.stopPropagation();
      selectAlert(alert);
    });

    tr.querySelector('.btn-known')?.addEventListener('click', async (e) => {
      e.stopPropagation();
      await setAlertStatus(alertId, 2, '', currentUserName(), 'Alerta marcado como conhecido.');
    });

    tr.querySelector('.btn-resolve')?.addEventListener('click', async (e) => {
      e.stopPropagation();
      await setAlertStatus(alertId, 3, 'manual', currentUserName(), 'Alerta finalizado manualmente.');
    });

    tr.addEventListener('click', () => selectAlert(alert));
    tbody.appendChild(tr);
  });
}

function renderResolvedAlerts(){
  const tbody = document.getElementById('alertsResolvedTable');
  if(!tbody) return;

  tbody.innerHTML = '';
  if(!alertsResolved.length){
    tbody.innerHTML = '<tr><td colspan="8">Nenhum alerta resolvido.</td></tr>';
    return;
  }

  alertsResolved.forEach(alert => {
    const tr = document.createElement('tr');
    tr.classList.add('alert-table-row');
    tr.innerHTML = `
      <td>${esc(alertIdOf(alert) || '--')}</td>
      <td>${esc(alert.received_at || '--')}</td>
      <td>${esc(alert.resolved_at || '--')}</td>
      <td>${esc(alert.resolution_type || '--')}</td>
      <td>${esc(alert.display_name || alert.event || '--')}</td>
      <td>${esc(alert.technique || alert.mitre_technique || '--')}</td>
      <td>${esc(alert.nist || alert.nist_control || '--')}</td>
      <td>${statusBadge(alert)}</td>`;
    tr.addEventListener('click', () => selectAlert(alert));
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

function selectAlert(alert, rerender = true){
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

  const alertId = alertIdOf(alert);
  const known = document.getElementById('detailKnownBtn');
  const resolve = document.getElementById('detailResolveBtn');

  if(known) known.onclick = () => setAlertStatus(alertId, 2, '', currentUserName(), 'Alerta marcado como conhecido.');
  if(resolve) resolve.onclick = () => setAlertStatus(alertId, 3, 'manual', currentUserName(), 'Alerta finalizado manualmente.');

  if(rerender) renderOpenAlerts();
}

function currentUserName(){
  try{
    return localStorage.getItem('username') || localStorage.getItem('user') || 'admin';
  }catch{
    return 'admin';
  }
}

async function setAlertStatus(alertId, status, resolution_type = '', resolved_by = 'admin', message = ''){
  if(!alertId){
    console.error('alertId ausente para atualização de status.');
    return;
  }

  const payload = {
    status,
    resolution_type: status === 3 ? (resolution_type || 'manual') : (resolution_type || ''),
    resolved_by: resolved_by || currentUserName(),
    message: message || (status === 2 ? 'Alerta marcado como conhecido.' : 'Alerta finalizado manualmente.')
  };

  const response = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/status`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });

  if(!response.ok){
    const errorText = await response.text();
    console.error('Erro ao atualizar status do alerta:', errorText);
    alert('Não foi possível atualizar o status do alerta.');
    return;
  }

  await loadAlertsPage();
}

function startLiveAlertsRefresh(){
  if(alertsRefreshTimer) clearInterval(alertsRefreshTimer);

  alertsRefreshTimer = setInterval(async () => {
    if(document.hidden) return;
    await loadAlertsPage({ silent: true });
  }, 5000);
}

async function bootAlerts(){
  buildHeader('alerts');
  const groups = [{
    title: 'Alertas',
    items: [
      { key: 'alertsOpenSection', label: 'Alertas recebidos' },
      { key: 'alertsResolvedSection', label: 'Alertas resolvidos' }
    ]
  }];

  renderModuleSidebar('alertsSidebar', groups, (key) => showAlertSection(key));
  showAlertSection('alertsOpenSection');

  await loadAlertsPage();
  startLiveAlertsRefresh();
}

bootAlerts();
