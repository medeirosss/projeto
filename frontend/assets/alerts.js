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

function riskLabel(level){
  const value = String(level || 'low').toLowerCase();
  if(value === 'critical') return 'Crítico';
  if(value === 'high') return 'Alto';
  if(value === 'medium') return 'Médio';
  return 'Baixo';
}

function riskBadge(alert){
  const level = String(alert.risk_level || 'low').toLowerCase();
  const score = Number(alert.risk_score || 0);
  let cls = 'risk-badge risk-low';
  if(level === 'critical') cls = 'risk-badge risk-critical';
  if(level === 'high') cls = 'risk-badge risk-high';
  if(level === 'medium') cls = 'risk-badge risk-medium';
  return `<span class="${cls}">${esc(riskLabel(level))}${score ? ` ${score}` : ''}</span>`;
}

function normalizeActions(actions){
  if(Array.isArray(actions)) return actions.map(a => String(a || '').trim()).filter(Boolean);
  if(typeof actions === 'string'){
    const text = actions.trim();
    if(!text) return [];
    try{
      const parsed = JSON.parse(text);
      if(Array.isArray(parsed)) return parsed.map(a => String(a || '').trim()).filter(Boolean);
    }catch{}
    return text.split(/[;\n]/).map(a => a.trim()).filter(Boolean);
  }
  return [];
}

function renderRecommendedActions(actions){
  const items = normalizeActions(actions);
  if(!items.length) return '<li>Nenhuma sugestão calculada para este alerta.</li>';
  return items.map(item => `<li>${esc(item)}</li>`).join('');
}

function automationBadge(alert){
  const status = String(alert.automation_status || 'none').toLowerCase();
  if(status === 'executed_ok') return '<span class="automation-badge automation-ok">Automação OK</span>';
  if(status === 'executed_failed') return '<span class="automation-badge automation-failed">Automação falhou</span>';
  return '<span class="automation-badge automation-none">Sem automação</span>';
}

function connectivityLabel(status){
  const value = String(status || 'not_checked').toLowerCase();
  if(value === 'checking') return 'Validando';
  if(value === 'reachable') return 'Alcançável';
  if(value === 'unreachable') return 'Não alcançável';
  if(value === 'check_failed') return 'Falha na validação';
  return 'Não validado';
}

function connectivityBadge(alert){
  const status = String(alert.connectivity_status || 'not_checked').toLowerCase();
  const label = connectivityLabel(status);
  let cls = 'connectivity-badge connectivity-not-checked';
  if(status === 'checking') cls = 'connectivity-badge connectivity-checking';
  if(status === 'reachable') cls = 'connectivity-badge connectivity-reachable';
  if(status === 'unreachable') cls = 'connectivity-badge connectivity-unreachable';
  if(status === 'check_failed') cls = 'connectivity-badge connectivity-failed';
  return `<span class="${cls}">${esc(label)}</span>`;
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
      if(tbody) tbody.innerHTML = `<tr><td colspan="11">Erro ao carregar alertas.</td></tr>`;
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
    tbody.innerHTML = '<tr><td colspan="11">Nenhum alerta ativo.</td></tr>';
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
      <td>${riskBadge(alert)}</td>
      <td>${automationBadge(alert)}</td>
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
  document.getElementById('alertDetailContent')?.classList.add('hidden-section');
  const slot = document.getElementById('detailStatusSlot');
  if(slot) slot.innerHTML = '';
}

function setText(id, value){
  const el = document.getElementById(id);
  if(el) el.textContent = value;
}

function statusLabel(alert){
  const status = Number(alert?.status || 0);
  if(status === 1) return alert.status_label || 'Novo Alarme';
  if(status === 2) return alert.status_label || 'Conhecido / em tratamento';
  if(status === 3) return alert.status_label || 'Finalizado';
  return alert.status_label || String(status || '--');
}

function selectAlert(alert, rerender = true){
  selectedAlert = alert;
  document.getElementById('alertDetailContent')?.classList.remove('hidden-section');

  const alertId = alertIdOf(alert);
  const title = val(alert.display_name || alert.event || alert.event_number, 'Alerta inbound');
  const source = val(alert.source_system, 'Origem não informada');
  const received = val(alert.received_at || getFromAlert(alert, 'received_at', 'event_time', 'timestamp'), '--');
  const resolvedAt = val(alert.resolved_at, '--');
  const resolvedBy = val(alert.resolved_by, '--');
  const resolutionMethod = val(alert.resolution_method || alert.resolution_type, '--');
  const eventNumber = val(alert.event_number || getFromAlert(alert, 'event_number', 'event_id', 'EventID'), '--');
  const targetUser = val(getFromAlert(alert, 'target_user', 'username', 'account_name', 'TargetUserName'), '--');
  const actor = val(getFromAlert(alert, 'actor_user', 'caller_user_name', 'subject_user', 'SubjectUserName'), '--');
  const host = val(getFromAlert(alert, 'hostname', 'host', 'computer', 'winlog.computer_name'), '--');
  const ip = val(getFromAlert(alert, 'ip_address', 'target_ip', 'source_ip', 'source.ip'), '--');
  const group = val(getFromAlert(alert, 'group_name', 'target_group', 'TargetGroupName', 'group'), '--');
  const mitre = val(alert.technique || alert.mitre_technique || getFromAlert(alert, 'mitre_technique', 'technique'), '--');
  const tactic = val(alert.tactic || alert.mitre_tactic || getFromAlert(alert, 'mitre_tactic', 'tactic'), '--');
  const nist = val(alert.nist || alert.nist_control || getFromAlert(alert, 'nist_control', 'nist'), '--');
  const recommendation = val(getFromAlert(alert, 'recommendation'), 'Validar o evento com o time responsável e confirmar se a atividade foi autorizada.');
  const severity = val(alert.severity, 'Media');
  const status = statusLabel(alert);
  const connectivityStatus = String(alert.connectivity_status || 'not_checked').toLowerCase();
  const connectivityMessage = val(alert.connectivity_message, connectivityLabel(connectivityStatus));
  const connectivityAt = val(alert.connectivity_at, '--');
  const riskLevel = String(alert.risk_level || 'low').toLowerCase();
  const riskScore = Number(alert.risk_score || 0);
  const contextSummary = val(alert.context_summary, 'Contexto ainda não calculado para este alerta.');
  const contextCategory = val(alert.context_category, 'Sem categoria');
  const recommendedActions = alert.recommended_actions || [];

  document.getElementById('detailStatusSlot').innerHTML = statusBadge(alert);
  setText('detailTitle', title);
  setText('detailSubtitle', `${source} • ${received}`);
  setText('detailUser', targetUser);
  setText('detailActor', actor);
  setText('detailHost', host);
  setText('detailIp', ip);
  setText('detailGroup', group);
  setText('detailAlertId', alertId || '--');
  setText('detailMitre', mitre);
  setText('detailTactic', tactic);
  setText('detailNist', nist);
  setText('detailRecommendation', recommendation);
  setText('detailReceived', received);
  setText('detailCurrentStatus', status);
  setText('detailResolved', resolvedAt);
  setText('detailResolvedBy', resolvedBy === '--' && resolutionMethod === '--' ? '--' : `${resolvedBy} / ${resolutionMethod}`);
  setText('detailEventBadge', `Evento ${eventNumber}`);
  setText('detailSeverityBadge', severity);
  setText('detailSourceBadge', source);
  setText('detailConnectivityIp', ip);
  setText('detailConnectivityMessage', connectivityMessage);
  setText('detailConnectivityAt', connectivityAt === '--' ? 'Sem execução registrada' : `Executada em ${connectivityAt}`);
  setText('detailRiskScore', riskScore ? `${riskScore}/100` : '--');
  setText('detailRiskLevelText', `Nível ${riskLabel(riskLevel)}`);
  setText('detailContextSummary', contextSummary);
  setText('detailContextCategory', contextCategory);

  const riskBadgeEl = document.getElementById('detailRiskBadge');
  if(riskBadgeEl){
    const level = String(alert.risk_level || 'low').toLowerCase();
    riskBadgeEl.className = `risk-badge risk-${['critical','high','medium','low'].includes(level) ? level : 'low'}`;
    riskBadgeEl.textContent = `${riskLabel(level)}${riskScore ? ` ${riskScore}` : ''}`;
  }

  const actionsList = document.getElementById('detailRecommendedActions');
  if(actionsList) actionsList.innerHTML = renderRecommendedActions(recommendedActions);

  const connBadge = document.getElementById('detailConnectivityBadge');
  if(connBadge){
    const connHtml = connectivityBadge(alert);
    const tmp = document.createElement('div');
    tmp.innerHTML = connHtml;
    const newBadge = tmp.firstElementChild;
    connBadge.className = newBadge?.className || 'connectivity-badge connectivity-not-checked';
    connBadge.textContent = newBadge?.textContent || 'Não validado';
  }

  const autoBadge = document.getElementById('detailAutomationBadge');
  if(autoBadge){
    const autoHtml = automationBadge(alert);
    const tmp = document.createElement('div');
    tmp.innerHTML = autoHtml;
    const newBadge = tmp.firstElementChild;
    autoBadge.className = newBadge?.className || 'automation-badge automation-none';
    autoBadge.textContent = newBadge?.textContent || 'Sem automação';
  }

  const severityBadgeEl = document.getElementById('detailSeverityBadge');
  if(severityBadgeEl) severityBadgeEl.className = `severity-badge ${severityClass(severity)}`;

  const icon = document.getElementById('detailSeverityIcon');
  if(icon){
    icon.className = `detail-icon ${severityClass(severity)}`;
    icon.textContent = severity.toLowerCase().includes('crit') ? '!' : severity.toLowerCase().includes('alta') ? '!' : 'i';
  }

  const payloadBox = document.getElementById('alertsPayloadBox');
  if(payloadBox) payloadBox.textContent = JSON.stringify(getRaw(alert), null, 2);

  const known = document.getElementById('detailKnownBtn');
  const resolve = document.getElementById('detailResolveBtn');
  const actionLink = document.getElementById('detailActionLink');

  if(known) known.onclick = () => setAlertStatus(alertId, 2, '', currentUserName(), 'Alerta marcado como conhecido.');
  if(resolve) resolve.onclick = () => setAlertStatus(alertId, 3, 'manual', currentUserName(), 'Alerta finalizado manualmente.');
  if(actionLink){
    const params = new URLSearchParams({
      alert_id: alertId || '',
      target_user: targetUser === '--' ? '' : targetUser,
      host: host === '--' ? '' : host,
      ip: ip === '--' ? '' : ip
    });
    actionLink.href = `/acoes?${params.toString()}`;
  }

  const connectivityBtn = document.getElementById('detailConnectivityBtn') || document.getElementById('detailValidateConnectivityBtn');
  if(connectivityBtn){
    connectivityBtn.dataset.alertId = alertId || '';
    connectivityBtn.disabled = connectivityStatus === 'checking';
    connectivityBtn.classList.toggle('is-loading', connectivityStatus === 'checking');
    connectivityBtn.innerHTML = connectivityStatus === 'checking'
      ? '<span class="btn-spinner"></span><span>Validando...</span>'
      : '<span>Validar conectividade</span>';
  }

  if(Number(alert.status || 0) === 3){
    known?.setAttribute('disabled','disabled');
    resolve?.setAttribute('disabled','disabled');
  }else{
    known?.removeAttribute('disabled');
    resolve?.removeAttribute('disabled');
  }

  if(rerender) renderOpenAlerts();
}

function currentUserName(){
  try{
    return localStorage.getItem('username') || localStorage.getItem('user') || 'admin';
  }catch{
    return 'admin';
  }
}


async function runConnectivityValidation(alertId, sourceButton = null){
  if(!alertId){
    alert('Alerta inválido para validação de conectividade.');
    return;
  }

  const btn = sourceButton || document.getElementById('detailConnectivityBtn') || document.getElementById('detailValidateConnectivityBtn');
  if(btn){
    btn.disabled = true;
    btn.classList.add('is-loading');
    btn.innerHTML = '<span class="btn-spinner"></span><span>Validando...</span>';
  }

  try{
    const response = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/validate-connectivity`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({})
    });

    if(!response.ok){
      const errorText = await response.text();
      console.error('Erro ao validar conectividade:', errorText);
      alert('Não foi possível iniciar a validação de conectividade.');
      return;
    }

    if(btn){
      btn.innerHTML = '<span class="btn-check">✓</span><span>Validação enviada</span>';
    }

    await loadAlertsPage({ silent: true });
  }catch(error){
    console.error('Erro ao validar conectividade:', error);
    alert('Não foi possível iniciar a validação de conectividade.');
  }finally{
    setTimeout(() => {
      const currentBtn = document.getElementById('detailConnectivityBtn') || document.getElementById('detailValidateConnectivityBtn');
      if(currentBtn){
        currentBtn.disabled = false;
        currentBtn.classList.remove('is-loading');
        currentBtn.innerHTML = '<span>Validar conectividade</span>';
      }
    }, 900);
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


document.addEventListener('click', async (event) => {
  const btn = event.target.closest('#detailConnectivityBtn, #detailValidateConnectivityBtn');
  if(!btn) return;

  event.preventDefault();
  event.stopPropagation();

  const alertId = btn.dataset.alertId || alertIdOf(selectedAlert);
  await runConnectivityValidation(alertId, btn);
});

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
