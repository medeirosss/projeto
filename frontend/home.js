let allOnlyAd = [];
let allOnlyEc = [];
let allCves = [];
let onlyAdPage = 1;
let onlyEcPage = 1;
let cvePage = 1;
let cvePageSize = 5;
const PAGE_SIZE = 5;
let refreshTimer = null;
let autoRefreshEnabled = true;

function percentColor(value){
  if(value <= 24) return "#ef4444";
  if(value <= 50) return "#f59e0b";
  if(value <= 79) return "#8b5cf6";
  return "#22c55e";
}

function statusText(value){ return Number(value) === 1 ? "Online" : "Offline"; }
function escapeHtml(value){ return String(value ?? "").replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }

function renderTable(rows, tbodyId, cols, page, pageInfoId, prevId, nextId){
  const start = (page - 1) * PAGE_SIZE;
  const chunk = rows.slice(start, start + PAGE_SIZE);
  const tbody = document.getElementById(tbodyId);
  tbody.innerHTML = chunk.map(r => `<tr>${cols.map(c => `<td>${escapeHtml(r[c])}</td>`).join('')}</tr>`).join('') || `<tr><td colspan="${cols.length}" class="empty-cell">Nenhum registro encontrado.</td></tr>`;
  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  document.getElementById(pageInfoId).textContent = `Mostrando ${chunk.length ? start + 1 : 0} a ${Math.min(start + chunk.length, rows.length)} de ${rows.length} registros`;
  document.getElementById(prevId).disabled = page <= 1;
  document.getElementById(nextId).disabled = page >= totalPages;
}

function renderOnlyEcTable(rows, page){
  const start = (page - 1) * PAGE_SIZE;
  const chunk = rows.slice(start, start + PAGE_SIZE);
  const tbody = document.getElementById("onlyEcTable");
  tbody.innerHTML = chunk.map(r => `<tr><td>${escapeHtml(r.full_name)}</td><td>${escapeHtml(r.agent_logged_on_users || "--")}</td><td><span class="status-pill ${Number(r.live_status) === 1 ? 'online' : 'offline'}">${statusText(r.live_status)}</span></td></tr>`).join('') || `<tr><td colspan="3" class="empty-cell">Nenhum registro encontrado.</td></tr>`;
  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  document.getElementById("onlyEcPageInfo").textContent = `Mostrando ${chunk.length ? start + 1 : 0} a ${Math.min(start + chunk.length, rows.length)} de ${rows.length} registros`;
  document.getElementById("onlyEcPrev").disabled = page <= 1;
  document.getElementById("onlyEcNext").disabled = page >= totalPages;
}

function normalizeCve(cve){
  const intel = cve.cve_intelligence || {};
  return {
    id: cve.id || cve.cve_id || cve.cve || intel.cve || "-",
    product: cve.product || cve.software || cve.name || "Microsoft Windows",
    platform: cve.platform || cve.os || "Windows",
    severity: cve.severity || "Crítico",
    published: cve.published || cve.published_date || cve.release_date || "-",
    magiRiskLevel: cve.magi_risk_level || intel.magi_risk_level || "Alto",
    magiRiskScore: cve.magi_risk_score || intel.magi_risk_score || "-",
    exploitType: cve.exploit_type || intel.exploit_type || "Unknown",
    recommendedPlaybook: cve.recommended_playbook || intel.recommended_playbook || "patch_urgent",
    recommendedAction: cve.recommended_action || intel.recommended_action || "Aplicar patch e validar exposição.",
    decisionReason: cve.decision_reason || intel.decision_reason || "Decisão baseada na severidade informada."
  };
}

function cveRiskClass(level){
  const value = String(level || '').toLowerCase();
  if(value.includes('crit')) return 'risk-critical';
  if(value.includes('alto')) return 'risk-high';
  if(value.includes('medio') || value.includes('médio')) return 'risk-medium';
  return 'risk-low';
}

function renderCriticalCves(cves){
  const tbody = document.getElementById("cveTable");
  const pages = document.getElementById("cvePages");
  const info = document.getElementById("cvePageInfo");
  const seenKey = "centric_seen_critical_cves";
  let seen = [];
  try { seen = JSON.parse(localStorage.getItem(seenKey) || "[]"); if(!Array.isArray(seen)) seen = []; } catch { seen = []; }

  allCves = Array.isArray(cves) ? cves.map(normalizeCve) : [];
  document.getElementById("criticalCveCount").textContent = allCves.length;
  const totalPages = Math.max(1, Math.ceil(allCves.length / cvePageSize));
  if(cvePage > totalPages) cvePage = totalPages;
  const start = (cvePage - 1) * cvePageSize;
  const chunk = allCves.slice(start, start + cvePageSize);

  if(!chunk.length){
    tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">Nenhuma CVE crítica identificada no momento.</td></tr>`;
    info.textContent = "Mostrando 0 CVEs";
    pages.innerHTML = "";
    document.getElementById("cvePrev").disabled = true;
    document.getElementById("cveNext").disabled = true;
    localStorage.setItem(seenKey, JSON.stringify([]));
    return;
  }

  tbody.innerHTML = chunk.map(cve => {
    const isNew = !seen.includes(cve.id);
    const riskClass = cveRiskClass(cve.magiRiskLevel);
    return `<tr class="${isNew ? 'new-cve-row' : ''}" title="${escapeHtml(cve.recommendedAction)}">
      <td class="cve-id">${escapeHtml(cve.id)}</td>
      <td><strong>${escapeHtml(cve.product)}</strong><small class="cve-subline">${escapeHtml(cve.platform)} • ${escapeHtml(cve.published)}</small></td>
      <td><span class="magi-risk-pill ${riskClass}">${escapeHtml(cve.magiRiskLevel)} ${escapeHtml(cve.magiRiskScore)}</span></td>
      <td>${escapeHtml(cve.exploitType)}</td>
      <td><span class="playbook-pill">${escapeHtml(cve.recommendedPlaybook)}</span></td>
      <td class="row-arrow">›</td>
    </tr>`;
  }).join('');

  info.textContent = `Mostrando ${start + 1} a ${Math.min(start + chunk.length, allCves.length)} de ${allCves.length} CVEs`;
  pages.innerHTML = buildPageButtons(cvePage, totalPages);
  document.getElementById("cvePrev").disabled = cvePage <= 1;
  document.getElementById("cveNext").disabled = cvePage >= totalPages;
  pages.querySelectorAll('button[data-page]').forEach(btn => btn.onclick = () => { cvePage = Number(btn.dataset.page); renderCriticalCves(allCves); });
  localStorage.setItem(seenKey, JSON.stringify(allCves.map(c => c.id)));
}

function buildPageButtons(current, total){
  const items = [];
  const add = p => items.push(`<button data-page="${p}" class="${p === current ? 'active' : ''}">${p}</button>`);
  add(1);
  if(current > 3) items.push(`<span>...</span>`);
  for(let p=Math.max(2,current-1); p<=Math.min(total-1,current+1); p++) add(p);
  if(current < total - 2) items.push(`<span>...</span>`);
  if(total > 1) add(total);
  return items.join('');
}

function updateGauge(pct){
  const gauge = document.getElementById("coverageGauge");
  const color = percentColor(pct);
  gauge.style.setProperty('--pct', pct);
  gauge.style.setProperty('--gauge-color', color);
  const pctEl = document.getElementById("percentValue");
  pctEl.textContent = `${pct}%`;
  pctEl.style.color = "inherit";
}

function calculateSecurityScore(summary, cves, alerts){
  const coverage = Number(summary.install_percent || 0);
  const cveCount = Array.isArray(cves) ? cves.length : 0;
  const alertCount = Array.isArray(alerts) ? alerts.length : 0;
  const vulnPenalty = Math.min(35, cveCount * 0.15);
  const alertPenalty = Math.min(20, alertCount * 2);
  const score = Math.max(0, Math.round((coverage * 0.65) + 35 - vulnPenalty - alertPenalty));
  document.getElementById('securityScore').textContent = score;
  document.getElementById('securityScoreBar').style.width = `${score}%`;
  document.getElementById('securityScoreLabel').textContent = score >= 80 ? 'Bom' : score >= 60 ? 'Atenção' : 'Crítico';
  document.getElementById('scoreCompliance').textContent = `${Math.round(coverage)}%`;
  document.getElementById('scoreVuln').textContent = `${Math.max(0, 100 - Math.round(vulnPenalty * 2))}%`;
  document.getElementById('scorePatch').textContent = `${Math.min(100, Math.round(coverage + 10))}%`;
  document.getElementById('scoreConfig').textContent = `${Math.max(0, 100 - alertCount * 5)}%`;
}

async function loadRecentAlerts(){
  const container = document.getElementById('recentAlerts');
  try{
    const res = await fetch('/api/alerts');
    if(!res.ok) throw new Error('alerts unavailable');
    const data = await res.json();
    const alerts = Array.isArray(data.alerts) ? data.alerts : [];
    document.getElementById('openAlertCount').textContent = data?.summary?.open ?? alerts.length;
    const recent = alerts.slice(0,3);
    container.innerHTML = recent.length ? recent.map(alert => {
      const title = alert.display_name || alert.event_type_text || alert.mitre_technique || 'Alerta recebido';
      const detail = `${alert.event_number || ''} ${alert.mitre_technique || ''}`.trim() || 'Aguardando classificação';
      const time = alert.received_at || alert.event_time || '';
      return `<div class="alert-row"><span class="alert-icon">!</span><div><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detail)}</small></div><time>${escapeHtml(formatRelativeTime(time))}</time><span>›</span></div>`;
    }).join('') : `<div class="empty-state">Nenhum alerta aberto no momento.</div>`;
    return alerts;
  }catch(_e){
    document.getElementById('openAlertCount').textContent = '0';
    container.innerHTML = `<div class="empty-state">Não foi possível carregar os alertas.</div>`;
    return [];
  }
}

function formatRelativeTime(value){
  if(!value) return '-';
  const dt = new Date(value);
  if(Number.isNaN(dt.getTime())) return value;
  const diff = Math.max(0, Date.now() - dt.getTime());
  const hours = Math.floor(diff / 3600000);
  if(hours < 1) return 'Agora';
  if(hours < 24) return `Há ${hours}h`;
  return dt.toLocaleDateString();
}

async function loadSettings(){
  const r = await fetch("/api/settings");
  const data = await r.json();
  if(data.configured){
    document.getElementById("refreshHours").value = String(data.refresh_hours || 1);
    setBrandLogo(data.logo_path || data?.theme?.logo_path);
  }
  return data;
}

async function updateRefreshSetting(hours){
  const current = await fetch("/api/settings").then(r=>r.json());
  if(!current.configured) return;
  await fetch("/api/settings", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ logo_path: current.logo_path || "logo.png", dc_host: current.dc_host, domain_username: current.domain_username, domain_password: null, manual_refresh_token: null, cutoff: current.cutoff || null, refresh_hours: Number(hours), page_size: Number(current.page_size || 25), debug_mode: !!current.debug_mode }) });
}

function scheduleAutoRefresh(hours){
  if(refreshTimer) clearInterval(refreshTimer);
  if(!autoRefreshEnabled) return;
  refreshTimer = setInterval(loadDashboard, Number(hours) * 60 * 60 * 1000);
}

async function loadDashboard(){
  const settings = await loadSettings();
  if(!settings.configured){ alert("Configure os parâmetros primeiro."); location.href = "/configuracoes"; return; }
  const pageSize = settings.page_size || 25;
  const res = await fetch(`/api/dashboard?page_size=${pageSize}`);
  const data = await res.json();
  if(!res.ok){ alert(data.detail || "Falha ao carregar dashboard."); return; }

  document.getElementById("adCount").textContent = data.summary.ad_count;
  document.getElementById("ecCount").textContent = data.summary.ec_count;
  document.getElementById("onlyAdCount").textContent = data.summary.only_in_ad_count;
  document.getElementById("inBothCount").textContent = data.summary.in_both_count;
  document.getElementById("logFileName").textContent = data.summary.log_file || "-";
  const now = new Date();
  document.getElementById("lastUpdate").textContent = now.toLocaleString();
  document.getElementById("coverageUpdated").textContent = now.toLocaleString();

  const pct = Number(data.summary.install_percent || 0);
  updateGauge(pct);
  cvePage = 1;
  renderCriticalCves(data.critical_cves || []);

  allOnlyAd = data.only_in_ad || [];
  allOnlyEc = data.only_in_ec || [];
  onlyAdPage = 1; onlyEcPage = 1;
  renderTable(allOnlyAd, "onlyAdTable", ["hostname","dns_host_name","last_logon_date"], onlyAdPage, "onlyAdPageInfo", "onlyAdPrev", "onlyAdNext");
  renderOnlyEcTable(allOnlyEc, onlyEcPage);

  const alerts = await loadRecentAlerts();
  calculateSecurityScore(data.summary, data.critical_cves || [], alerts);
  scheduleAutoRefresh(data.summary.refresh_hours || 1);
}

document.getElementById("onlyAdPrev").onclick = ()=>{ if(onlyAdPage>1){ onlyAdPage--; renderTable(allOnlyAd, "onlyAdTable", ["hostname","dns_host_name","last_logon_date"], onlyAdPage, "onlyAdPageInfo", "onlyAdPrev", "onlyAdNext"); } };
document.getElementById("onlyAdNext").onclick = ()=>{ if(onlyAdPage < Math.ceil(allOnlyAd.length / PAGE_SIZE)){ onlyAdPage++; renderTable(allOnlyAd, "onlyAdTable", ["hostname","dns_host_name","last_logon_date"], onlyAdPage, "onlyAdPageInfo", "onlyAdPrev", "onlyAdNext"); } };
document.getElementById("onlyEcPrev").onclick = ()=>{ if(onlyEcPage>1){ onlyEcPage--; renderOnlyEcTable(allOnlyEc, onlyEcPage); } };
document.getElementById("onlyEcNext").onclick = ()=>{ if(onlyEcPage < Math.ceil(allOnlyEc.length / PAGE_SIZE)){ onlyEcPage++; renderOnlyEcTable(allOnlyEc, onlyEcPage); } };
document.getElementById("cvePrev").onclick = ()=>{ if(cvePage>1){ cvePage--; renderCriticalCves(allCves); } };
document.getElementById("cveNext").onclick = ()=>{ if(cvePage < Math.ceil(allCves.length / cvePageSize)){ cvePage++; renderCriticalCves(allCves); } };
document.getElementById("cvePageSize").onchange = e => { cvePageSize = Number(e.target.value); cvePage = 1; renderCriticalCves(allCves); };
document.getElementById("autoRefreshToggle").onchange = e => { autoRefreshEnabled = e.target.checked; scheduleAutoRefresh(Number(document.getElementById('refreshHours').value)); };

async function bootHome(){
  buildHeader('centric');
  bindThemeToggle();
  const modules = await fetchModuleStatus();
  document.getElementById('moduleSummary').textContent = `UEM: ${modules.uem.enabled && modules.uem.online ? 'ativo' : 'indisponível'} | Security: ${modules.security.enabled && modules.security.online ? 'ativo' : 'indisponível'}`;
  document.getElementById("refreshHours").addEventListener("change", async (e)=>{ await updateRefreshSetting(e.target.value); scheduleAutoRefresh(Number(e.target.value)); });
  loadDashboard();
}

bootHome();
