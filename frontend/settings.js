let settingsModules = null;
let moduleState = { uem: true, security: false };
let currentSettings = null;

function showSettingsSection(section){
  document.querySelectorAll('.report-content .report-section').forEach(el => el.classList.add('hidden-section'));
  const target = document.getElementById(section);
  if(target) target.classList.remove('hidden-section');
}

function setModuleStatusVisual(){
  document.getElementById('statusUemText').innerHTML = `<span class="dot ${moduleState.uem ? 'dot-green' : 'dot-red'}"></span>${moduleState.uem ? 'Ativo' : 'Desativado'}`;
  document.getElementById('statusSecurityText').innerHTML = `<span class="dot ${moduleState.security ? 'dot-green' : 'dot-red'}"></span>${moduleState.security ? 'Ativo' : 'Desativado'}`;
}

function setMessage(id, text){
  const el = document.getElementById(id);
  if(el) el.textContent = text;
}

function buildPayload(){
  return {
    theme: {
      logo_path: document.getElementById('logo_path')?.value.trim() || 'logo.png',
      brand_name: document.getElementById('brand_name')?.value.trim() || 'Centric',
      accent_color: document.getElementById('accent_color')?.value || '#7c3aed'
    },
    modules: { uem: { enabled: moduleState.uem }, security: { enabled: moduleState.security } },
    mail_server: {
      host: document.getElementById('smtp_host').value.trim(),
      port: Number(document.getElementById('smtp_port').value || 587),
      username: document.getElementById('smtp_username').value.trim(),
      password: document.getElementById('smtp_password').value || '',
      sender: document.getElementById('smtp_sender').value.trim(),
      use_tls: document.getElementById('smtp_security').value === 'tls',
      use_ssl: document.getElementById('smtp_security').value === 'ssl',
      whatsapp_enabled: document.getElementById('whatsapp_enabled').checked,
      n8n_webhook_url: document.getElementById('n8n_webhook_url').value.trim()
    },
    discovery: {
      dns: {
        enabled: document.getElementById('discovery_dns_enabled')?.checked ?? false,
        servers: [document.getElementById('discovery_dns_primary')?.value.trim(), document.getElementById('discovery_dns_secondary')?.value.trim()].filter(Boolean),
        suffix: document.getElementById('discovery_dns_suffix')?.value.trim() || '',
        timeout_seconds: Number(document.getElementById('discovery_dns_timeout')?.value || 2),
        fallback_system: document.getElementById('discovery_dns_fallback')?.checked ?? true
      }
    },
    webhook: {
      enabled: document.getElementById('webhook_enabled')?.checked ?? true,
      token: document.getElementById('webhook_token')?.value || '',
      trusted_sources: (document.getElementById('webhook_trusted_sources')?.value || '').split('\n').map(v => v.trim()).filter(Boolean),
      require_token_external: document.getElementById('webhook_require_token_external')?.checked ?? true,
      proxy_enabled: document.getElementById('webhook_proxy_enabled')?.checked ?? false,
      trusted_proxies: (document.getElementById('webhook_trusted_proxies')?.value || '').split('\n').map(v => v.trim()).filter(Boolean),
      real_ip_header: document.getElementById('webhook_real_ip_header')?.value || 'X-Forwarded-For'
    },
    uem: {
      api: {
        client_id: document.getElementById('client_id').value.trim(),
        client_secret: document.getElementById('client_secret').value.trim(),
        refresh_token: document.getElementById('manual_refresh_token').value.trim()
      },
      active_directory: {
        dc_host: document.getElementById('dc_host').value.trim(),
        ldap_port: Number(document.getElementById('ldap_port').value || (document.getElementById('ad_use_ssl').value === 'true' ? 636 : 389)),
        use_ssl: document.getElementById('ad_use_ssl').value === 'true',
        domain_name: document.getElementById('ad_domain_name').value.trim(),
        base_dn: document.getElementById('ad_base_dn').value.trim(),
        domain_username: document.getElementById('domain_username').value.trim(),
        domain_password: document.getElementById('domain_password').value || ''
      },
      parameters: {
        cutoff_days: Number(document.getElementById('cutoff').value || 0) || null,
        refresh_hours: Number(document.getElementById('refresh_hours').value || 1),
        page_size: Number(document.getElementById('page_size').value || 25),
        debug_mode: document.getElementById('debug_mode').value === 'true'
      },
      ip_scope: { cidrs: document.getElementById('ip_scope').value.split('\n').map(v => v.trim()).filter(Boolean) }
    }
  };
}

function clearSensitiveInputs(){
  ['client_secret','manual_refresh_token','domain_password','smtp_password','webhook_token'].forEach(id => {
    const el = document.getElementById(id);
    if(el) el.value = '';
  });
}

async function saveSettings(messageTarget='statusBox'){
  const payload = buildPayload();
  const res = await fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
  const data = await res.json().catch(()=> ({}));
  if(!res.ok){ setMessage(messageTarget, data.detail || 'Erro ao salvar configurações.'); return false; }
  setMessage(messageTarget, 'Configurações salvas com sucesso.');
  clearSensitiveInputs();
  await loadSettings();
  return true;
}

async function loadSettings(){
  const data = await fetch('/api/settings').then(r=>r.json()).catch(()=> ({}));
  currentSettings = data;
  const branding = data?.theme || {};
  const savedLogo = branding.logo_path || 'logo.png';
  const savedName = branding.brand_name || 'Centric';
  const savedAccent = branding.accent_color || '#7c3aed';
  setBrandLogo(savedLogo);
  setBrandName(savedName);
  setAccentColor(savedAccent);
  if(document.getElementById('logo_path')) document.getElementById('logo_path').value = savedLogo;
  if(document.getElementById('brand_name')) document.getElementById('brand_name').value = savedName;
  if(document.getElementById('accent_color')) document.getElementById('accent_color').value = savedAccent;
  updateBrandingPreview();
  document.getElementById('dc_host').value = data?.uem?.active_directory?.dc_host || '';
  document.getElementById('ldap_port').value = data?.uem?.active_directory?.ldap_port || (data?.uem?.active_directory?.use_ssl ? 636 : 389);
  document.getElementById('ad_use_ssl').value = data?.uem?.active_directory?.use_ssl ? 'true' : 'false';
  document.getElementById('ad_domain_name').value = data?.uem?.active_directory?.domain_name || '';
  document.getElementById('ad_base_dn').value = data?.uem?.active_directory?.base_dn || '';
  document.getElementById('domain_username').value = data?.uem?.active_directory?.domain_username || '';
  document.getElementById('cutoff').value = data?.uem?.parameters?.cutoff_days ?? '';
  document.getElementById('refresh_hours').value = String(data?.uem?.parameters?.refresh_hours || 1);
  document.getElementById('page_size').value = String(data?.uem?.parameters?.page_size || 25);
  document.getElementById('debug_mode').value = String(!!data?.uem?.parameters?.debug_mode);
  document.getElementById('client_id').value = data?.uem?.api?.client_id || '';
  document.getElementById('client_secret').placeholder = data?.has_client_secret ? 'Secret já salvo. Deixe vazio para manter.' : 'Deixe vazio para manter';
  document.getElementById('manual_refresh_token').placeholder = data?.has_refresh_token ? 'Refresh token já salvo. Deixe vazio para manter.' : 'Deixe vazio para manter';
  document.getElementById('domain_password').placeholder = data?.has_password ? 'Senha já salva. Deixe vazio para manter.' : 'Deixe vazio para manter';
  document.getElementById('smtp_host').value = data?.mail_server?.host || '';
  document.getElementById('smtp_port').value = data?.mail_server?.port || 587;
  document.getElementById('smtp_username').value = data?.mail_server?.username || '';
  document.getElementById('smtp_password').placeholder = data?.has_mail_password ? 'Senha já salva. Deixe vazio para manter.' : 'Deixe vazio para manter';
  document.getElementById('smtp_security').value = data?.mail_server?.use_ssl ? 'ssl' : (data?.mail_server?.use_tls ? 'tls' : 'none');
  document.getElementById('smtp_sender').value = data?.mail_server?.sender || data?.mail_server?.from_email || '';
  document.getElementById('whatsapp_enabled').checked = !!data?.mail_server?.whatsapp_enabled;
  document.getElementById('n8n_webhook_url').value = data?.mail_server?.n8n_webhook_url || '';
  document.getElementById('ip_scope').value = Array.isArray(data?.uem?.ip_scope?.cidrs) ? data.uem.ip_scope.cidrs.join('\n') : '';

  const discoveryDns = data?.discovery?.dns || {};
  if(document.getElementById('discovery_dns_enabled')) document.getElementById('discovery_dns_enabled').checked = !!discoveryDns.enabled;
  if(document.getElementById('discovery_dns_primary')) document.getElementById('discovery_dns_primary').value = discoveryDns.servers?.[0] || '';
  if(document.getElementById('discovery_dns_secondary')) document.getElementById('discovery_dns_secondary').value = discoveryDns.servers?.[1] || '';
  if(document.getElementById('discovery_dns_suffix')) document.getElementById('discovery_dns_suffix').value = discoveryDns.suffix || '';
  if(document.getElementById('discovery_dns_timeout')) document.getElementById('discovery_dns_timeout').value = String(discoveryDns.timeout_seconds || 2);
  if(document.getElementById('discovery_dns_fallback')) document.getElementById('discovery_dns_fallback').checked = discoveryDns.fallback_system !== false;

  moduleState.uem = data?.modules?.uem?.enabled ?? true;
  moduleState.security = data?.modules?.security?.enabled ?? false;
  setModuleStatusVisual();
  setMessage('statusBox', data?.configured ? 'Configurações carregadas com sucesso.' : 'Preencha as credenciais para habilitar o módulo UEM.');
}

async function testAd(){
  setMessage('adStatusBox', 'Testando conectividade com o AD...');
  const res = await fetch('/api/settings/test-ad', { method:'POST' });
  const data = await res.json().catch(()=> ({}));
  setMessage('adStatusBox', res.ok ? `Conexão com AD OK. Objetos lidos: ${data.total}. Log: ${data.log_file}` : (data.detail || 'Falha no teste do AD.'));
}

async function testEc(){
  setMessage('apiStatusBox', 'Testando conexão com o Endpoint Central...');
  const res = await fetch('/api/settings/test-ec', { method:'POST' });
  const data = await res.json().catch(()=> ({}));
  setMessage('apiStatusBox', res.ok ? `Endpoint OK. Registros: ${data.total}. Origem do token: ${data.token_source}.` : (data.detail || 'Falha no teste do Endpoint Central.'));
}

async function refreshToken(){
  setMessage('apiStatusBox', 'Validando refresh token e gerando access token temporário...');
  const res = await fetch('/api/token/refresh', { method:'POST' });
  const data = await res.json().catch(()=> ({}));
  if(res.ok){
    setMessage('apiStatusBox', `Refresh token validado. Access token temporário gerado pelo backend. Origem: ${data.token_source}.`);
  }else{
    setMessage('apiStatusBox', data.detail || 'Falha ao gerar access token pelo refresh token.');
  }
}

async function forceScan(){
  setMessage('scanStatus', 'Executando scan... aguarde');
  const res = await fetch('/api/scan-now', { method:'POST' });
  const data = await res.json().catch(()=> ({}));
  setMessage('scanStatus', res.ok ? `Scan concluído | AD: ${data.ad_total} | EC: ${data.ec_total} | Token: ${data.token_source}` : (data.detail || 'Erro ao executar scan.'));
}


function updateBrandingPreview(){
  const logoValue = document.getElementById('logo_path')?.value || 'logo.png';
  const nameValue = document.getElementById('brand_name')?.value || 'Centric';
  const accentValue = document.getElementById('accent_color')?.value || '#7c3aed';
  const logo = document.getElementById('brandingPreviewLogo');
  const name = document.getElementById('brandingPreviewName');
  if(logo) logo.src = normalizeAssetPath(logoValue);
  if(name) name.textContent = nameValue;
  setBrandLogo(logoValue);
  setBrandName(nameValue);
  setAccentColor(accentValue);
}

function resetBranding(){
  const logo = document.getElementById('logo_path');
  const name = document.getElementById('brand_name');
  const color = document.getElementById('accent_color');
  if(logo) logo.value = 'logo.png';
  if(name) name.value = 'Centric';
  if(color) color.value = '#7c3aed';
  localStorage.removeItem('centric-brand-logo');
  localStorage.removeItem('centric-brand-name');
  localStorage.removeItem('centric-accent-color');
  updateBrandingPreview();
  setMessage('brandingStatusBox', 'Padrão restaurado. Clique em Salvar branding para persistir.');
}

function bindBrandingActions(){
  ['logo_path','brand_name','accent_color'].forEach(id => {
    const el = document.getElementById(id);
    if(el) el.addEventListener('input', updateBrandingPreview);
  });
  const file = document.getElementById('brand_logo_file');
  if(file){
    file.addEventListener('change', () => {
      const selected = file.files && file.files[0];
      if(!selected) return;
      const reader = new FileReader();
      reader.onload = () => {
        const logoInput = document.getElementById('logo_path');
        if(logoInput) logoInput.value = String(reader.result || '');
        updateBrandingPreview();
        setMessage('brandingStatusBox', 'Logo carregado para prévia. Clique em Salvar branding para persistir.');
      };
      reader.readAsDataURL(selected);
    });
  }
  document.getElementById('saveBrandingSettingsBtn')?.addEventListener('click', async () => {
    localStorage.setItem('centric-brand-logo', document.getElementById('logo_path')?.value || 'logo.png');
    localStorage.setItem('centric-brand-name', document.getElementById('brand_name')?.value || 'Centric');
    localStorage.setItem('centric-accent-color', document.getElementById('accent_color')?.value || '#7c3aed');
    await saveSettings('brandingStatusBox');
  });
  document.getElementById('resetBrandingBtn')?.addEventListener('click', resetBranding);
}

function bindFixedActions(){
  document.getElementById('saveMailSettingsBtn').addEventListener('click', ()=> saveSettings('statusBox'));
  document.getElementById('saveWebhookSettingsBtn')?.addEventListener('click', ()=> saveSettings('webhookStatusBox'));
  document.getElementById('saveApiSettingsBtn').addEventListener('click', ()=> saveSettings('apiStatusBox'));
  document.getElementById('saveAdSettingsBtn').addEventListener('click', ()=> saveSettings('adStatusBox'));
  document.getElementById('saveParametersBtn').addEventListener('click', ()=> saveSettings('scanStatus'));
  document.getElementById('saveDiscoveryDnsBtn')?.addEventListener('click', ()=> saveSettings('discoveryDnsStatusBox'));
  document.getElementById('saveIpScopeBtn').addEventListener('click', ()=> saveSettings('statusBox'));
  document.getElementById('saveModuleStateBtn').addEventListener('click', ()=> saveSettings('statusBox'));
  document.getElementById('toggleUemBtn').addEventListener('click', ()=> { moduleState.uem = !moduleState.uem; setModuleStatusVisual(); });
  document.getElementById('toggleSecurityBtn').addEventListener('click', ()=> { moduleState.security = !moduleState.security; setModuleStatusVisual(); });
  document.getElementById('ad_use_ssl').addEventListener('change', ()=> {
    const port = document.getElementById('ldap_port');
    if(port && (!port.value || port.value === '389' || port.value === '636')){
      port.value = document.getElementById('ad_use_ssl').value === 'true' ? '636' : '389';
    }
  });
  document.getElementById('testAdBtn').addEventListener('click', testAd);
  document.getElementById('testEcBtn').addEventListener('click', testEc);
  document.getElementById('refreshTokenBtn').addEventListener('click', refreshToken);
  document.getElementById('forceScanBtn').addEventListener('click', forceScan);
  bindBrandingActions();
}


async function bootSettings(){
  buildHeader('settings');
  settingsModules = await fetchModuleStatus();
  const groups = [
    { title:'Fixos', items:[{ key:'settingsMailSection', label:'Mail Server' }, { key:'settingsBrandingSection', label:'Branding' }, { key:'settingsStatusSection', label:'Status' }] },
    { title:'Discovery', items:[{ key:'settingsDiscoveryDnsSection', label:'DNS' }] },
    { title:'UEM', items:[{ key:'settingsUemApiSection', label:'APIs' }, { key:'settingsAdSection', label:'Active Directory' }, { key:'settingsParametersSection', label:'Parâmetros' }, { key:'settingsIpScopeSection', label:'IP Scope' }] }
  ];
  renderModuleSidebar('settingsSidebar', groups, (key)=> showSettingsSection(key));
  showSettingsSection('settingsMailSection');
  bindFixedActions();
  await loadSettings();
}


async function loadAuthAccess(){
  const usersBody = document.getElementById('allowedUsersTable');
  const groupsBody = document.getElementById('allowedGroupsTable');
  if(!usersBody || !groupsBody) return;
  try{
    const [usersRes, groupsRes] = await Promise.all([fetch('/api/auth/allowed-users'), fetch('/api/auth/allowed-groups')]);
    const users = await usersRes.json();
    const groups = await groupsRes.json();
    usersBody.innerHTML = (users.users || []).map(u => `<tr><td>${u.username}</td><td>${u.role}</td><td>${u.enabled ? 'Ativo' : 'Inativo'}</td><td><button class="btn danger auth-del-user" data-id="${u.id}" type="button">Remover</button></td></tr>`).join('') || '<tr><td colspan="4">Nenhum usuário configurado. Enquanto vazio, o bootstrap pode liberar o primeiro login AD como admin.</td></tr>';
    groupsBody.innerHTML = (groups.groups || []).map(g => `<tr><td>${g.group_name}</td><td>${g.role}</td><td>${g.enabled ? 'Ativo' : 'Inativo'}</td><td><button class="btn danger auth-del-group" data-id="${g.id}" type="button">Remover</button></td></tr>`).join('') || '<tr><td colspan="4">Nenhum grupo configurado.</td></tr>';
    document.querySelectorAll('.auth-del-user').forEach(btn => btn.addEventListener('click', async ()=>{ await fetch(`/api/auth/allowed-users/${btn.dataset.id}`, {method:'DELETE'}); await loadAuthAccess(); }));
    document.querySelectorAll('.auth-del-group').forEach(btn => btn.addEventListener('click', async ()=>{ await fetch(`/api/auth/allowed-groups/${btn.dataset.id}`, {method:'DELETE'}); await loadAuthAccess(); }));
  }catch(e){ setMessage('authStatusBox', 'Falha ao carregar usuários/grupos autorizados.'); }
}

async function saveAllowedUser(){
  const username = document.getElementById('auth_username').value.trim();
  const role = document.getElementById('auth_user_role').value;
  const res = await fetch('/api/auth/allowed-users', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, role, enabled:true})});
  const data = await res.json().catch(()=>({}));
  setMessage('authStatusBox', res.ok ? 'Usuário autorizado salvo.' : (data.detail || 'Falha ao salvar usuário.'));
  if(res.ok){ document.getElementById('auth_username').value=''; await loadAuthAccess(); }
}

async function saveAllowedGroup(){
  const group_name = document.getElementById('auth_group_name').value.trim();
  const role = document.getElementById('auth_group_role').value;
  const res = await fetch('/api/auth/allowed-groups', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({group_name, role, enabled:true})});
  const data = await res.json().catch(()=>({}));
  setMessage('authStatusBox', res.ok ? 'Grupo autorizado salvo.' : (data.detail || 'Falha ao salvar grupo.'));
  if(res.ok){ document.getElementById('auth_group_name').value=''; await loadAuthAccess(); }
}

const originalBindFixedActions = bindFixedActions;
bindFixedActions = function(){
  originalBindFixedActions();
  const userBtn = document.getElementById('saveAllowedUserBtn');
  const groupBtn = document.getElementById('saveAllowedGroupBtn');
  if(userBtn) userBtn.addEventListener('click', saveAllowedUser);
  if(groupBtn) groupBtn.addEventListener('click', saveAllowedGroup);
};

const originalBootSettings = bootSettings;
bootSettings = async function(){
  buildHeader('settings');
  settingsModules = await fetchModuleStatus();
  const groups = [
    { title:'Fixos', items:[{ key:'settingsMailSection', label:'Mail Server' }, { key:'settingsBrandingSection', label:'Branding' }, { key:'settingsWebhookSection', label:'Webhook' }, { key:'settingsUsersSection', label:'Usuários' }, { key:'settingsStatusSection', label:'Status' }] },
    { title:'Discovery', items:[{ key:'settingsDiscoveryDnsSection', label:'DNS' }] },
    { title:'UEM', items:[{ key:'settingsUemApiSection', label:'APIs' }, { key:'settingsAdSection', label:'Active Directory' }, { key:'settingsParametersSection', label:'Parâmetros' }, { key:'settingsIpScopeSection', label:'IP Scope' }] }
  ];
  renderModuleSidebar('settingsSidebar', groups, async (key)=> { showSettingsSection(key); if(key === 'settingsUsersSection') await loadAuthAccess(); });
  showSettingsSection('settingsMailSection');
  bindFixedActions();
  await loadSettings();
};


function runnerStatusBadge(status){
  const normalized = String(status || 'offline').toLowerCase();
  const cls = normalized === 'online' ? 'badge-low' : (normalized === 'disabled' ? 'badge-critical' : 'badge-medium');
  return `<span class="risk-badge ${cls}">${normalized}</span>`;
}

function formatRunnerDate(value){
  if(!value) return '-';
  try{ return new Date(value).toLocaleString('pt-BR'); }catch(e){ return String(value); }
}

async function loadRunners(){
  const body = document.getElementById('runnersTableBody');
  if(!body) return;
  body.innerHTML = '<tr><td colspan="10">Carregando runners...</td></tr>';
  try{
    const res = await fetch('/api/runner/runners');
    const data = await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(data.detail || 'Falha ao carregar runners.');
    const runners = data.runners || [];
    if(!runners.length){
      body.innerHTML = '<tr><td colspan="10">Nenhum runner registrado ainda.</td></tr>';
      setMessage('runnersStatusBox', 'Nenhum runner reportando para o Magi.');
      return;
    }
    body.innerHTML = runners.map(r => `
      <tr>
        <td>${r.runner_id || '-'}</td>
        <td>${runnerStatusBadge(r.status)}</td>
        <td>${r.hostname || r.name || '-'}</td>
        <td>${r.ip_address || r?.metadata?.remote_addr || '-'}</td>
        <td>${r.os || '-'}</td>
        <td>${r.atomic_mode || '-'}</td>
        <td>${r.open_jobs ?? 0}</td>
        <td>${r.queue_paused ? '<span class="risk-badge badge-critical">PAUSADA</span>' : '<span class="risk-badge badge-low">LIBERADA</span>'}</td>
        <td>${formatRunnerDate(r.last_heartbeat)}</td>
        <td><button class="btn danger btn-sm runner-clear-btn" data-runner-id="${r.runner_id || ''}" type="button">Limpar Runner</button> <button class="btn secondary btn-sm runner-resume-btn" data-runner-id="${r.runner_id || ''}" type="button">Liberar fila</button></td>
      </tr>
    `).join('');
    document.querySelectorAll('.runner-resume-btn').forEach(btn => btn.addEventListener('click', async()=>{
      const runnerId=btn.dataset.runnerId; if(!runnerId) return; btn.disabled=true;
      try{ const res=await fetch(`/api/settings/runners/${encodeURIComponent(runnerId)}/resume-queue`,{method:'POST'}); const data=await res.json().catch(()=>({})); if(!res.ok) throw new Error(data.detail||'Falha ao liberar fila.'); await loadRunners(); }catch(e){setMessage('runnersStatusBox',e.message);btn.disabled=false;}
    }));
    document.querySelectorAll('.runner-clear-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const runnerId = btn.dataset.runnerId;
        if(!runnerId) return;
        const ok = confirm(`Limpar o Runner ${runnerId}?\n\nTodos os jobs pendentes ou em execução serão marcados como CANCELLED. Jobs já concluídos serão preservados no histórico.`);
        if(!ok) return;
        btn.disabled = true;
        setMessage('runnersStatusBox', `Limpando fila do Runner ${runnerId}...`);
        try{
          const res = await fetch(`/api/settings/runners/${encodeURIComponent(runnerId)}/clear`, {method:'POST'});
          const data = await res.json().catch(()=>({}));
          if(!res.ok) throw new Error(data.detail || 'Falha ao limpar Runner.');
          await loadRunners();
          setMessage('runnersStatusBox', `Runner ${runnerId} limpo: ${data.jobs_cancelled ?? 0} job(s) cancelado(s), ${data.campaign_paths_cancelled ?? 0} path(s) da Campaign cancelado(s).`);
        }catch(e){
          setMessage('runnersStatusBox', e.message || 'Falha ao limpar Runner.');
          btn.disabled = false;
        }
      });
    });
    setMessage('runnersStatusBox', `${runners.length} runner(s) encontrados.`);
    if(runners[0]?.runner_id) await loadRunnerJobs(runners[0].runner_id);
  }catch(e){
    body.innerHTML = `<tr><td colspan="10">${e.message || 'Falha ao carregar runners.'}</td></tr>`;
    setMessage('runnersStatusBox', e.message || 'Falha ao carregar runners.');
  }
}

const previousBindFixedActionsForRunners = bindFixedActions;
bindFixedActions = function(){
  previousBindFixedActionsForRunners();
  document.getElementById('refreshRunnersBtn')?.addEventListener('click', loadRunners);
};

const previousBootSettingsForRunners = bootSettings;
bootSettings = async function(){
  buildHeader('settings');
  settingsModules = await fetchModuleStatus();
  const groups = [
    { title:'Fixos', items:[{ key:'settingsMailSection', label:'Mail Server' }, { key:'settingsBrandingSection', label:'Branding' }, { key:'settingsWebhookSection', label:'Webhook' }, { key:'settingsUsersSection', label:'Usuários' }, { key:'settingsStatusSection', label:'Status' }, { key:'settingsRunnersSection', label:'Runners' }] },
    { title:'Discovery', items:[{ key:'settingsDiscoveryDnsSection', label:'DNS' }] },
    { title:'UEM', items:[{ key:'settingsUemApiSection', label:'APIs' }, { key:'settingsAdSection', label:'Active Directory' }, { key:'settingsParametersSection', label:'Parâmetros' }, { key:'settingsIpScopeSection', label:'IP Scope' }] }
  ];
  renderModuleSidebar('settingsSidebar', groups, async (key)=> {
    showSettingsSection(key);
    if(key === 'settingsUsersSection') await loadAuthAccess();
    if(key === 'settingsRunnersSection') await loadRunners();
  });
  showSettingsSection('settingsMailSection');
  bindFixedActions();
  await loadSettings();
};



// Sprint 3.1 — Credential Engine
function credEsc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
function credentialTypeLabel(v){const m={windows:'Windows',ssh:'SSH',snmp_v2c:'SNMP v2c'};return m[String(v||'').toLowerCase()]||v||'—'}
async function loadCredentials(){
  const body=document.getElementById('credentialsTable'); if(!body)return;
  body.innerHTML='<tr><td colspan="6">Carregando...</td></tr>';
  try{
    const res=await fetch('/api/actions/credentials'); const data=await res.json(); if(!res.ok)throw new Error(data.detail||'Falha ao carregar credenciais.');
    const rows=data.credentials||[];
    body.innerHTML=rows.length?rows.map(c=>`<tr><td>${credEsc(c.name||'—')}</td><td>${credEsc(credentialTypeLabel(c.type))}</td><td>${credEsc(c.username||'—')}</td><td>${credEsc(c.domain||'—')}</td><td>${c.has_password?'••••••••':'—'}</td><td><button class="btn danger btn-sm cred-delete" data-id="${c.id}">Excluir</button></td></tr>`).join(''):'<tr><td colspan="6">Nenhuma credencial cadastrada.</td></tr>';
    document.querySelectorAll('.cred-delete').forEach(b=>b.onclick=async()=>{if(!confirm('Desabilitar esta credencial? Scans antigos manterão a referência para auditoria.'))return;await fetch(`/api/actions/credentials/${b.dataset.id}`,{method:'DELETE'});await loadCredentials()});
  }catch(e){body.innerHTML=`<tr><td colspan="6">${e.message}</td></tr>`}
}
async function saveDiscoveryCredential(){
  const type=document.getElementById('cred_type').value;
  const payload={name:document.getElementById('cred_name').value.trim(),type,username:document.getElementById('cred_username').value.trim(),domain:document.getElementById('cred_domain').value.trim(),password:document.getElementById('cred_password').value,metadata:{}};
  const port=Number(document.getElementById('cred_port').value||0); if(port)payload.metadata.port=port;
  if(type==='snmp_v2c'){payload.username='';payload.domain='';}
  const res=await fetch('/api/actions/credentials',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await res.json().catch(()=>({}));
  setMessage('credentialStatusBox',res.ok?'Credencial salva de forma criptografada.':(data.detail||'Falha ao salvar credencial.'));
  if(res.ok){document.getElementById('cred_password').value='';document.getElementById('cred_name').value='';await loadCredentials()}
}
const _bindCredPrevious=bindFixedActions;
bindFixedActions=function(){_bindCredPrevious();document.getElementById('saveCredentialBtn')?.addEventListener('click',saveDiscoveryCredential)};
const _bootCredPrevious=bootSettings;
bootSettings=async function(){
  buildHeader('settings');settingsModules=await fetchModuleStatus();
  const groups=[
    {title:'Fixos',items:[{key:'settingsMailSection',label:'Mail Server'},{key:'settingsBrandingSection',label:'Branding'},{key:'settingsWebhookSection',label:'Webhook'},{key:'settingsUsersSection',label:'Usuários'},{key:'settingsStatusSection',label:'Status'},{key:'settingsRunnersSection',label:'Runners'}]},
    {title:'Discovery',items:[{key:'settingsDiscoveryDnsSection',label:'DNS'},{key:'settingsCredentialsSection',label:'Credenciais'}]},
    {title:'UEM',items:[{key:'settingsUemApiSection',label:'APIs'},{key:'settingsAdSection',label:'Active Directory'},{key:'settingsParametersSection',label:'Parâmetros'},{key:'settingsIpScopeSection',label:'IP Scope'}]}
  ];
  renderModuleSidebar('settingsSidebar',groups,async key=>{showSettingsSection(key);if(key==='settingsUsersSection')await loadAuthAccess();if(key==='settingsRunnersSection')await loadRunners();if(key==='settingsCredentialsSection')await loadCredentials()});
  showSettingsSection('settingsMailSection');bindFixedActions();await loadSettings();
};

bootSettings();


async function loadRunnerJobs(runnerId){
  const body=document.getElementById('runnerJobsTableBody'); if(!body||!runnerId)return;
  body.innerHTML='<tr><td colspan="7">Carregando jobs...</td></tr>';
  try{
    const res=await fetch(`/api/settings/runners/${encodeURIComponent(runnerId)}/jobs?limit=100`); const data=await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(data.detail||'Falha ao carregar jobs.'); const jobs=data.jobs||[];
    body.innerHTML=jobs.length?jobs.map(j=>`<tr><td>${j.id}</td><td>${j.controlled ? (j.source_module||'-') : '<strong>ORPHAN / UNCONTROLLED</strong>'}</td><td>${j.job_type||'-'}</td><td>${j.target||'-'}</td><td>${j.status||'-'}</td><td>${formatRunnerDate(j.created_at)}</td><td>${['pending','running'].includes(j.status)?`<button class="btn danger btn-sm runner-job-cancel" data-id="${j.id}" data-runner="${runnerId}">Cancelar</button>`:'-'}</td></tr>`).join(''):'<tr><td colspan="7">Nenhum job encontrado.</td></tr>';
    document.querySelectorAll('.runner-job-cancel').forEach(b=>b.addEventListener('click',async()=>{const r=await fetch(`/api/settings/runners/${encodeURIComponent(b.dataset.runner)}/jobs/${b.dataset.id}/cancel`,{method:'POST'});if(r.ok)await loadRunnerJobs(b.dataset.runner);}));
    setMessage('runnerJobsStatusBox',`${jobs.length} job(s) recentes. Jobs sem controle são bloqueados e não são entregues ao Runner.`);
  }catch(e){body.innerHTML=`<tr><td colspan="7">${e.message}</td></tr>`;setMessage('runnerJobsStatusBox',e.message);}
}
