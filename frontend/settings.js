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
    theme: { logo_path: document.getElementById('logo_path').value.trim() || 'logo.png' },
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
  setBrandLogo(data?.theme?.logo_path || 'logo.png');
  document.getElementById('logo_path').value = data?.theme?.logo_path || 'logo.png';
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

function bindFixedActions(){
  document.getElementById('saveMailSettingsBtn').addEventListener('click', ()=> saveSettings('statusBox'));
  document.getElementById('saveWebhookSettingsBtn')?.addEventListener('click', ()=> saveSettings('webhookStatusBox'));
  document.getElementById('saveApiSettingsBtn').addEventListener('click', ()=> saveSettings('apiStatusBox'));
  document.getElementById('saveAdSettingsBtn').addEventListener('click', ()=> saveSettings('adStatusBox'));
  document.getElementById('saveParametersBtn').addEventListener('click', ()=> saveSettings('scanStatus'));
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
}

async function bootSettings(){
  buildHeader('settings');
  settingsModules = await fetchModuleStatus();
  const groups = [
    { title:'Fixos', items:[{ key:'settingsMailSection', label:'Mail Server' }, { key:'settingsStatusSection', label:'Status' }] },
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
    { title:'Fixos', items:[{ key:'settingsMailSection', label:'Mail Server' }, { key:'settingsWebhookSection', label:'Webhook' }, { key:'settingsUsersSection', label:'Usuários' }, { key:'settingsStatusSection', label:'Status' }] },
    { title:'UEM', items:[{ key:'settingsUemApiSection', label:'APIs' }, { key:'settingsAdSection', label:'Active Directory' }, { key:'settingsParametersSection', label:'Parâmetros' }, { key:'settingsIpScopeSection', label:'IP Scope' }] }
  ];
  renderModuleSidebar('settingsSidebar', groups, async (key)=> { showSettingsSection(key); if(key === 'settingsUsersSection') await loadAuthAccess(); });
  showSettingsSection('settingsMailSection');
  bindFixedActions();
  await loadSettings();
};

bootSettings();
