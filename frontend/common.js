const MODULE_FALLBACK = {
  uem: { enabled: true, online: true, label: 'UEM' },
  security: { enabled: false, online: false, label: 'Security' }
};

async function fetchModuleStatus(){
  try{
    const res = await fetch('/api/modules/status');
    if(!res.ok) throw new Error('status endpoint unavailable');
    const data = await res.json();
    const modules = data.modules || data;
    return {
      uem: {
        enabled: modules?.uem?.enabled ?? true,
        online: modules?.uem?.online ?? modules?.uem?.healthy ?? true,
        label: 'UEM'
      },
      security: {
        enabled: modules?.security?.enabled ?? false,
        online: modules?.security?.online ?? modules?.security?.healthy ?? false,
        label: 'Security'
      }
    };
  }catch(_e){
    return MODULE_FALLBACK;
  }
}

function getThemePreference(){
  return localStorage.getItem('centric-theme') || 'dark';
}

function applyTheme(theme){
  const appBody = document.body;
  if(!appBody || !appBody.classList.contains('centric-page')) return;
  const selectedTheme = theme === 'light' ? 'light' : 'dark';
  appBody.setAttribute('data-theme', selectedTheme);
  localStorage.setItem('centric-theme', selectedTheme);
  const btn = document.getElementById('themeToggle');
  if(btn) btn.textContent = selectedTheme === 'dark' ? 'Dark mode' : 'Light mode';
}

function bindThemeToggle(){
  const appBody = document.body;
  if(!appBody || !appBody.classList.contains('centric-page')) return;
  applyTheme(getThemePreference());
  const btn = document.getElementById('themeToggle');
  if(btn){
    btn.addEventListener('click', ()=> {
      const current = appBody.getAttribute('data-theme') || 'dark';
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });
  }
}

function buildHeader(activeKey){
  const menu = document.getElementById('mainMenu');
  if(!menu) return;
  const items = [
    { key:'centric', href:'/', label:'Centric' },
    { key:'reports', href:'/relatorios', label:'Relatórios' },
    { key:'actions', href:'/instalador', label:'Ações' },
    { key:'alerts', href:'/alertas', label:'Alertas' },
    { key:'settings', href:'/configuracoes', label:'Configurações' }
  ];
  menu.innerHTML = items.map(item => `<a class="${item.key===activeKey?'active':''}" href="${item.href}">${item.label}</a>`).join('');
}

function normalizeAssetPath(value){
  if(!value) return '';
  const path = String(value).trim();
  if(!path) return '';
  if(path.startsWith('http://') || path.startsWith('https://') || path.startsWith('data:') || path.startsWith('/')) return path;
  return `/assets/${path}`;
}

function setBrandLogo(logoPath){
  const src = normalizeAssetPath(logoPath);
  document.querySelectorAll('#brandLogo, .brand-logo').forEach(logo => {
    if(src) logo.src = src;
  });
}

function setBrandName(name){
  const value = String(name || '').trim();
  if(!value) return;
  document.querySelectorAll('.brand span, .sidebar-brand span, [data-brand-name]').forEach(el => {
    el.textContent = value;
  });
}

function setAccentColor(color){
  const value = String(color || '').trim();
  if(!/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(value)) return;
  document.documentElement.style.setProperty('--accent', value);
  document.documentElement.style.setProperty('--primary-color', value);
  document.documentElement.style.setProperty('--blue', value);
}

function applyBrandingSettings(settings = {}){
  const theme = settings.theme || settings.branding || {};
  const logoPath = settings.logo_path || theme.logo_path || theme.logo || localStorage.getItem('centric-brand-logo');
  const brandName = settings.brand_name || theme.brand_name || theme.name || localStorage.getItem('centric-brand-name');
  const accentColor = settings.accent_color || theme.accent_color || theme.primary_color || localStorage.getItem('centric-accent-color');
  setBrandLogo(logoPath || 'logo.png');
  setBrandName(brandName || 'Centric');
  setAccentColor(accentColor || '#7c3aed');
}

async function initializeBranding(){
  applyBrandingSettings();
  try{
    const res = await fetch('/api/settings');
    if(res.ok){
      const data = await res.json();
      applyBrandingSettings(data);
    }
  }catch(_e){
    // Mantém branding local/default quando o endpoint ainda não estiver disponível.
  }
}

function renderModuleSidebar(containerId, groups, onClick){
  const container = document.getElementById(containerId);
  if(!container) return;
  container.innerHTML = '';
  groups.forEach((group, groupIndex)=> {
    const wrap = document.createElement('div');
    wrap.className = 'sidebar-group';
    wrap.innerHTML = `<div class="report-group-title">${group.title}</div>`;
    const nav = document.createElement('nav');
    nav.className = 'report-nav';
    group.items.forEach((item, itemIndex)=> {
      const a = document.createElement('a');
      a.href = '#';
      a.dataset.key = item.key;
      a.textContent = item.label;
      if(groupIndex===0 && itemIndex===0) a.classList.add('active');
      a.addEventListener('click', (e)=> {
        e.preventDefault();
        container.querySelectorAll('a').forEach(link => link.classList.remove('active'));
        a.classList.add('active');
        onClick(item.key, item);
      });
      nav.appendChild(a);
    });
    wrap.appendChild(nav);
    container.appendChild(wrap);
  });
}

async function loadCurrentUser(){
  try{
    const res = await fetch('/api/auth/me');
    if(!res.ok) return null;
    const data = await res.json();
    return data.user || null;
  }catch(_e){ return null; }
}

async function bindUserMenu(){
  const user = await loadCurrentUser();
  const boxes = document.querySelectorAll('.sidebar-user');
  boxes.forEach(box => {
    if(!user) return;
    const name = user.username || 'Usuário';
    const role = user.role || 'viewer';
    box.innerHTML = `<div class="avatar">AD</div><div><strong>${name}</strong><span>${role}</span></div><button class="logout-btn" type="button" title="Sair">Sair</button>`;
    const btn = box.querySelector('.logout-btn');
    if(btn){
      btn.addEventListener('click', async ()=>{
        await fetch('/api/auth/logout', {method:'POST'});
        window.location.href = '/login';
      });
    }
  });
}

document.addEventListener('DOMContentLoaded', ()=>{ bindThemeToggle(); initializeBranding(); bindUserMenu(); });
