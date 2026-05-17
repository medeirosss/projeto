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
  const centricBody = document.body;
  if(!centricBody || !centricBody.classList.contains('centric-page')) return;
  centricBody.setAttribute('data-theme', theme);
  localStorage.setItem('centric-theme', theme);
  const btn = document.getElementById('themeToggle');
  if(btn) btn.textContent = theme === 'dark' ? 'Dark mode' : 'Light mode';
}

function bindThemeToggle(){
  const centricBody = document.body;
  if(!centricBody || !centricBody.classList.contains('centric-page')) return;
  applyTheme(getThemePreference());
  const btn = document.getElementById('themeToggle');
  if(btn){
    btn.addEventListener('click', ()=> {
      const current = centricBody.getAttribute('data-theme') || 'light';
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

function setBrandLogo(logoPath){
  const logo = document.getElementById('brandLogo');
  if(logo && logoPath) logo.src = `/assets/${logoPath}`;
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

document.addEventListener('DOMContentLoaded', ()=>{ bindUserMenu(); });
