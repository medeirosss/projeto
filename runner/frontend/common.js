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
    { key:'centric', href:'/', label:'Overview' },
    { key:'targets', href:'/ativos', label:'Assets' },
    { key:'validations', href:'/validacoes', label:'Security Validation' },
    { key:'attack', href:'/attack-simulator', label:'Attack Simulation' },
    { key:'alerts', href:'/alertas', label:'Monitoring & Alerts' },
    { key:'reports', href:'/relatorios', label:'Relatórios' },
    { key:'settings', href:'/configuracoes', label:'Administração' }
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

const MAGI_FRONTEND_BUILD = '6.0.1';
let magiBrandingCurrent = {logo_path:'logo.png',brand_name:'MAGI',accent_color:'#c6ff57'};
function setAccentColor(color){
  const value=String(color||'').trim();
  if(!/^#[0-9a-fA-F]{6}$/.test(value))return;
  document.documentElement.style.setProperty('--magi-accent',value);
  document.documentElement.style.setProperty('--accent',value);
  document.documentElement.style.setProperty('--primary-color',value);
  document.documentElement.style.setProperty('--blue',value);
}
function applyBrandingSettings(settings={}){
  const theme=settings.theme||settings.branding||{};
  const next={
    logo_path:theme.logo_path||settings.logo_path||'logo.png',
    brand_name:theme.brand_name||settings.brand_name||'MAGI',
    accent_color:theme.accent_color||settings.accent_color||'#c6ff57'
  };
  magiBrandingCurrent=next;
  setBrandLogo(next.logo_path);setBrandName(next.brand_name);setAccentColor(next.accent_color);
  document.dispatchEvent(new CustomEvent('magi:branding-updated',{detail:{...next}}));
}
async function initializeBranding(){
  applyBrandingSettings();
  try{const response=await fetch('/api/settings',{cache:'no-store'});if(response.ok)applyBrandingSettings(await response.json());}
  catch(_error){/* keep safe defaults if offline */}
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


// Shared branding editor. Server settings are authoritative; no conflicting localStorage overrides.
function initializeMagiBrandControl(){
  if(document.getElementById('magiBrandOpen')||!document.body.classList.contains('centric-page'))return;
  const header=document.querySelector('.topbar,.modern-topbar');
  if(!header)return;
  let right=header.querySelector('.top-right');
  if(!right){right=document.createElement('div');right.className='top-right';header.appendChild(right);}
  const trigger=document.createElement('button');trigger.type='button';trigger.id='magiBrandOpen';trigger.className='magi-brand-open';trigger.textContent='◉ Personalizar';right.prepend(trigger);
  const version=document.createElement('span');version.className='magi-build-id';version.textContent='UI '+MAGI_FRONTEND_BUILD;version.title='Versão do frontend';right.appendChild(version);
  const modal=document.createElement('div');modal.id='magiBrandDialog';modal.className='magi-brand-dialog';
  modal.innerHTML=`<section class="magi-brand-panel" role="dialog" aria-modal="true" aria-labelledby="magiBrandTitle"><h2 id="magiBrandTitle">Identidade visual MAGI</h2><p>Personalização compartilhada entre os módulos. Alterações são salvas no servidor.</p><label for="magiBrandName">Nome do produto</label><input type="text" id="magiBrandName" maxlength="80"><label for="magiBrandLogo">Logotipo (caminho ou URL)</label><input type="text" id="magiBrandLogo"><label>Cor principal</label><div id="magiBrandSwatches" class="magi-brand-swatches"></div><input type="color" id="magiBrandCustom" aria-label="Cor personalizada"><label for="magiBrandAppearance">Aparência neste navegador</label><select id="magiBrandAppearance"><option value="dark">Escuro</option><option value="light">Claro</option></select><p id="magiBrandStatus" role="status" aria-live="polite"></p><div class="actions"><button type="button" id="magiBrandCancel">Cancelar</button><button type="button" id="magiBrandSave" class="save">Salvar</button></div></section>`;
  document.body.appendChild(modal);
  const colors=['#c6ff57','#2998ff','#a855f7','#ff983f','#ff4858','#ec46b7','#00d5e8'];
  const swatches=modal.querySelector('#magiBrandSwatches');const picker=modal.querySelector('#magiBrandCustom');
  const name=modal.querySelector('#magiBrandName');const logo=modal.querySelector('#magiBrandLogo');const appearance=modal.querySelector('#magiBrandAppearance');const status=modal.querySelector('#magiBrandStatus');
  let selected='#c6ff57', previousAppearance='dark';
  const render=()=>{picker.value=selected;swatches.querySelectorAll('button').forEach(b=>b.classList.toggle('selected',b.dataset.color===selected));setAccentColor(selected);};
  colors.forEach(color=>{const button=document.createElement('button');button.type='button';button.className='magi-brand-swatch';button.dataset.color=color;button.style.background=color;button.setAttribute('aria-label','Selecionar '+color);button.addEventListener('click',()=>{selected=color;render();});swatches.appendChild(button);});
  const restore=()=>{applyBrandingSettings({theme:magiBrandingCurrent});applyTheme(previousAppearance);};
  const close=(revert=true)=>{if(revert)restore();modal.classList.remove('open');trigger.focus();};
  trigger.addEventListener('click',()=>{name.value=magiBrandingCurrent.brand_name;logo.value=magiBrandingCurrent.logo_path;selected=magiBrandingCurrent.accent_color;previousAppearance=getThemePreference();appearance.value=previousAppearance;status.textContent='';render();modal.classList.add('open');name.focus();});
  picker.addEventListener('input',()=>{selected=picker.value;render();});
  appearance.addEventListener('change',()=>applyTheme(appearance.value));
  modal.querySelector('#magiBrandCancel').addEventListener('click',()=>close());
  modal.querySelector('#magiBrandSave').addEventListener('click',async()=>{
    const save=modal.querySelector('#magiBrandSave');save.disabled=true;status.textContent='Salvando...';
    const payload={theme:{logo_path:logo.value.trim()||'logo.png',brand_name:name.value.trim()||'MAGI',accent_color:selected,dark_mode:appearance.value!=='light'}};
    try{const response=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(!response.ok)throw new Error('HTTP '+response.status);applyBrandingSettings({theme:payload.theme});applyTheme(appearance.value);document.dispatchEvent(new CustomEvent('magi:branding-saved',{detail:payload.theme}));close(false);}
    catch(error){status.textContent='Não foi possível salvar: '+error.message;}
    finally{save.disabled=false;}
  });
  modal.addEventListener('click',event=>{if(event.target===modal)close();});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&modal.classList.contains('open'))close();});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initializeMagiBrandControl);else initializeMagiBrandControl();
