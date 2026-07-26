let targetsSearchTimer = null;

function escapeHtml(value){
  return String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
}

function formatDate(value){
  if(!value) return '—';
  const date = new Date(value.endsWith?.('Z') ? value : `${value}Z`);
  if(Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('pt-BR');
}

async function readJson(response){
  const data = await response.json().catch(()=> ({}));
  if(!response.ok) throw new Error(data.detail || data.message || `Erro HTTP ${response.status}`);
  return data;
}

async function loadTargets(){
  const table = document.getElementById('targetsTable');
  const search = document.getElementById('targetsSearch').value.trim();
  table.innerHTML = '<tr><td colspan="4">Carregando...</td></tr>';
  try{
    const data = await readJson(await fetch(`/api/targets?search=${encodeURIComponent(search)}&limit=500`));
    document.getElementById('targetsTotal').textContent = data.total ?? 0;
    const items = data.items || [];
    table.innerHTML = items.length ? items.map(item => `<tr>
      <td>${escapeHtml(item.hostname || 'Nome não identificado')}</td>
      <td><code>${escapeHtml(item.ip_address)}</code></td>
      <td><code>${escapeHtml(item.mac_address || 'Não disponível')}</code></td>
      <td>${escapeHtml(formatDate(item.last_seen_at))}</td>
    </tr>`).join('') : '<tr><td colspan="4">Nenhum alvo encontrado.</td></tr>';
  }catch(error){
    table.innerHTML = `<tr><td colspan="4">${escapeHtml(error.message)}</td></tr>`;
  }
}

async function loadLastDiscovery(){
  try{
    const data = await readJson(await fetch('/api/targets/discovery-runs?limit=1'));
    const run = data.items?.[0];
    const label = document.getElementById('lastDiscoveryStatus');
    label.textContent = run ? `${run.status} · ${formatDate(run.started_at)}` : 'Ainda não executada';
  }catch(_error){
    document.getElementById('lastDiscoveryStatus').textContent = 'Indisponível';
  }
}

async function startDiscovery(){
  const button = document.getElementById('discoveryStartBtn');
  const result = document.getElementById('discoveryResult');
  const targetSpec = document.getElementById('discoveryTargetSpec').value.trim();
  if(!targetSpec){ result.textContent = 'Informe um IPv4 ou CIDR.'; return; }
  button.disabled = true;
  result.textContent = `Executando descoberta em ${targetSpec}...`;
  try{
    const data = await readJson(await fetch('/api/targets/discover', {
      method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({target_spec:targetSpec})
    }));
    result.textContent = `Descoberta concluída. ${data.discovered_count} alvo(s) detectado(s).\nExecução: ${data.run_uuid}`;
    await Promise.all([loadTargets(), loadLastDiscovery()]);
  }catch(error){
    result.textContent = `Falha na descoberta: ${error.message}`;
    await loadLastDiscovery();
  }finally{
    button.disabled = false;
  }
}

document.addEventListener('DOMContentLoaded', ()=>{
  buildHeader('targets');
  document.getElementById('targetsRefreshBtn').addEventListener('click', ()=> Promise.all([loadTargets(), loadLastDiscovery()]));
  document.getElementById('discoveryStartBtn').addEventListener('click', startDiscovery);
  document.getElementById('discoveryTargetSpec').addEventListener('keydown', event => { if(event.key === 'Enter') startDiscovery(); });
  document.getElementById('targetsSearch').addEventListener('input', ()=>{
    clearTimeout(targetsSearchTimer);
    targetsSearchTimer = setTimeout(loadTargets, 300);
  });
  loadTargets();
  loadLastDiscovery();
});
