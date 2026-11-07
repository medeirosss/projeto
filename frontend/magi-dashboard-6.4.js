/* MAGI 6.4.0 — Security Overview; read-only API consumers, no synthetic findings. */
(()=>{'use strict';
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const put=(id,v)=>{const el=$(id);if(el)el.textContent=v??'—';};
async function get(path){const r=await fetch(path,{credentials:'same-origin'});if(!r.ok)throw Error(`${path}: HTTP ${r.status}`);return r.json();}
const num=v=>Number.isFinite(Number(v))?Number(v):null;
const severityKey=v=>{const s=String(v||'').toLowerCase();if(/critical|cr[ií]tic/.test(s))return 'critical';if(/high|alta|alto/.test(s))return 'high';if(/medium|m[eé]di/.test(s))return 'medium';if(/low|baix/.test(s))return 'low';return 'unknown';};
function drawSeverity(items,summary){
 const values={critical:0,high:0,medium:0,low:0,unknown:0};
 const summaryCounts=summary?.by_severity||summary?.severity_counts||summary?.severity||null;
 let total=null;
 if(summaryCounts && typeof summaryCounts==='object'&&!Array.isArray(summaryCounts)){
   Object.entries(summaryCounts).forEach(([k,v])=>{const n=num(v);if(n!==null)values[severityKey(k)]+=n;});
   total=Object.values(values).reduce((a,b)=>a+b,0);
 }else if(Array.isArray(items)){
   items.forEach(x=>values[severityKey(x.severity||x.risk_level)]++);total=items.length;
 }
 if(total===null){$('m64SeverityLegend').textContent='Distribuição indisponível';return;}
 const count=num(summary?.total??summary?.total_findings??summary?.count);
 put('m64Exposures',count??total);
 const colors={critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#3b82f6',unknown:'#64748b'};
 const labels={critical:'Crítica',high:'Alta',medium:'Média',low:'Baixa',unknown:'Não classificada'};
 let start=0;const stops=[];
 Object.entries(values).forEach(([k,v])=>{if(!v)return;const end=start+v/Math.max(1,total)*100;stops.push(`${colors[k]} ${start}% ${end}%`);start=end;});
 $('m64Donut').style.background=stops.length?`conic-gradient(${stops.join(',')})`:'';
 $('m64Donut').querySelector('span').innerHTML=`${total}<small>Exposições</small>`;
 $('m64SeverityLegend').innerHTML=Object.entries(values).map(([k,v])=>`<div class="magi64-legend-row"><i class="magi64-dot" style="background:${colors[k]}"></i>${labels[k]}<b>${v}</b></div>`).join('');
}
async function exposures(){try{const data=await get('/api/exposures?limit=1000');drawSeverity(data.items,data.summary);}catch(e){put('m64Exposures','—');$('m64SeverityLegend').textContent='Fonte de exposições indisponível';console.warn('[MAGI 6.4.1] Exposições indisponíveis',e);}}
async function alerts(){try{const d=await get('/api/alerts');const a=Array.isArray(d.alerts)?d.alerts:[];put('m64Alerts',d.summary?.open??(a.filter(x=>String(x.status||'').toLowerCase()==='open').length||a.length));$('m64RecentAlerts').innerHTML=a.slice(0,4).map(x=>`<div class="magi64-alert"><div><b>${esc(x.display_name||x.event_type_text||'Alerta')}</b><small>${esc(x.event_time||x.received_at||'Data não informada')}</small></div><span>${esc(x.severity||'')}</span></div>`).join('')||'<p class="magi64-empty">Nenhum alerta retornado.</p>';}catch(e){put('m64Alerts','—');$('m64RecentAlerts').textContent='Alertas indisponíveis.';}}
async function cves(){try{const d=await get('/api/dashboard?page_size=5');const meta=d.critical_cves_meta||{};const source=String(meta.source||'none').toLowerCase();const connected=source.includes('nuclei');const rows=connected&&Array.isArray(d.critical_cves)?d.critical_cves:[];
 put('m64Cves',connected?rows.length:'—');put('m64CveSource',connected?'Nuclei':'Aguardando dados do Nuclei');put('m64CveNotice',connected?'Fonte: Nuclei':'Aguardando integração Nuclei');$('m64CveRows').innerHTML=rows.length?rows.slice(0,10).map(x=>`<tr><td>${esc(x.cve_id||x.cve||x.id||'—')}</td><td>${esc(x.hostname||x.asset||'—')}</td><td>${esc(x.product||x.name||'—')}</td><td>${esc(x.severity||'—')}</td></tr>`).join(''):'<tr><td colspan="4">'+(connected?'Nenhuma CVE crítica retornada pelo Nuclei.':'Aguardando dados do Nuclei.')+'</td></tr>';
 }catch(e){put('m64Cves','—');}}
function campaignsFrom(d){return Array.isArray(d)?d:Array.isArray(d.items)?d.items:Array.isArray(d.campaigns)?d.campaigns:[];}
async function campaigns(){const select=$('m64Campaign');const previous=select.value||sessionStorage.getItem('magi64_campaign')||'';try{const d=await get('/api/attack-simulator/campaigns');const list=campaignsFrom(d);select.innerHTML='<option value="">Selecione uma Campaign</option>'+list.map(c=>{const id=c.campaign_uuid||c.uuid||c.id;return `<option value="${esc(id)}">${esc(c.name||c.title||id)}</option>`;}).join('');select.onchange=()=>{sessionStorage.setItem('magi64_campaign',select.value);loadPath();};if(list.length){select.value=previous;if(!select.value)select.selectedIndex=1;await loadPath();}}catch(e){select.innerHTML='<option value="">Campaigns indisponíveis</option>';}}
async function loadPath(){const id=$('m64Campaign').value;const root=$('m64AttackGraph');if(!id){root.textContent='Selecione uma Campaign.';put('m64Paths','—');return;}try{const d=await get(`/api/attack-simulator/campaigns/${encodeURIComponent(id)}/attack-path`);const graph=d.attack_path||d;const edges=graph.edges||[];put('m64Paths',num(graph.summary?.access_confirmed)??edges.filter(e=>String(e.kind||'').toUpperCase()==='ACCESS').length);if(window.MAGIAttackPath?.mount)window.MAGIAttackPath.mount(root,graph,{compact:true});else root.textContent='Componente Attack Path indisponível.';}catch(e){root.textContent='Não foi possível carregar o Attack Path desta Campaign.';put('m64Paths','—');}}
async function optionalMetrics(){
 try{const d=await get('/api/targets?limit=500');put('m64Assets',num(d.total)??(Array.isArray(d.items)?d.items.length:'—'));}
 catch(e){put('m64Assets','—');console.warn('[MAGI 6.4.1] Inventário indisponível',e);}
 // Ativos monitorados: manter indisponível até confirmar o contrato de Monitoring.
 put('m64Monitored','—');
}
function trendPlot(rows){
 const root=$('m64Trend');if(!root)return;
 if(!Array.isArray(rows)||!rows.length){root.innerHTML='<p class="magi64-empty">Nenhum snapshot registrado. A primeira coleta será exibida quando o backend iniciar.</p>';return;}
 const W=760,H=260,L=44,R=18,T=22,B=40;const max=Math.max(1,...rows.map(r=>Math.max(Number(r.open||0),Number(r.total||0))));const X=i=>L+(W-L-R)*(rows.length===1?.5:i/(rows.length-1));const Y=v=>T+(H-T-B)*(1-Number(v||0)/max);
 const path=key=>rows.map((r,i)=>(i?'L':'M')+X(i).toFixed(1)+' '+Y(r[key]).toFixed(1)).join(' ');
 const ticks=[0,.25,.5,.75,1].map(f=>{const y=Y(max*f);return `<line x1="${L}" y1="${y}" x2="${W-R}" y2="${y}" class="magi64-trend-grid"/><text x="${L-8}" y="${y+4}" text-anchor="end" class="magi64-trend-text">${Math.round(max*f)}</text>`;}).join('');
 const dates=[0,Math.floor((rows.length-1)/2),rows.length-1].filter((v,i,a)=>a.indexOf(v)===i).map(i=>`<text x="${X(i)}" y="${H-12}" text-anchor="middle" class="magi64-trend-text">${esc(String(rows[i].day||'').slice(5))}</text>`).join('');
 root.innerHTML=`<div style="width:100%"><svg class="magi64-trend-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Histórico real de exposições: total e abertas">${ticks}<path d="${path('total')}" class="magi64-trend-total"/><path d="${path('open')}" class="magi64-trend-open"/>${rows.map((r,i)=>`<circle class="magi64-trend-point" cx="${X(i)}" cy="${Y(r.open)}" r="3"><title>${esc(r.day)}: ${Number(r.open)} abertas, ${Number(r.total)} total</title></circle>`).join('')}${dates}</svg><div class="magi64-trend-text" style="display:flex;justify-content:space-between;gap:10px"><span>● Abertas</span><span>┄ Total registrado</span><span>${rows.length} dia(s) com coleta</span></div></div>`;
}
async function history(){try{const days=Number($('m64TrendRange')?.value||30);const d=await get(`/api/exposures/history?days=${days}`);trendPlot(d.items||[]);}catch(e){$('m64Trend').innerHTML='<p class="magi64-empty">Histórico indisponível. Verifique a migração e o agendador de snapshots.</p>';console.warn('[MAGI 6.4.2] Histórico indisponível',e);}}
$('m64TrendRange')?.addEventListener('change',history);
async function boot(){try{if(typeof buildHeader==='function')buildHeader('centric');if(typeof bindThemeToggle==='function')bindThemeToggle();}catch(e){}await Promise.allSettled([exposures(),alerts(),cves(),campaigns(),optionalMetrics(),history()]);put('magi64Status','Atualizado em '+new Date().toLocaleString('pt-BR'));put('lastUpdate',new Date().toLocaleString('pt-BR'));}
$('autoRefreshToggle')?.addEventListener('change',()=>{});let timer=null;$('refreshHours')?.addEventListener('change',()=>{if(timer)clearInterval(timer);schedule();});function schedule(){if(timer)clearInterval(timer);if(!$('autoRefreshToggle')?.checked)return;timer=setInterval(boot,Number($('refreshHours')?.value||1)*3600000);}boot().then(schedule);
})();
