import {hasCaseUpdate,recordUpdate,markCaseRead,sortedCases} from './cases.js';
import {streamCase,syncWatches} from './api.js';
import {PRODUCTS,VENDORS,migrateProducts,validId,vendorURL,summary,assess,assessmentStatus} from './data.js';
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const KEY='cve-desk-v1', HOUR=3600000;
let chooserOpen=false;
let watchQueue=Promise.resolve(),lastWatchlist='';
function syncWatchlist(force=false){const cases=state.cases.map(c=>({id:c.id,products:[...c.products]})),key=JSON.stringify(cases);watchQueue=watchQueue.then(async()=>{if(!force&&key===lastWatchlist)return;try{await syncWatches(cases);lastWatchlist=key;}catch(e){toast(`Could not sync server watches: ${e.message}`);}});return watchQueue;}
let state={version:1,cases:[],products:['rhel9','rhel10','debian12'],auto:true,activity:[]}, active=null, busy=new Set(), storageError=false;
try {const saved=localStorage.getItem(KEY);if(saved) state=validate(JSON.parse(saved));} catch {storageError=true;}
function validate(s) {
  if(s?.version!==1 || !Array.isArray(s.cases) || !Array.isArray(s.products) || !Array.isArray(s.activity) || s.cases.length>1000) throw Error('Invalid workspace backup.');
  const ids=new Set();
  for(const c of s.cases) {if(!validId(c.id)||ids.has(c.id)||!Array.isArray(c.products)||typeof c.notes!=='string'|| (c.record && c.record.cveMetadata?.cveId!==c.id)) throw Error('Invalid case in backup.');ids.add(c.id);c.products=migrateProducts(c.products);}
  s.products=migrateProducts(s.products);return s;
}
function save() {try{localStorage.setItem(KEY,JSON.stringify(state));storageError=false;}catch{storageError=true;toast('Storage unavailable or full. Export a backup to avoid losing changes.');}}
function toast(message){$('#toast').textContent=message;$('#toast').classList.add('visible');clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('#toast').classList.remove('visible'),6000);}
function log(id,text){recordUpdate(state,id,text);save();renderSidebar();}
const date=t=>t?new Date(t).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'Never';
const selected=c=>PRODUCTS.filter(p=>c.products.includes(p.id));
function status(c){if(!c.record&&!c.vex&&!c.vendorData) return 'unknown';const rows=selected(c).map(p=>assessmentStatus(assess(c.record || {cveMetadata:{cveId:c.id}},p,c.vex,c.vendorData)));return rows.includes('affected')?'affected':!rows.length||rows.includes('unknown')?'unknown':rows.includes('fix_available')?'fix_available':'unaffected';}
const labels={affected:'Affected',unknown:'Needs review',fixed:'Fix published',fix_available:'Fix available',unaffected:'Not affected'};
const badge=s=>`<span class="status ${s}"><span class="dot"></span>${labels[s]}</span>`;
function renderSidebar(){const q=$('#search').value.toLowerCase();$('#case-count').textContent=state.cases.length;$('#case-list').innerHTML=sortedCases(state).filter(c=>`${c.id} ${summary(c.record).title}`.toLowerCase().includes(q)).map(c=>`<button class="case-item ${active===c.id?'selected':''}" data-case="${c.id}"><span class="case-id"><span class="dot ${status(c)}"></span>${c.id}${hasCaseUpdate(state,c)?'<span class="case-update" aria-label="Unread update">New</span>':''}</span><small>${esc(c.record?summary(c.record).title:'Awaiting lookup')}</small></button><button class="delete-case" data-delete="${c.id}" aria-label="Delete ${c.id}">Delete</button>`).join('')||'<p class="sidebar-empty">No cases here yet.</p>';}
function render(){renderSidebar(); const c=state.cases.find(c=>c.id===active);if(!c){renderHome();return;}const s=summary(c.record);const loading=busy.has(c.id);
$('#main').innerHTML=`<div class="page-heading"><div><h1>${c.id}</h1><p class="case-title">${esc(s.title)}</p></div><div class="actions"><button id="refresh" ${loading?'disabled':''}>${loading?'↻ Checking…':'↻ Refresh data'}</button><details class="freshness"><summary>Evidence · ${date(c.checked)}</summary><div class="panel source-panel">${sourceHealth(c)}</div></details></div></div>
${c.error?`<div class="alert" role="alert">${esc(c.error)} ${c.record?'Showing the last saved snapshot.':'Try refreshing again.'}</div>`:''}
${s.rejected?'<div class="alert">This CVE has been rejected. Review the source before taking action.</div>':''}
<section class="overview panel"><div class="score ${esc(s.severity.toLowerCase())}"><strong>${s.score??'—'}</strong><span>${esc(s.severity)}${s.score!=null?' · CVSS':''}</span></div><div class="overview-content"><div class="eyebrow">${esc(s.category)}</div><details class="description"><summary>Vulnerability description</summary><p>${esc(s.description)}</p>${s.vector?`<code>${esc(s.vector)}</code>`:''}</details><div class="reference-links"><a target="_blank" rel="noopener noreferrer" href="https://www.cve.org/CVERecord?id=${c.id}">CVE record ↗</a><a target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/${c.id}">NIST / NVD ↗</a><a target="_blank" rel="noopener noreferrer" href="https://euvd.enisa.europa.eu/">EUVD search ↗</a></div></div></section>
<section class="products-section"><div class="section-heading"><div><h2>Operating systems <span class="count">${c.products.length}</span></h2></div><button id="edit-products" class="text-button">Select OS versions</button></div><div id="case-products" class="product-choices panel" ${chooserOpen?'':'hidden'}>${choices(c.products,'case')}</div><div class="panel product-table"><div class="table-head"><span>PRODUCT / PLATFORM</span><span>ASSESSMENT</span><span>FIX & MITIGATION</span><span></span></div>${groupRows(c)||'<p class="empty-row">Select products to start assessing this case.</p>'}</div></section>
`;
$('#refresh').onclick=()=>refresh(c);
$('#edit-products').onclick=()=>{chooserOpen=!chooserOpen;$('#case-products').hidden=!chooserOpen;};
$('#case-products').onchange=e=>{c.products=readChoices(e,$('#case-products'));save();syncWatchlist();render();$('#case-products').hidden=false;refresh(c,false);};

}
const logo=p=>`<img class="vendor-logo" src="assets/logos/${VENDORS.find(v=>v.id===p.family)?.logo || p.logo}.svg" alt="" width="28" height="28">`;
const safeURL=url=>{try{const u=new URL(url);return u.protocol==='https:'?esc(u.href):'#';}catch{return '#';}};
function assessmentSources(c,p,evidence){
  const sources=[...new Set(evidence.map(e=>e.source || 'CNA statement'))];
  if(!sources.length)return '';
  return `<div class="assessment-source">Source: ${sources.map(name=>{
    let url;
    if(name==='Imported VEX')url=c.vex?.document?.references?.find(r=>r.category==='self')?.url;
    else if(name==='CNA statement')url=`https://cveawg.mitre.org/api/cve/${c.id}`;
    else url=c.vendorData?.sources?.[p.family]?.url;
    if(!url && name!=='Imported VEX')url=vendorURL(p,c.id);
    return url&&safeURL(url)!=='#'?`<a href="${safeURL(url)}" target="_blank" rel="noopener noreferrer">${esc(name)} ↗</a>`:`${esc(name)} (local file)`;
  }).join(', ')}</div>`;
}
function sourceAdvisories(source){
  if(!source?.advisories?.length)return '';
  return `<details class="source-advisories"><summary>Advisories in source document (${source.advisories.length})</summary><p>Check each advisory's product and service-pack scope.</p><div>${source.advisories.map(a=>`<a href="${safeURL(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.label)} ↗</a>`).join('')}</div></details>`;
}
function sourceHealth(c){return `<div class="feed-health">${[...new Set(selected(c).map(p=>p.family))].map(f=>{const v=VENDORS.find(v=>v.id===f),s=c.vendorData?.sources?.[f];return `<div><strong>${esc(v.name)}</strong><small>${s?.checked?`${esc(s.mode || 'Snapshot')} · ${date(s.checked)}`:'No vendor data'}${s?.checked&&Date.now()-s.checked>HOUR?' · Stale':''}</small>${s?.sourceUpdated?`<small>Source updated ${date(s.sourceUpdated)}</small>`:''}${s?.url&&safeURL(s.url)!=='#'?`<small class="feed-source">Source: <a href="${safeURL(s.url)}" target="_blank" rel="noopener noreferrer">Vendor data ↗</a></small>`:''}${s?.error?`<small class="source-warning">${esc(s.error)}. Showing saved evidence if available.</small>`:s?.notPublished?`<small class="source-warning">${esc(s.notPublished)} Check the vendor page.</small>`:!s?'<small>No snapshot yet.</small>':''}${s?.excludedImages?`<small>${s.excludedImages} public-cloud image entr${s.excludedImages===1?'y':'ies'} not counted in OS rows; see the vendor source.</small>`:''}${sourceAdvisories(s)}</div>`;}).join('')}</div>`;}
function productRow(c,p){
  const a=assess(c.record || {cveMetadata:{cveId:c.id}},p,c.vex,c.vendorData);
  const shortFix=f=>f.replace(/ as (?:a )?component of .*/, '').replace(/-0:/g,'-').replace(/\.(?:aarch64|x86_64|ppc64le|s390x|src|noarch|i686|armv7hl)$/,'');
  const fixes=[...new Set(a.evidence.flatMap(e=>e.fix).map(shortFix))].sort((a,b)=>Number(/^kernel-(?:0:)?\d+\./.test(b))-Number(/^kernel-(?:0:)?\d+\./.test(a)));
  const mitigations=[...new Set(a.evidence.flatMap(e=>e.mitigation))];
  const links=[...new Set(a.evidence.flatMap(e=>e.links || []))];
  return `<div class="product-row"><div class="product-name">${logo(p)}<div><strong>${p.name}</strong><small><a href="${vendorURL(p,c.id)}" target="_blank" rel="noopener noreferrer">${p.vendor} ↗</a></small></div></div><div>${badge(assessmentStatus(a))}${a.fixAvailable&&a.status==='affected'?'<small>Older builds / other components remain affected</small>':''}${a.status==='unknown'?'<small>No conclusive vendor evidence</small>':''}${assessmentSources(c,p,a.evidence)}</div><div class="fix-summary">${fixes.length?`<strong>Fixed package${fixes.length>1?'s':''}</strong><small class="fixed-version">${fixes.slice(0,2).map(f=>esc(shortFix(f))).join('<br>')}</small>${fixes.length>2?`<details><summary>${fixes.length-2} more package builds</summary><p>${fixes.slice(2).map(f=>esc(shortFix(f))).join('<br>')}</p></details>`:''}`:'<span class="muted">No explicit fix in available evidence</span>'}${links.length?`<div class="advisory-links">${links.map(url=>`<a target="_blank" rel="noopener noreferrer" href="${safeURL(url)}">${esc(url.split('/').pop())} ↗</a>`).join('')}</div>`:''}${mitigations.length?`<details><summary>Mitigation available</summary><p>${esc(mitigations.join('\n'))}</p></details>`:'<small>Mitigation: not reported</small>'}</div>${a.evidence.length?`<details class="evidence"><summary>Product / version evidence (${a.evidence.length})</summary>${a.evidence.map(e=>`<p><strong>${esc(e.name)}</strong> · ${esc(labels[e.status])}${e.affected.length?`<br>Affected: ${esc(e.affected.join('; '))}`:''}${e.unaffected.length?`<br>Unaffected ranges: ${esc(e.unaffected.join('; '))}`:''}${e.note?`<br>${esc(e.note)}`:''}</p>`).join('')}</details>`:''}</div>`;
}
function renderHome(){const counts={affected:0,unknown:0,fix_available:0,unaffected:0};state.cases.forEach(c=>counts[status(c)]++);$('#main').innerHTML=`<div class="page-heading"><div><div class="eyebrow">YOUR SECURITY WORKSPACE</div><h1>A little clarity.<br>A lot less noise.</h1><p class="case-title">Track the vulnerabilities that matter to your environment.</p></div><span class="workspace-symbol" aria-hidden="true">✳</span></div><div class="stats">${['affected','unknown','fix_available','unaffected'].map(s=>`<div class="panel"><span class="dot ${s}"></span><strong>${counts[s]}</strong><span>${labels[s]}</span></div>`).join('')}</div><section class="panel welcome"><div class="eyebrow">FOCUS ON WHAT MATTERS</div><h2>${state.cases.length?'Your next decision starts here.':'Your first case starts here.'}</h2><p>Enter a CVE. See which of your products are affected,<br>what’s fixed, and where to go next.</p><button class="primary" id="home-add">＋ Open a case</button><button class="text-button" id="example">Try CVE-2024-3094 ↗</button></section><div class="home-foot"><span>01 <strong>Choose your products</strong><small>Set the scope. Keep the signal.</small></span><span>02 <strong>Check the evidence</strong><small>Compact status, direct vendor links.</small></span><span>03 <strong>Keep a watchful eye</strong><small>Hourly checks on watched cases.</small></span></div>${storageError?'<div class="alert">Browser storage could not be loaded. Export any changes before closing this page.</div>':''}`;$('#home-add').onclick=openAdd;$('#example').onclick=()=>addCase('CVE-2024-3094');}
function orderedVendors(){const order=Array.isArray(state.osOrder)?state.osOrder:[];return [...VENDORS].sort((a,b)=>(order.includes(a.id)?order.indexOf(a.id):99)-(order.includes(b.id)?order.indexOf(b.id):99));}
const collapsed=new Set(), choiceOpen=new Set();
function groupRows(c){return orderedVendors().map(v=>{const rows=selected(c).filter(p=>p.family===v.id);return rows.length?`<details class="os-group" data-os="${v.id}" ${collapsed.has(v.id)?'':'open'}><summary>${logo({...v,family:v.id})} ${esc(v.name)} <span>${rows.length}</span></summary>${rows.map(p=>productRow(c,p)).join('')}</details>`:'';}).join('');}
document.addEventListener('toggle',e=>{if(e.target.matches('.os-group')){if(e.target.open)collapsed.delete(e.target.dataset.os);else collapsed.add(e.target.dataset.os);}if(e.target.matches('.vendor-choice')){const key=e.target.dataset.choice;if(e.target.open)choiceOpen.add(key);else choiceOpen.delete(key);}},true);
function choices(ids,prefix){return orderedVendors().map(v=>{const products=PRODUCTS.filter(p=>p.family===v.id),count=products.filter(p=>ids.includes(p.id)).length;return `<details class="vendor-choice ${count?'enabled':''}" data-choice="${prefix}-${v.id}" ${choiceOpen.has(`${prefix}-${v.id}`)?'open':''}><summary>${logo({...v,family:v.id})} ${v.name} <span>${count} selected</span></summary><div class="version-choices">${products.map(p=>`<label><input type="checkbox" value="${p.id}" ${ids.includes(p.id)?'checked':''}>${p.version}</label>`).join('')}</div></details>`;}).join('');}
function readChoices(e,container){return [...container.querySelectorAll('input[value]:checked')].map(i=>i.value);}
function renderOrder(){$('#os-order').innerHTML=orderedVendors().map((v,i)=>`<div class="order-row"><span>${esc(v.name)}</span><button data-move="${v.id}" data-direction="-1" ${i===0?'disabled':''} aria-label="Move ${v.name} up">↑</button><button data-move="${v.id}" data-direction="1" ${i===VENDORS.length-1?'disabled':''} aria-label="Move ${v.name} down">↓</button></div>`).join('');}
$('#os-order').onclick=e=>{const b=e.target.closest('[data-move]');if(!b)return;const ids=orderedVendors().map(v=>v.id),i=ids.indexOf(b.dataset.move),j=i+Number(b.dataset.direction);[ids[i],ids[j]]=[ids[j],ids[i]];state.osOrder=ids;save();renderOrder();render();};
function openAdd(){$('#add-error').textContent='';$('#add-dialog').showModal();$('#cve-input').focus();}
async function addCase(id){let c=state.cases.find(c=>c.id===id);if(c){active=id;markCaseRead(state,id);save();render();toast('Opened existing case.');return;}c={id,products:[...state.products],notes:'',created:Date.now()};state.cases.unshift(c);active=id;save();render();await refresh(c);}
async function refresh(c,force=true){
  if(busy.has(c.id))return;busy.add(c.id);if(active===c.id)render();
  const before=JSON.stringify({record:c.record,evidence:c.vendorData?.evidence});
  const hadEvidence=Boolean(c.record || c.vendorData);
  try{
    await syncWatchlist();
    const data=await streamCase(c.id,c.products,force,area=>{if(area.record){c.record=area.record;c.checked=area.checked;}c.vendorData=area.vendorData;save();if(active===c.id)render();});
    if(data.record){c.record=data.record;c.checked=data.checked;}
    c.vendorData=data.vendorData;c.apiChecked=Date.now();c.cache=data.cache;
    if(data.error)c.error=data.error;else delete c.error;
    if(hadEvidence&&before!==JSON.stringify({record:c.record,evidence:c.vendorData?.evidence})){
      log(c.id,'CVE or vendor evidence updated. Review product status and fixed versions.');
      if(globalThis.Notification?.permission==='granted')new Notification(`${c.id} updated`,{body:'New source evidence is available in CVE Desk.'});
    }
  }catch(e){c.error=e.message;c.attempted=Date.now();}
  finally{busy.delete(c.id);save();renderSidebar();if(active===c.id)render();}
}
async function importVex(e,c){try{const file=e.target.files[0];if(!file)return;if(file.size>15000000)throw Error('Document exceeds the 15 MB import limit.');const doc=JSON.parse(await file.text());if(doc.document?.csaf_version!=='2.0'||!Array.isArray(doc.vulnerabilities)||!doc.vulnerabilities.some(v=>v.cve?.toUpperCase()===c.id))throw Error('Choose a CSAF 2.0 document containing this CVE.');c.vex=doc;c.vexImported=Date.now();log(c.id,'Vendor VEX evidence imported.');save();render();toast('Vendor evidence imported.');}catch(err){toast(`Import failed: ${err.message}`);}}
$('#new-case').onclick=openAdd;$('#search').oninput=renderSidebar;$('#case-list').onclick=e=>{const del=e.target.closest('[data-delete]');if(del){if(confirm(`Delete ${del.dataset.delete}?`)){state.cases=state.cases.filter(c=>c.id!==del.dataset.delete);if(active===del.dataset.delete)active=null;save();render();syncWatchlist();}return;}const b=e.target.closest('[data-case]');if(b){active=b.dataset.case;markCaseRead(state,active);save();render();}};
$('#add-form').onsubmit=e=>{e.preventDefault();const id=$('#cve-input').value.trim().toUpperCase();if(!validId(id)){$('#add-error').textContent='Use a CVE identifier such as CVE-2024-3094.';return;}$('#add-dialog').close();$('#cve-input').value='';addCase(id);};
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>document.getElementById(b.dataset.close).close());
$('#settings-button').onclick=()=>{renderOrder();$('#default-products').innerHTML=choices(state.products,'default');$('#auto-refresh').checked=state.auto;$('#settings-dialog').showModal();};
$('#default-products').onchange=e=>{state.products=readChoices(e,$('#default-products'));save();$('#default-products').innerHTML=choices(state.products,'default');};$('#auto-refresh').onchange=e=>{state.auto=e.target.checked;save();};
$('#notifications').onclick=async()=>{if(!('Notification'in window)){toast('This browser does not support desktop notifications.');return;}const p=await Notification.requestPermission();toast(p==='granted'?'Desktop notifications enabled.':'Desktop notifications are disabled. Updated cases are marked in the sidebar.');};
$('#export').onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(state,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`cve-desk-${new Date().toISOString().slice(0,10)}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
$('#restore').onchange=async e=>{try{const f=e.target.files[0];if(!f)return;if(f.size>30000000)throw Error('Backup exceeds 30 MB.');const next=validate(JSON.parse(await f.text()));if(!confirm(`Replace this workspace with ${next.cases.length} backed-up cases?`))return;if(busy.size)throw Error('Wait for running refreshes to finish before restoring.');state=next;active=null;save();syncWatchlist();$('#settings-dialog').close();render();toast('Workspace restored.');}catch(err){toast(err.message);}finally{e.target.value='';}};
document.addEventListener('keydown',e=>{if(e.key.toLowerCase()==='n'&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!['INPUT','TEXTAREA'].includes(document.activeElement.tagName)&&!document.querySelector('dialog[open]')){e.preventDefault();openAdd();}});
async function catchUp(){if(!state.auto||document.hidden)return;for(const c of [...state.cases]){if(Date.now()-Math.max(c.apiChecked||0,c.attempted||0)>=HOUR)await refresh(c,false);}}
setInterval(catchUp,60000);setInterval(()=>syncWatchlist(true),300000);document.addEventListener('visibilitychange',catchUp);window.addEventListener('online',()=>{syncWatchlist(true).then(catchUp);});render();syncWatchlist().then(catchUp);
