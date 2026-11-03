import {hasCaseUpdate,recordUpdate,markCaseRead,sortedCases} from './cases.js';
import {streamCase,syncWatches,fetchAgents} from './api.js';
import {PRODUCTS,VENDORS,migrateProducts,validId,vendorURL,summary,assess,assessmentStatus,tmdsSupport,isKernelFix,extractCveIds,groupFixes,splitPackage,CVSS_VERSIONS} from './data.js';
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const KEY='cve-desk-v1', HOUR=3600000;
let agents={products:{}},chooserOpen=false,archivedOpen=false,homeFilter=null;
fetchAgents().then(data=>{agents=data;render();}).catch(()=>{});
setInterval(()=>fetchAgents().then(data=>{agents=data;render();}).catch(()=>{}),3600000);
let watchQueue=Promise.resolve(),lastWatchlist='';
function syncWatchlist(force=false){const cases=state.cases.filter(c=>!c.archived).map(c=>({id:c.id,products:[...c.products]})),key=JSON.stringify(cases);watchQueue=watchQueue.then(async()=>{if(!force&&key===lastWatchlist)return;try{await syncWatches(cases);lastWatchlist=key;}catch(e){toast(`Could not sync server watches: ${e.message}`);}});return watchQueue;}
let state={version:1,cases:[],products:['rhel9','rhel10','debian12'],auto:true,activity:[]}, active=null, busy=new Set(), storageError=false;
try {const saved=localStorage.getItem(KEY);if(saved) state=validate(JSON.parse(saved));} catch {storageError=true;}
function validate(s) {
  if(s?.version!==1 || !Array.isArray(s.cases) || !Array.isArray(s.products) || !Array.isArray(s.activity) || s.cases.length>1000) throw Error('Invalid workspace backup.');
  const ids=new Set();
  for(const c of s.cases) {if(!validId(c.id)||ids.has(c.id)||!Array.isArray(c.products)||typeof c.notes!=='string'||(c.archived!==undefined&&typeof c.archived!=='number')|| (c.record && c.record.cveMetadata?.cveId!==c.id)) throw Error('Invalid case in backup.');ids.add(c.id);c.products=migrateProducts(c.products);}
  if(s.cvss!==undefined&&!CVSS_VERSIONS.includes(s.cvss))delete s.cvss;s.products=migrateProducts(s.products);return s;
}
function save() {try{localStorage.setItem(KEY,JSON.stringify(state));storageError=false;}catch{storageError=true;toast('Storage unavailable or full. Export a backup to avoid losing changes.');}}
function toast(message){$('#toast').textContent=message;$('#toast').classList.add('visible');clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('#toast').classList.remove('visible'),6000);}
function log(id,text){recordUpdate(state,id,text);save();renderSidebar();}
const sum=r=>summary(r,state.cvss||'3.1');
const date=t=>t?new Date(t).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'Never';
const selected=c=>PRODUCTS.filter(p=>c.products.includes(p.id));
const STATUS_ORDER=['affected','fix_available','inconclusive','unaffected','unknown'];
function status(c){if(!c.record&&!c.vex&&!c.vendorData)return 'unknown';const counts=statusCounts(c,selected(c));return STATUS_ORDER.find(s=>counts[s])||'unknown';}
const labels={affected:'Affected',inconclusive:'Inconclusive',unknown:'No data',fixed:'Fix published',fix_available:'Fix available',unaffected:'Not affected'};
const badge=(s,label=labels[s])=>`<span class="status ${s}"><span class="dot"></span>${label}</span>`;
const shareIcon='<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 15V3M8 7l4-4 4 4M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-7"/></svg>';
// Share sheet where available (mobile, some desktops); otherwise copy the link.
async function shareCase(c){
  const url=`${location.origin}/${c.id}`,title=`${c.id} · ${sum(c.record).title}`;
  if(navigator.share&&matchMedia('(pointer:coarse)').matches){try{await navigator.share({title,url});return;}catch(e){if(e.name==='AbortError')return;}}
  try{await navigator.clipboard.writeText(url);toast(`Link copied: ${url}`);}catch{prompt('Copy this link',url);}
}
const archiveIcon='<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 4h18v4H3zM5 8v12h14V8M10 12h4"/></svg>';
const unarchiveIcon='<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 4h18v4H3zM5 8v12h14V8M12 18v-6M9 14l3-3 3 3"/></svg>';
const trashIcon='<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6M14 10v6"/></svg>';
const statusSymbols={affected:'!',fix_available:'↑',inconclusive:'?',unaffected:'✓',unknown:'–'};
function statusCounts(c,products){const counts={affected:0,fix_available:0,unaffected:0,unknown:0,inconclusive:0};for(const p of products){const a=assess(c.record||{cveMetadata:{cveId:c.id}},p,c.vex,c.vendorData),s=assessmentStatus(a);counts[s==='unknown'&&a.evidence.length?'inconclusive':s]++;}return counts;}
function statusDescription(c){const counts=statusCounts(c,selected(c));return STATUS_ORDER.filter(s=>counts[s]).map(s=>`${counts[s]} ${labels[s].toLowerCase()}`).join(', ')||'No OS versions selected';}
// Thin bar with one segment per OS version, in status order.
function statusBar(c){const counts=statusCounts(c,selected(c)),total=Object.values(counts).reduce((a,b)=>a+b,0);return total?`<span class="status-bar" aria-hidden="true">${STATUS_ORDER.filter(s=>counts[s]).map(s=>`<span class="${s}" style="flex:${counts[s]}"></span>`).join('')}</span>`:'';}
const cvssChip=s=>s.score!=null?`<span class="cvss ${esc(s.severity.toLowerCase())}" title="CVSS ${s.cvssVersion} · ${esc(s.severity.toLowerCase())}">${s.score.toFixed(1)}</span>`:'';
const ago=t=>{if(!t)return 'never';const m=Math.round((Date.now()-t)/60000);return m<1?'just now':m<60?`${m} min ago`:m<1440?`${Math.round(m/60)} h ago`:`${Math.round(m/1440)} d ago`;};
const day=t=>t?new Date(t).toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'}):'';
// Share, archive and delete; used by the sidebar and the home page.
function caseActions(c){const archived=Boolean(c.archived),verb=archived?'Unarchive':'Archive';return `<span class="case-actions"><button data-share="${c.id}" aria-label="Share ${c.id}" title="Share ${c.id}">${shareIcon}</button><button data-archive="${c.id}" aria-label="${verb} ${c.id}" title="${verb} ${c.id}">${archived?unarchiveIcon:archiveIcon}</button><button class="delete-case" data-delete="${c.id}" aria-label="Delete ${c.id}" title="Delete ${c.id}">${trashIcon}</button></span>`;}
function caseAction(e){
  const b=e.target.closest('[data-share],[data-archive],[data-delete]');if(!b)return false;
  const id=b.dataset.share||b.dataset.archive||b.dataset.delete,c=state.cases.find(c=>c.id===id);if(!c)return true;
  if(b.dataset.share)shareCase(c);
  else if(b.dataset.archive)setArchived(c,!c.archived);
  else if(confirm(`Delete ${id}?`)){state.cases=state.cases.filter(x=>x.id!==id);if(active===id)active=null;save();render();syncWatchlist();}
  return true;
}
function caseEntry(c){
  const s=status(c),description=`Selected OS versions: ${statusDescription(c)}`,archived=Boolean(c.archived);
  return `<div class="case-entry ${archived?'archived':''}"><button class="case-item ${active===c.id?'selected':''}" data-case="${c.id}" ${active===c.id?'aria-current="page"':''} title="${esc(description)}"><span class="case-id"><span class="case-status ${s}" role="img" aria-label="${esc(description)}" title="${esc(description)}">${statusSymbols[s]}</span>${c.id}${cvssChip(sum(c.record))}${hasCaseUpdate(state,c)&&!archived?'<span class="case-update" aria-label="Unread update">New</span>':''}</span><small>${esc(c.record?sum(c.record).title:'Awaiting lookup')}</small>${statusBar(c)}</button>${caseActions(c)}</div>`;
}
function renderSidebar(){
  const q=$('#search').value.toLowerCase(),match=c=>`${c.id} ${sum(c.record).title}`.toLowerCase().includes(q);
  const cases=sortedCases(state).filter(match),open=cases.filter(c=>!c.archived),archived=cases.filter(c=>c.archived);
  $('#case-count').textContent=state.cases.filter(c=>!c.archived).length;
  // Show archived matches while searching and keep the open case visible.
  const showArchived=archivedOpen||Boolean(q);
  $('#case-list').innerHTML=open.map(caseEntry).join('')||`<p class="sidebar-empty">${q?'No matching cases.':'No open cases.'}</p>`;
  $('#archived-list').hidden=!archived.length;
  $('#archived-list').innerHTML=archived.length?`<button class="archive-toggle" aria-expanded="${showArchived}">${chevronIcon}Archived <span>${archived.length}</span></button>${showArchived?`<div class="archived-entries">${archived.map(caseEntry).join('')}</div>`:''}`:'';
}
function setArchived(c,archived){
  if(archived){c.archived=Date.now();markCaseRead(state,c.id);if(active===c.id)archivedOpen=true;}else delete c.archived;
  save();syncWatchlist();render();toast(archived?`${c.id} archived. It is no longer checked for updates.`:`${c.id} restored to your cases.`);
  if(!archived)refresh(c,false);
}
function syncRoute(){
  const path=active?`/${active}`:'/';document.title=active?`${active} · CVE Desk`:'CVE Desk — your vulnerability workspace';
  if(location.pathname===path)return;
  history[location.pathname.toUpperCase()===path.toUpperCase()?'replaceState':'pushState'](null,'',path+location.hash);
}
function routeFromURL(){const id=extractCveIds(decodeURIComponent(location.pathname))[0];if(!id){active=null;render();return;}if(state.cases.some(c=>c.id===id))openCase(id);else addCase(id);}
window.addEventListener('popstate',routeFromURL);
function render(){syncRoute();renderSidebar(); const c=state.cases.find(c=>c.id===active);if(!c){renderHome();return;}const s=sum(c.record);const loading=busy.has(c.id);
$('#main').innerHTML=`<div class="page-heading"><div><h1>${c.id}</h1><p class="case-title">${esc(s.title)}</p></div><div class="actions"><button id="share-case" title="Share a link to this case">${shareIcon}Share</button><button id="archive-case">${c.archived?unarchiveIcon+'Unarchive':archiveIcon+'Archive'}</button><button id="refresh" ${loading?'disabled':''}>${loading?'↻ Checking…':'↻ Refresh data'}</button><details class="freshness"><summary>Evidence · ${date(c.checked)}</summary><div class="panel source-panel">${sourceHealth(c)}</div></details></div></div>
${c.archived?`<div class="alert archived-note">Archived ${date(c.archived)}. This case is not checked for updates until you unarchive it.</div>`:''}
${c.error?`<div class="alert" role="alert">${esc(c.error)} ${c.record?'Showing the last saved snapshot.':'Try refreshing again.'}</div>`:''}
${s.rejected?'<div class="alert">This CVE has been rejected. Review the source before taking action.</div>':''}
<section class="overview panel"><div class="score ${esc(s.severity.toLowerCase())}"><strong>${s.score??'—'}</strong><span ${s.score!=null&&s.cvssVersion!==(state.cvss||'3.1')?`title="CVSS ${state.cvss||'3.1'} not published; showing ${s.cvssVersion}"`:''}>${esc(s.severity)}${s.score!=null?` · CVSS ${s.cvssVersion}`:''}</span></div><div class="overview-content"><div class="overview-meta"><div class="eyebrow">${esc(s.category)}</div>${s.published?`<p class="case-dates"><span>Published ${day(s.published)}</span>${s.updated&&day(s.updated)!==day(s.published)?`<span>Updated ${day(s.updated)}</span>`:''}</p>`:''}</div><details class="description"><summary>Vulnerability description</summary><p>${esc(s.description)}</p>${s.vector?`<code>${esc(s.vector)}</code>`:''}</details><div class="reference-links"><a target="_blank" rel="noopener noreferrer" href="https://www.cve.org/CVERecord?id=${c.id}">CVE record ↗</a><a target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/${c.id}">NIST / NVD ↗</a><a target="_blank" rel="noopener noreferrer" href="https://euvd.enisa.europa.eu/">EUVD search ↗</a></div></div></section>
<section class="products-section"><div class="section-heading"><div><h2>Operating systems <span class="count">${c.products.length}</span></h2></div><button id="edit-products" class="disclosure-button" aria-expanded="${chooserOpen}" aria-controls="case-products">${chevronIcon}Choose OS versions</button></div><div id="case-products" class="product-choices panel" ${chooserOpen?'':'hidden'}>${choices(c.products)}</div><div class="panel product-table"><div class="table-head"><span>VERSION</span><span>ASSESSMENT</span><span>FIX & MITIGATION</span></div>${unlistedNote(c)}${groupRows(c)||'<p class="empty-row">Select products to start assessing this case.</p>'}</div></section>
`;
$('#refresh').onclick=()=>refresh(c);$('#archive-case').onclick=()=>setArchived(c,!c.archived);$('#share-case').onclick=()=>shareCase(c);
$('#edit-products').onclick=e=>{chooserOpen=!chooserOpen;$('#case-products').hidden=!chooserOpen;e.currentTarget.setAttribute('aria-expanded',chooserOpen);};
$('#case-products').onchange=e=>{c.products=readChoices($('#case-products'));save();syncWatchlist();render();$(`#case-products input[value="${e.target.value}"]`)?.focus();refresh(c,false);};

}
const logo=p=>`<img class="vendor-logo logo-${p.family}" src="assets/logos/${VENDORS.find(v=>v.id===p.family)?.logo || p.logo}.svg" alt="" width="28" height="28">`;
const chevronIcon='<svg class="chevron" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>';
const gripIcon='<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><circle cx="9" cy="6" r="1.6"/><circle cx="15" cy="6" r="1.6"/><circle cx="9" cy="12" r="1.6"/><circle cx="15" cy="12" r="1.6"/><circle cx="9" cy="18" r="1.6"/><circle cx="15" cy="18" r="1.6"/></svg>';
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
function sourceHealth(c){return `<div class="feed-health">${[...new Set(selected(c).map(p=>p.family))].map(f=>{const v=VENDORS.find(v=>v.id===f),s=c.vendorData?.sources?.[f];return `<div><strong>${esc(v.name)}</strong><small>${s?.checked?`${esc(s.mode || 'Snapshot')} · ${date(s.checked)}`:'No data'}${s?.checked&&Date.now()-s.checked>HOUR?' · Stale':''}</small>${s?.sourceUpdated?`<small>Source updated ${date(s.sourceUpdated)}</small>`:''}${s?.url&&safeURL(s.url)!=='#'?`<small class="feed-source">Source: <a href="${safeURL(s.url)}" target="_blank" rel="noopener noreferrer">Vendor data ↗</a></small>`:''}${s?.error?`<small class="source-warning">${esc(s.error)}. Showing saved evidence if available.</small>`:s?.notPublished?`<small class="source-warning">${esc(s.notPublished)} Check the vendor page.</small>`:!s?'<small>No snapshot yet.</small>':''}${s?.excludedImages?`<small>${s.excludedImages} public-cloud image entr${s.excludedImages===1?'y':'ies'} not counted in OS rows; see the vendor source.</small>`:''}${sourceAdvisories(s)}</div>`;}).join('')}</div>`;}
const tmdsLabels={supported:'Supported',partial:'Partly supported',pending:'Not yet supported',unknown:'Not verifiable'};
// One line of the fix column. With details it expands in place, below its own summary.
function fact(label,value,body='',cls=''){
  const head=`<span class="fact-label">${label}</span><span class="fact-value">${value}</span>`;
  return body?`<details class="fact ${cls}"><summary>${head}${chevronIcon}</summary><div class="fact-body">${body}</div></details>`:`<div class="fact ${cls}">${head}</div>`;
}
function tmdsFact(p,fixes){
  const kernels=fixes.filter(isKernelFix);if(!kernels.length)return '';
  const releases=agents.products?.[p.id]||[],t=tmdsSupport(p.family,kernels,releases);
  if(t.status==='none')return '';
  const status=releases.length?t.status:'unknown';
  const agent=r=>`<a href="${safeURL(r.download)}" target="_blank" rel="noopener noreferrer">Agent ${esc(r.release)} ↗</a>`;
  const unknownText=p.family==='debian'?'Debian package versions of this kernel series do not map to kernel ABI names (such as 6.1.0-N), so support cannot be matched automatically.':'No bundled kernel of this stream to compare against.';
    const items=releases.length?t.branches.map(b=>`<li class="${b.status}"><span class="dot"></span><div>${t.branches.length>1?`<code>${esc(b.fix)}</code><br>`:''}${b.status==='supported'?`${b.exact?'Bundled':'Covered by newer bundled kernel'} <code>${esc(b.kernel)}</code><br>${esc(b.arches.join(', '))} · ${agent(b.release)}`:b.status==='pending'?`Not bundled yet. Newest in this stream: <code>${esc(b.kernel)}</code><br>${esc(b.arches.join(', '))}`:unknownText}</div></li>`).join(''):`<li class="unknown"><span class="dot"></span><div>${agents.error?'Agent inventory refresh failed. Try again later.':'Agent inventory is not available for this OS yet.'}</div></li>`;
  return fact('TMDS Agent',`<span class="tmds-state ${status}">${tmdsLabels[status]}</span>`,`<ul class="tmds-list">${items}</ul><p class="fact-note">Checked against kernels bundled in Deep Security Agent 20 LTS. Separately published Kernel Support Packages can add newer kernels.</p>`,`tmds ${status}`);
}
// Kernel and runtime packages first; debug, devel and doc builds last.
const fixRank=f=>{const n=splitPackage(f).name;return (/^(?:kernel|kernel-default|linux)$/.test(n)?0:/^(?:kernel|linux)-/.test(n)?1:2)+(/-(?:debug|debuginfo|debugsource|devel|doc|headers|source)\b/.test(n)?3:0);};
const rowFixes=a=>{const shortFix=f=>f.replace(/ as (?:a )?component of .*/, '').replace(/-0:/g,'-').replace(/\.(?:aarch64|x86_64|ppc64le|s390x|src|noarch|i686|armv7hl)$/,'');return [...new Set(a.evidence.flatMap(e=>e.fix).map(shortFix))].sort((x,y)=>fixRank(x)-fixRank(y)||splitPackage(x).name.length-splitPackage(y).name.length);};
function productRow(c,p){
  const a=assess(c.record || {cveMetadata:{cveId:c.id}},p,c.vex,c.vendorData),s=assessmentStatus(a);
  const fixes=rowFixes(a),groups=groupFixes(fixes);
  // Windows: label builds by release (23H2 · 22H3), main edition first, newest build first.
  if(p.family==='windows'){
    const release=n=>n.replace(/^windows (?:\d+|server \d{4})\b,?\s*(?:version\s*)?/i,'')||n;
    for(const g of groups)g.main=[...new Set(g.packages.map(f=>release(splitPackage(f).name)))].join(' · ');
    const edition=g=>/edition/i.test(g.main)?1:0;
    groups.sort((x,y)=>edition(x)-edition(y)||y.version.localeCompare(x.version,undefined,{numeric:true}));
  }
  const mitigations=[...new Set(a.evidence.flatMap(e=>e.mitigation).map(m=>m.replace(/^[\w.-]+>\s*/gm,'').trim()))];
  const links=[...new Set(a.evidence.flatMap(e=>e.links || []))];
  const link=url=>`<a target="_blank" rel="noopener noreferrer" href="${safeURL(url)}">${esc(url.split('/').pop())} ↗</a>`;
  const build=g=>g.version?`<code><span>${esc(g.main)}</span> ${esc(g.version)}</code>`:esc(g.main);
  const count=n=>`${n} package${n===1?'':'s'}`;
  // Closed: the main build. Open: a count, with every build listed once below by package name.
  const windows=p.family==='windows',total=groups.reduce((n,g)=>n+g.packages.length,0);
  const fixFact=groups.length?fact('Fix',`<span class="when-closed">${build(groups[0])}${groups.length>1?` <span class="fact-more">+${groups.length-1} more build${groups.length>2?'s':''}</span>`:groups[0].packages.length>1&&!windows?` <span class="fact-more">${count(groups[0].packages.length)}</span>`:''}</span><span class="when-open">${groups.length} build${groups.length>1?'s':''}${windows?'':` · ${count(total)}`}</span>`,
      groups.length>1||groups[0].packages.length>1?groups.map(g=>`<div class="build"><div class="build-head">${build(g)}</div>${windows?'':`<div class="package-list">${g.packages.map(f=>`<span>${esc(g.version?splitPackage(f).name:f)}</span>`).join('')}</div>`}</div>`).join(''):'','fix')
    :fact('Fix','<span class="fact-none">None in available evidence</span>');
  const advisoryFact=links.length?fact(links.length>1?'Advisories':'Advisory',`<span class="advisory-links">${links.slice(0,2).map(link).join('')}${links.length>2?`<span class="fact-more">+${links.length-2}</span>`:''}</span>`):'';
  const text=mitigations.join('\n'),mitigationFact=mitigations.length?fact('Mitigation',`<span class="fact-text">${esc(text.split('\n').find(l=>l.trim()))}</span>`,text.length>70||mitigations.length>1?`<p>${esc(text)}</p>`:'','mitigation'):fact('Mitigation','<span class="fact-none">None reported</span>');
  const changed=c.changedRows?.ids?.includes(p.id);
  // Short vendor notes (Debian triage, Microsoft scope); skip VEX build boilerplate.
  const notes=[...new Set(a.evidence.map(e=>e.note).filter(n=>n&&!/^Recommended (?:patched )?build/.test(n)))];
  return `<div class="product-row ${changed?'changed':''}"><div class="product-name"><strong>${esc(p.name)}</strong><a href="${vendorURL(p,c.id)}" target="_blank" rel="noopener noreferrer">${esc(p.vendor)} ↗</a>${changed?`<span class="row-updated" title="Changed in the update of ${date(c.changedRows.at)}">Updated</span>`:''}</div><div class="assessment">${badge(s,s==='unknown'&&a.evidence.length?'Inconclusive':labels[s])}${a.fixAvailable&&a.status==='affected'?'<small>Older builds / other components remain affected</small>':''}${a.status==='unknown'&&a.evidence.length?'<small>Available evidence does not establish status</small>':''}${notes.length&&notes.length<=2?notes.map(n=>`<small>${esc(n)}</small>`).join(''):''}${assessmentSources(c,p,a.evidence)}</div><div class="fix-summary">${fixFact}${advisoryFact}${tmdsFact(p,fixes)}${mitigationFact}</div></div>`;
}
// Compact per-row fingerprint used to highlight rows that change in an update.
function rowFingerprints(c){const out={};for(const p of selected(c)){const a=assess(c.record||{cveMetadata:{cveId:c.id}},p,c.vex,c.vendorData);out[p.id]=JSON.stringify([assessmentStatus(a),rowFixes(a),[...new Set(a.evidence.flatMap(e=>e.mitigation))]]);}return out;}
function renderHome(){
  const open=state.cases.filter(c=>!c.archived),counts=Object.fromEntries(STATUS_ORDER.map(s=>[s,0]));open.forEach(c=>counts[status(c)]++);
  const rank=c=>STATUS_ORDER.indexOf(status(c))*100-(sum(c.record).score||0);
  const attention=open.filter(c=>['affected','fix_available','inconclusive'].includes(status(c))||hasCaseUpdate(state,c)).sort((a,b)=>Number(hasCaseUpdate(state,b))-Number(hasCaseUpdate(state,a))||rank(a)-rank(b));
  const rest=open.filter(c=>!attention.includes(c));
  const filtered=homeFilter?open.filter(c=>status(c)===homeFilter).sort((a,b)=>rank(a)-rank(b)):null;
  const row=c=>{const s=sum(c.record),st=status(c);return `<div class="home-case-entry"><button class="home-case" data-case="${c.id}"><span class="case-status ${st}" aria-hidden="true">${statusSymbols[st]}</span><span class="home-case-main"><span class="home-case-id">${c.id}${cvssChip(s)}${hasCaseUpdate(state,c)?'<span class="case-update">New</span>':''}</span><small>${esc(c.record?s.title:'Awaiting lookup')}</small></span><span class="home-case-meta"><span>${esc(statusDescription(c))}</span>${statusBar(c)}<small>Checked ${ago(c.apiChecked||c.checked)}</small></span></button>${caseActions(c)}</div>`;};
  const agentCount=Object.values(agents.products||{}).reduce((n,r)=>n+r.length,0);
  const examples=['CVE-2024-3094','CVE-2024-6387','CVE-2024-1086','CVE-2024-21338'];
  $('#main').innerHTML=`<section class="home-hero"><div><h1>${open.length?attention.length?`${attention.length} case${attention.length>1?'s':''} need${attention.length>1?'':'s'} a look`:'All clear for now':'Check a vulnerability'}</h1><p class="home-lede">${open.length?`Tracking ${open.length} CVE${open.length>1?'s':''} across ${state.products.length} default OS versions. Evidence is checked ${state.auto?'every hour while open':'when you refresh'}.`:'Paste a CVE ID or any advisory link. CVE Desk checks the vendor trackers for the OS versions you care about.'}</p>
  <form id="home-form" class="home-open"><input id="home-input" placeholder="CVE-2024-3094 or a link that contains it" autocomplete="off" spellcheck="false" aria-label="CVE ID or link"><button class="primary">Open case →</button></form><p id="home-error" class="error" role="alert"></p>
  ${open.length?'':`<p class="home-examples">Try ${examples.map(id=>`<button class="example" data-example="${id}">${id}</button>`).join('')}</p>`}</div></section>
  ${open.length?`<div class="home-stats" role="group" aria-label="Filter cases by status">${STATUS_ORDER.map(s=>`<button class="home-stat ${s} ${counts[s]?'':'empty'}" data-filter="${s}" aria-pressed="${homeFilter===s}" ${counts[s]||homeFilter===s?'':'disabled'}><span class="case-status ${s}">${statusSymbols[s]}</span><strong>${counts[s]}</strong><span>${labels[s]}</span></button>`).join('')}</div>`:''}
  <div class="home-grid"><div>${filtered?`<section class="panel home-list"><h2>${labels[homeFilter]} <button class="text-button clear-filter" data-filter="${homeFilter}">Show all</button></h2>${filtered.map(row).join('')||'<p class="muted home-empty">No cases with this status.</p>'}</section>`:`${attention.length?`<section class="panel home-list"><h2>Needs attention</h2>${attention.map(row).join('')}</section>`:''}${rest.length?`<section class="panel home-list"><h2>${attention.length?'Other cases':'Your cases'}</h2>${rest.map(row).join('')}</section>`:''}`}${open.length?'':`<section class="panel home-how"><h2>How it works</h2><ol><li><strong>Open a case</strong><span>One CVE, checked against Red Hat, SUSE, Debian, Ubuntu, Alpine and Microsoft.</span></li><li><strong>See what to do</strong><span>Status, fixed builds, advisories and mitigations per OS version.</span></li><li><strong>Stay informed</strong><span>Cases are re-checked hourly; changed rows are highlighted.</span></li></ol></section>`}</div>
  <aside><section class="panel home-side"><h2>Recent activity</h2>${state.activity.slice(0,6).map(a=>`<button class="activity-item" data-case="${a.id}"><span>${a.id}</span><small>${esc(a.text)}</small><small>${ago(a.time)}</small></button>`).join('')||'<p class="muted">Updates to your cases appear here.</p>'}</section>
  <section class="panel home-side"><h2>TMDS Agent inventory</h2><p class="muted">${agentCount?`${agentCount} bundled agent builds checked ${ago(agents.attempted)}.`:agents.error?'Inventory refresh failed.':'Inventory loading…'} Kernel fixes are matched against Deep Security Agent 20 LTS.</p></section></aside></div>`;
  $('#home-form').onsubmit=e=>{e.preventDefault();openFromText($('#home-input').value,$('#home-error'));};
  $('#main').onclick=e=>{if(caseAction(e))return;const f=e.target.closest('[data-filter]');if(f){homeFilter=homeFilter===f.dataset.filter?null:f.dataset.filter;renderHome();$(`[data-filter="${f.dataset.filter}"].home-stat`)?.focus();return;}const ex=e.target.closest('[data-example]');if(ex){addCase(ex.dataset.example);return;}const b=e.target.closest('[data-case]');if(b)openCase(b.dataset.case);};
}
function orderedVendors(){const order=Array.isArray(state.osOrder)?state.osOrder:[];return [...VENDORS].sort((a,b)=>(order.includes(a.id)?order.indexOf(a.id):99)-(order.includes(b.id)?order.indexOf(b.id):99));}
const groupOverride=new Map();
function unlistedNote(c){
  if(!c.record||busy.has(c.id))return '';
  const rows=selected(c);if(!rows.length||rows.some(p=>assess(c.record,p,c.vex,c.vendorData).evidence.length))return '';
  const listed=[...new Set((c.record.containers?.cna?.affected||[]).map(a=>[a.vendor,a.product].filter(v=>v&&v!=='n/a').join(' ')).filter(Boolean))];
  return `<p class="unlisted-note">None of the selected OS vendors list this CVE.${listed.length?` The CVE record names ${esc(listed.slice(0,3).join(', '))}${listed.length>3?` and ${listed.length-3} more`:''}.`:''}</p>`;
}
function groupRows(c){return orderedVendors().map(v=>{const rows=selected(c).filter(p=>p.family===v.id);if(!rows.length)return '';const counts=statusCounts(c,rows),key=`${c.id}:${v.id}`;
  const quiet=counts.unaffected+counts.unknown===rows.length&&!rows.some(p=>c.changedRows?.ids?.includes(p.id));
  const open=groupOverride.has(key)?groupOverride.get(key):!quiet;
  return `<details class="os-group ${quiet?'quiet':''}" data-os="${key}" ${open?'open':''}><summary>${chevronIcon}${logo({...v,family:v.id})}<strong>${esc(v.name)}</strong><span class="os-status-summary">${Object.entries(counts).filter(([,n])=>n).map(([s,n])=>`<span class="status ${s==='inconclusive'?'unknown':s}">${n} ${s==='inconclusive'?'Inconclusive':labels[s]}</span>`).join('')}</span></summary>${rows.map(p=>productRow(c,p)).join('')}</details>`;}).join('');}
document.addEventListener('toggle',e=>{if(e.target.matches('.os-group'))groupOverride.set(e.target.dataset.os,e.target.open);},true);
function choices(ids,sortable=false){return orderedVendors().map(v=>{const products=PRODUCTS.filter(p=>p.family===v.id),count=products.filter(p=>ids.includes(p.id)).length;return `<div class="vendor-choice ${count?'enabled':''}" data-vendor="${v.id}">${sortable?`<button type="button" class="drag-handle" data-handle="${v.id}" aria-label="Move ${esc(v.name)}. Drag, or press the up and down arrow keys." title="Drag to reorder">${gripIcon}</button>`:''}<div class="vendor-choice-name">${logo({...v,family:v.id})}<div><strong>${esc(v.name)}</strong><small>${count?`${count} of ${products.length} selected`:'None selected'}</small></div></div><div class="version-choices" role="group" aria-label="${esc(v.name)} versions">${products.map(p=>`<label class="version-chip"><input type="checkbox" value="${p.id}" ${ids.includes(p.id)?'checked':''}><span>${esc(p.version)}</span></label>`).join('')}</div></div>`;}).join('');}
function readChoices(container){return [...container.querySelectorAll('input[value]:checked')].map(i=>i.value);}
const defaultsList=$('#default-products');
function renderDefaults(focus){defaultsList.innerHTML=choices(state.products,true);if(focus)defaultsList.querySelector(focus)?.focus();}
function moveVendors(ids,id){state.osOrder=ids;save();renderDefaults(`[data-handle="${id}"]`);render();}
defaultsList.onpointerdown=e=>{
  const handle=e.target.closest('[data-handle]');if(!handle||e.button!==0)return;
  // Window listeners: moving the row in the DOM releases pointer capture.
  e.preventDefault();handle.focus();
  const row=handle.closest('.vendor-choice'),stop=new AbortController();row.classList.add('dragging');defaultsList.classList.add('sorting');
  window.addEventListener('pointermove',ev=>{const next=[...defaultsList.querySelectorAll('.vendor-choice:not(.dragging)')].find(r=>{const b=r.getBoundingClientRect();return ev.clientY<b.top+b.height/2;});if(next!==row.nextElementSibling)defaultsList.insertBefore(row,next||null);},{signal:stop.signal});
  const end=()=>{stop.abort();row.classList.remove('dragging');defaultsList.classList.remove('sorting');moveVendors([...defaultsList.querySelectorAll('.vendor-choice')].map(r=>r.dataset.vendor),handle.dataset.handle);};
  window.addEventListener('pointerup',end,{signal:stop.signal});window.addEventListener('pointercancel',end,{signal:stop.signal});
};
defaultsList.onkeydown=e=>{
  const handle=e.target.closest('[data-handle]');if(!handle||!['ArrowUp','ArrowDown'].includes(e.key))return;e.preventDefault();
  const ids=orderedVendors().map(v=>v.id),i=ids.indexOf(handle.dataset.handle),j=i+(e.key==='ArrowUp'?-1:1);
  if(j<0||j>=ids.length)return;[ids[i],ids[j]]=[ids[j],ids[i]];moveVendors(ids,handle.dataset.handle);
};
defaultsList.onchange=e=>{state.products=readChoices(defaultsList);save();renderDefaults(`input[value="${e.target.value}"]`);};
// Highlights stay while the case is on screen and clear once you leave it after reading.
function openCase(id){const previous=state.cases.find(c=>c.id===active);if(previous&&previous.id!==id&&!previous.hasUpdate)delete previous.changedRows;active=id;markCaseRead(state,id);save();render();}
function openAdd(){$('#add-error').textContent='';$('#add-dialog').showModal();$('#cve-input').focus();}
async function addCase(id){let c=state.cases.find(c=>c.id===id);if(c){const wasArchived=Boolean(c.archived);if(wasArchived){delete c.archived;syncWatchlist();}openCase(id);toast(wasArchived?'Restored from the archive.':'Opened existing case.');if(wasArchived)refresh(c,false);return;}c={id,products:[...state.products],notes:'',created:Date.now()};state.cases.unshift(c);active=id;save();render();await refresh(c);}
async function refresh(c,force=true){
  if(busy.has(c.id))return;busy.add(c.id);if(active===c.id)render();
  const requestedProducts=[...c.products];
  const before=JSON.stringify({record:c.record,evidence:c.vendorData?.evidence});
  const hadEvidence=Boolean(c.record || c.vendorData),beforeRows=rowFingerprints(c);
  try{
    await syncWatchlist();
    const data=await streamCase(c.id,c.products,force,area=>{if(area.record){c.record=area.record;c.checked=area.checked;}c.vendorData=area.vendorData;save();if(active===c.id)render();});
    if(data.record){c.record=data.record;c.checked=data.checked;}
    c.vendorData=data.vendorData;c.apiChecked=Date.now();c.cache=data.cache;
    if(data.error)c.error=data.error;else delete c.error;
    if(hadEvidence&&before!==JSON.stringify({record:c.record,evidence:c.vendorData?.evidence})){
      const afterRows=rowFingerprints(c),ids=Object.keys(afterRows).filter(id=>id in beforeRows&&beforeRows[id]!==afterRows[id]);
      if(ids.length)c.changedRows={ids,at:Date.now()};
      const names=ids.map(id=>PRODUCTS.find(p=>p.id===id).name);
      log(c.id,names.length?`Updated: ${names.join(', ')}. Review status and fixed versions.`:'CVE or vendor evidence updated. Review product status and fixed versions.');
      if(globalThis.Notification?.permission==='granted')new Notification(`${c.id} updated`,{body:'New source evidence is available in CVE Desk.'});
    }
  }catch(e){c.error=e.message;c.attempted=Date.now();}
  finally{busy.delete(c.id);save();renderSidebar();if(active===c.id)render();if(JSON.stringify(requestedProducts)!==JSON.stringify(c.products))refresh(c,false);}
}
const resizeHandle=$('#sidebar-resize');
function sidebarWidth(value,persist=false){
  const max=Math.min(480,Math.max(220,window.innerWidth-420));
  const width=Math.round(Math.max(220,Math.min(max,Number(value)||265)));
  document.documentElement.style.setProperty('--sidebar-width',`${width}px`);
  resizeHandle.setAttribute('aria-valuenow',width);resizeHandle.setAttribute('aria-valuemax',max);
  if(persist){state.sidebarWidth=width;save();}
}
sidebarWidth(state.sidebarWidth);
let resizing=false;
resizeHandle.onpointerdown=e=>{if(e.button!==0)return;e.preventDefault();resizing=true;resizeHandle.setPointerCapture(e.pointerId);document.body.classList.add('resizing-sidebar');};
resizeHandle.onpointermove=e=>{if(resizing)sidebarWidth(e.clientX);};
function finishResize(){if(!resizing)return;resizing=false;document.body.classList.remove('resizing-sidebar');sidebarWidth(resizeHandle.getAttribute('aria-valuenow'),true);}
resizeHandle.onpointerup=finishResize;resizeHandle.onpointercancel=finishResize;resizeHandle.onlostpointercapture=finishResize;
resizeHandle.onkeydown=e=>{const current=Number(resizeHandle.getAttribute('aria-valuenow')),step=e.shiftKey?40:10;const values={ArrowLeft:current-step,ArrowRight:current+step,Home:220,End:480};if(e.key in values){e.preventDefault();sidebarWidth(values[e.key],true);}};
resizeHandle.ondblclick=()=>sidebarWidth(265,true);
window.addEventListener('resize',()=>sidebarWidth(state.sidebarWidth));
$('#new-case').onclick=openAdd;$('#search').oninput=renderSidebar;$('#case-list').onclick=$('#archived-list').onclick=e=>{if(caseAction(e))return;if(e.target.closest('.archive-toggle')){archivedOpen=!archivedOpen;renderSidebar();$('.archive-toggle')?.focus();return;}const b=e.target.closest('[data-case]');if(b)openCase(b.dataset.case);};
function openFromText(text,error){const ids=extractCveIds(text).filter(validId);if(!ids.length){error.textContent='No CVE ID found. Paste an ID such as CVE-2024-3094 or a link that contains one.';return false;}addCase(ids[0]);if(ids.length>1)setTimeout(()=>toast(`Found ${ids.length} CVE IDs; opened ${ids[0]}.`),50);return true;}
$('#add-form').onsubmit=e=>{e.preventDefault();if(openFromText($('#cve-input').value,$('#add-error'))){$('#add-dialog').close();$('#cve-input').value='';}};
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>document.getElementById(b.dataset.close).close());
$('#settings-button').onclick=()=>{renderDefaults();$('#cvss-version').value=state.cvss||'3.1';$('#auto-refresh').checked=state.auto;$('#settings-dialog').showModal();};
$('#auto-refresh').onchange=e=>{state.auto=e.target.checked;save();};
$('#cvss-version').innerHTML=CVSS_VERSIONS.map(v=>`<option value="${v}">CVSS ${v}${v==='3.1'?' (default)':''}</option>`).join('');
$('#cvss-version').onchange=e=>{state.cvss=e.target.value;save();render();};
$('.brand').onclick=e=>{if(e.button||e.ctrlKey||e.metaKey||e.shiftKey)return;e.preventDefault();const previous=state.cases.find(c=>c.id===active);if(previous&&!previous.hasUpdate)delete previous.changedRows;active=null;render();};
$('#notifications').onclick=async()=>{if(!('Notification'in window)){toast('This browser does not support desktop notifications.');return;}const p=await Notification.requestPermission();toast(p==='granted'?'Desktop notifications enabled.':'Desktop notifications are disabled. Updated cases are marked in the sidebar.');};
$('#export').onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(state,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`cve-desk-${new Date().toISOString().slice(0,10)}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
$('#restore').onchange=async e=>{try{const f=e.target.files[0];if(!f)return;if(f.size>30000000)throw Error('Backup exceeds 30 MB.');const next=validate(JSON.parse(await f.text()));if(!confirm(`Replace this workspace with ${next.cases.length} backed-up cases?`))return;if(busy.size)throw Error('Wait for running refreshes to finish before restoring.');state=next;active=null;save();syncWatchlist();$('#settings-dialog').close();render();toast('Workspace restored.');}catch(err){toast(err.message);}finally{e.target.value='';}};
document.addEventListener('keydown',e=>{
  const key=e.key.toLowerCase(),mod=e.ctrlKey||e.metaKey,typing=['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName);
  if(document.querySelector('dialog[open]')||e.altKey)return;
  if((mod&&(key==='n'||key==='k'))||(key==='n'&&!mod&&!typing)){e.preventDefault();openAdd();}
});
async function catchUp(){if(!state.auto||document.hidden)return;for(const c of state.cases.filter(c=>!c.archived)){if(Date.now()-Math.max(c.apiChecked||0,c.attempted||0)>=HOUR)await refresh(c,false);}}
setInterval(catchUp,60000);setInterval(()=>syncWatchlist(true),300000);document.addEventListener('visibilitychange',catchUp);window.addEventListener('online',()=>{syncWatchlist(true).then(catchUp);});routeFromURL();syncWatchlist().then(catchUp);
