export const VENDORS = [
  {id:'rhel',name:'Red Hat Enterprise Linux',vendor:'Red Hat',logo:'redhat'},
  {id:'debian',name:'Debian',vendor:'Debian',logo:'debian'},
  {id:'sles',name:'SUSE Linux Enterprise',vendor:'SUSE',logo:'suse'},
  {id:'windows',name:'Windows',vendor:'Microsoft',logo:'windows'},
  {id:'ubuntu',name:'Ubuntu',vendor:'Canonical',logo:'ubuntu'},
  {id:'alpine',name:'Alpine Linux',vendor:'Alpine',logo:'alpinelinux'},
];
export const PRODUCTS = [
  ...[8,9,10].map(v=>({id:`rhel${v}`,family:'rhel',name:`RHEL ${v}`,version:String(v),vendor:'Red Hat',match:new RegExp(`\\bred hat enterprise linux(?: ${v}\\b|[^()]*\\(v\\. ${v}\\))`,'i')})),
  ...[[11,'Bullseye'],[12,'Bookworm'],[13,'Trixie']].map(([v,code])=>({id:`debian${v}`,family:'debian',name:`Debian ${v} · ${code}`,version:`${v} · ${code}`,code:code.toLowerCase(),vendor:'Debian',match:new RegExp(`\\bdebian.*(?:${code}|${v}\\b)`,'i')})),
  ...[15,16].map(v=>({id:`sles${v}`,family:'sles',name:`SLES ${v}`,version:String(v),vendor:'SUSE',match:new RegExp(`\\b(?:suse linux enterprise server|sles) ${v}\\b`,'i')})),
  ...[['windows10','10'],['windows11','11'],['server2022','Server 2022'],['server2025','Server 2025']].map(([id,v])=>({id,family:'windows',name:`Windows ${v}`,version:v,vendor:'Microsoft',match:new RegExp(`\\bwindows ${v}\\b`,'i')})),
  ...[['2004','20.04','focal'],['2204','22.04','jammy'],['2404','24.04','noble'],['2604','26.04','resolute']].map(([id,v,code])=>({id:`ubuntu${id}`,family:'ubuntu',name:`Ubuntu ${v} LTS`,version:`${v} LTS`,code,vendor:'Canonical',match:new RegExp(`\\bubuntu.*(?:${v.replace('.','\\.')}|${code})`,'i')})),
  ...['3.20','3.21','3.22','3.23','3.24'].map(v=>({id:`alpine${v.replace('.','')}`,family:'alpine',name:`Alpine ${v}`,version:v,vendor:'Alpine',match:new RegExp(`\\balpine.*${v.replace('.','\\.')}\\b`,'i')})),
];
export function migrateProducts(ids) { return [...new Set(ids.flatMap(id=>id==='windows'?['windows10','windows11','server2022','server2025']:PRODUCTS.some(p=>p.id===id)?[id]:[]))]; }
export const validId = id => /^CVE-\d{4}-\d{4,}$/.test(id);
export function vendorURL(product,id) {
  if(product.vendor==='Red Hat') return `https://access.redhat.com/security/cve/${id}`;
  if(product.vendor==='Debian') return `https://security-tracker.debian.org/tracker/${id}`;
  if(product.vendor==='SUSE') return `https://www.suse.com/security/cve/${id}.html`;
  if(product.vendor==='Microsoft') return `https://msrc.microsoft.com/update-guide/vulnerability/${id}`;
  if(product.family==='ubuntu') return `https://ubuntu.com/security/${id}`;
  if(product.family==='alpine') return `https://security.alpinelinux.org/vuln/${id}`;
  return `https://www.cve.org/CVERecord?id=${id}`;
}
export function summary(record) {
  const cna=record?.containers?.cna || {};
  const containers=[cna,...(record?.containers?.adp || [])];
  const metric=containers.flatMap(c=>c.metrics || []).flatMap(m=>[m.cvssV4_0,m.cvssV3_1,m.cvssV3_0,m.cvssV2_0]).find(Boolean);
  return { title:cna.title || record?.cveMetadata?.state || 'Awaiting source data', description:cna.descriptions?.find(d=>d.lang?.startsWith('en'))?.value || 'No English description published.', score:metric?.baseScore, severity:metric?.baseSeverity || 'Unrated', vector:metric?.vectorString || '', category:cna.problemTypes?.flatMap(p=>p.descriptions || []).find(d=>d.lang==='en')?.description || 'Category not published', rejected:record?.cveMetadata?.state==='REJECTED' };
}
const range=v=>`${v.version || 'Unspecified'}${v.lessThan ? ` to < ${v.lessThan}` : v.lessThanOrEqual ? ` to ≤ ${v.lessThanOrEqual}` : ''}${v.changes?.length ? ` (status changes: ${v.changes.map(c=>`${c.at}: ${c.status}`).join(', ')})` : ''}`;
export function assess(record, product, vex, vendorData) {
  const cna=record?.containers?.cna;
  const entries=(cna?.affected || []).filter(a=>product.match.test(a.product || a.packageName || ''));
  let evidence=entries.map(a=>{
    const versions=a.versions || [];
    const affected=versions.filter(v=>v.status==='affected');
    const unaffected=versions.filter(v=>v.status==='unaffected');
    // Unaffected ranges are not necessarily fixes; never infer a fixed release.
    const status=affected.length || a.defaultStatus==='affected'?'affected':versions.some(v=>v.status==='unknown')?'unknown':a.defaultStatus==='unaffected' && !versions.length?'unaffected':'unknown';
    return {name:a.packageName || a.product,status,affected:affected.map(range),unaffected:unaffected.map(range),fix:[],mitigation:[]};
  });
  const vendorEvidence=vendorData?.evidence?.[product.id];
  if(vendorEvidence?.length) evidence=vendorEvidence;
  if(vex) evidence=[...evidence,...assessVex(vex,record?.cveMetadata?.cveId,product)];
  const status=evidence.some(e=>e.status==='affected')?'affected':evidence.some(e=>e.status==='unknown')?'unknown':evidence.some(e=>e.status==='fixed')?'fixed':evidence.length?'unaffected':'unknown';
  return {status,evidence,fixAvailable:evidence.some(e=>e.status==='fixed'||e.fix.length>0)};
}
// Presentation highlights the available action without changing the underlying
// affected-component evidence or claiming that a patch has been installed.
export const assessmentStatus = assessment => assessment.fixAvailable?'fix_available':assessment.status;
export function assessVex(doc,id,product,source='Imported VEX') {
  const names=new Map(), shortNames=new Map();
  const groups=new Map((doc.product_tree?.product_groups || []).map(g=>[g.group_id,g.product_ids || []]));
  function walk(branches,path=[]) { for(const b of branches || []) {const next=[...path,b.name || ''];if(b.product) {names.set(b.product.product_id,[...next,b.product.name || ''].join(' '));shortNames.set(b.product.product_id,b.product.name || b.name);}walk(b.branches,next);} }
  walk(doc.product_tree?.branches);
  for(const p of doc.product_tree?.full_product_names || []) {names.set(p.product_id,p.name);shortNames.set(p.product_id,p.name);}
  for(const r of doc.product_tree?.relationships || []) names.set(r.full_product_name.product_id,`${names.get(r.product_reference)||''} ${names.get(r.relates_to_product_reference)||''} ${r.full_product_name.name}`);
  const v=doc.vulnerabilities?.find(v=>v.cve?.toUpperCase()===id);
  if(!v) return [];
  const result=[];
  for(const [key,reportedStatus] of [['known_affected','affected'],['known_not_affected','unaffected'],['fixed','fixed'],['recommended','recommended'],['under_investigation','unknown']]) {
    for(const pid of v.product_status?.[key] || []) {
      const name=names.get(pid) || pid.replaceAll('_',' ');
      if(!product.match.test(name)) continue;
      const rem=(v.remediations || []).filter(r=>(!r.product_ids?.length&&!r.group_ids?.length)||r.product_ids?.includes(pid)||r.group_ids?.some(g=>groups.get(g)?.includes(pid)));
      const status=reportedStatus==='recommended'?(rem.some(r=>r.category==='vendor_fix')?'fixed':'unknown'):reportedStatus;
      const short=shortNames.get(pid) || doc.product_tree?.relationships?.find(r=>r.full_product_name.product_id===pid)?.full_product_name.name || name;
      result.push({name:short,status,affected:status==='affected'?[short]:[],unaffected:[],fix:status==='fixed'?[short]:rem.filter(r=>r.category==='vendor_fix').map(r=>r.details),mitigation:rem.filter(r=>['mitigation','workaround'].includes(r.category)).map(r=>r.details),source,links:rem.filter(r=>r.category==='vendor_fix'&&r.url).map(r=>r.url),...(reportedStatus==='recommended'?{note:status==='fixed'?'Recommended patched build; vendor-fix remediation published.':'Recommended build; no explicit vendor-fix remediation published.'}:{})});
    }
  }
  return result;
}
export async function fetchRecord(id) {
  const response=await fetch(`https://cveawg.mitre.org/api/cve/${id}`,{signal:AbortSignal.timeout(20000)});
  if(!response.ok) throw new Error(response.status===404?'CVE not published or not found.':`CVE source returned HTTP ${response.status}. Try again later.`);
  const data=await response.json();
  if(data.cveMetadata?.cveId!==id || !data.containers) throw new Error('The source returned an invalid CVE record.');
  return data;
}
