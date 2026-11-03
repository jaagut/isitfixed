import {PRODUCTS,assessVex} from './data.js';
export const redhatURL=id=>`https://security.access.redhat.com/data/csaf/v2/vex/${id.split('-')[1]}/${id.toLowerCase()}.json`;
export const ubuntuURL=id=>`https://ubuntu.com/security/cves/${id}.json`;
export const suseURL=id=>`https://ftp.suse.com/pub/projects/security/csaf-vex/${Math.max(2023,Number(id.split('-')[1]))}/${id.toLowerCase()}.json`;
const entry=(name,status,source,fix=[],extra={})=>({name,status,source,fix,affected:[],unaffected:[],mitigation:[],links:[],...extra});
export function parseUbuntu(doc,p) {
  const entries=(doc.packages || []).flatMap(pkg=>(pkg.statuses || []).filter(s=>s.release_codename===p.code).map(s=>entry(pkg.name,
    s.status==='released'?'fixed':['not-affected','DNE'].includes(s.status)?'unaffected':['needed','pending','ignored','deferred'].includes(s.status)?'affected':'unknown',
    'Ubuntu security tracker',s.status==='released'?[`${pkg.name} ${s.description}`]:[],{note:`${s.status}${s.description?`: ${s.description}`:''}${s.pocket?` · ${s.pocket}`:''}`})));
  if(entries.length && doc.mitigation)entries[0].mitigation=[doc.mitigation];
  return entries;
}
export function parseAlpine(doc,id) {
  return (doc.packages || []).flatMap(({pkg})=>Object.entries(pkg.secfixes || {}).filter(([,ids])=>ids.some(value=>value.split(/\s+/).includes(id))).map(([version])=>entry(pkg.name,'fixed','Alpine secdb',[`${pkg.name} ${version}`])));
}
export function parseDebian(doc,id,p) {
  return Object.entries(doc).flatMap(([pkg,cves])=>{
    const release=cves[id]?.releases?.[p.code];if(!release)return [];
    const fix=release.fixed_version;
    return [entry(pkg,release.status==='resolved'?(fix==='0'?'unaffected':fix?'fixed':'unknown'):release.status==='open'?'affected':'unknown','Debian security tracker',fix&&fix!=='0'?[`${pkg} ${fix}`]:[],{note:release.nodsa || ''})];
  });
}
export function parseRedhat(doc,id) {return Object.fromEntries(PRODUCTS.filter(p=>p.family==='rhel').map(p=>[p.id,assessVex(doc,id,p,'Red Hat VEX')]));}
export function parseSuse(doc,id) {
  if(doc.document?.csaf_version!=='2.0' || !doc.vulnerabilities?.some(v=>v.cve?.toUpperCase()===id))throw Error('Invalid SUSE CSAF document or mismatched CVE.');
  return Object.fromEntries(PRODUCTS.filter(p=>p.family==='sles').map(p=>[p.id,assessVex(doc,id,p,'SUSE CSAF')]));
}
export function suseMetadata(doc) {
  return {sourceUpdated:doc.document?.tracking?.current_release_date,advisories:(doc.document?.references || []).filter(r=>r.summary?.startsWith('Advisory link for ')&&r.url).map(r=>({url:r.url,label:r.summary.replace('Advisory link for ','')}))};
}
