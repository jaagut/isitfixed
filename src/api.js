import {API_BASE} from './config.js';
import {PRODUCTS} from './data.js';
const implemented=new Set(['rhel','sles','debian','ubuntu','alpine']);
const families=products=>[...new Set(products.map(id=>PRODUCTS.find(p=>p.id===id)?.family).filter(f=>implemented.has(f)))].sort();
async function request(path,options={}){
  let response;
  try{response=await fetch(`${API_BASE.replace(/\/$/,'')}${path}`,{...options,signal:AbortSignal.timeout(180000),cache:'no-store'});}catch{throw Error('CVE API unavailable. Check your connection or backend configuration. Saved evidence is still available.');}
  if(!response.ok){let message=`CVE API returned HTTP ${response.status}.`;try{const body=await response.json();if(typeof body.detail==='string')message=body.detail;}catch{}throw Error(message);}
  return response.json();
}
export async function fetchCase(id,products,force=false){
  const params=new URLSearchParams({families:families(products).join(','),refresh:String(force)});
  const data=await request(`/cves/${encodeURIComponent(id)}?${params}`);
  if(data.id!==id||data.vendorData?.id!==id)throw Error('CVE API returned mismatched case data.');
  return data;
}
let workspace;
function workspaceId(){
  if(workspace)return workspace;
  workspace=localStorage.getItem('cve-desk-workspace');
  if(!workspace){
    if(crypto.randomUUID)workspace=crypto.randomUUID();
    else{const bytes=crypto.getRandomValues(new Uint8Array(16));bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;const hex=[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');workspace=`${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;}
    localStorage.setItem('cve-desk-workspace',workspace);
  }
  return workspace;
}
export async function syncWatches(cases){
  return request(`/workspaces/${workspaceId()}/watches`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({cases:cases.map(c=>({id:c.id,families:families(c.products)}))})});
}

export async function streamCase(id,products,force,onArea){
  const params=new URLSearchParams({families:families(products).join(','),refresh:String(force)});
  const response=await fetch(`${API_BASE.replace(/\/$/,'')}/cves/${encodeURIComponent(id)}/stream?${params}`,{signal:AbortSignal.timeout(180000),cache:'no-store'});
  if(!response.ok)throw Error(`CVE API returned HTTP ${response.status}`);
  const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='',latest;
  const consume=line=>{if(!line.trim())return;const data=JSON.parse(line);if(data.failed)throw Error(data.error);if(data.id!==id||data.vendorData?.id!==id)throw Error('Mismatched case data');latest=data;onArea(data);};
  try{while(true){const {value,done}=await reader.read();buffer+=decoder.decode(value,{stream:!done});const lines=buffer.split('\n');buffer=lines.pop();lines.forEach(consume);if(done)break;}if(buffer.trim())consume(buffer);return latest;}finally{await reader.cancel();}
}

export const fetchAgents=()=>request('/tmds');
