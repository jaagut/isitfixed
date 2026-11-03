// Build-time sync: the deployed app remains entirely static.
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {PRODUCTS,validId} from '../src/data.js';
import {redhatURL,ubuntuURL,suseURL,parseSuse,suseMetadata,parseRedhat,parseUbuntu,parseAlpine,parseDebian} from '../src/feeds.js';
const ids=process.argv.slice(2).length?process.argv.slice(2):JSON.parse(await readFile(new URL('../vendor-data/watchlist.json',import.meta.url)));
if(!ids.every(validId))throw Error('Use valid CVE IDs.');
const get=async url=>{const r=await fetch(url,{signal:AbortSignal.timeout(90000)});if(!r.ok)throw Error(`${url}: HTTP ${r.status}`);return r.json();};
const cache=new Map();const cached=url=>{if(!cache.has(url))cache.set(url,get(url));return cache.get(url);};
await mkdir(new URL('../vendor-data/',import.meta.url),{recursive:true});
let failures=0;
for(const id of ids){
  const path=new URL(`../vendor-data/${id}.json`,import.meta.url);
  let result={id,evidence:{},sources:{}};
  try{result=JSON.parse(await readFile(path));}catch{}
  for(const family of ['rhel','sles','ubuntu','alpine','debian']){
    let url;
    try{
      const evidence={};
      let metadata={};
      if(family==='rhel'){url=redhatURL(id);Object.assign(evidence,parseRedhat(await get(url),id));}
      if(family==='sles'){url=suseURL(id);const doc=await get(url);Object.assign(evidence,parseSuse(doc,id));metadata=suseMetadata(doc);}
      if(family==='ubuntu'){url=ubuntuURL(id);const doc=await get(url);if(doc.id!==id)throw Error('Wrong Ubuntu CVE');for(const p of PRODUCTS.filter(p=>p.family===family))evidence[p.id]=parseUbuntu(doc,p);}
      if(family==='debian'){url='https://security-tracker.debian.org/tracker/data/json';const doc=await cached(url);for(const p of PRODUCTS.filter(p=>p.family===family))evidence[p.id]=parseDebian(doc,id,p);}
      if(family==='alpine'){url='https://secdb.alpinelinux.org/';for(const p of PRODUCTS.filter(p=>p.family===family)){const docs=await Promise.all(['main','community'].map(repo=>cached(`${url}v${p.version}/${repo}.json`)));evidence[p.id]=docs.flatMap(d=>parseAlpine(d,id));}}
      Object.assign(result.evidence,evidence);result.sources[family]={url,checked:Date.now(),mode:'static snapshot',...metadata};console.log(`${id}: ${family} synced`);
    }catch(e){failures++;result.sources[family]={...result.sources[family],url,error:e.message,attempted:Date.now()};console.error(e.message);}
  }
  await writeFile(path,JSON.stringify(result));
}
if(failures)process.exitCode=1;
