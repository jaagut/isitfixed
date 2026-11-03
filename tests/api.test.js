import {test} from 'node:test';
import assert from 'node:assert/strict';
import {fetchCase,syncWatches} from '../src/api.js';
test('case refresh uses only the API, including selected vendor families and force flag',async()=>{
  const original=globalThis.fetch,calls=[];
  try{
    globalThis.fetch=async(url,options)=>{calls.push({url,options});return Response.json({id:'CVE-2026-98432',vendorData:{id:'CVE-2026-98432'}});};
    await fetchCase('CVE-2026-98432',['sles15','rhel9','sles16','windows11'],true);
    assert.equal(calls.length,1);assert.equal(calls[0].url,'/api/cves/CVE-2026-98432?families=rhel%2Csles&refresh=true');
  }finally{globalThis.fetch=original;}
});
test('watch sync sends case IDs and vendor choices without private notes or snapshots',async()=>{
  const original=globalThis.fetch,storage=globalThis.localStorage;let sent;
  try{
    globalThis.localStorage={getItem:()=> 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'};
    globalThis.fetch=async(url,options)=>{sent={url,options};return Response.json({watched:1});};
    await syncWatches([{id:'CVE-2026-98432',products:['rhel9'],notes:'Private incident notes',record:{secret:'internal'}}]);
    assert.equal(sent.options.method,'PUT');
    assert.deepEqual(JSON.parse(sent.options.body),{cases:[{id:'CVE-2026-98432',families:['rhel']}]});
  }finally{globalThis.fetch=original;globalThis.localStorage=storage;}
});
test('API failures and wrong CVE IDs are errors, without vendor proxy fallback',async()=>{
  const original=globalThis.fetch;
  try{
    globalThis.fetch=async()=>new Response('backend offline',{status:503});
    await assert.rejects(()=>fetchCase('CVE-2026-98432',[]),/HTTP 503/);
    globalThis.fetch=async()=>Response.json({id:'CVE-2026-1111',vendorData:{id:'CVE-2026-1111'}});
    await assert.rejects(()=>fetchCase('CVE-2026-98432',[]),/mismatched/);
  }finally{globalThis.fetch=original;}
});
test('progressive case results decode across chunk boundaries',async()=>{
  const {streamCase}=await import('../src/api.js');const original=globalThis.fetch;
  try{
    const first={id:'CVE-2026-98432',vendorData:{id:'CVE-2026-98432',sources:{}}};
    const last={...first,record:{cveMetadata:{cveId:first.id}}};
    const text=JSON.stringify(first)+'\n'+JSON.stringify(last)+'\n',encoder=new TextEncoder();
    globalThis.fetch=async()=>new Response(new ReadableStream({start(c){c.enqueue(encoder.encode(text.slice(0,20)));c.enqueue(encoder.encode(text.slice(20)));c.close();}}));
    const areas=[];const result=await streamCase(first.id,[],false,data=>areas.push(data));
    assert.equal(areas.length,2);assert.deepEqual(result,last);
  }finally{globalThis.fetch=original;}
});
