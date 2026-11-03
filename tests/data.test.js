import {test} from 'node:test';
import assert from 'node:assert/strict';
import {assess,PRODUCTS,summary,validId,migrateProducts} from '../src/data.js';
const p=PRODUCTS.find(p=>p.id==='rhel9');
const record=affected=>({cveMetadata:{cveId:'CVE-2024-3094'},containers:{cna:{affected}}});
test('missing product is unknown and RHEL major versions stay separate',()=>{
  assert.equal(assess(record([{product:'Red Hat Enterprise Linux 10',defaultStatus:'unaffected'}]),p).status,'unknown');
});
test('explicit unaffected statement is preserved',()=>{
  assert.equal(assess(record([{product:'Red Hat Enterprise Linux 9',defaultStatus:'unaffected'}]),p).status,'unaffected');
});
test('unaffected versions are not inferred to be fixes',()=>{
  const a=assess(record([{product:'Red Hat Enterprise Linux 9',versions:[{version:'1',lessThan:'2',status:'affected'},{version:'2',status:'unaffected'}]}]),p);
  assert.equal(a.status,'affected');assert.deepEqual(a.evidence[0].fix,[]);assert.deepEqual(a.evidence[0].affected,['1 to < 2']);
});
test('VEX relationships inherit context; remediations stay product-scoped',()=>{
  const vex={product_tree:{branches:[{name:'Red Hat Enterprise Linux 9',product:{product_id:'platform',name:'kernel'}}],full_product_names:[{product_id:'pkg',name:'kernel-1.2.3'}],relationships:[{product_reference:'pkg',relates_to_product_reference:'platform',full_product_name:{product_id:'combined',name:'fixed kernel'}}]},vulnerabilities:[{cve:'CVE-2024-3094',product_status:{fixed:['combined']},remediations:[{category:'mitigation',product_ids:['combined'],details:'Disable feature'},{category:'mitigation',product_ids:['other'],details:'Unrelated'}]}]};
  const a=assess(record([]),p,vex);assert.equal(a.status,'fixed');assert.deepEqual(a.evidence[0].mitigation,['Disable feature']);assert.equal(a.evidence[0].fix.length,1);
  assert.equal(assess({...record([]),cveMetadata:{cveId:'CVE-2025-1234'}},p,vex).status,'unknown');
});
test('affected evidence wins over a fixed component',()=>{
  const vex={vulnerabilities:[{cve:'CVE-2024-3094',product_status:{fixed:['red_hat_enterprise_linux_9:kernel']}}]};
  assert.equal(assess(record([{product:'Red Hat Enterprise Linux 9',versions:[{version:'1',status:'affected'}]}]),p,vex).status,'affected');
});
test('missing metrics and identifiers',()=>{
  assert.equal(summary(null).score,undefined);assert.equal(validId('CVE-2024-3094'),true);assert.equal(validId('CVE-2024-<script>'),false);
});
