import {test} from 'node:test';
import assert from 'node:assert/strict';
import {hasCaseUpdate,recordUpdate,markCaseRead,sortedCases} from '../src/cases.js';
test('a changed case moves to the top with a persistent unread indicator',()=>{
  const state={cases:[{id:'CVE-2026-2222',created:20},{id:'CVE-2026-1111',created:10}],activity:[]};
  recordUpdate(state,'CVE-2026-1111','Fix published',30);
  const restored=JSON.parse(JSON.stringify(state));
  assert.equal(sortedCases(restored)[0].id,'CVE-2026-1111');
  assert.equal(hasCaseUpdate(restored,restored.cases[1]),true);
  assert.equal(hasCaseUpdate(restored,restored.cases[0]),false);
  markCaseRead(restored,'CVE-2026-1111');
  assert.equal(hasCaseUpdate(restored,restored.cases[1]),false);
  assert.equal(sortedCases(restored)[0].id,'CVE-2026-1111');
  recordUpdate(restored,'CVE-2026-2222','New evidence',40);
  assert.equal(sortedCases(restored)[0].id,'CVE-2026-2222');
});
test('legacy unread activity gets a sidebar indicator and opening clears only that case',()=>{
  const state={cases:[{id:'CVE-2026-1111'},{id:'CVE-2026-2222'}],activity:[{id:'CVE-2026-1111',time:10,unread:true},{id:'CVE-2026-2222',time:5,unread:true}]};
  assert.ok(hasCaseUpdate(state,state.cases[0]));
  markCaseRead(state,'CVE-2026-1111');
  assert.equal(hasCaseUpdate(state,state.cases[0]),false);
  assert.ok(hasCaseUpdate(state,state.cases[1]));
});
