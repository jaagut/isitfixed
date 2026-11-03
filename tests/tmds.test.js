import {test} from 'node:test';
import assert from 'node:assert/strict';
import {tmdsSupport,isKernelFix} from '../src/data.js';
const agent=(architecture,kernels)=>({release:'20.0.3-28120',architecture,kernels,download:'https://files.trendmicro.com/x.zip'});
test('kernel fixes exclude firmware and tools',()=>{
  assert.ok(isKernelFix('kernel-5.14.0-427.13.1.el9_4'));assert.ok(isKernelFix('linux 6.12.113-1'));assert.ok(isKernelFix('linux-aws 5.15.0-1070.76'));
  assert.ok(!isKernelFix('linux-firmware 20220329.git681281e4-0ubuntu3.36'));assert.ok(!isKernelFix('bpftool-7.3.0-427.13.1.el9_4'));
});
test('RHEL: exact or newer kernel of the same minor stream supports the fix',()=>{
  const r=[agent('x86_64',['5_14_0_427_13_1_el9_4_x86_64','5_14_0_687_70_1_el9_8_x86_64'])];
  const t=tmdsSupport('rhel',['kernel-5.14.0-427.13.1.el9_4','kernel-5.14.0-687.64.1.el9_8'],r);
  assert.equal(t.status,'supported');assert.equal(t.branches[0].exact,true);
  assert.equal(t.branches[1].exact,false);assert.equal(t.branches[1].kernel,'5.14.0-687.70.1.el9_8');
  // A newer minor release does not cover an EUS stream fix.
  assert.equal(tmdsSupport('rhel',['kernel-5.14.0-427.50.1.el9_4'],r).status,'pending');
});
test('SUSE drops the rebuild counter and keeps flavours apart',()=>{
  const r=[agent('x86_64',['5_14_21_150500_55_195_default','5_14_21_150500_33_60_azure'])];
  const t=tmdsSupport('sles',['kernel-default-5.14.21-150500.55.195.1','kernel-azure-5.14.21-150500.33.72.1'],r);
  assert.deepEqual(t.branches.map(b=>b.status),['supported','pending']);assert.equal(t.status,'partial');
});
test('Ubuntu maps package versions to ABI and separates cloud kernels',()=>{
  const r=[agent('x86_64',['5_15_0_130_generic','5_15_0_1060_aws'])];
  const t=tmdsSupport('ubuntu',['linux 5.15.0-130.140','linux-aws 5.15.0-1070.76'],r);
  assert.deepEqual(t.branches.map(b=>[b.fix,b.status]),[['5.15.0-130','supported'],['5.15.0-1070-aws','pending']]);
});
test('Debian 6.12+ matches upstream versions; ABI-named kernels are not verifiable',()=>{
  const r=[agent('x86_64',['6_12_113+deb13_amd64','6_1_0_44_amd64'])];
  assert.equal(tmdsSupport('debian',['linux 6.12.113-1'],r).status,'supported');
  assert.equal(tmdsSupport('debian',['linux 6.1.190-1'],r).status,'unknown');
  assert.equal(tmdsSupport('debian',['linux 6.1.190-1','linux-6.12 6.12.113-1~deb12u1'],r).status,'partial');
});
test('flavours TMDS does not bundle are ignored',()=>{
  const r=[agent('x86_64',['5_15_0_130_generic'])];
  assert.equal(tmdsSupport('ubuntu',['linux 5.15.0-130.140','linux-raspi 5.15.0-1049.52'],r).status,'supported');
  assert.equal(tmdsSupport('ubuntu',['linux-raspi-realtime 6.8.0-2001.1'],r).status,'none');
});
