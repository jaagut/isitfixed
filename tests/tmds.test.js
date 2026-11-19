import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  kernelSupport,
  supportSummary,
  isKernelFix,
  compareRelease,
  combineStatus,
  productInventory,
  kspName,
} from '../src/tmds.js';

// Bundled Deep Security Agent release for one architecture (Plugin-VFS descriptor names).
const agent = (architecture, kernels, release = '20.0.3-31610') => ({
  release,
  architecture,
  kernels,
  download: `https://files.trendmicro.com/products/deepsecurity/en/20.0/Agent-${release}.${architecture}.zip`,
});
// Kernel Support Package entry: tuples [kernelRelease, flavor, since, partial] as on the KSP page.
const ksp = (platform, architecture, kernels, release = '20.0.3-36500') => ({
  architecture,
  platform,
  release,
  filename: `KernelSupport-${platform}-${release}.${architecture}.zip`,
  download: `https://files.trendmicro.com/products/deepsecurity/en/20.0/KernelSupport-${platform}-${release}.${architecture}.zip`,
  kernels,
});
const statuses = (t) => t.branches.map((b) => [b.fix, b.status]);
const cell = (t, i, arch = 'x86_64') => t.branches[i].cells.find((c) => c.arch === arch);

test('kernel fixes exclude firmware and tools', () => {
  assert.ok(isKernelFix('kernel-5.14.0-427.13.1.el9_4'));
  assert.ok(isKernelFix('linux 6.12.113-1'));
  assert.ok(isKernelFix('linux-aws 5.15.0-1070.76'));
  assert.ok(isKernelFix('kernel-default-6.4.0-150700.53.31.1'));
  assert.ok(!isKernelFix('linux-firmware 20220329.git681281e4-0ubuntu3.36'));
  assert.ok(!isKernelFix('bpftool-7.3.0-427.13.1.el9_4'));
});

test('release strings compare numerically', () => {
  assert.ok(compareRelease('20.0.3-36500', '20.0.3-9999') > 0);
  assert.ok(compareRelease('20.0.1-24160', '20.0.3-100') < 0);
  assert.equal(compareRelease('20.0.3-36500', '20.0.3-36500'), 0);
  assert.equal(combineStatus(['supported', 'nodata']), 'supported');
  assert.equal(combineStatus(['supported', 'pending']), 'partial');
  assert.equal(combineStatus(['unknown', 'pending']), 'pending');
  assert.equal(combineStatus(['nodata']), 'nodata');
});

test('RHEL 9: bundled agent and KSP each evaluate the same minor stream', () => {
  const inventory = {
    releases: [agent('x86_64', ['5_14_0_427_13_1_el9_4_x86_64', '5_14_0_687_70_1_el9_8_x86_64'])],
    ksp: [
      ksp('RedHat_EL9', 'x86_64', [
        ['5.14.0-427.13.1.el9_4.x86_64', 'default', '20.0.3-36000', false],
        ['5.14.0-427.20.1.el9_4.x86_64', 'default', '20.0.3-36200', false],
        ['5.14.0-687.64.1.el9_8.x86_64', 'default', null, false],
        ['5.14.0-284.18.1.el9_2.cloud.x86_64', 'cloud', null, false],
      ]),
    ],
  };
  const t = kernelSupport('rhel', ['kernel-5.14.0-427.13.1.el9_4', 'kernel-5.14.0-687.64.1.el9_8'], inventory);
  assert.equal(t.status, 'supported');
  assert.deepEqual(statuses(t), [
    ['5.14.0-427.13.1.el9_4', 'supported'],
    ['5.14.0-687.64.1.el9_8', 'supported'],
  ]);
  const first = cell(t, 0);
  assert.equal(first.agent.status, 'supported');
  assert.equal(first.agent.exact, true);
  assert.equal(first.agent.release.release, '20.0.3-31610');
  assert.equal(first.ksp.kernel, '5.14.0-427.13.1.el9_4.x86_64');
  assert.equal(first.ksp.since, '20.0.3-36000');
  const second = cell(t, 1);
  assert.equal(second.agent.exact, false);
  assert.equal(second.agent.kernel, '5.14.0-687.70.1.el9_8');
  assert.equal(second.ksp.since, null, 'listed when first observed: only "current KSP or earlier" is known');
  assert.equal(t.ksp.release, null);
  assert.equal(t.ksp.current, '20.0.3-36500');
  assert.equal(supportSummary(t), 'KSP 20.0.3-36500 · Agent 20.0.3-31610');
});

test('RHEL 9: a newer stream is "not yet" for the agent while the KSP already lists it', () => {
  const inventory = {
    releases: [agent('x86_64', ['5_14_0_687_70_1_el9_8_x86_64'])],
    ksp: [
      ksp('RedHat_EL9', 'x86_64', [
        ['5.14.0-741.14.1.el9_9.x86_64', 'default', '20.0.3-36400', false],
        ['5.14.0-741.22.1.el9_9.x86_64', 'default', '20.0.3-36500', false],
      ]),
    ],
  };
  const t = kernelSupport('rhel', ['kernel-5.14.0-741.20.1.el9_9', 'kernel-core-5.14.0-741.20.1.el9_9'], inventory);
  assert.equal(t.status, 'supported');
  assert.equal(cell(t, 0).agent.status, 'pending');
  assert.equal(cell(t, 0).agent.kernel, '5.14.0-687.70.1.el9_8', 'newest bundled kernel of RHEL 9');
  assert.equal(cell(t, 0).ksp.kernel, '5.14.0-741.22.1.el9_9.x86_64');
  assert.equal(t.ksp.release, '20.0.3-36500', 'minimum KSP that lists a kernel >= the fix');
  assert.equal(supportSummary(t), 'KSP 20.0.3-36500 · Agent not yet');
});

test('RHEL 8 and 10: EUS streams stay separate, GA names without a minor parse, Δ is partial', () => {
  const rhel8 = kernelSupport('rhel', ['kernel-4.18.0-553.186.1.el8_10', 'kernel-4.18.0-372.137.1.el8_6'], {
    releases: [agent('x86_64', ['4_18_0_553_100_1_el8_10_x86_64', '4_18_0_80_el8_x86_64'])],
    ksp: [
      ksp('RedHat_EL8', 'x86_64', [
        ['4.18.0-80.el8.x86_64', 'default', null, false],
        ['4.18.0-553.186.1.el8_10.x86_64', 'default', '20.0.3-36500', false],
        ['4.18.0-553.147.1.el8_10.cloud.0.1.x86_64', 'cloud', null, false],
      ]),
    ],
  });
  assert.deepEqual(statuses(rhel8), [
    ['4.18.0-553.186.1.el8_10', 'supported'],
    ['4.18.0-372.137.1.el8_6', 'unknown'],
  ]);
  assert.equal(rhel8.status, 'partial');
  const rhel10 = kernelSupport('rhel', ['kernel-6.12.0-211.20.1.el10_2'], {
    releases: [],
    ksp: [
      ksp('RedHat_EL10', 'x86_64', [
        ['6.12.0-211.18.1.el10_2.x86_64', 'default', '20.0.3-36400', true],
        ['6.12.0-211.22.1.el10_2.x86_64', 'default', '20.0.3-36500', true],
      ]),
      ksp('RedHat_EL10', 'aarch64', [['6.12.0-211.22.1.el10_2.aarch64', 'default', '20.0.3-36480', false]]),
    ],
  });
  assert.equal(rhel10.status, 'partial', 'status is for x86_64, where only Δ (WRS/FW/IPS) support exists');
  assert.equal(cell(rhel10, 0).ksp.partial, true);
  assert.equal(cell(rhel10, 0, 'aarch64').ksp.status, 'supported');
  assert.equal(rhel10.agent.status, 'nodata');
  assert.equal(supportSummary(rhel10), 'KSP Δ 20.0.3-36500 · Agent no data');
});

test('SLES 15: drops the rebuild counter, keeps azure and default apart, flavour from any name segment', () => {
  const inventory = {
    releases: [agent('x86_64', ['5_14_21_150500_55_195_default', '5_14_21_150500_33_60_azure'])],
    ksp: [
      ksp('SuSE_15', 'x86_64', [
        ['5.14.21-150500.55.195-default', 'default', '20.0.3-36100', false],
        ['5.14.21-150500.33.69-azure', 'azure', null, false],
        ['5.14.21-150500.33.72-azure', 'azure', '20.0.3-36300', false],
        ['4.12.14-25.13-default', 'default', null, false],
      ]),
    ],
  };
  const t = kernelSupport(
    'sles',
    [
      'kernel-default-5.14.21-150500.55.195.1',
      'kernel-default-base-5.14.21-150500.55.195.1.150500.6.89.1',
      'kernel-devel-azure-5.14.21-150500.33.72.1',
      'kernel-azure-5.14.21-150500.33.72.1',
    ],
    inventory,
  );
  assert.deepEqual(statuses(t), [
    ['5.14.21-150500.55.195-default', 'supported'],
    ['5.14.21-150500.33.72-azure', 'supported'],
  ]);
  assert.equal(cell(t, 1).agent.status, 'pending', 'bundled azure kernel is older');
  assert.equal(cell(t, 1).ksp.since, '20.0.3-36300');
  assert.equal(t.agent.status, 'partial');
  assert.equal(t.ksp.release, '20.0.3-36300');
});

test('SLES and RHEL: preempt, rt, 64kb and other flavours match only kernels of the same flavour', () => {
  const sles = {
    releases: [agent('x86_64', ['5_3_18_150300_59_158_preempt', '5_3_18_150300_59_226_default'])],
    ksp: [
      ksp('SuSE_15', 'x86_64', [
        ['5.3.18-150300.59.230-default', 'default', '20.0.3-36500', false],
        ['5.3.18-150300.59.230-azure', 'azure', '20.0.3-36500', false],
      ]),
      ksp('SuSE_15', 'aarch64', [['6.4.0-150600.23.70-64kb', '64kb', '20.0.3-36500', false]]),
    ],
  };
  const preempt = kernelSupport('sles', ['kernel-preempt-5.3.18-150300.59.200.1'], sles);
  assert.deepEqual(statuses(preempt), [['5.3.18-150300.59.200-preempt', 'pending']]);
  assert.equal(cell(preempt, 0).agent.kernel, '5.3.18-150300.59.158-preempt');
  assert.equal(cell(preempt, 0).ksp.status, 'unknown', 'a newer default kernel does not cover preempt');
  // Flavours Trend Micro lists nowhere stay out instead of borrowing the default kernel.
  assert.equal(kernelSupport('sles', ['kernel-rt-5.3.18-150300.59.200.1'], sles).status, 'none');
  assert.equal(kernelSupport('sles', ['kernel-zfcpdump-5.3.18-150300.59.200.1'], sles).status, 'none');
  const arm = kernelSupport('sles', ['kernel-64kb-6.4.0-150600.23.70.1', 'kernel-default-6.4.0-150600.23.70.1'], sles);
  assert.equal(cell(arm, 0, 'aarch64').ksp.kernel, '6.4.0-150600.23.70-64kb');
  assert.equal(cell(arm, 1, 'aarch64').ksp.status, 'unknown', 'default is not covered by a 64kb kernel');
  const rhel = {
    ksp: [
      ksp('RedHat_EL9', 'x86_64', [
        ['5.14.0-427.20.1.el9_4.x86_64', 'default', null, false],
        ['5.14.0-427.13.1.el9_4.x86_64+rt', 'rt', null, false],
      ]),
    ],
  };
  const rt = kernelSupport('rhel', ['kernel-rt-5.14.0-427.18.1.el9_4', 'kernel-rt-core-5.14.0-427.18.1.el9_4'], rhel);
  assert.deepEqual(statuses(rt), [['5.14.0-427.18.1.el9_4+rt', 'pending']]);
  assert.equal(cell(rt, 0).ksp.kernel, '5.14.0-427.13.1.el9_4.x86_64+rt');
  assert.equal(kernelSupport('rhel', ['kernel-64k-5.14.0-427.18.1.el9_4'], rhel).status, 'none');
  assert.equal(kernelSupport('rhel', ['kernel-core-5.14.0-427.18.1.el9_4'], rhel).status, 'supported');
});

test('SLES 15 SP7 and 16: a newer service pack is "not yet"; an old unlisted one is unknown', () => {
  const sp7 = kernelSupport('sles', ['kernel-default-6.4.0-150700.53.34.1'], {
    releases: [agent('x86_64', ['6_4_0_150600_23_70_default'])],
    ksp: [ksp('SuSE_15', 'x86_64', [['6.4.0-150700.53.31-default', 'default', '20.0.3-36500', false]])],
  });
  assert.equal(sp7.status, 'pending');
  assert.equal(cell(sp7, 0).agent.kernel, '6.4.0-150600.23.70-default');
  assert.equal(cell(sp7, 0).ksp.kernel, '6.4.0-150700.53.31-default');
  assert.equal(supportSummary(sp7), 'KSP not yet · Agent not yet');
  const sp2 = kernelSupport('sles', ['kernel-default-5.3.18-150200.24.178.1'], {
    releases: [],
    ksp: [ksp('SuSE_15', 'aarch64', [['6.4.0-150700.53.31-default', 'default', null, false]])],
  });
  assert.equal(sp2.status, 'unknown');
  const sles16 = kernelSupport('sles', ['kernel-default-6.12.0-160000.5.1', 'kernel-64kb-6.12.0-160000.5.1'], {
    releases: [agent('x86_64', ['6_12_0_160000_27_default'])],
    ksp: [ksp('SuSE_16', 'x86_64', [['6.12.0-160000.5-default', 'default', '20.0.3-36450', false]])],
  });
  assert.equal(sles16.status, 'supported');
  assert.equal(cell(sles16, 0).ksp.exact, true);
  assert.equal(supportSummary(sles16), 'KSP 20.0.3-36450 · Agent 20.0.3-31610');
});

test('Ubuntu 22.04: package versions map to ABI names; cloud flavours (ABI >= 1000) stay apart', () => {
  const inventory = {
    releases: [agent('x86_64', ['5_15_0_130_generic', '5_15_0_1060_aws', '5_15_0_1056_aws_fips'])],
    ksp: [
      ksp('Ubuntu_22.04', 'x86_64', [
        ['5.15.0-130-generic', 'generic', '20.0.3-36000', false],
        ['5.15.0-1070-aws', 'aws', '20.0.3-36450', false],
        ['5.15.0-145-fips', 'fips', null, false],
      ]),
    ],
  };
  const t = kernelSupport(
    'ubuntu',
    [
      'linux 5.15.0-130.140',
      'linux-aws 5.15.0-1070.76',
      'linux-aws-fips 5.15.0-1056.61+fips1',
      'linux-fips 5.15.0-145.155+fips1',
      'linux-hwe-6.8 6.8.0-90.91~22.04.1',
    ],
    inventory,
  );
  assert.deepEqual(statuses(t), [
    ['5.15.0-130-generic', 'supported'],
    ['5.15.0-1070-aws', 'supported'],
    ['5.15.0-1056-aws-fips', 'supported'],
    ['5.15.0-145-fips', 'supported'],
    ['6.8.0-90-generic', 'pending'],
  ]);
  assert.equal(cell(t, 1).agent.status, 'pending', 'bundled aws kernel 1060 < 1070');
  assert.equal(cell(t, 1).ksp.kernel, '5.15.0-1070-aws');
  assert.equal(cell(t, 2).ksp.status, 'unknown', 'aws-fips is not the aws flavour');
  assert.equal(cell(t, 4).agent.kernel, '5.15.0-130-generic', 'HWE 6.8 is newer than every listed generic kernel');
  assert.equal(t.status, 'partial');
});

test('Ubuntu 24.04: azure and nvidia cloud kernels; unlisted flavours are left out', () => {
  const inventory = {
    releases: [agent('x86_64', ['6_8_0_90_generic'])],
    ksp: [
      ksp('Ubuntu_24.04', 'x86_64', [
        ['6.8.0-1056-azure', 'azure', null, false],
        ['7.0.0-1020-azure', 'azure', '20.0.3-36500', false],
        ['7.0.0-1025-nvidia', 'nvidia', '20.0.3-36480', false],
      ]),
    ],
  };
  const t = kernelSupport(
    'ubuntu',
    ['linux-azure 6.8.0-1050.56', 'linux-nvidia-7.0 7.0.0-1025.25', 'linux-raspi 6.8.0-1030.34'],
    inventory,
  );
  assert.deepEqual(statuses(t), [
    ['6.8.0-1050-azure', 'supported'],
    ['7.0.0-1025-nvidia', 'supported'],
  ]);
  assert.equal(cell(t, 0).ksp.exact, false);
  assert.equal(t.ksp.release, null, 'one qualifying kernel has an unknown first KSP');
  assert.equal(supportSummary(t), 'KSP 20.0.3-36500 · Agent unverified');
  assert.equal(kernelSupport('ubuntu', ['linux-raspi-realtime 6.8.0-2001.1'], inventory).status, 'none');
});

test('Debian 13: kernels match the fix only within its upstream series (backports are other series)', () => {
  const inventory = {
    releases: [agent('x86_64', ['6_12_100+deb13_amd64', '6_12_100+deb13_cloud_amd64', '6_12_74+deb13+1_amd64'])],
    ksp: [
      ksp('Debian_13', 'x86_64', [
        ['6.12.38+deb13-amd64', 'default', null, false],
        ['6.12.41+deb13-cloud-amd64', 'cloud', null, false],
        // trixie-backports kernels carry +deb13 too.
        ['6.16.3+deb13-amd64', 'default', '20.0.3-36400', false],
        ['7.1.13+deb13-amd64', 'default', '20.0.3-36500', false],
      ]),
    ],
  };
  const t = kernelSupport('debian', ['linux 6.12.113-1'], inventory);
  assert.equal(cell(t, 0).agent.status, 'pending');
  assert.equal(cell(t, 0).agent.kernel, '6.12.100+deb13-amd64');
  assert.equal(cell(t, 0).ksp.status, 'pending', 'a 6.16 or 7.1 backport kernel says nothing about 6.12');
  assert.equal(cell(t, 0).ksp.kernel, '6.12.38+deb13-amd64');
  assert.equal(t.status, 'pending');
  const listed = kernelSupport('debian', ['linux 6.12.38-1'], inventory);
  assert.equal(listed.status, 'supported');
  assert.equal(cell(listed, 0).ksp.exact, true);
  assert.equal(cell(listed, 0).agent.kernel, '6.12.74+deb13+1-amd64');
  // Fixed before the release: every kernel of trixie's 6.12 series is a later version of `linux`.
  const old = kernelSupport('debian', ['linux 6.6.15-1'], inventory);
  assert.equal(old.status, 'supported');
  assert.equal(cell(old, 0).ksp.kernel, '6.12.38+deb13-amd64');
  assert.equal(cell(old, 0).agent.exact, false);
});

test('Debian: a fix in a later revision of a listed upstream version is not verifiable', () => {
  const inventory = {
    releases: [],
    ksp: [
      ksp('Debian_13', 'x86_64', [
        ['6.12.90+deb13-amd64', 'default', null, false],
        ['6.12.90+deb13.1-amd64', 'default', null, false],
        ['6.12.94+deb13-amd64', 'default', '20.0.3-36500', false],
      ]),
    ],
  };
  // The first upload of 6.12.90 is 6.12.90+deb13; a respin is newer than it.
  const first = kernelSupport('debian', ['linux 6.12.90-1'], inventory);
  assert.equal(cell(first, 0).ksp.exact, true);
  // 6.12.90-2 may or may not be the +deb13.1 respin: unverifiable, never an exact match.
  const only = { releases: [], ksp: [ksp('Debian_13', 'x86_64', inventory.ksp[0].kernels.slice(0, 2))] };
  const respin = kernelSupport('debian', ['linux 6.12.90-2'], only);
  assert.equal(respin.status, 'unknown');
  assert.equal(cell(respin, 0).ksp.revision, true);
  assert.equal(cell(respin, 0).ksp.kernel, '6.12.90+deb13.1-amd64');
  // A newer upstream version is a later version of the package either way.
  const newer = kernelSupport('debian', ['linux 6.12.90-2'], inventory);
  assert.equal(newer.status, 'supported');
  assert.equal(cell(newer, 0).ksp.kernel, '6.12.94+deb13-amd64');
  assert.equal(cell(newer, 0).ksp.exact, false);
  // bookworm's linux-6.12: ~deb12u1 is the first upload, ~deb12u2 a later revision.
  const bookworm = {
    releases: [],
    ksp: [ksp('Debian_12', 'x86_64', [['6.12.90+deb12-amd64', 'default', null, false]])],
  };
  assert.equal(kernelSupport('debian', ['linux-6.12 6.12.90-1~deb12u1'], bookworm).status, 'supported');
  assert.equal(kernelSupport('debian', ['linux-6.12 6.12.90-1~deb12u2'], bookworm).status, 'unknown');
});

test('Debian 12: ABI-named kernels are not verifiable; linux-6.12 and backports are separate', () => {
  const inventory = {
    releases: [agent('x86_64', ['6_1_0_44_amd64', '6_10_11+bpo_amd64', '6_12_90+deb12_1_amd64'])],
    ksp: [
      ksp('Debian_12', 'x86_64', [
        ['6.1.0-9-amd64', 'default', null, false],
        ['6.1.0-44-cloud-amd64', 'cloud', null, false],
        ['6.12.90+deb12.1-cloud-amd64', 'cloud', null, false],
        ['6.12.117+deb12-amd64', 'default', '20.0.3-36500', false],
      ]),
    ],
  };
  assert.equal(kernelSupport('debian', ['linux 6.1.190-1'], inventory).status, 'unknown');
  const t = kernelSupport('debian', ['linux 6.1.190-1', 'linux-6.12 6.12.113-1~deb12u1'], inventory);
  assert.deepEqual(statuses(t), [
    ['linux 6.1.190-1', 'unknown'],
    ['linux-6.12 6.12.113-1~deb12u1', 'supported'],
  ]);
  assert.equal(cell(t, 1).agent.status, 'pending', 'bundled 6.12.90+deb12.1 is older');
  assert.equal(cell(t, 1).ksp.kernel, '6.12.117+deb12-amd64');
  assert.equal(t.status, 'partial');
});

test('the earliest bundling agent release is chosen; only x86_64 drives the status', () => {
  const t = kernelSupport('rhel', ['kernel-5.14.0-427.13.1.el9_4'], {
    releases: [
      agent('x86_64', ['5_14_0_427_13_1_el9_4_x86_64'], '20.0.3-31610'),
      agent('x86_64', ['5_14_0_427_13_1_el9_4_x86_64'], '20.0.3-30990'),
      agent('s390x', ['5_14_0_427_10_1_el9_4_s390x']),
    ],
  });
  assert.equal(cell(t, 0).agent.release.release, '20.0.3-30990');
  assert.equal(cell(t, 0, 's390x').agent.status, 'pending');
  assert.equal(t.status, 'supported');
  assert.deepEqual(t.arches, ['x86_64', 's390x']);
});

test('missing inventory and unknown families', () => {
  const none = kernelSupport('rhel', ['kernel-5.14.0-427.13.1.el9_4'], {});
  assert.equal(none.status, 'unknown');
  assert.equal(supportSummary(none), 'KSP no data · Agent no data');
  assert.equal(kernelSupport('alpine', ['linux-lts 6.12.1-r0']).status, 'unknown');
  assert.deepEqual(productInventory({ products: { rhel9: [1] }, ksp: { products: { rhel9: [2] } } }, 'rhel9'), {
    releases: [1],
    ksp: [2],
  });
  assert.deepEqual(productInventory({ enabled: false }, 'rhel9'), { releases: [], ksp: [] });
  assert.equal(
    kspName({ filename: 'KernelSupport-RedHat_EL9-20.0.3-36500.x86_64.zip' }),
    'KernelSupport-RedHat_EL9-20.0.3-36500',
  );
});
