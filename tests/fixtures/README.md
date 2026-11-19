# Test fixtures

Reduced excerpts of public vendor documents, used only as test data. They are not a production cache and are not
kept up to date. Each fixture lists its source, fetch date and license; keep only what a test needs.

`suse-cve-2026-98432.json` is a reduced excerpt of SUSE's [CVE-2026-98432 CSAF/VEX document](https://ftp.suse.com/pub/projects/security/csaf-vex/2026/cve-2026-98432.json), fetched November 3, 2026. It retains selected affected/recommended product relationships, vendor remediations and document metadata. Unrelated products and references were removed. Provided by SUSE under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); this excerpt is modified for testing.

`vendor-CVE-2026-98432.json` contains selected normalized entries from [Red Hat's CVE-2026-98432 VEX document](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-98432.json), fetched November 3, 2026. Most entries and metadata were removed. Provided by Red Hat Inc. under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); this fixture is a modified, reduced representation for testing, not a production cache.

`backend/fixtures/ksp-kernels.html` is a heavily reduced excerpt of Trend Micro's [Deep Security 20.0 Supported Linux Kernels](https://files.trendmicro.com/documentation/guides/deep_security/Kernel%20Support/20.0/Deep_Security_20_0_kernels_EN.html) page, fetched November 18, 2026. It keeps the page structure and a handful of kernel and Kernel Support Package rows to test the parser. Trend Micro and Deep Security are trademarks of Trend Micro Incorporated; the excerpt is used for interoperability testing only.

`backend/fixtures/redhat-cve-2023-52425.json` and `backend/fixtures/redhat-cve-2024-2511.json` are reduced excerpts of Red Hat's CSAF/VEX documents for [CVE-2023-52425](https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-52425.json) and [CVE-2024-2511](https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-2511.json), fetched November 18, 2026, keeping the "Will not fix" and "Fix deferred" remediations. Provided by Red Hat Inc. under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); modified for testing.

`backend/fixtures/ubuntu-cve-2025-9230.json` is a reduced excerpt of the [Ubuntu CVE tracker entry for CVE-2025-9230](https://ubuntu.com/security/cves/CVE-2025-9230.json), fetched November 18, 2026, keeping release statuses, pockets and notices. Ubuntu is a trademark of Canonical Ltd.; used under Canonical's terms for testing.

`backend/fixtures/debian-tracker-excerpt.json` and `backend/fixtures/debian-advisories-excerpt.txt` are reduced excerpts of the [Debian security tracker JSON](https://security-tracker.debian.org/tracker/data/json) and its [DSA](https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list) and [DLA](https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list) lists, fetched November 18, 2026, used for testing.
