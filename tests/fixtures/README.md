# Test fixtures

Reduced excerpts of public vendor documents, used only as test data. They are not a production cache and are not
kept up to date. Each fixture lists its source, fetch date and license; keep only what a test needs.

`suse-cve-2026-98432.json` is a reduced excerpt of SUSE's [CVE-2026-98432 CSAF/VEX document](https://ftp.suse.com/pub/projects/security/csaf-vex/2026/cve-2026-98432.json), fetched November 3, 2026. It retains selected affected/recommended product relationships, vendor remediations and document metadata. Unrelated products and references were removed. Provided by SUSE under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); this excerpt is modified for testing.

`vendor-CVE-2026-98432.json` contains selected normalized entries from [Red Hat's CVE-2026-98432 VEX document](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-98432.json), fetched November 3, 2026. Most entries and metadata were removed. Provided by Red Hat Inc. under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); this fixture is a modified, reduced representation for testing, not a production cache.

`backend/fixtures/ksp-kernels.html` is a heavily reduced excerpt of Trend Micro's [Deep Security 20.0 Supported Linux Kernels](https://files.trendmicro.com/documentation/guides/deep_security/Kernel%20Support/20.0/Deep_Security_20_0_kernels_EN.html) page, fetched November 18, 2026. It keeps the page structure and a handful of kernel and Kernel Support Package rows to test the parser. Trend Micro and Deep Security are trademarks of Trend Micro Incorporated; the excerpt is used for interoperability testing only.
