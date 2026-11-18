# Trend Micro Deep Security Agent matching

Deep Security Agent (TMDS) on Linux loads kernel-specific modules. After a kernel fix, the question is whether the agent
supports the fixed kernel yet. CVE Desk answers this from two public Trend Micro sources, both checked hourly.

TMDS support can be hidden per user in **Settings** (no TMDS elements are shown and `/api/tmds` is not fetched) and
disabled per server with `TMDS_ENABLED=false` (no inventory jobs run).

## Bundled agent kernels

- Source: the Deep Security download center feed (`products_lts.json`).
- For each supported OS and architecture stream (RHEL 8/9/10, SLES 15/16, Debian 12/13, Ubuntu 20.04/22.04/24.04/26.04)
  the latest enabled LTS 20 agent ZIP is downloaded, its published SHA-256 checksum is verified, and the names of the
  bundled `Plugin-VFS_Filter_<kernel>` descriptors are recorded.
- Archives are inspected in memory. They are never executed, never extracted to disk and not kept; downloads are
  limited in size. Only release metadata, checksums, source URLs and descriptor names are stored.
- Releases that are already known are not downloaded again. Initial discovery starts with the current release per stream
  and does not backfill historical releases; it may take several minutes after the first start.
- Superseded releases expire 10 days after they were last current; current releases are kept.

## Kernel Support Packages (KSP)

- Source: Trend Micro's "Deep Security 20 supported kernels" page.
- Kernels are recorded per product, architecture and flavor column (for example RHEL `default`/`cloud`, SLES
  `default`/`azure`, Ubuntu `generic`/`aws`/`azure`/`gcp`, Debian `default`/`cloud`).
- **Partial (Δ):** the page marks some kernels as supported only for Web Reputation, Firewall and Intrusion Prevention
  in the latest KSP. These are shown as partial support.
- **Since:** the KSP release that was current when this server first saw a kernel listed. Kernels that were already
  listed the first time the server looked at a platform have no known first release; they are shown as "current KSP or
  earlier". A new instance therefore starts without this history.
- Notes from the page (for example minimum Deep Security Manager and Agent versions) are shown with the data.

## How a fix is matched

Vendor package versions and kernel release names use different schemes, so each vendor has a parser that maps both to a
kernel branch and build number:

| Vendor | Fixed package example                    | Kernel name example             |
| ------ | ---------------------------------------- | ------------------------------- |
| RHEL   | `kernel-5.14.0-570.12.1.el9_6`           | `5.14.0-570.12.1.el9_6.x86_64`  |
| SLES   | `kernel-default-5.14.21-150500.55.195.1` | `5.14.21-150500.55.195-default` |
| Ubuntu | `linux 5.15.0-130.140`                   | `5.15.0-130-generic`            |
| Debian | `linux 6.12.38-1`                        | `6.12.38+deb13-amd64`           |

A listed kernel of the same branch with an equal or newer build counts as support for the fix. Cases show per branch
whether support is listed, still pending (only older kernels of that branch are listed) or unknown.

## Limits

- This compares names in Trend Micro's published lists. It is not a runtime certification and says nothing about an
  installed agent, its configuration or the Deep Security Manager version.
- A missing match is **unverified**, not unsupported. Kernel flavors that TMDS does not cover (for example `rt` or
  `raspi`) are left out.
- Debian kernels are matched only for the 6.12+ naming scheme, which carries the upstream version.
- Trend Micro can change the feed or page format at any time; on failure the last good data is kept and an error is
  shown.

Deep Security and Trend Micro are trademarks of Trend Micro Incorporated. CVE Desk is not affiliated with or endorsed by
Trend Micro; see [trademarks.md](trademarks.md).
