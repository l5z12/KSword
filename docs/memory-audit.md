# System memory audit

[简体中文](zh-CN/memory-audit.md) · [Documentation index](README.md)

**Memory → System memory audit** explains physical-memory use beyond a sum of
process working sets. It combines installed/usable RAM, resident mappings,
kernel process snapshots, pool tags, and big-pool allocations. Its pool-tag
delta presentation follows the approach used by PoolMonXv3.

## Evidence sources

| View | Source and interpretation |
| --- | --- |
| Installed RAM | `GetPhysicallyInstalledSystemMemory`; the difference from Windows-usable RAM is reported separately as hardware/firmware reserved. |
| Physical boundary | `SystemMemoryUsageInformation`, `GlobalMemoryStatusEx`, and `GetPerformanceInfo` provide usable, available, in-use, and committed quantities. |
| Page states | `SystemMemoryListInformation` separates standby priorities 0–7, free, zeroed, modified, modified-no-write, and bad pages. |
| User resident mappings | A background scan uses `QueryWorkingSet`, `VirtualQueryEx`, and `GetMappedFileNameW` to relate processes, private allocations/images/mapped files/pagefile sections, and backing files. It reports private residency, shareable/actually shared references, and a proportional estimate. |
| Processes | `SystemProcessInformation` supplies private residency, working-set references, private commit, pool quotas, and hard faults. Private residency is additive; shared working sets are not. |
| Pool tags | `SystemPoolTagInformation` supplies paged/nonpaged bytes, outstanding allocations, and snapshot deltas. Installed Debugging Tools' `pooltag.txt` can provide descriptions. |
| Big pool | `SystemBigPoolInformation` supplies address, size, tag, and paged/nonpaged attributes. These allocations are already included in pool totals. |
| Kernel residency | `SystemPerformanceInformation` includes nonpaged pool, resident paged pool, system/driver code, and system cache; newer systems may expose MDL, PFN database, page-table, and contiguous-page evidence. |

The deep user-residency scan runs when opening the page or requesting it manually.
The two-second refresh only collects lightweight system snapshots. Inaccessible,
protected, and exiting processes stay in the coverage denominator; they are not
presented as successfully attributed.

## Shared pages and unattributed memory

A physical page may appear in several processes' working sets and be referenced
by images, mapped files, system cache, or the kernel. The working-set interface's
share count saturates at 7. Proportional attribution is an estimate, not exact
deduplication by PFN.

The page preserves ownership relationships: private pages belong to a process;
image/file pages retain both their process references and backing file. Shared
references are explicitly non-additive. Unobservable ownership stays unattributed
instead of producing a false 100% accounting.

The identified lower bound includes safely additive categories: process private
residency, nonpaged pool, resident paged pool, resident kernel/driver code, and
modified page lists. In-use physical memory minus that lower bound is the
**unattributed in-use remainder**.

The remainder is not automatically an error or leak. It can include shared/image
pages, process/system page tables, kernel stacks, MDL-locked pages, AWE/large pages,
compression, VBS/Hyper-V secure memory, and device-related use. Do not add overlapping
cache, shared working sets, Big Pool, or commit to force the remainder to zero.

## Investigation order

1. Compare in-use and remainder deltas to distinguish growth from a one-time cache change.
2. Deep-scan user residency, sort by private residency or proportional estimate,
   inspect mapping relationships, and check accessible-process coverage.
3. Examine private-residency deltas in the kernel process snapshot, including
   protected processes, System, and compression-related activity.
4. Compare paged/nonpaged/outstanding pool-tag deltas. A tag alone does not prove ownership.
5. Use Big Pool to check whether specific large nonpaged allocations persist.
6. If the remainder keeps growing, collect a WPR/WPA Memory Footprint/Reference Set
   trace for time-dependent causality. Stable R3 snapshots do not identify every PFN's unique owner.

Implementation references include PoolMonXv3, System Informer, MemProcFS, and
Windows Performance Toolkit. This page is read-only: it does not clear standby,
trim working sets, modify pools, or scan/export physical-memory contents.
