# 12 — Q90T Reference Device (Tizen 5.5, kernel 4.1.10)

Companion findings from a second, newer device in the same kernel family:
**QN55Q90TAFXZC** (2020 QLED, armv7), Tizen 5.5, firmware
`T-NKMAKUC-REL-202505100505`, live kernel
`Linux 4.1.10 #1 SMP PREEMPT Fri May 9 15:52:43 UTC 2025` (gcc 6.2.1).

Why this device matters: it ships the **same 4.1.10 kernel family as the
MU6290**, but Samsung publishes its full opensource release
(`linux-4.1.10-tizen5.0`) *including* platform defconfigs and the split-out
`tztv-*` driver packages. That enables **source-verified** verdicts where the
MU6290 has only "banner untrusted" range estimates.

## Access model (differences from the MU6290)

| Channel | Q90T state |
|---|---|
| sdb (dev mode) | shell channel dead; `sdb push`/`pull` refuse `/proc` and `/usr/bin` paths |
| Command exec | uid-901 "sdk" runner via the SVE-2025-50109 appinstall injection; runs with SMACK label `System` |
| Package install | `pkgcmd` rejects both unsigned *and* q90t-sdk-signed TPKs (`-12`); **Apps2Samsung is the only channel** (passes pre-signed through) |
| App launch | `on-boot` ignored, app-selector rules dropped at install, `app_launcher` wedges sdb/appinstall for minutes; **long-press XF86Exit (3s) key rule is the only working trigger** for sideloaded services |
| UEP | Same SFD-UEP exec gate as doc 03 (RSA-2048 signature on exec/mmap from writable fs; ro-`/` files bypass) |

## Config gates (Kant.M / Kant.M2 / Kant.SU release defconfigs — identical on all decision symbols)

`CONFIG_USER_NS` off, `KALLSYMS` off, `NF_TABLES` off, `IP_DCCP` off,
`PPPOE` off, `TUN` off, `XFRM_USER` off, `AF_RXRPC` off, `HUGETLBFS` off,
`OVERLAY_FS` off, `BINFMT_MISC` off, `DEVMEM` off; `PACKET=y`, `KEYS=y`,
`SMACK=y`, `MODULES=y`, `INET6_AH=m`. armv7 has no `CONFIG_COMPAT`, so the
x_tables compat class (CVE-2021-22555) is dead code even where unpatched.

## Source-verified backports (2025 build)

Dirty COW (`FOLL_COW` in `mm/gup.c`), CVE-2016-8655 (`pg_vec_lock` race fix),
CVE-2017-7308 (`BLK_PLUS_PRIV` check), CVE-2016-0728 (`__key_get` in keyring
lookup). Contrast with doc 07: the MU6290's "Dirty COW = HIGH" is an
unverified range estimate; the Q90T's source shows the fix backported, so
treat the MU6290 banner the same way — its fixes may also be silently in.

## Modern exploit families — all structurally N/A

CopyFail (4.14+), Dirty Frag (xfrm/RxRPC, 2017+), Fragnesia (5.4 espintcp),
RefluXFS (4.9 reflink), Dirty Pipe (5.8 pipe), `copy_file_range` class (4.5),
tc-pedit (5.x refactor), CVE-2024-1086 / CVE-2024-27397 (`NF_TABLES` **not
compiled**), CVE-2026-46333 (4.10), CrackArmor (4.11 + AppArmor-only),
TUNderflow (no OVS), PPPoEject (pattern present in source but `PPPOE` not
compiled), DiagSpill (no `sctp_diag` in tree), DirtyAH6 (AH6 receive-path
module only), PTRACE_TRACEME setuid race (patched since 2007, check present).

## setuid sweep — matches doc 06's shape

`/usr/bin/wasutility` (4755; same AppRecoveryTool — the doc 06 dead-end
verdict carries over), `/usr/lib/dbus/dbus-daemon-launch-helper` (4750
root:dbus — unreachable), `/usr/libexec/gstreamer-1.0/gst-ptp-helper`
(4755, gstreamer 1.12.2 — no file writes, low value). No setgid binaries.

## Driver vulnerabilities — live-verified via a dotnet capp probe TPK

Probe methodology that worked on this firmware: dotnet (tizen60)
`service-application` TPK, Apps2Samsung install, long-press key-rule launch,
dual logging (`/tmp` + `apps_rw/<pkgid>/data/` — the latter survives reboots),
TCP 127.0.0.1:8788 command/result channel read back through the uid-901
runner's bash `/dev/tcp`.

| Surface | Node (perms) | Verdict |
|---|---|---|
| system_drv i2c read/write | `/dev/system` (0666) | Unbounded user-sized kernel-stack VLA (ioctl layout confirmed live, `rc=0`). **DoS only by geometry**: any sweep reaching below the stack page zeroes the caller's own `thread_info` (`task`/`preempt_count`/`addr_limit` together) — the thread dies on its next `current` deref; narrow sweeps stay in free stack. |
| micom ISP upgrade | `/dev/micom-isp` (0666) | `set_fs(KERNEL_DS)` leak exists in the museM/kantm2 upgrade variants — **dead on this build**: the shipped package links the `-def` stub (`RUN_UPGRADE` always `rc=0`; leak detector returns `-1`). |
| tztv-hdmi-sw ext-controls | `/dev/video28` (group video) | `ctrl->string` is dereferenced as a kernel pointer with zero validation (verified: kernel address accepted, `rc=0`). Sentinel-page tests prove **no write primitive** through it; kernel reads land but with no strong exfiltration channel — weak recon only. Control IDs are sequential from `V4L2_CID_DV_CLASS_BASE` (G_EDID=+174; S_FACTORY_ITEM=+150, S_DEPENDENCE=+151 — derived from case order, verified live). |
| hcas RAW-mmap physmap | `/dev/RAW-mmap` | Source-confirmed arbitrary `ioremap`+`remap_pfn_range` — **node absent** on this TV (no tvkey_cma/CAS). |
| eeprom / kfactory / bptime / i2c-* | 0666 | Same as doc 06: eeprom = hardware-write primitive (bounds-checked driver), kfactory = factory-register handshake only, bptime = boot-time-offset spoof, `/dev/i2c-0..10` remain the open driver-audit lane. |

## Open lanes shared with the MU6290

1. **`/dev/i2c-*` adapter-driver audit** (doc 07's remaining candidate) — the
   Q90T has the same world-open nodes plus the full kernel source to audit the
   Tizen-custom i2c controller driver against.
2. Read-oracle reconnaissance (hdmi-sw kernel deref) as an address/state
   verification tool during any future exploit development.
3. system_drv VLA as a controlled reboot-DoS for recovery-behavior tests.
