# Sealed measurement platform — `frozen_parameters` row 9

**Every value below is READ FROM THE MACHINE by `src/harness/measurement_platform.py`.** The
Commander's transcription is a **cross-check only**: where the two differ, the machine-read value is
what is sealed and the difference is reported, never reconciled. Row 9 is the only frozen row that is
*read* rather than *chosen*.

Recorded 2026-08-02, immediately before gate **G-3** was adjudicated. ADR 0025:
*any change to row 9 invalidates a G-3 adjudication on the previous platform.*

## Row 9 identity

```
Windows 25H2 build 26200.8875; 12th Gen Intel(R) Core(TM) i7-12700H; 14C/20T (12P/8E logical); 15.75 GiB; power scheme 高性能 (da75b896-eea0-461c-a43a-73a73caf9f43)
```

## Machine-read, field by field

| field | value (machine-read) |
|---|---|
| OS version (4-part) | `10.0.26200.8875` |
| OS build | `26200.8875` |
| `DisplayVersion` | `25H2` |
| registry `ProductName` | `Windows 10 Pro` |
| CPU | `12th Gen Intel(R) Core(TM) i7-12700H` |
| physical cores | `14` |
| logical processors | `20` |
| performance logical CPUs (highest efficiency class) | `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]` |
| efficiency logical CPUs | `[12, 13, 14, 15, 16, 17, 18, 19]` |
| installed RAM | `16911523840` bytes (15.75 GiB) |
| RAM type (SMBIOS) | `DDR4` |
| active power scheme | `高性能` (`da75b896-eea0-461c-a43a-73a73caf9f43`) |
| on AC power | `True` |
| Python | `3.13.5` |

## Cross-check against the Commander's transcription

| field | transcribed | machine-read | |
|---|---|---|---|
| OS build | `10.0.26200.8875` | `10.0.26200.8875` | match |
| DisplayVersion | `25H2` | `25H2` | match |
| CPU | `12th Gen Intel Core i7-12700H` | `12th Gen Intel(R) Core(TM) i7-12700H` | match |
| RAM | `16.0 GB DDR4` | `15.75 GiB DDR4` | **SEE NOTE** |
| Power plan GUID | `da75b896-eea0-461c-a43a-73a73caf9f43` | `da75b896-eea0-461c-a43a-73a73caf9f43` | match |

**One nuance, recorded rather than smoothed:** the registry `ProductName` reads
`Windows 10 Pro` while the build is `26200.8875`. That is a well-known Windows 11 registry
artefact — `ProductName` was never updated from the Windows 10 string — and the **build number is
authoritative**: `26200` is Windows 11. The Commander's *"Windows 11"* and the machine's
`ProductName` disagree, the build settles it, and the sealed identity uses `DisplayVersion` and the
build rather than `ProductName`.

**The power scheme name is localised** (`高性能` = "High performance"). The **GUID** is
what the cross-check matches on, because it is locale-independent.

## Hazard state, as found (EXP8B STEP 4)

| setting | value | note |
|---|---|---|
| sleep after (AC) | `600` s | **NOT off.** Reported as found; **not changed**, because changing the power plan between locking row 9 and adjudicating G-3 is forbidden. Mitigated by keeping the measurement far shorter than this |
| hibernate after (AC) | `0` s | `0` = never |
| USB selective suspend (AC) | `1` | enabled. No USB device is in the measured path — G-3 times signature verification with no effect ledger — so it cannot reach the quantity |

## How the P/E split was DETECTED, not assumed

`GetSystemCpuSetInformation` is walked record by record and each logical processor's
`EfficiencyClass` is read. The performance set is the **highest** class, which is Microsoft's stated
rule rather than an inference. The detection **fails closed**: if the topology cannot be read, no
mask is guessed, because a guessed logical-processor range would silently reintroduce exactly the
scheduler bias the pinning exists to remove.

Observed here: two efficiency classes, `12` performance logical processors and
`8` efficiency ones — consistent with the i7-12700H's 6 P-cores (hyper-threaded)
and 8 E-cores, but **derived from the API, not from that expectation**.
