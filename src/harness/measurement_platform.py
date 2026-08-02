"""The sealed measurement platform, **read from the machine** (`frozen_parameters` row 9).

Row 9 is the last open frozen row and it is the only one that is **read rather
than chosen**: ADR 0014 binds the campaign to Windows, and ADR 0025 requires the
G-3 adjudication to happen on a platform identified exactly, because *"any
change to row 9 invalidates a G-3 adjudication on the previous platform."*

**Every value here comes from the machine.** A transcription is a cross-check,
never the source: a mismatch between what the machine says and what a human
wrote down is **reported, not reconciled**, and the machine-read value is what
gets sealed.

**Why this module exists at all rather than a shell one-liner.** The measurement
this platform carries is taken on a **hybrid-architecture laptop**, and two of
its properties would *bias* a timing result rather than merely add noise:

1. **P-core / E-core scheduling.** The i7-12700H has performance and efficiency
   cores and Windows Thread Director moves threads between them. Repetitions
   landing on an E-core are substantially slower, so the distribution goes
   **bimodal and its spread is the scheduler's, not the mechanism's** — which
   §E.5's p95 and IQR would then report as the mechanism's. `performance_cpus()`
   detects the efficiency class through `GetSystemCpuSetInformation` and **fails
   closed** if it cannot: a guessed mask would silently reintroduce exactly the
   bias it exists to remove.
2. **AC versus battery.** A laptop on battery throttles whatever the power plan
   says. `require_ac_power()` refuses rather than measuring.

Nothing here times anything. It identifies and constrains the machine; the
measurement is `smoke/g3/`'s.
"""

import ctypes
import os
import platform
import re
import subprocess
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Any

WINDOWS = os.name == "nt"


class PlatformError(Exception):
    """The platform could not be identified or constrained. Always fail closed:
    a measurement on an unidentified platform cannot be sealed under row 9."""


# ---------------------------------------------------------------------------
# CPU sets — the efficiency class, DETECTED
# ---------------------------------------------------------------------------
class _CPU_SET_INFORMATION(ctypes.Structure):
    """`SYSTEM_CPU_SET_INFORMATION`, the `CpuSet` arm of its union.

    Laid out to match the Win32 header exactly; `Size` lets the caller walk the
    buffer without assuming a fixed record length, which is how the API is
    documented to be consumed and what keeps this correct if a future Windows
    grows the structure.
    """

    _fields_ = [
        ("Size", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("Id", wintypes.DWORD),
        ("Group", wintypes.WORD),
        ("LogicalProcessorIndex", ctypes.c_ubyte),
        ("CoreIndex", ctypes.c_ubyte),
        ("LastLevelCacheIndex", ctypes.c_ubyte),
        ("NumaNodeIndex", ctypes.c_ubyte),
        ("EfficiencyClass", ctypes.c_ubyte),
        ("AllFlags", ctypes.c_ubyte),
        ("Reserved", wintypes.DWORD),
        ("AllocationTag", ctypes.c_ulonglong),
    ]


_CPU_SET_INFORMATION_TYPE = 0  # `CpuSetInformation`


@dataclass(frozen=True)
class CpuTopology:
    """What the scheduler sees, per logical processor."""

    logical: tuple[int, ...]
    efficiency_class: dict[int, int]

    @property
    def classes(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.efficiency_class.values())))

    @property
    def performance(self) -> tuple[int, ...]:
        """The logical processors in the **highest** efficiency class.

        Microsoft's rule, not an inference: *a higher `EfficiencyClass` value
        indicates better performance.* On a homogeneous machine there is one
        class and this is every processor, which is correct — there is nothing
        to pin away from.
        """
        best = max(self.efficiency_class.values())
        return tuple(sorted(cpu for cpu, klass in self.efficiency_class.items() if klass == best))

    @property
    def efficiency(self) -> tuple[int, ...]:
        return tuple(cpu for cpu in self.logical if cpu not in set(self.performance))

    def as_dict(self) -> dict[str, Any]:
        return {
            "logical_processors": len(self.logical),
            "efficiency_classes": list(self.classes),
            "performance_cpus": list(self.performance),
            "efficiency_cpus": list(self.efficiency),
        }


def cpu_topology() -> CpuTopology:
    """Read the per-CPU efficiency class. **Fails closed rather than guessing.**"""
    if not WINDOWS:
        raise PlatformError("cpu_topology is a Win32 query; this platform is not Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Declared explicitly. `GetCurrentProcess` returns a HANDLE, and ctypes'
    # default `c_int` restype TRUNCATES it on 64-bit -- the call then fails
    # with a zero-length buffer, which is indistinguishable from "this machine
    # has no CPU-set information" unless the signature is pinned.
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetSystemCpuSetInformation.restype = wintypes.BOOL
    kernel32.GetSystemCpuSetInformation.argtypes = [
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
        wintypes.HANDLE,
        wintypes.ULONG,
    ]
    handle = kernel32.GetCurrentProcess()

    needed = wintypes.ULONG(0)
    kernel32.GetSystemCpuSetInformation(None, 0, ctypes.byref(needed), handle, 0)
    if needed.value == 0:
        raise PlatformError(
            "GetSystemCpuSetInformation reported a zero-length buffer; the CPU-set topology "
            "cannot be read, so the performance-core mask cannot be DETECTED. Refusing rather "
            "than guessing a logical-processor range -- a guessed mask reintroduces exactly the "
            "scheduler bias pinning exists to remove"
        )
    buffer = (ctypes.c_ubyte * needed.value)()
    if not kernel32.GetSystemCpuSetInformation(
        ctypes.cast(buffer, ctypes.c_void_p), needed.value, ctypes.byref(needed), handle, 0
    ):
        raise PlatformError(f"GetSystemCpuSetInformation failed (error {ctypes.get_last_error()})")

    efficiency: dict[int, int] = {}
    order: list[int] = []
    offset = 0
    while offset < needed.value:
        record = _CPU_SET_INFORMATION.from_buffer(buffer, offset)
        if record.Size == 0:
            raise PlatformError("a CPU-set record reported Size 0; refusing to walk the buffer")
        if record.Type == _CPU_SET_INFORMATION_TYPE:
            cpu = int(record.LogicalProcessorIndex)
            efficiency[cpu] = int(record.EfficiencyClass)
            order.append(cpu)
        offset += record.Size
    if not efficiency:
        raise PlatformError("no CPU-set records were returned; the topology is unknown")
    return CpuTopology(logical=tuple(order), efficiency_class=efficiency)


def pin_to_performance_cores() -> tuple[int, ...]:
    """Restrict this process to the highest efficiency class. Returns the mask.

    Uses `os.sched_setaffinity`'s Windows counterpart via
    `SetProcessAffinityMask`. Raises rather than continuing unpinned: an
    unpinned run on this machine produces a **bimodal** distribution whose
    spread belongs to Thread Director, and §E.5 asks for p95 and IQR.
    """
    topology = cpu_topology()
    cpus = topology.performance
    if not cpus:
        raise PlatformError("no performance cores were identified")
    if max(cpus) > 63:
        raise PlatformError("a processor index above 63 needs processor groups; refusing")
    mask = 0
    for cpu in cpus:
        mask |= 1 << cpu
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    kernel32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
    if not kernel32.SetProcessAffinityMask(kernel32.GetCurrentProcess(), ctypes.c_size_t(mask)):
        raise PlatformError(
            f"SetProcessAffinityMask({mask:#x}) failed (error {ctypes.get_last_error()})"
        )
    return cpus


# ---------------------------------------------------------------------------
# power
# ---------------------------------------------------------------------------
def _powershell(script: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout.strip()


def on_ac_power() -> bool:
    """`True` when the machine is on mains. Read from the battery status."""
    value = _powershell(
        "(Get-CimInstance -Namespace root\\wmi -ClassName BatteryStatus "
        "-ErrorAction SilentlyContinue).PowerOnline"
    )
    if not value:
        # No battery device at all: a desktop, which is on mains by definition.
        return True
    return value.splitlines()[0].strip().lower() in ("true", "1")


def require_ac_power() -> None:
    """Refuse to measure on battery, with a named error.

    A laptop on battery throttles regardless of the power plan, so a measurement
    taken there is not a measurement of the mechanism.
    """
    if not on_ac_power():
        raise PlatformError(
            "this machine is on BATTERY. A laptop throttles on battery whatever the power plan "
            "says, so the number would be the battery's and not the mechanism's. Refusing to "
            "adjudicate (EXP8B STEP 4.2)"
        )


def active_power_scheme() -> dict[str, str]:
    raw = _powershell("powercfg /getactivescheme")
    guid = re.search(r"([0-9a-fA-F-]{36})", raw)
    name = re.search(r"\(([^)]*)\)\s*$", raw)
    return {
        "guid": guid.group(1) if guid else "",
        "name": name.group(1) if name else "",
        "raw": raw,
    }


def sleep_settings() -> dict[str, str]:
    """Sleep, hibernate and USB selective suspend, **as found**.

    Reported rather than assumed: the power plan does not imply these, and a
    machine that suspends a bus mid-run would show it as an outlier nobody
    could explain afterwards.

    **Parsed positionally, not by an English string.** This machine's `powercfg`
    output is localised, so matching *"Current AC Power Setting Index"* silently
    returned nothing and every value read `unavailable` -- a check that reports
    "I could not tell" while looking like a check. The AC index is the first
    hex value after the setting's GUID, in every locale, so that is what is
    read. Values are seconds for the two timeouts, `0` meaning never.
    """
    settings = {
        "standby_ac_seconds": (
            "238c9fa8-0aad-41ed-83f4-97be242c8f20",
            "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
        ),
        "hibernate_ac_seconds": (
            "238c9fa8-0aad-41ed-83f4-97be242c8f20",
            "9d7815a6-7ee4-497e-8888-515a05f02364",
        ),
        "usb_selective_suspend_ac": (
            "2a737441-1930-4402-8d77-b2bebba308a3",
            "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
        ),
    }
    scheme = active_power_scheme()["guid"]
    found: dict[str, str] = {}
    for name, (sub, setting) in settings.items():
        raw = _powershell(f"powercfg /query {scheme} {sub} {setting}")
        indices = re.findall(r"0x([0-9a-fA-F]{8})", raw)
        # Counted from the END: `powercfg` prints the POSSIBLE-SETTINGS range
        # (minimum, maximum, increment) before the current AC and DC indices,
        # so the first hex value is the minimum -- which for a sleep timeout is
        # `0`, i.e. exactly the reassuring answer. Taking `indices[0]` reported
        # "never sleep" on a machine set to sleep after ten minutes. The last
        # two values are AC then DC in every locale.
        found[name] = str(int(indices[-2], 16)) if len(indices) >= 2 else "unavailable"
    return found


# ---------------------------------------------------------------------------
# the platform record
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MeasurementPlatform:
    """`frozen_parameters` row 9, as the machine reports it."""

    os_version: str
    os_build: str
    display_version: str
    product_name: str
    cpu_model: str
    physical_cores: int
    logical_processors: int
    performance_cpus: tuple[int, ...]
    efficiency_cpus: tuple[int, ...]
    ram_bytes: int
    ram_type: str
    power_scheme_guid: str
    power_scheme_name: str
    on_ac: bool
    python_version: str
    sleep: dict[str, str] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        """The one-line identity row 9 records."""
        return (
            f"Windows {self.display_version} build {self.os_build}; {self.cpu_model}; "
            f"{self.physical_cores}C/{self.logical_processors}T "
            f"({len(self.performance_cpus)}P/{len(self.efficiency_cpus)}E logical); "
            f"{self.ram_bytes / 1024**3:.2f} GiB; power scheme {self.power_scheme_name} "
            f"({self.power_scheme_guid})"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "os_version": self.os_version,
            "os_build": self.os_build,
            "display_version": self.display_version,
            "product_name": self.product_name,
            "cpu_model": self.cpu_model,
            "physical_cores": self.physical_cores,
            "logical_processors": self.logical_processors,
            "performance_cpus": list(self.performance_cpus),
            "efficiency_cpus": list(self.efficiency_cpus),
            "ram_bytes": self.ram_bytes,
            "ram_type": self.ram_type,
            "power_scheme_guid": self.power_scheme_guid,
            "power_scheme_name": self.power_scheme_name,
            "on_ac": self.on_ac,
            "python_version": self.python_version,
            "sleep": dict(self.sleep),
            "identity": self.identity,
        }


def read_platform() -> MeasurementPlatform:
    """Read every row 9 field from the machine. No value here is transcribed."""
    if not WINDOWS:
        raise PlatformError(
            "row 9's platform is Windows (ADR 0014: the effect ledger's enforcement is Win32 "
            "share-mode locking and does not degrade). Refusing to identify a platform that "
            "cannot carry the campaign"
        )
    facts = _powershell(
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "$cs=Get-CimInstance Win32_ComputerSystem;"
        "$cpu=Get-CimInstance Win32_Processor;"
        "$cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
        "$mem=Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1;"
        '"os_version=$($os.Version)";"ubr=$($cv.UBR)";'
        '"display_version=$($cv.DisplayVersion)";"product_name=$($cv.ProductName)";'
        '"cpu_model=$($cpu.Name)";"physical_cores=$($cpu.NumberOfCores)";'
        '"logical=$($cpu.NumberOfLogicalProcessors)";'
        '"ram_bytes=$($cs.TotalPhysicalMemory)";'
        '"ram_type=$($mem.SMBIOSMemoryType)"'
    )
    read: dict[str, str] = {}
    for line in facts.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            read[key.strip()] = value.strip()
    missing = {
        "os_version",
        "display_version",
        "cpu_model",
        "physical_cores",
        "logical",
        "ram_bytes",
    } - set(read)
    if missing:
        raise PlatformError(f"the machine did not report {sorted(missing)}; refusing to seal row 9")

    topology = cpu_topology()
    scheme = active_power_scheme()
    # SMBIOS memory types: 26 = DDR4, 34 = DDR5. Named rather than numbered so
    # the sealed document is readable without a lookup table.
    smbios = {"20": "DDR", "21": "DDR2", "24": "DDR3", "26": "DDR4", "34": "DDR5"}
    return MeasurementPlatform(
        os_version=f"{read['os_version']}.{read.get('ubr', '?')}",
        os_build=f"{read['os_version'].split('.')[-1]}.{read.get('ubr', '?')}",
        display_version=read["display_version"],
        product_name=read.get("product_name", ""),
        cpu_model=read["cpu_model"],
        physical_cores=int(read["physical_cores"]),
        logical_processors=int(read["logical"]),
        performance_cpus=topology.performance,
        efficiency_cpus=topology.efficiency,
        ram_bytes=int(read["ram_bytes"]),
        ram_type=smbios.get(read.get("ram_type", ""), f"SMBIOS {read.get('ram_type', '?')}"),
        power_scheme_guid=scheme["guid"],
        power_scheme_name=scheme["name"],
        on_ac=on_ac_power(),
        python_version=platform.python_version(),
        sleep=sleep_settings(),
    )


__all__ = [
    "CpuTopology",
    "MeasurementPlatform",
    "PlatformError",
    "active_power_scheme",
    "cpu_topology",
    "on_ac_power",
    "pin_to_performance_cores",
    "read_platform",
    "require_ac_power",
    "sleep_settings",
]
