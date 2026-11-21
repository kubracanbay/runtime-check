#!/usr/bin/env python3
"""
runtime-check: find the PHP, Node.js and Java versions on this machine
and compare them with recent security fixes.

Usage:
    python3 runtime_check.py          # human-readable report
    python3 runtime_check.py --json   # machine-readable output

Exit codes: 0 = nothing known to be vulnerable, 1 = action needed, 2 = error.

The checks are based on the notes in https://github.com/kubracanbay/Security-Notes.
Version numbers alone can't tell you everything: Linux distributions often
backport fixes without changing the version. Always confirm with your vendor.
"""

import json
import platform
import re
import shutil
import subprocess
import sys

NOTES = "https://github.com/kubracanbay/Security-Notes"

# ---------------------------------------------------------------------------
# Known issues. To add a new one, add an entry here and a note in Security-Notes.
# "fixed" maps a release line to the first fixed version on that line.
# ---------------------------------------------------------------------------
ADVISORIES = {
    "php": {
        "name": "PHP2Shell (CVE-2026-109618, CVE-2026-109619)",
        "note": NOTES + "/blob/main/2026-10-21-php-and-nodejs.md",
        "line_parts": 2,  # release line = major.minor, e.g. 8.3
        "fixed": {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"},
        "eol_below": "8.2",  # lines older than this get no official fix
    },
    "node": {
        "name": "Node.js October 2026 security releases",
        "note": NOTES + "/blob/main/2026-10-21-php-and-nodejs.md",
        "line_parts": 1,  # release line = major, e.g. 24
        "fixed": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"},
        "eol_below": "22",
    },
    "java": {
        "name": "Java4Shell (CVE-2026-114938)",
        "note": NOTES + "/blob/main/2026-11-java4shell.md",
        "line_parts": 1,
        "fixed": {"17": "17.0.21.1", "21": "21.0.13.1", "25": "25.0.5.1", "27": "27.0.1.1"},
        "first_affected": {"17": "17.0.6"},
        "not_affected_lines": ["8", "11"],
    },
}


def parse_version(text):
    """'v24.22.0' -> (24, 22, 0); '1.8.0_391' -> (8, 0, 391)."""
    if text is None:
        return None
    text = text.strip().lstrip("v")
    old_java = re.match(r"^1\.(\d+)\.(\d+)(?:_(\d+))?", text)
    if old_java:  # Java 8 and older report themselves as 1.x
        return tuple(int(p) for p in old_java.groups() if p is not None)
    parts = re.findall(r"\d+", text.split("-")[0].split("+")[0])
    return tuple(int(p) for p in parts) if parts else None


def vstr(v):
    return ".".join(str(p) for p in v)


def run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return (out.stdout or "") + (out.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return None


def detect_php():
    if not shutil.which("php"):
        return None
    return parse_version(run(["php", "-r", "echo PHP_VERSION;"]))


def detect_node():
    if not shutil.which("node"):
        return None
    return parse_version(run(["node", "-v"]))


def detect_java():
    if not shutil.which("java"):
        return None
    out = run(["java", "-version"]) or ""
    match = re.search(r'version "([^"]+)"', out)
    return parse_version(match.group(1)) if match else None


def java_mitigation_active(java_output=""):
    """True if Base64 intrinsics are switched off, the interim Java4Shell mitigation."""
    import os
    flag = "-XX:-UseBASE64Intrinsics"
    sources = [os.environ.get(k, "") for k in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")]
    return any(flag in s for s in sources) or flag in (java_output or "")


def cpu_uses_vulnerable_java_path():
    """Java4Shell needs x86-64 with AVX-512 VBMI. Returns True, False or None (unknown)."""
    arch = platform.machine().lower()
    if arch in ("arm64", "aarch64"):
        return False
    if arch not in ("x86_64", "amd64"):
        return None
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/cpuinfo") as f:
                return " avx512vbmi " in f.read().replace("\n", " ")
        if sys.platform == "darwin":
            flags = run(["sysctl", "-n", "machdep.cpu.leaf7_features"]) or ""
            return "AVX512VBMI" in flags.upper()
    except OSError:
        pass
    return None


def check(runtime, version):
    adv = ADVISORIES[runtime]
    result = {"runtime": runtime, "issue": adv["name"], "note": adv["note"]}
    if version is None:
        return dict(result, version=None, status="not found",
                    advice="Not installed or not on PATH.")
    result["version"] = vstr(version)
    line = ".".join(str(p) for p in version[: adv["line_parts"]])

    if line in adv.get("not_affected_lines", []):
        return dict(result, status="ok", advice="This release line is not affected.")

    fixed = adv["fixed"].get(line)
    if fixed is None:
        eol = adv.get("eol_below")
        if eol and version[: adv["line_parts"]] < parse_version(eol):
            return dict(result, status="end of life",
                        advice="This line gets no official fix. Upgrade to a supported line.")
        if runtime == "node" and version[0] % 2 == 1:
            return dict(result, status="end of life",
                        advice="Odd-numbered Node.js lines are short-lived. Upgrade to a supported LTS line.")
        return dict(result, status="unknown",
                    advice="This line is not covered by the advisory. Check the vendor's site.")

    first = adv.get("first_affected", {}).get(line)
    if first and version < parse_version(first):
        return dict(result, status="ok", advice="Older than the first affected build.")
    if version >= parse_version(fixed):
        return dict(result, status="ok", advice="Patched (%s or later)." % fixed)

    advice = "Update to %s or later." % fixed
    if runtime == "java":
        if java_mitigation_active(run(["java", "-version"]) if shutil.which("java") else ""):
            advice += " Interim mitigation detected (Base64 intrinsics off); still update."
        cpu = cpu_uses_vulnerable_java_path()
        if cpu is False:
            advice += " This CPU doesn't use the vulnerable code path, but update anyway."
        elif cpu is None:
            advice += " Could not tell whether this CPU supports AVX-512 VBMI."
    return dict(result, status="vulnerable", advice=advice)


def main():
    results = [
        check("php", detect_php()),
        check("node", detect_node()),
        check("java", detect_java()),
    ]
    needs_action = any(r["status"] in ("vulnerable", "end of life") for r in results)

    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
    else:
        marks = {"ok": "OK  ", "vulnerable": "FIX ", "end of life": "EOL ",
                 "not found": "--  ", "unknown": "??  "}
        print("runtime-check\n")
        for r in results:
            print("%s %-5s %-12s %s" % (marks[r["status"]], r["runtime"],
                                         r["version"] or "-", r["advice"]))
            if r["status"] in ("vulnerable", "end of life"):
                print("            %s\n            %s" % (r["issue"], r["note"]))
        print("\nVersion numbers can't show backported fixes from Linux distributions."
              "\nConfirm with your vendor's advisory.")
    return 1 if needs_action else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # keep the tool friendly
        print("runtime-check failed: %s" % exc, file=sys.stderr)
        sys.exit(2)
