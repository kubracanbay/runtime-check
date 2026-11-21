# runtime-check

Checks which PHP, Node.js and Java versions are installed on a machine and whether they need a security update.

I wrote it after the incidents in my [Security Notes](https://github.com/kubracanbay/Security-Notes). Each one came down to knowing which runtime versions you run, and that is surprisingly easy to lose track of.

## How to use it

You need Python 3. There is nothing else to install.

```
curl -O https://raw.githubusercontent.com/kubracanbay/runtime-check/main/runtime_check.py
python3 runtime_check.py
```

It takes a few seconds. Example from a test server:

```
runtime-check

--   php   -            Not installed or not on PATH.
OK   node  22.23.5      Patched (22.23.4 or later).
FIX  java  21.0.13.0.3  Update to 21.0.13.1 or later. Interim mitigation detected (Base64 intrinsics off); still update.
            Java4Shell (CVE-2026-114938)
            https://github.com/kubracanbay/Security-Notes/blob/main/2026-11-java4shell.md
```

Each line starts with a short status:

| Status | Meaning |
| --- | --- |
| `OK` | Up to date for the issues below |
| `FIX` | Needs an update |
| `EOL` | The release line no longer gets fixes |
| `--` | Not installed |
| `??` | Not covered by the issues below |

Add `--json` for output that other tools can read. The script exits with code 1 when something needs attention, so it also works as a step in a CI pipeline.

## What it checks

| Runtime | Issue | Note |
| --- | --- | --- |
| PHP | PHP2Shell (CVE-2026-109618, CVE-2026-109619) | [Read](https://github.com/kubracanbay/Security-Notes/blob/main/2026-10-21-php-and-nodejs.md) |
| Node.js | October 2026 security releases | [Read](https://github.com/kubracanbay/Security-Notes/blob/main/2026-10-21-php-and-nodejs.md) |
| Java | Java4Shell (CVE-2026-114938) | [Read](https://github.com/kubracanbay/Security-Notes/blob/main/2026-11-java4shell.md) |

For Java, it also looks at whether the CPU uses the affected code path and whether the temporary mitigation is turned on.

## What it doesn't do

It only reads version numbers. It doesn't connect to the internet, change anything on the machine or need admin rights. The whole tool is one short file, so you can read it before you run it.

## Limits

- Only runtimes on your `PATH` are checked. For a container image, run the script inside the container.
- Linux distributions often backport fixes without changing the version number. Confirm with your vendor.
- It only knows about the issues listed above. I add new ones when I write a new note.
