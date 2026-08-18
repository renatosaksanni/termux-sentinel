# Termux Sentinel

A terminal malware and device-posture scanner for Android, built to run inside
Termux on a device that is not rooted.

## Install

Run from a plain Termux shell — not from PRoot, chroot, or as root. Termux
blocks package operations as root, and PRoot cannot execute Android binaries,
which would leave the scanner blind to every installed app.

```bash
git clone https://github.com/renatosaksanni/termux-sentinel
cd termux-sentinel
./install.sh
```

Then:

```bash
sentinel doctor       # what this environment can actually inspect
sentinel update       # download signatures (~250 MB, one time)
sentinel scan --full  # installed apps + storage + device posture
```

Run `doctor` first. It reports which capabilities are live, so "nothing was
found" is never mistaken for "nothing was scanned".

## Usage

```bash
sentinel scan --full                 # everything
sentinel scan --apps                 # installed applications only
sentinel scan --files                # filesystem only
sentinel scan --path /sdcard/Download
sentinel scan --recent 24            # only files written in the last 24h
sentinel scan --deep                 # also inspect media file contents
sentinel scan --json -o report.json  # machine readable

sentinel watch --catch-up 24         # real-time watch, after a catch-up pass
sentinel update                      # refresh signature databases
sentinel quarantine list
sentinel quarantine restore <id>
sentinel config show
```

Output is verbose by default: every phase, engine, and finding is printed as it
happens, with elapsed timestamps and a live progress bar. Use `-q` for findings
only, `--debug` for per-file tracing and raw evidence.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Medium findings |
| 2 | High or critical findings |
| 3 | The scan could not run |

Suitable for cron:

```bash
0 3 * * * cd ~/termux-sentinel && ./bin/sentinel scan --full -q --json -o ~/report.json
```

## Detection

Three independent layers, each contributing findings separately rather than
blending into one verdict:

| Layer | Engine | Catches |
|---|---|---|
| Signature | ClamAV | Known malware samples, by hash and pattern |
| Behavioural | YARA | Malware families by what the code does, surviving recompilation |
| Structural | Built-in heuristics | Dangerous permission combinations, impersonation, bad provenance |

Plus a device posture audit — patch level, verified boot, SELinux, sideloading
policy, debugging state — and a real-time watcher on the directories where
files arrive from outside.

A single permission is never treated as a verdict. Android malware is
identified by combinations, and each rule states the combination and the
reason:

- `REQUEST_INSTALL_PACKAGES` + `INTERNET` + `DexClassLoader` → dropper
- `SYSTEM_ALERT_WINDOW` + accessibility automation → banking overlay trojan
- `RECEIVE_SMS` + network access → one-time-passcode theft
- Microphone + precise location + hidden launcher + upload → stalkerware
- `targetSdk < 23` → all permissions auto-granted, no prompts ever shown

Provenance shifts severity: the same capabilities are more suspicious in a
sideloaded app than in one from a store. Apps whose purpose is installing other
apps are exempt from the dropper rule only when their signing certificate
matches a pinned fingerprint, so the exemption cannot be claimed by copying a
package name.

## Limits

An unrooted device places hard limits on any scanner, this one included. It
cannot intercept a file before it is written, read another app's private
storage, scan process memory, or uninstall anything on your behalf. Android
package visibility filtering also restricts which apps it can enumerate at all.

[docs/CAPABILITIES.md](docs/CAPABILITIES.md) states each limit and what it means
in practice. Worth reading before relying on a clean result.

## The adb backend

A normal app cannot call `dumpsys`, and Android restricts which packages it may
even see. Enabling wireless debugging and connecting `adb` to the device itself
grants shell-level access, which lifts both restrictions without root.

```bash
pkg install android-tools
# Settings > Developer options > Wireless debugging > Pair device with code
adb pair 127.0.0.1:PORT
adb connect 127.0.0.1:PORT
sentinel scan --apps --backend adb
```

The scanner picks the richest backend available and always reports which one it
used.

## Privacy

Everything runs locally. The only optional network calls are `freshclam`
downloading public signature databases, and VirusTotal lookups — disabled
unless you set an API key, and sending SHA-256 hashes only, never file
contents.

## Layout

```
sentinel/
  env.py           capability detection; every feature is gated on this
  axml.py          binary AndroidManifest.xml decoder, pure Python
  apk.py           static APK analysis: manifest, certificate, DEX indicators
  scan.py          orchestration across engines
  findings.py      shared finding model, dedup, exit codes
  engines/         clamav, yara, heuristics, hash reputation
  scanners/        android packages, filesystem, device posture
  watch/           inotify binding and the real-time watcher
rules/             YARA rules for Android payloads and shell threats
docs/              capability and limitation reference
```

No pip dependencies. The standard library plus the ClamAV and YARA binaries is
the entire runtime.

## Licence

MIT. See [LICENSE](LICENSE).
