# Capabilities and limits

This document exists because the most dangerous property of a security tool is
overstated coverage. A scan that reports "clean" while having examined nothing
is worse than no scan, because it produces confidence that is not earned.

Every limitation below is a property of the Android platform, not a gap in this
implementation. None of them can be engineered around without root.

---

## 1. Where you run it decides what it sees

| Environment | Installed apps | Device posture | Filesystem |
|---|---|---|---|
| Termux (native) | Yes, via `pm` | Yes, via `getprop` | Yes |
| Termux + adb backend | Yes, plus `dumpsys` | Yes, full | Yes |
| PRoot / chroot / Ubuntu | **No** | **No** | Yes |

Inside PRoot, executing `/system/bin/*` fails with exit code 126. `pm`,
`getprop`, and `dumpsys` are therefore unreachable, and **no installed
application is examined at all**. The scanner detects this and says so rather
than reporting a clean result.

Run `sentinel doctor` to see which row you are in.

---

## 2. Real-time protection is not on-access scanning

Desktop antivirus hooks the kernel and inspects a file *before* any process can
open it. That requires privileges Android does not grant to apps.

`sentinel watch` uses inotify, so it learns of a file **after** the write
completes — typically within one to two seconds. In practice this is early
enough for downloaded APKs, which must still be tapped and installed by you.
It is not early enough to stop code that executes the instant it lands.

Coverage is limited to directories this process can read: shared storage and
the Termux home. Files written into another app's private storage are invisible.

---

## 3. Private app storage cannot be read

`/data/data/<package>/` is readable only by the app that owns it. A scanner
running as the Termux uid cannot inspect:

- Files an app has downloaded into its own sandbox
- Databases, preferences, or cached payloads
- Code an app has loaded dynamically at runtime

An app can therefore download and execute a second-stage payload entirely
inside its own sandbox, and no unrooted scanner will see it. This is why the
heuristics engine flags **dropper capability** at install time: catching the
capability is possible, catching the payload afterwards is not.

---

## 4. Installed APK readability varies

The scanner reads each installed app's APK from `/data/app/...`. On most Android
versions these files are world-readable and this works. On some builds the
platform denies access, and the scanner reports `APK not readable` for that
package rather than skipping it silently.

The adb backend resolves this: the `shell` user can read `/data/app`, and the
APK is streamed out with `adb exec-out cat`.

---

## 5. Nothing can be removed automatically

An app cannot uninstall another app. Findings name the package and the exact
action to take; you perform it.

Quarantine applies only to loose files the scanner can write to — items in
shared storage and the Termux home. Quarantined files are moved to private
storage, stripped of all permission bits, and recorded so they can be restored
exactly. Nothing is deleted without you asking.

---

## 6. Below the app layer, all bets are off

If the bootloader is unlocked, verified boot is not `green`, SELinux is
permissive, or an unexpected `su` binary exists, then code is running with
privileges above the app sandbox. In that state a scanner running *inside* the
sandbox can be lied to about everything it observes.

The posture audit checks all four conditions and reports them as CRITICAL or
HIGH, because they invalidate the rest of the scan rather than merely adding to
it.

---

## 7. Detection is imperfect in both directions

**False negatives.** Signature engines only know samples that have been seen and
catalogued. Behavioural rules can be evaded by an author who reads them — these
rules are public. A commercially packed app hides its payload from static
analysis entirely; the scanner reports the packing as a MEDIUM finding rather
than claiming the contents are clean.

**False positives.** Legitimate apps sometimes hold genuinely dangerous
permission combinations. An SMS backup tool really does read SMS and really does
use the network. Findings are written to explain the reasoning so you can judge
the specific case, and the `suppress` list in the config accepts finding
fingerprints for issues you have reviewed and accepted.

---

## 8. What this tool is actually good at

Given the above, the honest statement of value:

1. **Provenance and permission auditing of installed apps.** The single highest
   yield check on Android, and fully available without root.
2. **Impersonation detection.** Fake banking apps are caught by name similarity
   plus signing certificate, before you enter credentials.
3. **Catching malicious files at the doorway.** Most Android compromise starts
   with an APK from chat or a browser download. That path is watched.
4. **Posture.** Knowing your patch level is 400 days old is more actionable than
   any individual malware detection.
5. **Auditing the Termux environment itself.** Shell droppers, reverse shells,
   miners, and credential harvesters aimed at your Linux userland, which no
   Android antivirus looks at.
