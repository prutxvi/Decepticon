---
name: dynamic
description: iOS dynamic instrumentation on jailbroken device — Frida/Objection setup, SSL Kill Switch pinning bypass, jailbreak-detection bypass, keychain dump, biometric/LAContext bypass, and ObjC runtime method hooking.
allowed-tools: Bash Read Write
metadata:
  subdomain: mobile
  when_to_use: "ios dynamic frida objection jailbreak ssl kill switch pinning bypass keychain dump biometric faceid touchid lacontext jailbreak-detection palera1n unc0ver checkra1n cycript"
  tags: ios, frida, objection, ssl-pinning, jailbreak, keychain, biometric, lacontext
  mitre_attack: T1635, T1521.003, T1517, T1633
---

# iOS Dynamic Instrumentation Playbook

> Jailbroken device required for full Frida/Objection access. Most
> enterprise and bounty-program iOS testing falls here. For static-only
> analysis (no jailbreak) see `reverser/ios-static/SKILL.md`.

## Prerequisites

- iOS device jailbroken with **palera1n** (A8-A11 on iOS 16+),
  **checkra1n** (A5-A11, up to iOS 14.8), or **unc0ver** (A12+ up to
  iOS 14.8 with supported blobs). Confirm with `uname -v` in SSH.
- Frida server installed via Cydia / Sileo (search "Frida") or manually:

```bash
# SSH to device (default Cydia SSH cred: alpine)
ssh root@<device-ip>

# Verify jailbreak + SSH works
id   # should return uid=0(root)
uname -v
```

- Host side: `pip install frida-tools objection`
- Confirm connectivity:

```bash
frida-ps -U   # lists processes on USB-connected device
```

## Path A: SSL Pinning Bypass

### SSL Kill Switch 2 / 3

Install via Cydia/Sileo (search "SSL Kill Switch 2" or "SSL Kill
Switch 3" for iOS 15+). Toggle per-app in Settings → SSL Kill Switch.
Relaunch the app; verify traffic appears in Burp (set device proxy to
Burp listener IP:8080, install Burp CA as trusted profile via
Settings → General → VPN & Device Management).

### Objection pinning disable (preferred for on-demand toggle)

```bash
# Attach to running app
objection --gadget "TargetApp" explore

# In the Objection REPL:
ios sslpinning disable

# Verify: open the app, check Burp proxy for decrypted HTTPS
```

### Frida codeshare scripts (NSURLSession / AFNetworking / TrustKit)

```bash
# Universal iOS pinning bypass (covers NSURLSession, Alamofire, AFNetworking)
frida -U -f com.target.bundle \
  --codeshare "wan-make/ios-ssl-pinning-bypass" \
  --no-pause

# TrustKit-specific bypass
frida -U -f com.target.bundle \
  --codeshare "machorka/trustkit-bypass" \
  --no-pause
```

### Manual Frida script for custom pinners

```javascript
// Hook SecTrustEvaluate + SecTrustEvaluateWithError
// Load with: frida -U -f com.target -l bypass-pin.js
if (ObjC.available) {
    var SecTrustEvaluateWithError = Module.findExportByName(
        "Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError,
            new NativeCallback(function(trust, error) {
                if (error !== 0) Memory.writePointer(error, ptr(0));
                return 1;  // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
    }
}
```

Verify in Burp: `HTTPS` traffic from the target app appears decrypted.

## Path B: Jailbreak-Detection Bypass

### Objection built-in

```bash
objection --gadget "TargetApp" explore

# Disable JB detection (covers fileExistsAtPath Cydia checks + fork())
ios jailbreak disable
```

### Common detection patterns to hook manually

| Pattern | API to hook |
|---|---|
| File presence (`/Applications/Cydia.app`, `/bin/bash`) | `NSFileManager fileExistsAtPath:` |
| URL scheme (`cydia://`) | `UIApplication canOpenURL:` |
| `fork()` syscall return | `fork` (libc) |
| `/proc/self/maps` inspection | `open` / `fopen` |
| Dyld image name scan | `_dyld_get_image_name` |

```javascript
// Frida: hook fileExistsAtPath to suppress JB file checks
var NSFileManager = ObjC.classes.NSFileManager;
var orig = NSFileManager["- fileExistsAtPath:"].implementation;
Interceptor.replace(orig, ObjC.implement(
    NSFileManager["- fileExistsAtPath:"],
    function(self, sel, path) {
        var p = ObjC.Object(path).toString();
        var jbPaths = ["/Applications/Cydia.app", "/bin/bash",
                       "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/"];
        for (var i = 0; i < jbPaths.length; i++) {
            if (p.indexOf(jbPaths[i]) !== -1) return 0;  // false
        }
        return orig(self, sel, path);
    }
));
```

### Liberty Lite / A-Bypass (tweak-side)

Install Liberty Lite or A-Bypass from Cydia/Sileo → enable per-app
toggle before launch. Faster than scripting for commodity JB checks.

## Path C: Keychain Dump

### Objection keychain dump

```bash
objection --gadget "TargetApp" explore

# Dump all items accessible in app context
ios keychain dump

# Output: account, service, access group, kSecAttrAccessible class, value
```

### Frida hook on SecItemCopyMatching

```javascript
// Log every keychain query result
var SecItemCopyMatching = Module.findExportByName(
    "Security", "SecItemCopyMatching");
Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) { this.result = args[1]; },
    onLeave: function(retval) {
        if (retval.toInt32() === 0 && !this.result.isNull()) {
            var items = new ObjC.Object(this.result.readPointer());
            console.log("[KC]", items.toString());
        }
    }
});
```

### `kSecAttrAccessible` misconfig findings

| Value | Finding |
|---|---|
| `kSecAttrAccessibleAlways` | Critical — readable without unlock, even after reboot |
| `kSecAttrAccessibleAlwaysThisDeviceOnly` | High — readable without unlock |
| `kSecAttrAccessibleAfterFirstUnlock` | Medium if secrets are high-value |
| `kSecAttrAccessibleWhenUnlocked` | Acceptable baseline |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Secure — requires passcode |

## Path D: Biometric / LAContext Bypass

### Hook evaluatePolicy to always succeed

```javascript
// Bypass LAContext biometric prompt — returns kLAErrorSuccess
var LAContext = ObjC.classes.LAContext;
Interceptor.attach(
    LAContext["- evaluatePolicy:localizedReason:reply:"].implementation,
    {
        onEnter: function(args) {
            // args[3] = reply block (id, NSError*)
            var replyBlock = new ObjC.Block(args[3]);
            var origImpl = replyBlock.implementation;
            replyBlock.implementation = function(success, error) {
                origImpl(1, null);  // force success=YES, error=nil
            };
        }
    }
);
```

### Objection biometric bypass

```bash
objection --gadget "TargetApp" explore
ios ui biometrics_bypass
```

## Path E: ObjC Runtime Method Swizzling (License / Auth Checks)

```javascript
// Example: patch -[LicenseManager isPremiumUser] to return YES
Java.perform(function() {});  // no-op; use ObjC.available block

var LicenseMgr = ObjC.classes.LicenseManager;
if (LicenseMgr && LicenseMgr["- isPremiumUser"]) {
    Interceptor.replace(
        LicenseMgr["- isPremiumUser"].implementation,
        ObjC.implement(LicenseMgr["- isPremiumUser"], function(self, sel) {
            console.log("[+] isPremiumUser hooked -> returning YES");
            return 1;
        })
    );
}
```

```bash
# One-liner attach to running process
frida -U -n TargetApp -e "ObjC.classes.LicenseManager['- isPremiumUser'].implementation = ObjC.implement(ObjC.classes.LicenseManager['- isPremiumUser'], function(self,sel){return 1;});"
```

## Evidence

Capture Burp traffic screenshot showing decrypted HTTPS after pinning
bypass. Save keychain dump to `/workspace/evidence/mobile/<bundle-id>/keychain.txt`.

```python
kg_add_node(
    kind="finding",
    label="iOS SSL pinning bypassable",
    props={
        "key": f"ios-ssl-pin::{bundle_id}",
        "severity": "high",
        "cvss": 7.4,
        "bundle_id": bundle_id,
        "bypass_method": "objection+ssl-kill-switch",
        "traffic_captured": True,
    },
)

kg_add_node(
    kind="finding",
    label="iOS keychain kSecAttrAccessibleAlways item",
    props={
        "key": f"ios-keychain-acl::{bundle_id}",
        "severity": "critical",
        "service": "<service-name>",
        "account": "<account-name>",
        "accessible_class": "kSecAttrAccessibleAlways",
    },
)
```

## ZFP

Two-method evidence per finding:

1. **Pinning bypass**: Burp HTTP history screenshot with decrypted HTTPS
   requests from the target app visible.
2. **Keychain misconfig**: `ios keychain dump` output showing
   `kSecAttrAccessibleAlways` class + sensitive value.
3. **Biometric bypass**: screen recording of the app unlocking without
   presenting a Face ID prompt after the hook fires.

## OPSEC Notes

- Jailbreaking leaves fingerprints: jailbroken device connects to
  Apple ID — use a dedicated Apple ID for testing; avoid using personal
  iCloud account.
- Frida injects a Gadget dylib; some apps detect `frida-agent` in
  the dyld image list. Counter: Frida Gadget injection via
  `objection patchipa` or `optool` (embed Gadget, re-sign with
  `codesign`).
- SSL Kill Switch modifies a system library; some app-layer integrity
  checks may detect it. Script-based bypass (injected Frida) leaves
  fewer static artifacts than a system tweak.
- `palera1n` tethered jailbreak: device reboots to unjailbroken state;
  re-jailbreak each power cycle during long engagements.

## Severity Table

| Bug | Severity |
|---|---|
| Keychain `kSecAttrAccessibleAlways` with auth token | Critical 9.5 |
| SSL pinning fully absent or bypassable without JB | High 8.0 |
| Jailbreak detection absent | Informational |
| Biometric bypass exposing auth flow | High 7.5 |
| `kSecAttrAccessibleAfterFirstUnlock` with secrets | Medium 5.5 |

## References

- palera1n: https://github.com/palera1n/palera1n
- Frida: https://frida.re/docs/ios/
- Objection: https://github.com/sensepost/objection
- SSL Kill Switch 3: https://github.com/Tym0n/SSL-Kill-Switch3
- Codeshare universal bypass: https://codeshare.frida.re/@wan-make/ios-ssl-pinning-bypass/
- Cross-ref static analysis: `reverser/ios-static/SKILL.md`
