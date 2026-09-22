# MikroTrick PoC - (RouterOS unauthenticated full takeover)

`poc_mikrotrick.py` is a self-contained exploit for the SSH attack chain that
CERT Polska disclosed as **"MikroTrick"** on 2026-09-05, exploited in the wild
since at least 2026-09-02 against internet-facing MikroTik RouterOS devices.
A single run turns an unauthenticated SSH connection into a full
administrator console. No credentials, no user interaction.

## The three CVEs

| CVE | Role in the chain | Defect |
|---|---|---|
| **CVE-2026-86060** (CVSS 9.2) | Privilege escalation | The SSH login helper treats a dash-led username as a file descriptor and reads a replacement identity and policy mask from it |
| **CVE-2026-67279** (CVSS 6.9) | Authentication bypass | A client-requested rekey before authentication drops the server's "must be authenticated" gate |
| **CVE-2026-67277** (CVSS 8.8) | Not used by this PoC | The bandwidth-test (btest) service allows pre-auth memory disclosure and restart; relevant for fingerprinting and exposure assessment |

An additional, unnamed state bug is required: a rejected login leaves the
username pending in the server's session state. The exploit relies on it in
step 1 below. MikroTik's patches (2026-09-03) close the entire chain.

## How the exploit works

1. **Pending username.** The client attempts password authentication as the
   username `-2`. The server rejects it but leaves it pending in the session
   state. This is the campaign's first IoC: `login failure for user -2`.
2. **Pre-auth rekey (CVE-2026-67279).** A key re-exchange before
   authentication completes makes the server drop its authentication gate.
3. **Channel open + PTY.** A session channel is opened without
   authentication, and the interactive shell spawns the login helper with
   the pending `-2`.
4. **Policy-mask swap (CVE-2026-86060).** The login helper reads up to 4096
   bytes from file descriptor 2 and splits them on NUL into a replacement
   identity and policy mask. The exploit sends an all-ones mask, which
   RouterOS clamps to the full policy set. The session comes up as full
   administrator; further actions are logged as `ssh:-2@<ip>`, the campaign
   fingerprint.

The real-world campaign used this access to create a highly privileged
account named `ops`; the exploit's default mode replicates that tradecraft
as its proof (it creates and immediately removes the account).

## Usage

```
python3 poc_mikrotrick.py <host>                  # prove full admin, exit
python3 poc_mikrotrick.py <host> "<ros command>"  # run one command, exit
```

Requirement: `python3-paramiko`. The script is a lab client and refuses
non-private IP targets.

## Affected and fixed versions

- Vulnerable: RouterOS `[7.24, 7.24.2)`, `[7.0.0, 7.23.4)`, `[6.0.0, 6.49.21)`
- Fixed: 7.25beta3, 7.24.2, 7.23.4, 6.49.21
- Tested: CHR 7.23.3 (exploitable) vs CHR 7.23.4 (exploit correctly fails).
  Deterministic across repeated runs.

## Detection

- Log line `login failure for user -2 via ssh`
- Log lines `user <name> added by ssh:-2@<ip>`
- Unknown highly privileged account `ops`
- `/system/device-mode/print` showing the "Flagged" marker (its absence
  proves nothing)

If any of these appear on a device, treat it as compromised: isolate, patch,
and review all users, scripts, scheduler tasks, and tunnels.

## References

- [CERT Polska disclosure](https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/)
- [MikroTik security bulletin (2026-09-03)](https://mikrotik.com/supportsec/september-2026-vulnerability/)
- CISA Known Exploited Vulnerabilities: CVE-2026-86060, CVE-2026-67277
  (added 2026-09-10)

## Legal

Run this only against RouterOS instances you own or are explicitly
authorized to test. Attacking devices you do not own is a crime.
