#!/usr/bin/env python3
"""Synchronous MCP smoke test for Heisenberg.

Drives the built server over stdio the correct way (send a request, read exactly
one response line, repeat) — piping all requests then closing stdin makes rmcp
cancel the last in-flight tool call, so a batch-and-EOF test drops responses.

Usage:  python scripts/smoke.py [path\\to\\heisenberg.exe]
Default exe: target\\debug\\heisenberg.exe (run from the repo root).
Runs read-only checks plus one dump.capture of a throwaway process; uses a
temp HEISENBERG_HOME and a sandbox policy so nothing touches the real machine.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

EXE = sys.argv[1] if len(sys.argv) > 1 else r"target\debug\heisenberg.exe"


class Client:
    def __init__(self, exe, env):
        self.p = subprocess.Popen(
            [exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env,
        )
        self._id = 0

    def call(self, method, params=None, notif=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notif:
            self._id += 1
            msg["id"] = self._id
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notif:
            return None
        return json.loads(self.p.stdout.readline())

    def tool(self, name, args=None):
        r = self.call("tools/call", {"name": name, "arguments": args or {}})
        return json.loads(r["result"]["content"][0]["text"])

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=5)


def main():
    if not os.path.isfile(EXE):
        print(f"exe not found: {EXE} (build with `cargo build` first)")
        return 1

    home = tempfile.mkdtemp(prefix="heisenberg_smoke_")
    policy = os.path.join(home, "policy.json")
    with open(policy, "w") as f:
        f.write('{"class":"sandbox"}')
    env = dict(os.environ, HEISENBERG_HOME=home, HEISENBERG_POLICY=policy,
               HEISENBERG_TRUST_UNSIGNED="1", RUST_LOG="error")

    target = subprocess.Popen(["ping", "-n", "1000", "127.0.0.1"],
                              stdout=subprocess.DEVNULL)
    time.sleep(0.4)
    c = Client(EXE, env)
    ok = True
    try:
        init = c.call("initialize", {"protocolVersion": "2024-11-05",
                                     "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}})
        print("server :", init["result"]["serverInfo"])
        c.call("notifications/initialized", notif=True)

        names = sorted(t["name"] for t in c.call("tools/list")["result"]["tools"])
        print(f"tools  : {len(names)}")

        checks = [
            ("env.check", {}),
            ("policy.show", {}),
            ("tools.list", {}),
            ("system.triage", {}),
            ("inspect.processTree", {}),
            ("inspect.network", {}),
            ("gate.check", {"tool": "kernel.forceBugcheck", "tier": "machine-disrupting"}),
        ]
        for name, args in checks:
            d = c.tool(name, args)
            status = "ok" if d.get("ok") else f"ERR {d.get('error', {}).get('kind')}"
            print(f"  {name:22} {status}  {d.get('summary', '')[:60]}")
            ok = ok and d.get("ok", False)

        cap = c.tool("dump.capture", {"pid": target.pid})
        print(f"  {'dump.capture':22} {'ok' if cap['ok'] else 'ERR'}  {cap.get('summary','')[:60]}")
        ok = ok and cap.get("ok", False)

        rep = c.tool("report.generate", {})
        print(f"  {'report.generate':22} {'ok' if rep['ok'] else 'ERR'}")
        ok = ok and rep.get("ok", False)
    finally:
        c.close()
        target.terminate()

    print("SMOKE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
