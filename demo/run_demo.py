#!/usr/bin/env python3
"""Heisenberg demo driver — the thing you screen-record.

Tells one story end to end: an agent diagnoses a hung Windows process from a
memory dump, then proposes a machine change that the Critical-box safety policy
blocks until a human approves it out of band — and that is reversed cleanly
afterwards. Every line below is a real Heisenberg tool call over MCP; the
narration just frames what the agent is doing.

Run from the repo root in a terminal sized ~100x32 for recording:

    python demo/run_demo.py

Options via env:
    DEMO_PAUSE   seconds between beats (default 1.2; set 0 for no pacing)
    DEMO_EXE     path to heisenberg.exe (default target/release/heisenberg.exe)

Needs: a release build of heisenberg + the patient (the driver builds them if
missing), and cdb from the Debugging Tools for Windows for the dump analysis
(selfcheck will tell you if it's present).
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time

# The demo prints box-drawing and status glyphs; force UTF-8 so it renders the
# same whatever the console code page is (Windows Terminal handles UTF-8 fine).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.environ.get("DEMO_EXE", os.path.join(REPO, "target", "release", "heisenberg.exe"))
PATIENT = os.path.join(REPO, "demo", "patient", "target", "release", "patient.exe")
PAUSE = float(os.environ.get("DEMO_PAUSE", "1.2"))

# --- pretty output -----------------------------------------------------------
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
CYAN, GREEN, YELLOW, RED, MAG = "\033[36m", "\033[32m", "\033[33m", "\033[31m", "\033[35m"


def pause(mult=1.0):
    if PAUSE:
        time.sleep(PAUSE * mult)


def section(n, title):
    print()
    print(f"{BOLD}{CYAN}{'─' * 78}{RESET}")
    print(f"{BOLD}{CYAN} {n}. {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 78}{RESET}")
    pause(0.6)


def agent(msg):
    print(f"{BOLD}{MAG}  agent ▸{RESET} {msg}")
    pause()


def operator(msg):
    print(f"{BOLD}{YELLOW}  operator ⌨{RESET} {msg}")
    pause()


def result(ok, msg):
    mark = f"{GREEN}✓{RESET}" if ok else f"{YELLOW}✋ blocked{RESET}"
    print(f"         {mark} {msg}")
    pause()


def shell(desc, cmd, env=None):
    print(f"{DIM}  $ {desc}{RESET}")
    out = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, env=env)
    for line in (out.stdout or "").splitlines():
        print(f"    {line}")
    pause()
    return out.stdout


# --- MCP client (synchronous; one request -> one response line) --------------
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
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def ensure_built():
    if not os.path.isfile(EXE):
        print("building heisenberg (release)...")
        subprocess.run(["cargo", "build", "--release"], cwd=REPO, check=True)
    if not os.path.isfile(PATIENT):
        print("building the patient (release)...")
        subprocess.run(["cargo", "build", "--release"], cwd=os.path.join(REPO, "demo", "patient"), check=True)


SYM = re.compile(r"[A-Za-z_]\w*![\w:~]+(?:\+0x[0-9a-fA-F]+)?")


def show_deadlock_evidence(raw):
    """Surface the signal from cdb's !locks/!cs/~*kb output: critical-section
    ownership lines when present, plus the lock-wait frames the threads are
    parked on (the symbol sits past the hex columns, so extract the token)."""
    wait = ("WaitForSingleObject", "NtWaitFor", "WaitOnAddress", "CriticalSection", "RtlpWait")
    lock_lines, wait_syms = [], []
    for line in raw.splitlines():
        if "Reading initial" in line:
            continue
        s = line.strip()
        if any(k in s for k in ("CritSec", "Owning thread", "OwningThread", "Lock count", "Critical section")):
            if s not in lock_lines:
                lock_lines.append(s)
        m = SYM.search(s)
        if m and any(w in m.group() for w in wait) and m.group() not in wait_syms:
            wait_syms.append(m.group())
    shown = lock_lines[:6] + [f"threads parked in {s}" for s in wait_syms[:3]]
    if not shown:
        shown = [m.group() for m in (SYM.search(l) for l in raw.splitlines()) if m][:6]
    for s in shown[:10]:
        print(f"    {DIM}{s[:92]}{RESET}")


def main():
    ensure_built()

    # A Critical box: no policy file + no trust escape hatch => fail-safe Critical.
    # Point the symbol path at the Microsoft server so cdb resolves ntdll for !locks.
    home = tempfile.mkdtemp(prefix="heisenberg_demo_")
    symcache = os.path.join(home, "symbols")
    env = dict(
        os.environ,
        HEISENBERG_HOME=home,
        RUST_LOG="error",
        _NT_SYMBOL_PATH=f"srv*{symcache}*https://msdl.microsoft.com/download/symbols",
    )
    env.pop("HEISENBERG_POLICY", None)
    env.pop("HEISENBERG_TRUST_UNSIGNED", None)

    print(f"{BOLD}Heisenberg — live debugging demo{RESET}")
    print(f"{DIM}an agent diagnoses a hung process, then hits the safety spine{RESET}")
    pause()

    # 1. Deploy check -------------------------------------------------------
    section(1, "Drop the binary on the box and check it's wired up")
    shell("heisenberg selfcheck", [EXE, "selfcheck"])

    # 2. The patient --------------------------------------------------------
    section(2, "A process is hung")
    patient = subprocess.Popen([PATIENT], stdout=subprocess.PIPE, text=True, env=env)
    line = patient.stdout.readline().strip()
    line2 = patient.stdout.readline().strip()
    print(f"    {DIM}{line}{RESET}")
    print(f"    {DIM}{line2}{RESET}")
    pid = patient.pid
    print(f"    the app stopped responding. pid {BOLD}{pid}{RESET}.")
    pause()

    c = Client(EXE, env)
    cleanup_tool = None
    try:
        c.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                              "clientInfo": {"name": "demo", "version": "0"}})
        c.call("notifications/initialized", notif=True)

        # 3. Agent investigates ---------------------------------------------
        section(3, "The agent investigates")
        who = c.tool("env.check", {})
        admin = who["data"].get("isAdmin", False)
        agent(f"checking the environment… {who['data']['os']['name']} build "
              f"{who['data']['os']['build']}, "
              f"{'elevated' if admin else 'not elevated'}")

        agent(f"capturing a full memory dump of the hung process (pid {pid})…")
        cap = c.tool("dump.capture", {"pid": pid, "full": True})
        if not cap.get("ok"):
            result(False, f"capture failed: {cap.get('error', {}).get('kind')}")
            return 1
        dump_id = cap["data"]["dumpId"]
        result(True, f"{cap['summary']}")

        agent("analyzing the dump for lock contention (!locks, !cs, all stacks)…")
        an = c.tool("analyze.deadlock", {"dump": dump_id})
        result(an.get("ok", False), an.get("summary", ""))
        raw = an.get("data", {}).get("raw", "") or ""
        print(f"    {BOLD}evidence:{RESET}")
        show_deadlock_evidence(raw)
        agent(f"{BOLD}root cause:{RESET} two worker threads deadlocked AB-BA — each "
              f"holds one critical section and blocks forever on the other.")

        # 4 + 5. Safety gate + human approval -------------------------------
        section(4, "The agent proposes a machine change — and the box says no")
        if admin:
            tool, args, token, what = (
                "gflags.set", {"image": "patient.exe"}, "enable-page-heap",
                "enable Full Page Heap on patient.exe to catch heap corruption on the next run",
            )
        else:
            tool, args, token, what = (
                "symbols.configure",
                {"path": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"},
                "set-symbol-path",
                "persist the Microsoft symbol path so the team can re-analyze this dump",
            )
        agent(f"I'd like to {what}.")
        blocked = c.tool(tool, args)
        result(blocked.get("ok", False),
               f"{tool}: {blocked.get('error', {}).get('kind')} — "
               f"{blocked.get('error', {}).get('message', '')}")
        print(f"    {DIM}this box is unclassified → fail-safe Critical → every mutation "
              f"needs a human.{RESET}")
        pause()

        section(5, "A human approves it out of band")
        operator(f"a person on the box runs:  heisenberg approve {tool}")
        shell(f"heisenberg approve {tool}", [EXE, "approve", tool], env=env)
        agent(f"retrying {tool} now that approval was granted…")
        done = c.tool(tool, dict(args, confirm=token))
        result(done.get("ok", False), done.get("summary", ""))
        cleanup_tool = tool if done.get("ok") else None

        # 6. Reversible -----------------------------------------------------
        section(6, "Every change is reversible")
        changes = c.tool("changes.list", {})
        entries = changes.get("data", {}).get("changes", []) or changes.get("data", {}).get("entries", [])
        if entries:
            ch = entries[-1]
            cid = ch.get("id")
            print(f"    ledger: {BOLD}{ch.get('tool', tool)}{RESET} → {ch.get('status','applied')} "
                  f"(id {cid})")
            pause()
            agent("rolling the change back…")
            rev = c.tool("changes.revert", {"id": cid})
            result(rev.get("ok", False), rev.get("summary", "reverted"))
            cleanup_tool = None
        else:
            print(f"    {DIM}(no ledger entry found to revert){RESET}")

        # 7. Wrap -----------------------------------------------------------
        section(7, "Done")
        print(f"    {GREEN}diagnosed a real deadlock from a dump, proposed a fix, kept a "
              f"human in control, and left the box as we found it.{RESET}")
        print(f"    {DIM}audit trail + dump are under {home}{RESET}")
        pause()
    finally:
        # Best-effort: if we approved+applied but didn't reach revert, undo it.
        if cleanup_tool:
            try:
                chs = c.tool("changes.list", {})
                for ch in chs.get("data", {}).get("changes", []):
                    if ch.get("status") == "applied":
                        c.tool("changes.revert", {"id": ch.get("id")})
            except Exception:
                pass
        c.close()
        patient.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
