#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deploy.py  v1.0  -  cross-platform deployer + supervisor for puzzle_sniper.py
=============================================================================
ONE FILE. PURE PYTHON STDLIB. WINDOWS CMD / macOS / LINUX.

WHAT IT DOES
  * verifies the working dir + puzzle_sniper.py presence (optionally fetches it)
  * launches the sniper SILENTLY in the background (pythonw on Windows, no window)
  * IS the always-on supervisor: 2s poll, crash/exit auto-restart with backoff,
    heartbeat file, duplicate-instance guard, clean shutdown (kills child tree)
  * registers ITSELF at logon/boot:
      Windows  -> Task Scheduler          (schtasks, onlogon, highest)
      macOS    -> LaunchAgent plist       (RunAtLoad + KeepAlive)
      Linux    -> systemd user unit       (Restart=always; crontab @reboot fallback)

COMMANDS
  deploy.py install     register auto-start AND start now
  deploy.py uninstall   remove auto-start AND stop
  deploy.py start       launch supervisor in background now
  deploy.py stop        stop supervisor + child
  deploy.py restart     stop then start
  deploy.py status      supervisor + child state, restarts, heartbeat age
  deploy.py logs        tail deploy.out + sniper.out
  deploy.py run         foreground supervisor (this is what autostart calls)
  deploy.py selftest    environment / path / permissions check

OPTIONS
  --dir DIR         working dir (default: dir of this script)
  --prio idle|below|normal   child priority (default idle)
  --sniper FILE     sniper filename (default puzzle_sniper.py)
  --fetch URL       download puzzle_sniper.py into the working dir if missing
  --console         keep a visible child console (default: silent)
"""

import argparse
import datetime as _dt
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time

IS_WIN = (os.name == "nt")
IS_MAC = (sys.platform == "darwin")
IS_LINUX = sys.platform.startswith("linux")

IDLE_PRIORITY         = 0x00000040
BELOW_NORMAL_PRIORITY = 0x00004000
NORMAL_PRIORITY       = 0x00000020

TASK_NAME   = "PuzzleSniperDeploy"
SVC_PID     = "supervisor.pid"
SVC_STATE   = "supervisor.json"
DEPLOY_OUT  = "deploy.out"
SNIPER_OUT  = "sniper.out"
LAUNCH_AGENT = "co.hackerai.puzzle_sniper.deploy.plist"
SYSTEMD_UNIT = "puzzle-sniper.service"

BACKOFF_MIN = 5
BACKOFF_MAX = 300
POLL        = 2

RUNNING = [True]
ARGS    = None
WORKDIR = None


# --------------------------------------------------------------------- console
def setup_console():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def log(msg):
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        with open(os.path.join(WORKDIR or ".", DEPLOY_OUT), "a",
                  encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
    except Exception:
        pass


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return default


# ---------------------------------------------------------------- process util
def pid_alive(pid):
    if not pid:
        return False
    pid = int(pid)
    if IS_WIN:
        try:
            import ctypes
            h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if not h:
                return False
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def kill_pid(pid):
    pid = int(pid)
    if not pid_alive(pid):
        return False
    if IS_WIN:
        subprocess.call(["taskkill", "/PID", str(pid), "/F", "/T"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(10):
                if not pid_alive(pid):
                    break
                time.sleep(0.5)
            if pid_alive(pid):
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    return True


# ------------------------------------------------------------------ state i/o
def state_write(child_pid, restarts, started, status):
    obj = {"supervisor_pid": os.getpid(), "child_pid": child_pid,
           "restarts": restarts, "started": started,
           "last_beat": time.time(), "status": status,
           "host": platform.node(), "platform": platform.system()}
    try:
        with open(os.path.join(WORKDIR, SVC_STATE), "w",
                  encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=2)
    except Exception:
        pass
    return obj


def state_read():
    try:
        with open(os.path.join(WORKDIR, SVC_STATE), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def heartbeat_age():
    st = state_read()
    if not st.get("last_beat"):
        return None
    return time.time() - st["last_beat"]


# ------------------------------------------------------------------ sniper cmd
def python_launcher(silent=True):
    """pythonw.exe on Windows when silent, else current interpreter."""
    py = sys.executable
    if IS_WIN and silent:
        alt = os.path.join(os.path.dirname(py), "pythonw.exe")
        if os.path.exists(alt):
            return alt
    return py


def sniper_path():
    return os.path.join(WORKDIR, ARGS.sniper)


def launch_child():
    sp = sniper_path()
    if not os.path.exists(sp):
        log("SNIPER MISSING: %s (use --fetch URL or drop the file there)" % sp)
        return None
    py = python_launcher(silent=not ARGS.console)
    cmd = [py, sp, "--no-dashboard", "--priority", ARGS.prio]
    out = open(os.path.join(WORKDIR, SNIPER_OUT), "ab")
    kw = {"cwd": WORKDIR, "stdout": out, "stderr": subprocess.STDOUT,
          "stdin": subprocess.DEVNULL}
    if IS_WIN:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        flags |= IDLE_PRIORITY if ARGS.prio == "idle" else (
            BELOW_NORMAL_PRIORITY if ARGS.prio == "below" else NORMAL_PRIORITY)
        if not ARGS.console:
            kw["creationflags"] = flags
    else:
        if hasattr(os, "nice"):
            kw["preexec_fn"] = lambda: os.nice(19)
    try:
        pr = subprocess.Popen(cmd, **kw)
    except Exception as e:
        log("spawn failed: %s" % e)
        try:
            out.close()
        except Exception:
            pass
        return None
    log("child started pid=%d cmd=%s" % (pr.pid, " ".join(cmd)))
    return pr


# ------------------------------------------------------------------- supervisor
def _on_signal(signum, _frame):
    RUNNING[0] = False


def supervisor_loop():
    sp = os.path.join(WORKDIR, SVC_PID)
    if os.path.exists(sp):
        try:
            old = int(read_text(sp).strip())
            if old != os.getpid() and pid_alive(old):
                log("another supervisor running (pid %d) - aborting" % old)
                return 1
        except Exception:
            pass
    write_text(sp, str(os.getpid()))
    log("supervisor up pid=%d dir=%s prio=%s" % (os.getpid(), WORKDIR, ARGS.prio))

    if IS_WIN:
        for s in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(s, _on_signal)
            except Exception:
                pass
    else:
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(s, _on_signal)
            except Exception:
                pass

    child = None
    restarts = 0
    started = time.time()
    delay = BACKOFF_MIN
    exit_code = 0

    try:
        while RUNNING[0]:
            if child is None:
                child = launch_child()
                if child is None:
                    state_write(0, restarts, started, "sniper-missing")
                    _sleep_interruptible(10)
                    continue
                state_write(child.pid, restarts, started, "running")
            rc = child.poll()
            if rc is not None:
                log("child exited rc=%s" % rc)
                child = None
                restarts += 1
                delay = min(BACKOFF_MAX, BACKOFF_MIN if restarts <= 1 else delay * 2)
                state_write(0, restarts, started, "restart-wait")
                log("restart #%d in %ds" % (restarts, delay))
                _sleep_interruptible(delay)
                continue
            state_write(child.pid, restarts, started, "running")
            _sleep_interruptible(POLL)
    finally:
        if child is not None and child.poll() is None:
            log("terminating child pid=%d" % child.pid)
            kill_pid(child.pid)
        state_write(0, restarts, started, "stopped")
        try:
            os.remove(sp)
        except Exception:
            pass
        log("supervisor down")
    return exit_code


def _sleep_interruptible(seconds):
    end = time.time() + seconds
    while RUNNING[0] and time.time() < end:
        time.sleep(min(1, max(0.05, end - time.time())))


# ------------------------------------------------------------------ autostart
def _self_cmd(background=False):
    py = python_launcher(silent=True) if not ARGS.console else sys.executable
    script = os.path.abspath(__file__)
    cmd = [py, script]
    if ARGS.dir:
        cmd += ["--dir", os.path.abspath(WORKDIR)]
    cmd += ["--prio", ARGS.prio]
    if ARGS.sniper != "puzzle_sniper.py":
        cmd += ["--sniper", ARGS.sniper]
    if not ARGS.console:
        pass
    return cmd


def install_startup():
    cmd = _self_cmd() + ["run"]
    if IS_WIN:
        tr = subprocess.list2cmdline(cmd)
        r = subprocess.run(["schtasks", "/create", "/tn", TASK_NAME,
                            "/tr", tr, "/sc", "onlogon", "/rl", "highest", "/f"],
                           capture_output=True, text=True)
        print((r.stdout or r.stderr).strip() or "schtasks create done")
    elif IS_MAC:
        plist = os.path.expanduser("~/Library/LaunchAgents/" + LAUNCH_AGENT)
        os.makedirs(os.path.dirname(plist), exist_ok=True)
        args_xml = "".join("<string>%s</string>" % a for a in cmd)
        write_text(plist, """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>co.hackerai.puzzle_sniper.deploy</string>
  <key>ProgramArguments</key><array>%s</array>
  <key>WorkingDirectory</key><string>%s</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>""" % (args_xml, WORKDIR,
                     os.path.join(WORKDIR, DEPLOY_OUT),
                     os.path.join(WORKDIR, DEPLOY_OUT)))
        subprocess.call(["launchctl", "unload", plist],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["launchctl", "load", plist])
        print("launchd agent installed: %s" % plist)
    else:
        unit_dir = os.path.expanduser("~/.config/systemd/user")
        unit_path = os.path.join(unit_dir, SYSTEMD_UNIT)
        have_systemd = bool(shutil.which("systemctl"))
        if have_systemd:
            os.makedirs(unit_dir, exist_ok=True)
            write_text(unit_path, """[Unit]
Description=HackerAI Puzzle Sniper (supervisor)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=10
Nice=19

[Install]
WantedBy=default.target
""" % (WORKDIR, subprocess.list2cmdline(cmd)))
            subprocess.call(["systemctl", "--user", "daemon-reload"])
            subprocess.call(["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT])
            print("systemd user unit installed + started: %s" % unit_path)
        else:
            line = "%s >/dev/null 2>&1" % subprocess.list2cmdline(cmd)
            subprocess.run('(crontab -l 2>/dev/null; echo "@reboot %s") | crontab -'
                           % line, shell=True)
            print("crontab @reboot installed (no systemd found)")
    print("auto-start installed -> supervisor relaunches sniper on crash + reboot")


def uninstall_startup():
    if IS_WIN:
        r = subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
                           capture_output=True, text=True)
        print((r.stdout or r.stderr).strip() or "schtasks delete done")
    elif IS_MAC:
        plist = os.path.expanduser("~/Library/LaunchAgents/" + LAUNCH_AGENT)
        subprocess.call(["launchctl", "unload", plist])
        try:
            os.remove(plist)
            print("launchd agent removed")
        except Exception:
            print("no plist found")
    else:
        if shutil.which("systemctl"):
            subprocess.call(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT])
            try:
                os.remove(os.path.expanduser("~/.config/systemd/user/" + SYSTEMD_UNIT))
            except Exception:
                pass
            subprocess.call(["systemctl", "--user", "daemon-reload"])
            print("systemd user unit removed")
        subprocess.run('crontab -l 2>/dev/null | grep -v "deploy.py" | crontab -',
                       shell=True)
        print("crontab entry removed (if any)")


# ---------------------------------------------------------- bg / stop / status
def start_bg():
    if pid_alive(int(st_read_pid() or 0)):
        print("supervisor already running (pid %s)" % st_read_pid())
        return 0
    cmd = _self_cmd() + ["run"]
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
          "stderr": subprocess.DEVNULL, "cwd": WORKDIR}
    if IS_WIN:
        kw["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0) |
                               getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) |
                               getattr(subprocess, "CREATE_NO_WINDOW", 0))
        kw["close_fds"] = True
    else:
        kw["start_new_session"] = True
    subprocess.Popen(cmd, **kw)
    print("supervisor launched in background -> %s" % os.path.join(WORKDIR, SVC_STATE))
    return 0


def st_read_pid():
    sp = os.path.join(WORKDIR, SVC_PID)
    return read_text(sp).strip() or str(state_read().get("supervisor_pid") or "")


def stop_all():
    st = state_read()
    cpid = st.get("child_pid")
    if cpid:
        log("stopping child pid=%s" % cpid)
        kill_pid(cpid)
    spid = st_read_pid()
    if spid:
        log("stopping supervisor pid=%s" % spid)
        kill_pid(spid)
    try:
        os.remove(os.path.join(WORKDIR, SVC_PID))
    except Exception:
        pass
    state_write(0, st.get("restarts", 0), st.get("started", 0), "stopped")
    print("stopped (supervisor + child)")


def status():
    st = state_read()
    spid = st_read_pid()
    sup_up = pid_alive(spid) if spid else False
    cpid = st.get("child_pid") or 0
    child_up = pid_alive(cpid) if cpid else False
    age = heartbeat_age()
    print("dir          : %s" % WORKDIR)
    print("sniper file  : %s (%s)" %
          (sniper_path(), "present" if os.path.exists(sniper_path()) else "MISSING"))
    print("supervisor   : %s (pid %s)" % ("UP" if sup_up else "DOWN", spid or "-"))
    print("child sniper : %s (pid %s)" % ("UP" if child_up else "DOWN", cpid or "-"))
    print("restarts     : %s" % st.get("restarts", 0))
    print("status       : %s" % st.get("status", "-"))
    print("heartbeat    : %s" % ("%.1fs ago" % age if age is not None else "none"))
    print("platform     : %s %s" % (platform.system(), platform.release()))
    return 0


def logs():
    for name in (DEPLOY_OUT, SNIPER_OUT):
        p = os.path.join(WORKDIR, name)
        print("==== %s ====" % p)
        if not os.path.exists(p):
            print("(none)")
            continue
        try:
            with open(p, "rb") as f:
                f.seek(max(0, os.path.getsize(p) - 6000))
                tail = f.read().decode("utf-8", "replace")
            for line in tail.splitlines()[-40:]:
                print(line)
        except Exception as e:
            print("read error: %s" % e)
    return 0


# ------------------------------------------------------------------- selftest
def selftest():
    ok = True
    print("python     : %s" % platform.python_version())
    print("platform   : %s" % platform.system())
    print("workdir    : %s" % WORKDIR)
    ok &= os.path.isdir(WORKDIR)
    ok &= os.path.exists(sniper_path())
    print("sniper     : %s" % ("OK" if os.path.exists(sniper_path()) else "MISSING"))
    pid = os.getpid()
    ok &= pid_alive(pid)
    print("pid_alive  : %s" % ok)
    probe = os.path.join(WORKDIR, ".deploy_probe")
    try:
        write_text(probe, "x"); os.remove(probe); w_ok = True
    except Exception:
        w_ok = False
    ok &= w_ok
    print("writable   : %s" % w_ok)
    if IS_WIN:
        ok &= bool(shutil.which("schtasks"))
        print("schtasks   : %s" % bool(shutil.which("schtasks")))
    elif IS_MAC:
        ok &= bool(shutil.which("launchctl"))
        print("launchctl  : %s" % bool(shutil.which("launchctl")))
    else:
        print("systemctl  : %s" % bool(shutil.which("systemctl")))
    print("hashcat    : %s" % (shutil.which("hashcat") or "not in PATH (optional)"))
    print("SELFTEST   : %s" % ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


# ----------------------------------------------------------------------- fetch
def fetch_sniper(url):
    dest = sniper_path()
    if os.path.exists(dest):
        print("sniper already present: %s" % dest)
        return 0
    import urllib.request
    print("fetching %s" % url)
    req = urllib.request.Request(url, headers={"User-Agent": "deploy/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    print("wrote %s (%d bytes)" % (dest, os.path.getsize(dest)))
    return 0


# ------------------------------------------------------------------------ main
def main():
    global ARGS, WORKDIR
    ap = argparse.ArgumentParser(
        description="deploy.py - cross-platform deployer/supervisor for puzzle_sniper.py")
    ap.add_argument("command", choices=["install", "uninstall", "start", "stop",
                                        "restart", "status", "logs", "run", "selftest"])
    ap.add_argument("--dir", default="")
    ap.add_argument("--prio", choices=["idle", "below", "normal"], default="idle")
    ap.add_argument("--sniper", default="puzzle_sniper.py")
    ap.add_argument("--fetch", metavar="URL")
    ap.add_argument("--console", action="store_true")
    ARGS = ap.parse_args()

    WORKDIR = os.path.abspath(ARGS.dir) if ARGS.dir else \
        os.path.dirname(os.path.abspath(__file__))
    if not os.path.isdir(WORKDIR):
        os.makedirs(WORKDIR, exist_ok=True)
    try:
        os.chdir(WORKDIR)
    except Exception:
        pass

    setup_console()

    if ARGS.fetch:
        fetch_sniper(ARGS.fetch); sys.exit(0)

    cmd = ARGS.command
    if cmd == "selftest": sys.exit(selftest())
    if cmd == "run":      sys.exit(supervisor_loop())
    if cmd == "start":    sys.exit(start_bg())
    if cmd == "stop":     stop_all(); sys.exit(0)
    if cmd == "restart":  stop_all(); time.sleep(2); sys.exit(start_bg())
    if cmd == "status":   sys.exit(status())
    if cmd == "logs":     sys.exit(logs())
    if cmd == "install":
        install_startup()
        if not pid_alive(int(st_read_pid() or 0)):
            start_bg()
        sys.exit(0)
    if cmd == "uninstall":
        uninstall_startup(); stop_all(); sys.exit(0)
    sys.exit(0)


if __name__ == "__main__":
    main()
