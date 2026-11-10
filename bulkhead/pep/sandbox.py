"""Partitions: the sandbox launcher (design, Section 4.5; consideration 1).

A partition is a set of processes that share one user, mount, network
and PID namespace and one Landlock domain. The core starts it with
`Partition.start()`, which runs this module as a fresh interpreter:

  helper   unshare(USER | NS | NET | PID); map its own uid and gid; fork
  init     (PID 1 of the partition) make every mount private; mount a
           new /proc, a private /tmp, /dev/shm and /run; hide what the policy
           denies (an empty read-only tmpfs over a folder, /dev/null over
           a file) and bind read-only what it only lets the project read;
           raise loopback; create the egress listeners on 127.0.0.1 and
           hand their descriptors to the core; set no_new_privs; apply
           Landlock (read-only system paths, read-write HOME and the
           private /tmp, devices; signals and abstract sockets scoped);
           then serve commands from the core until told to stop.

Commands the core sends run as children of init, so they inherit every
namespace and the Landlock domain, and none can undo them. Besides
one-shot commands, init can spawn a long-running process whose stdin and
stdout are a socket handed to the core (a tool server speaking MCP), and
can freeze and thaw every process in the partition (SIGSTOP and SIGCONT
to all of them, which only PID 1 of the namespace can do). The
partition's only route out is the listeners, whose other ends the core's
PEPs accept on; the project of every connection is that of the
partition, by construction (consideration 4). No socket path is visible
in the partition, so it cannot reach another project's PEP. When init
exits, the kernel kills every process in the partition.
"""
import ctypes
import fcntl
import glob
import json
import os
import selectors
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from . import landlock

PROTOTYPE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYSTEM_RO = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt",
             "/proc", PROTOTYPE)
DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty")
EGRESS = (("tools", 3128), ("browser", 3129))
MAX_OUT = 1 << 20
BROWSER_FLAGS = ("--no-sandbox", "--disable-gpu", "--no-first-run", "--disable-sync",
                 "--disable-background-networking", "--disable-component-update",
                 "--disable-default-apps", "--no-default-browser-check",
                 "--disable-dev-shm-usage", "--password-store=basic", "--use-mock-keychain",
                 "--disable-breakpad")
_FDS_HEADER = b"BULKHEAD-FDS"

_libc = ctypes.CDLL(None, use_errno=True)
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 1 << 18
PR_SET_PDEATHSIG, PR_SET_NO_NEW_PRIVS = 1, 38


class SandboxError(RuntimeError):
    pass


# -- framing over the control socket ---------------------------------------------
def send_frame(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("control socket closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock):
    (n,) = struct.unpack("!I", _recv_exact(sock, 4))
    return json.loads(_recv_exact(sock, n))


# -- system calls ------------------------------------------------------------------
def _check(r, what):
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"{what}: {os.strerror(e)}")


def mount(source, target, fstype, flags, data=None):
    enc = (lambda s: s.encode() if s is not None else None)
    _check(_libc.mount(enc(source), enc(target), enc(fstype), ctypes.c_ulong(flags),
                       enc(data)), f"mount {target}")


def prctl(option, arg):
    _check(_libc.prctl(option, ctypes.c_ulong(arg), 0, 0, 0), f"prctl {option}")


def loopback_up():
    SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        ifr = struct.pack("16sH14s", b"lo", 0, b"\0" * 14)
        flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b"\0" * 14))


# -- inside: helper and init ------------------------------------------------------------
def _under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _setup(cfg, ctl):
    """Runs as PID 1 of the new namespaces; returns the summary for the core."""
    notes = []
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    try:
        mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
        notes.append("/proc: this partition's processes only")
    except OSError as e:          # e.g. a container whose /proc is partly masked
        notes.append(f"/proc: shared with the host ({e.strerror})")
    # a private /tmp, /dev/shm and /run: besides keeping scratch files
    # apart, this hides the host's UNIX sockets (a desktop's D-Bus, the
    # Docker socket), which Landlock before ABI 9 does not stop a process
    # from connecting to. Folders of the partition that live there (a HOME
    # under /tmp, say) are bound back at the same path.
    scratch = [d for d in ("/tmp", "/dev/shm", "/run") if os.path.isdir(d)
               and not os.path.islink(d)]
    keep = []
    for path in sorted(cfg["rw"] + cfg["ro"]):
        if any(_under(path, d) for d in scratch) and not any(_under(path, k) for k in keep):
            keep.append(path)
    kept = {path: os.open(path, os.O_PATH | os.O_CLOEXEC) for path in keep
            if os.path.exists(path)}
    for d in scratch:
        mount("tmpfs", d, "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=256m")
    for path, fd in kept.items():
        if os.path.isdir(f"/proc/self/fd/{fd}"):
            os.makedirs(path, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "a").close()
        mount(f"/proc/self/fd/{fd}", path, None, MS_BIND | MS_REC)
        os.close(fd)
    for path in cfg.get("hide", []):
        if os.path.isdir(path):
            mount("tmpfs", path, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  "mode=0555,size=4k")
        elif os.path.lexists(path):
            mount("/dev/null", path, None, MS_BIND)
            mount(None, path, None, MS_BIND | MS_REMOUNT | MS_RDONLY)
    for path in cfg.get("readonly", []):
        if os.path.exists(path):
            mount(path, path, None, MS_BIND | MS_REC)
            mount(None, path, None, MS_BIND | MS_REMOUNT | MS_RDONLY)
    loopback_up()
    listeners = []
    for _, port in cfg["egress"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(128)
        listeners.append(s)
    socket.send_fds(ctl, [_FDS_HEADER], [s.fileno() for s in listeners])
    for s in listeners:
        s.close()
    prctl(PR_SET_NO_NEW_PRIVS, 1)
    rules = [(p, landlock.READ_ONLY) for p in cfg["ro"]]
    rules += [(p, landlock.DEVICE) for p in DEVICES]
    rules += [(p, (1 << 16) - 1) for p in cfg["rw"] + ["/tmp", "/dev/shm"]]
    try:
        summary = landlock.restrict(rules, scoped=True)
    except landlock.LandlockError as e:
        if cfg.get("landlock") == "required":
            raise
        summary = {"abi": 0, "error": str(e)}
        notes.append("Landlock: not applied")
    return {"landlock": summary, "notes": notes}


def _run(req, base_env):
    """Run one command as a child of init; returns exit code and output."""
    env = dict(base_env, **(req.get("env") or {}))
    argv, cwd = req["argv"], req.get("cwd") or env.get("HOME", "/")
    data = (req.get("stdin") or "").encode()
    deadline = time.monotonic() + float(req.get("timeout", 60))
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            os.dup2(in_r, 0)
            os.dup2(out_w, 1)
            os.dup2(err_w, 2)
            os.closerange(3, 1 << 16)
            os.chdir(cwd)
            os.execvpe(argv[0], argv, env)
        except BaseException as e:      # noqa: BLE001 - report and leave
            os.write(2, f"bulkhead: cannot run {argv[0]}: {e}\n".encode())
        finally:
            os._exit(127)
    for fd in (in_r, out_w, err_w):
        os.close(fd)
    sel = selectors.DefaultSelector()
    bufs = {out_r: bytearray(), err_r: bytearray()}
    for fd in bufs:
        os.set_blocking(fd, False)
        sel.register(fd, selectors.EVENT_READ)
    if data:
        os.set_blocking(in_w, False)
        sel.register(in_w, selectors.EVENT_WRITE)
    else:
        os.close(in_w)
    status, timed_out, exited_at = None, False, None
    while sel.get_map():
        now = time.monotonic()
        if now > deadline:
            timed_out = True
            break
        if exited_at and now - exited_at > 0.2:   # output left open by background jobs
            break
        for key, _ in sel.select(timeout=0.05):
            fd = key.fd
            if fd == in_w:
                try:
                    n = os.write(fd, data)
                    data = data[n:]
                except BrokenPipeError:
                    data = b""
                if not data:
                    sel.unregister(fd)
                    os.close(fd)
                continue
            chunk = os.read(fd, 65536)
            if chunk:
                if len(bufs[fd]) < MAX_OUT:
                    bufs[fd] += chunk[:MAX_OUT - len(bufs[fd])]
            else:
                sel.unregister(fd)
        if status is None:
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status, exited_at = st, time.monotonic()
    for key in list(sel.get_map().values()):
        sel.unregister(key.fd)
        os.close(key.fd)
    for fd in (out_r, err_r):
        try:
            os.close(fd)
        except OSError:
            pass
    if status is None:
        if timed_out:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        _, status = os.waitpid(pid, 0)
    return {"exit": os.waitstatus_to_exitcode(status), "timed_out": timed_out,
            "stdout": bufs[out_r].decode(errors="replace"),
            "stderr": bufs[err_r].decode(errors="replace")}


def _spawn(req, base_env, ctl):
    """Start a long-running process whose stdin and stdout are one end of a
    socket pair; the other end goes to the core."""
    env = dict(base_env, **(req.get("env") or {}))
    argv, cwd = req["argv"], req.get("cwd") or env.get("HOME", "/")
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            os.dup2(theirs.fileno(), 0)
            os.dup2(theirs.fileno(), 1)
            null = os.open("/dev/null", os.O_WRONLY)
            os.dup2(null, 2)
            os.closerange(3, 1 << 16)
            os.chdir(cwd)
            os.execvpe(argv[0], argv, env)
        except BaseException:      # noqa: BLE001
            pass
        finally:
            os._exit(127)
    theirs.close()
    socket.send_fds(ctl, [_FDS_HEADER], [ours.fileno()])
    ours.close()
    return {"pid": pid}


def _signal_all(sig):
    try:
        os.kill(-1, sig)          # from PID 1: every process in the namespace
    except ProcessLookupError:
        pass
    return {"ok": True}


def _reap():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _init(cfg, ctl):
    prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    try:
        summary = _setup(cfg, ctl)
    except Exception as e:     # noqa: BLE001 - the core decides what to do
        send_frame(ctl, {"error": f"{type(e).__name__}: {e}"})
        os._exit(1)
    send_frame(ctl, dict(summary, ready=True, pid=os.getpid()))
    while True:
        try:
            req = recv_frame(ctl)
        except (EOFError, OSError):
            break
        op = req.get("op")
        if op == "exit":
            break
        try:
            if op == "spawn":
                resp = _spawn(req, cfg["env"], ctl)
            elif op == "freeze":
                resp = _signal_all(signal.SIGSTOP)
            elif op == "thaw":
                resp = _signal_all(signal.SIGCONT)
            else:
                resp = _run(req, cfg["env"])
        except Exception as e:     # noqa: BLE001
            resp = {"exit": 127, "timed_out": False, "stdout": "",
                    "stderr": f"bulkhead: {type(e).__name__}: {e}"}
        _reap()
        send_frame(ctl, resp)
    os._exit(0)


def _helper(fd):
    ctl = socket.socket(fileno=fd)
    prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    cfg = recv_frame(ctl)
    uid, gid = os.getuid(), os.getgid()
    try:
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS | os.CLONE_NEWNET | os.CLONE_NEWPID)
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
        with open("/proc/self/uid_map", "w") as f:
            f.write(f"{uid} {uid} 1")
        with open("/proc/self/gid_map", "w") as f:
            f.write(f"{gid} {gid} 1")
    except OSError as e:
        send_frame(ctl, {"error": f"namespaces: {e}"})
        return 1
    pid = os.fork()
    if pid == 0:
        _init(cfg, ctl)
    ctl.close()
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


# -- outside: the core's handle on a partition ---------------------------------------------
class Partition:
    """A running partition of one project.

    home     the partition's HOME (read-write)
    rw, ro   further folders, read-write or read-only
    hide     paths inside the writable area that the policy denies
    readonly paths inside it that the policy lets the project only read
    env      the environment of every command (scrubbed; proxy and CA
             variables point at the partition's egress and Bulkhead's CA)
    """

    def __init__(self, project, home, env, rw=(), ro=(), hide=(), readonly=(),
                 egress=EGRESS, landlock_mode="required"):
        self.project, self.home = project, home
        self.cfg = {"env": dict(env, HOME=home), "rw": [home, *rw],
                    "ro": [p for p in (*SYSTEM_RO, *ro) if os.path.exists(p)],
                    "hide": list(hide), "readonly": list(readonly),
                    "egress": list(egress), "landlock": landlock_mode}
        self.listeners, self.summary = {}, None
        self.proc = self.ctl = None
        self.frozen = False
        self.lock = threading.Lock()

    def start(self, timeout=15):
        ctl, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "bulkhead.pep.sandbox", str(child.fileno())],
            pass_fds=[child.fileno()], cwd=PROTOTYPE, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": PROTOTYPE})
        child.close()
        self.ctl = ctl
        ctl.settimeout(timeout)
        try:
            send_frame(ctl, self.cfg)
            msg, fds, _, _ = socket.recv_fds(ctl, len(_FDS_HEADER), len(self.cfg["egress"]))
            if msg != _FDS_HEADER:
                raise SandboxError(self._error(msg))
            for (channel, _), fd in zip(self.cfg["egress"], fds):
                self.listeners[channel] = socket.socket(fileno=fd)
            ready = recv_frame(ctl)
            if not ready.get("ready"):
                raise SandboxError(ready.get("error", "partition failed to start"))
        except BaseException:
            self.stop()
            raise
        self.summary = ready
        return self

    def _error(self, first):
        rest = first
        try:
            rest += self.ctl.recv(65536)
        except OSError:
            pass
        try:
            return json.loads(rest[4:])["error"]
        except (ValueError, KeyError):
            return "partition failed to start"

    def run(self, argv, cwd=None, env=None, stdin=None, timeout=60):
        with self.lock:
            self.ctl.settimeout(timeout + 10)
            send_frame(self.ctl, {"op": "run", "argv": list(argv), "cwd": cwd, "env": env or {},
                                  "stdin": stdin, "timeout": timeout})
            return recv_frame(self.ctl)

    def spawn(self, argv, env=None, cwd=None):
        """Start a long-running process in the partition; returns a socket
        connected to its stdin and stdout."""
        with self.lock:
            self.ctl.settimeout(30)
            send_frame(self.ctl, {"op": "spawn", "argv": list(argv), "env": env or {},
                                  "cwd": cwd})
            msg, fds, _, _ = socket.recv_fds(self.ctl, len(_FDS_HEADER), 1)
            if msg != _FDS_HEADER or not fds:
                raise SandboxError(self._error(msg))
            resp = recv_frame(self.ctl)
        sock = socket.socket(fileno=fds[0])
        return sock, resp["pid"]

    def freeze(self):
        """Stop every process in the partition (SIGSTOP)."""
        with self.lock:
            send_frame(self.ctl, {"op": "freeze"})
            recv_frame(self.ctl)
        self.frozen = True

    def thaw(self):
        with self.lock:
            send_frame(self.ctl, {"op": "thaw"})
            recv_frame(self.ctl)
        self.frozen = False

    def trust_browser(self, ca_path, timeout=30):
        """Make browsers in the partition trust Bulkhead's CA (an NSS
        database in HOME, where Chromium looks); needs certutil."""
        script = ('mkdir -p "$HOME/.pki/nssdb" && '
                  '{ [ -f "$HOME/.pki/nssdb/cert9.db" ] || '
                  'certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password; } && '
                  'certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n bulkhead -i "$1"')
        r = self.run(["bash", "-c", script, "trust", ca_path], timeout=timeout)
        if r["exit"]:
            raise SandboxError(f"cannot add the CA to the browser: {r['stderr'].strip()}")

    def browse(self, url, browser, timeout=30):
        """Load `url` in a headless browser in the partition, with its own
        profile in HOME, through the browser egress; returns the DOM."""
        port = dict(self.cfg["egress"])["browser"]
        return self.run([browser, *BROWSER_FLAGS, f"--user-data-dir={self.home}/.browser",
                         f"--proxy-server=http://127.0.0.1:{port}", "--dump-dom", url],
                        timeout=timeout)

    def stop(self):
        for s in self.listeners.values():
            s.close()
        self.listeners = {}
        if self.ctl:
            try:
                send_frame(self.ctl, {"op": "exit"})
            except OSError:
                pass
            self.ctl.close()
            self.ctl = None
        if self.proc:
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None


def headless_browser():
    """Playwright's headless Chromium shell, if installed."""
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH",
                          os.path.expanduser("~/.cache/ms-playwright"))
    hits = sorted(glob.glob(os.path.join(root, "chromium_headless_shell-*", "*",
                                         "chrome-headless-shell")))
    return hits[-1] if hits else None


def policy_layout(policy, home):
    """Folders the policy hides or makes read-only inside HOME.

    For each file entry `file://~/<p>/**`, the folder is hidden where the
    project may not read it, and bound read-only where it may read but not
    write. The kernel cannot ask, so ask counts as deny here: the partition
    is then stricter than the policy, and the result says where.
    """
    from ..decisions import Decision
    from ..policy import patterns
    hide, readonly, stricter = [], [], []
    for e in policy.entries:
        if patterns.scheme(e.pattern) != "file":
            continue
        rest = e.pattern[len("file://"):]
        if not rest.startswith("~/"):
            continue
        base = rest[2:].rstrip("/")
        base = base[:-3] if base.endswith("/**") else base
        if any(patterns.is_glob(s) for s in base.split("/")):
            continue
        witness = f"file://~/{base}/{patterns.ANY}"
        r, _ = policy.decide(witness, "read")
        w, _ = policy.decide(witness, "write")
        path = os.path.join(home, base)
        if r < Decision.ALLOW:
            hide.append(path)
            if r == Decision.ASK:
                stricter.append((base, "read"))
        elif w < Decision.ALLOW:
            readonly.append(path)
            if w == Decision.ASK:
                stricter.append((base, "write"))
    return sorted(set(hide)), sorted(set(readonly)), stricter


if __name__ == "__main__":
    sys.exit(_helper(int(sys.argv[1])))
