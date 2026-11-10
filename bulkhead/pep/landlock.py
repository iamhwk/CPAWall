"""Landlock through its three system calls (Linux 5.13+; ctypes, no deps).

Landlock lets an unprivileged process restrict itself and its future
children: a ruleset names the access rights it handles, path-beneath
rules allow some of them below given directories (or on given files),
and landlock_restrict_self() enforces the ruleset on the calling thread,
irreversibly and for every descendant. Rights a kernel does not know are
dropped (best effort), following the kernel documentation's advice to
check the ABI version at run time.

Reference: Linux kernel documentation, "Landlock: unprivileged access
control" (M. Salaun); ABI 2 adds REFER, 3 TRUNCATE, 4 TCP, 5 IOCTL_DEV,
6 scoping of abstract UNIX sockets and signals.
"""
import ctypes
import os
import platform

_SYSCALLS = {"x86_64": (444, 445, 446), "aarch64": (444, 445, 446)}

# filesystem access rights
EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR = 1 << 4, 1 << 5, 1 << 6, 1 << 7
MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK = 1 << 8, 1 << 9, 1 << 10, 1 << 11
MAKE_SYM, REFER, TRUNCATE, IOCTL_DEV = 1 << 12, 1 << 13, 1 << 14, 1 << 15
# scopes (ABI 6)
SCOPE_ABSTRACT_UNIX_SOCKET, SCOPE_SIGNAL = 1 << 0, 1 << 1

_FS_BY_ABI = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1, 4: (1 << 15) - 1}
FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV
READ_ONLY = EXECUTE | READ_FILE | READ_DIR
DEVICE = READ_FILE | WRITE_FILE | TRUNCATE | IOCTL_DEV


class LandlockError(OSError):
    pass


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _nr():
    try:
        return _SYSCALLS[platform.machine()]
    except KeyError:
        raise LandlockError(f"no Landlock syscall numbers for {platform.machine()}") from None


def abi_version():
    """The kernel's Landlock ABI version, or 0 if Landlock is unavailable."""
    try:
        create, _, _ = _nr()
    except LandlockError:
        return 0
    r = _libc.syscall(create, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
    return int(r) if r > 0 else 0


def handled_fs(abi):
    if abi >= 5:
        return (1 << 16) - 1
    return _FS_BY_ABI.get(abi, 0)


def scopes(abi):
    return SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL if abi >= 6 else 0


def restrict(rules, scoped=True, abi=None):
    """Enforce `rules`, [(path, rights)], on this thread and its future
    children. Paths that do not exist are skipped. Returns a summary.

    The caller must have set no_new_privs (or hold CAP_SYS_ADMIN).
    """
    abi = abi_version() if abi is None else abi
    if abi < 1:
        raise LandlockError("Landlock is not available")
    create, add_rule, restrict_self = _nr()
    fs = handled_fs(abi)
    attr = _RulesetAttr(fs, 0, scopes(abi) if scoped else 0)
    size = ctypes.sizeof(_RulesetAttr) if abi >= 6 else 16   # scoped field from ABI 6
    rfd = _libc.syscall(create, ctypes.byref(attr), ctypes.c_size_t(size), ctypes.c_uint32(0))
    if rfd < 0:
        raise LandlockError(ctypes.get_errno(), "landlock_create_ruleset failed")
    added, skipped = [], []
    try:
        for path, rights in rules:
            try:
                fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                skipped.append(path)
                continue
            try:
                allowed = rights & fs
                if not os.path.isdir(path):
                    allowed &= FILE_RIGHTS
                if not allowed:
                    continue
                rule = _PathBeneath(allowed, fd)
                if _libc.syscall(add_rule, ctypes.c_int(rfd), ctypes.c_int(1), ctypes.byref(rule),
                                 ctypes.c_uint32(0)) < 0:
                    raise LandlockError(ctypes.get_errno(), f"landlock_add_rule failed for {path}")
                added.append(path)
            finally:
                os.close(fd)
        if _libc.syscall(restrict_self, ctypes.c_int(rfd), ctypes.c_uint32(0)) < 0:
            raise LandlockError(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        os.close(rfd)
    return {"abi": abi, "rules": added, "skipped": skipped,
            "scoped": bool(scoped and abi >= 6)}
