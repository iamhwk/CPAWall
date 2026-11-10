"""Helpers shared by the test suites."""
import os
import socket
import time
import unittest

from testbed import setup as tb
from testbed.services import ADDRS, PORT


def testbed_unavailable():
    """None if the testbed can run here, else the reason it cannot."""
    if not tb.ensure_hosts():
        return "the testbed host names are not in /etc/hosts"
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # as the servers do
    try:
        s.bind((ADDRS["git"], PORT))
    except OSError as e:
        return f"cannot bind {ADDRS['git']}:{PORT}: {e}"
    finally:
        s.close()
    return None


def require(reason):
    """Class decorator: skip the suite if `reason` is set, but fail under CI,
    where every suite is expected to run."""
    def wrap(cls):
        if not reason:
            return cls
        if not os.environ.get("CI"):
            return unittest.skip(reason)(cls)

        def fail(_cls):
            raise RuntimeError(reason)
        cls.setUpClass = classmethod(fail)
        return cls
    return wrap


def require_testbed(cls):
    return require(testbed_unavailable())(cls)


def sandbox_unavailable():
    """None if partitions can run here (Landlock, unprivileged user and
    network namespaces), else the reason they cannot."""
    import subprocess
    import sys
    from bulkhead.pep import landlock
    if landlock.abi_version() < 1:
        return "Landlock is not available"
    r = subprocess.run([sys.executable, "-c",
                        "import os; os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)"],
                       capture_output=True, text=True)
    if r.returncode:
        return "unprivileged user namespaces are not available"
    return None


def require_sandbox(cls):
    return require(sandbox_unavailable())(cls)


HERE = os.path.dirname(os.path.abspath(__file__))
TESTBED = os.path.join(HERE, "..", "testbed")


def testbed_file(*parts):
    return os.path.join(TESTBED, *parts)


def ontology():
    from bulkhead.policy.ontology import Ontology
    return Ontology.load(testbed_file("ontology.yaml"))


def inventory():
    import yaml
    with open(testbed_file("inventory.yaml")) as f:
        return yaml.safe_load(f)["resources"]


def manifest_data(project):
    import yaml
    with open(testbed_file("manifests", f"{project}.yaml")) as f:
        return yaml.safe_load(f)


def compiled(project, drop_policy=False, **changes):
    """Compile a testbed manifest, optionally without its declared policy
    or with top-level fields replaced."""
    from bulkhead.policy.compiler import compile_manifest
    from bulkhead.policy.schema import parse_manifest
    data = manifest_data(project)
    if drop_policy:
        data.pop("policy")
    data.update(changes)
    return compile_manifest(parse_manifest(data), ontology(), inventory())


def settle(log, quiet=0.2, limit=5.0):
    """Wait until `log` has stopped growing. A PEP appends a request's record
    after it has relayed the response, so a client can be ahead of the log."""
    deadline = time.monotonic() + limit
    last = log.offset()
    while time.monotonic() < deadline:
        time.sleep(quiet)
        now = log.offset()
        if now == last:
            return
        last = now
