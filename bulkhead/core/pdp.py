"""Policy decision point (design, Section 4.4; considerations 3 and 7).

decide(pi, c, r, o) is a pure function of the project's current policy
P^v_pi: the minimum over the entries that match r and list o, deny if
none. It returns the decision, the version v, and the matching entries,
and ignores the channel except for the record (P2, P3).

authorize() is what a PEP calls. It adds three things to decide():
- tighten-only hooks: a checker (for example a model-based one) may
  lower a decision, never raise it;
- ask: a stored approval of matching scope and version answers it, and
  otherwise the trusted UI (an approval oracle in experiments) is asked;
- the record of what happened, for the log.

Policies are versioned: installing a policy gives it version v+1, and
approvals carry the version they were given under, so they lapse when it
changes (L2, stale).

Because a decision depends only on (P^v_pi, r, o), the PDP caches it under
(project, version, resource, operation): a new version is a new key, so
nothing has to be invalidated.
"""
import collections
import itertools
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass

from ..decisions import Decision
from ..policy.compiler import CompiledPolicy

SCOPES = ("request", "task", "project")


@dataclass(frozen=True)
class Verdict:
    decision: Decision            # what the PEP enforces: allow or deny (ask resolved)
    policy_decision: Decision     # decide() before hooks and approvals
    project: str
    channel: str
    resource: str
    op: str
    version: int
    entries: tuple = ()           # sources of the matching policy entries
    mapped: bool = True
    hooked: Decision | None = None   # after tighten-only hooks, if any lowered it
    asked: bool = False
    approval: str | None = None   # id of the approval that turned ask into allow

    def record(self):
        return {"project": self.project, "channel": self.channel, "resource": self.resource,
                "op": self.op, "policy_version": self.version,
                "decision": str(self.policy_decision), "final": str(self.decision),
                "rules": list(self.entries), "mapped": self.mapped,
                "hooked": str(self.hooked) if self.hooked is not None else None,
                "asked": self.asked, "approval": self.approval}


class PolicyStore:
    """Versioned policies per project; every version is archived."""

    def __init__(self, archive=None):
        self.archive = archive
        self._versions = {}
        self._lock = threading.Lock()

    def install(self, compiled):
        with self._lock:
            versions = self._versions.setdefault(compiled.project, [])
            v = len(versions) + 1
            compiled = compiled.with_version(v)
            versions.append(compiled)
        if self.archive:
            d = os.path.join(self.archive, compiled.project)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, f"v{v}.json"), "w") as f:
                json.dump(compiled.to_dict(), f, indent=1)
        return v

    def current(self, project):
        try:
            return self._versions[project][-1]
        except (KeyError, IndexError):
            raise KeyError(f"no policy installed for project {project!r}") from None

    def get(self, project, version):
        return self._versions[project][version - 1]

    def projects(self):
        return sorted(self._versions)

    @staticmethod
    def load_archived(path):
        with open(path) as f:
            return CompiledPolicy.from_dict(json.load(f))


@dataclass(frozen=True)
class Approval:
    id: str
    project: str
    resource: str
    op: str
    version: int
    scope: str = "request"        # request | task | project
    task: str | None = None
    expires: float | None = None  # project scope: time limit
    by: str = "trusted-ui"
    ts: float = 0.0

    def covers(self, project, resource, op, version, task, now):
        if (self.project, self.resource, self.op, self.version) != (project, resource, op, version):
            return False
        if self.scope == "task":
            return task is not None and task == self.task
        if self.scope == "project":
            return self.expires is None or now < self.expires
        return False                  # request scope: used once, when given


class Approvals:
    """Approvals given by the trusted UI; with `path`, each one is also
    appended there for the auditor (C5)."""

    def __init__(self, clock=time.time, path=None):
        self.clock = clock
        self.items = []
        self.path = path
        self._prefix = secrets.token_hex(3)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def grant(self, project, resource, op, version, scope="request", task=None, ttl=None,
              by="trusted-ui"):
        if scope not in SCOPES:
            raise ValueError(f"approval scope must be one of {SCOPES}")
        now = self.clock()
        with self._lock:
            a = Approval(f"a-{self._prefix}-{next(self._ids)}", project, resource, op, version,
                         scope, task, now + ttl if (scope == "project" and ttl) else None, by,
                         now)
            self.items.append(a)
            if self.path:
                with open(self.path, "a") as f:
                    f.write(json.dumps(a.__dict__) + "\n")
        return a

    def find(self, project, resource, op, version, task=None):
        now = self.clock()
        with self._lock:
            for a in reversed(self.items):
                if a.covers(project, resource, op, version, task, now):
                    return a
        return None

    def revoke(self, approval_id):
        with self._lock:
            self.items = [a for a in self.items if a.id != approval_id]

    def revoke_project(self, project):
        with self._lock:
            self.items = [a for a in self.items if a.project != project]


def _oracle_answer(answer):
    """An oracle answers True/False, or a dict with approve, scope, ttl."""
    if isinstance(answer, dict):
        return (bool(answer.get("approve")), answer.get("scope", "request"),
                answer.get("ttl"))
    return bool(answer), "request", None


class PDP:
    def __init__(self, store, oracle=None, approvals=None, cache_size=8192):
        self.store = store
        self.oracle = oracle              # the trusted UI; None: ask -> deny
        self.approvals = approvals or Approvals()
        self.hooks = []
        self.cache_size = cache_size      # 0: no cache
        self._cache = collections.OrderedDict()
        self._cache_lock = threading.Lock()

    def add_hook(self, hook):
        """hook(project, channel, resource, op, decision) -> Decision or None.
        A hook can only lower a decision (consideration 3)."""
        self.hooks.append(hook)

    def _policy_decide(self, policy, resource, op):
        if not self.cache_size or policy.version is None:
            return policy.decide(resource, op)
        key = (policy.project, policy.version, resource, op)
        hit = self._cache.get(key)
        if hit is None:
            hit = policy.decide(resource, op)
            with self._cache_lock:
                self._cache[key] = hit
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)          # oldest first
        return hit

    def decide(self, project, channel, resource, op, mapped=True):
        policy = self.store.current(project)
        d, hits = self._policy_decide(policy, resource, op)
        if not mapped and op != "read":
            d = min(d, policy.unmapped)   # unmapped state-changing requests
        return d, policy.version, tuple(e.source for e in hits)

    def authorize(self, project, channel, resource, op, mapped=True, task=None,
                  request=None):
        d0, v, entries = self.decide(project, channel, resource, op, mapped)
        d, hooked = d0, None
        for hook in self.hooks:
            h = hook(project, channel, resource, op, d)
            if h is not None and Decision.parse(h) < d:
                d = hooked = Decision.parse(h)
        asked, approval = False, None
        if d == Decision.ASK:
            a = self.approvals.find(project, resource, op, v, task)
            if a is None and self.oracle is not None:
                asked = True
                ok, scope, ttl = _oracle_answer(self.oracle(
                    {"project": project, "channel": channel, "resource": resource, "op": op,
                     "version": v, "task": task, "request": request}))
                if ok:
                    a = self.approvals.grant(project, resource, op, v, scope, task, ttl)
            if a is not None and self.store.current(project).version == v:
                d, approval = Decision.ALLOW, a.id
            else:
                d = Decision.DENY
        return Verdict(d, d0, project, channel, resource, op, v, entries, mapped, hooked,
                       asked, approval)
