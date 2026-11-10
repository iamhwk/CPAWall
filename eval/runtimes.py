"""Configurations: the platform a trial runs on.

A runtime holds one trial's contexts, one per project the trial touches,
and carries out the harness actions a probe can take: switch the active
project, change the policy, and run steps left in the background.

  baseline           shared substrate: one HOME for both projects; the
                     platform applies its per-channel settings; tool
                     servers run with each project's token; connectors of
                     the platform account reach every project
  pep-shared         the baseline, with every HTTP(S) request through the
                     project's PEP (ablation: no partitions)
  capscope           CapScope-style harness on the shared substrate: each
                     agent holds read, write and execute capabilities by
                     path and argument-vector prefix, minted from the
                     trusted task (paper, Sec. 4, RQ5); network and
                     secrets are left to process sandboxing
  simple-isolation   one container per project: own HOME and sign-ins,
                     partitions with an allow-all forwarder, no policy,
                     PDP or log; the platform still applies its settings
                     inside each container, and its account connectors
                     still reach every project (paper, Sec. 3.6)
  bulkhead           partitions, PEPs, the MCP gateway, the vault, the
                     session manager; connectors granted per project
  bulkhead-perchannel   ablation: each channel enforces its own grant
  bulkhead-noversions   ablation: approvals ignore the policy version
  bulkhead-nolabels     ablation: background work is attributed to the
                        active project

Platform behaviour emulated in the baselines, stated so it can be checked
against real platforms: an approval the user scopes beyond one request
("don't ask again") is kept for the session, and background work of a
single-session platform resolves settings and tool servers from the
active project.
"""
import copy
import json
import os
import shutil
import ssl
import urllib.error
import urllib.request
from urllib.parse import quote

from bulkhead.agent.scripted import Context
from bulkhead.agent.toolservers import GitHubServer, StagingDbServer
from bulkhead.core.pdp import PDP, Approvals
from bulkhead.env import proxy_env, trust_env
from bulkhead.pep import sandbox
from bulkhead.pep.forwarder import Forwarder
from bulkhead.pep.http_proxy import PepRunner
from testbed import setup as tb
from testbed.services import URLS


def deep_merge(base, patch):
    out = copy.deepcopy(base)
    for k, v in (patch or {}).items():
        out[k] = deep_merge(out.get(k, {}), v) if isinstance(v, dict) and \
            isinstance(out.get(k), dict) else copy.deepcopy(v)
    return out


def connector_call(service, name, args, headers=None, cafile=None, proxy=None):
    """One call of a first-party connector (the team chat)."""
    if service != "chat" or name not in ("read", "send"):
        return "error", f"unknown connector {service}.{name}"
    url = f"{URLS['chat']}/channels/{quote(str(args.get('channel', '')), safe='')}/messages"
    data = json.dumps({"text": args.get("text", "")}).encode() if name == "send" else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers=dict(headers or {}, **{"Content-Type": "application/json"}))
    handlers = [urllib.request.ProxyHandler({"https": proxy} if proxy else {})]
    if cafile:
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(
            cafile=cafile)))
    try:
        with urllib.request.build_opener(*handlers).open(req, timeout=30) as r:
            return "ok", r.read().decode()
    except urllib.error.HTTPError as e:
        return "error", f"HTTP {e.code}: {e.read().decode(errors='replace')}"
    except (urllib.error.URLError, OSError) as e:
        return "error", str(getattr(e, "reason", e))


class Runtime:
    substrate = "shared"          # shared | isolated | partitioned
    deployment = False            # needs Bulkhead's core
    misattributes = True          # background work runs as the active project

    def __init__(self, ws, dep, homes, probe, cond, oracle, task):
        self.ws, self.dep, self.homes, self.probe = ws, dep, homes, probe
        self.oracle, self.task = oracle, task
        self.active = probe["project"]
        self.connected = probe["conditions"][cond].get("connectors", {})
        self.ctxs = {}
        self.platform_approvals = {}            # one platform session

    # -- contexts ----------------------------------------------------------------------
    def context(self, project):
        if project not in self.ctxs:
            self.ctxs[project] = self.make_context(project)
        return self.ctxs[project]

    def background_context(self, origin):
        """Where a step left in the background runs, or None if suspended."""
        return self.context(self.active if self.misattributes else origin)

    def settings(self, project):
        with open(os.path.join(self.project_dir(project), ".agent", "settings.json")) as f:
            return json.load(f)

    def project_dir(self, project):
        return os.path.join(self.homes[project], tb.PROJECT_DIRS[project])

    def tool_servers(self, project, env):
        creds, ident = self.ws.creds(), f"{project}-bot"
        out = {"github": GitHubServer(URLS["git"], ident, creds["git"][ident], env=env)}
        if ident in creds.get("db", {}):
            out["stagingdb"] = StagingDbServer(URLS["db"], creds["db"][ident], env=env)
        return out

    def account_connector(self, service, name, args):
        """The platform account's connector, connected once by the user and
        offered in every project (it runs in the platform, not locally)."""
        owner = self.connected.get(service)
        if not owner:
            return "error", f"the {service} connector is not connected"
        token = self.ws.creds()[service][f"{owner}-bot"]
        return connector_call(service, name, args, {"Authorization": f"Bearer {token}"},
                              cafile=self.ws.ca_bundle())

    def make_context(self, project):
        env = trust_env(self.ws.ca_bundle())
        return Context(project=project, project_dir=self.project_dir(project),
                       home=self.homes[project], env=env, settings=self.settings(project),
                       oracle=self.oracle, tool_servers=self.tool_servers(project, env),
                       connectors=self.account_connector,
                       platform_approvals=self.platform_approvals, task=self.task)

    # -- harness actions ----------------------------------------------------------------------
    def switch(self, project):
        self.active = project
        self.context(project)

    def change_policy(self, change):
        ctx = self.context(change["project"])
        if ctx.settings is not None:
            ctx.settings = deep_merge(ctx.settings, change.get("settings"))

    def close(self):
        pass


class Baseline(Runtime):
    pass


class PepShared(Runtime):
    deployment = True

    def make_context(self, project):
        ctx = super().make_context(project)
        ctx.env = self.dep.env(project)
        for srv in ctx.tool_servers.values():
            srv.env = ctx.env
        return ctx

    def change_policy(self, change):
        super().change_policy(change)
        self.dep.install(change["project"], policy_patch=change.get("policy"))


class CapScope(Runtime):
    def make_context(self, project):
        ctx = super().make_context(project)
        ctx.settings = None                     # the harness replaces the platform's checks
        task = self.probe.get("task", {})
        ctx.capabilities = {k: task.get(k, []) for k in
                            ("read", "write", "execute", "tools", "connectors")}
        return ctx

    def change_policy(self, change):
        pass                                    # minted capabilities stand for the task


class SimpleIsolation(Runtime):
    substrate = "isolated"
    misattributes = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.runner, self.forwarder = PepRunner(), Forwarder()
        self.parts, self.servers = {}, []
        self.approvals_by_project = {}

    def make_context(self, project):
        home = self.homes[project]
        ca = os.path.join(home, ".config", "testbed", "ca.pem")
        os.makedirs(os.path.dirname(ca), exist_ok=True)
        shutil.copyfile(self.ws.ca_bundle(), ca)        # the container trusts the services
        egress = dict(sandbox.EGRESS)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": "/tmp",
               "GIT_TERMINAL_PROMPT": "0", **proxy_env(f"http://127.0.0.1:{egress['tools']}"),
               **trust_env(ca)}
        part = sandbox.Partition(project, home, env).start()
        self.parts[project] = part
        for ch in ("tools", "browser"):
            self.servers.append(self.runner.add_sock(self.forwarder, part.listeners[ch]))
        creds, ident = self.ws.creds(), f"{project}-bot"
        tool_env = {"PYTHONPATH": sandbox.PROTOTYPE,
                    "TOOLSERVER_GITHUB_URL": URLS["git"], "TOOLSERVER_GITHUB_USER": ident,
                    "TOOLSERVER_GITHUB_SECRET": creds["git"][ident],
                    "TOOLSERVER_DB_URL": URLS["db"],
                    "TOOLSERVER_DB_SECRET": creds.get("db", {}).get(ident, "")}
        return Context(project=project, project_dir=self.project_dir(project), home=home,
                       settings=self.settings(project), oracle=self.oracle, partition=part,
                       tool_env=tool_env, connectors=self.account_connector,
                       platform_approvals=self.approvals_by_project.setdefault(project, {}),
                       task=self.task)

    def close(self):
        for srv in self.servers:
            self.runner.remove(self.forwarder, srv)
        for part in self.parts.values():
            part.stop()
        self.runner.stop()


class Bulkhead(Runtime):
    substrate = "partitioned"
    deployment = True
    misattributes = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        for project, overrides in self.probe.get("manifest_overrides", {}).items():
            self.dep.install(project, overrides=overrides)
        self.sessions = self.dep.sessions(self.homes)
        self.sessions.switch(self.active)

    def make_context(self, project):
        return Context(project=project, project_dir=self.project_dir(project),
                       home=self.homes[project], settings=None, oracle=self.oracle,
                       partition=self.sessions.partition(project),
                       gateway=self.sessions.gateway, task=self.task,
                       connectors=lambda s, n, a: self.dep.connector(project, s, n, a))

    def background_context(self, origin):
        if self.misattributes:
            return self.context(self.active)
        part = self.sessions.parts.get(origin)
        if part and part[0].frozen:
            return None                          # its project may not run in the background
        return self.context(origin)

    def switch(self, project):
        self.sessions.switch(project)
        super().switch(project)

    def change_policy(self, change):
        project = change["project"]
        self.dep.dirty = True
        self.sessions.install(self.dep.compile(project, policy_patch=change.get("policy")))
        self.ctxs.pop(project, None)             # its partition may have been restarted

    def close(self):
        self.sessions.stop_all()


class PerChannel(PDP):
    """Ablation: each channel enforces its own grant where it has one."""
    def decide(self, project, channel, resource, op, mapped=True):
        pol = self.store.current(project)
        g, rules = pol.channel_grant({"tools": "shell"}.get(channel, channel), resource, op)
        if g is None:
            return super().decide(project, channel, resource, op, mapped)
        return g, pol.version, tuple(r.source for r in rules)


class UnversionedApprovals(Approvals):
    """Ablation: an approval outlives the policy version it was given under."""
    def find(self, project, resource, op, version, task=None):
        for a in reversed(self.items):
            if (a.project, a.resource, a.op) == (project, resource, op) and \
                    a.covers(project, resource, op, a.version, task, self.clock()):
                return a
        return None


class Unversioned(PDP):
    @property
    def approvals(self):
        return self._approvals

    @approvals.setter
    def approvals(self, value):
        self._approvals = value if isinstance(value, UnversionedApprovals) else \
            UnversionedApprovals(value.clock, value.path)


class BulkheadPerChannel(Bulkhead):
    pdp_class = PerChannel


class BulkheadNoVersions(Bulkhead):
    pdp_class = Unversioned


class BulkheadNoLabels(Bulkhead):
    misattributes = True


CONFIGS = {"baseline": Baseline, "pep-shared": PepShared, "capscope": CapScope,
           "simple-isolation": SimpleIsolation, "bulkhead": Bulkhead,
           "bulkhead-perchannel": BulkheadPerChannel, "bulkhead-noversions": BulkheadNoVersions,
           "bulkhead-nolabels": BulkheadNoLabels}
