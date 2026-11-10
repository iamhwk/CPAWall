"""Session manager (design, Section 4.5, Figure 3).

The session manager is driven only by the trusted UI: the agent has no
interface to it, so neither the agent nor injected content can switch
projects. It
- starts a project's partition when the project is first used, and keeps
  it, so the project's sessions persist (R5);
- switches the active project: partitions of other projects that may not
  work in the background are frozen, and the new active one is thawed;
- installs new policy versions: approvals lapse with the version (in the
  PDP), and a partition whose file layout changes is stopped, to be
  started again on its next use;
- logs every transition with the policy versions of the projects it
  concerns.
Attribution never depends on which project is active: a request belongs
to the partition whose egress it arrives on (consideration 4).
"""
import threading


class SessionManager:
    def __init__(self, start, store, log=None, layout=None, gateway=None):
        """start(project) -> (partition, stop); layout(project) -> a value
        that changes when the project's file layout changes."""
        self.start, self.store, self.log = start, store, log
        self.layout, self.gateway = layout, gateway
        self.parts = {}
        self.active = None
        self.lock = threading.RLock()

    def _event(self, **rec):
        rec = dict(rec, pep="session", channel="session")
        return self.log.append(rec) if self.log else rec

    def _version(self, project):
        try:
            return self.store.current(project).version
        except KeyError:
            return None

    def background(self, project):
        return self.store.current(project).background

    def partition(self, project):
        """The project's partition, started on first use. Call it first
        from a thread that lives as long as the partition should: the
        sandbox kills a partition when the thread that started it exits
        (PR_SET_PDEATHSIG is per thread)."""
        with self.lock:
            if project not in self.parts:
                part, stop = self.start(project)
                self.parts[project] = (part, stop,
                                       self.layout(project) if self.layout else None)
                if self.active and project != self.active and not self.background(project):
                    part.freeze()
                self._event(event="start", project=project,
                            policy_version=self._version(project))
            return self.parts[project][0]

    def switch(self, project, by="trusted-ui"):
        with self.lock:
            previous, self.active = self.active, project
            frozen = []
            for p, (part, _, _) in self.parts.items():
                if p == project:
                    if part.frozen:
                        part.thaw()
                elif not self.background(p) and not part.frozen:
                    part.freeze()
                    frozen.append(p)
            return self._event(event="switch", by=by, project=project, previous=previous,
                               versions={p: self._version(p) for p in {project, previous} if p},
                               frozen=frozen)

    def install(self, compiled, by="trusted-ui"):
        """Install a new policy version for its project."""
        with self.lock:
            project = compiled.project
            v = self.store.install(compiled)
            restarted = False
            if project in self.parts and self.layout:
                if self.layout(project) != self.parts[project][2]:
                    self.stop(project)
                    restarted = True
            self._event(event="policy", by=by, project=project, policy_version=v,
                        restarted=restarted)
            return v

    def stop(self, project):
        with self.lock:
            entry = self.parts.pop(project, None)
            if self.gateway:
                self.gateway.close_project(project)
            if entry:
                entry[1]()
                self._event(event="stop", project=project)

    def stop_all(self):
        with self.lock:
            for project in list(self.parts):
                self.stop(project)
