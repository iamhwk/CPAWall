"""Manifest schema (design, Section 4.2).

A manifest states one project's reference policy (`policy`, optional) and
the grants of its channels (`grants`). Without a declared policy the
compiler takes the meet over the channels. The schema checks structure;
the compiler checks schemes and operations against the request mapping.
"""
from typing import Annotated, Literal

import yaml
from pydantic import (BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer,
                      ValidationError, model_validator)

from ..decisions import Decision

CHANNELS = ("shell", "fs", "web", "browser", "mcp", "connectors")

DecisionField = Annotated[Decision, BeforeValidator(Decision.parse),
                          PlainSerializer(str, return_type=str)]
OpTable = dict[str, DecisionField]


class Grant(BaseModel):
    """One grant of one channel: a resource pattern, a site, or (for the
    file tool) a path, with a decision per operation."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource: str | None = None
    site: str | None = None
    path: str | None = None
    server: str | None = None       # mcp: the tool server
    service: str | None = None      # connectors: the service
    ops: OpTable

    @model_validator(mode="after")
    def _one_target(self):
        if sum(x is not None for x in (self.resource, self.site, self.path)) != 1:
            raise ValueError("a grant names exactly one of resource, site, path")
        if not self.ops:
            raise ValueError("a grant lists at least one operation")
        return self

    def target(self):
        if self.resource is not None:
            return f"resource {self.resource}"
        if self.site is not None:
            return f"site {self.site}"
        return f"path {self.path}"


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    background: bool = False
    conflicts: list[str] = []       # projects that must share nothing with this one
    unmapped: Literal["ask", "deny"] = "ask"   # cap for unmapped state-changing requests
    policy: dict[str, OpTable] | None = None
    grants: dict[Literal[CHANNELS], list[Grant]] = {}

    @model_validator(mode="after")
    def _channel_shapes(self):
        for channel, grants in self.grants.items():
            for i, g in enumerate(grants):
                where = f"grants.{channel}[{i}]"
                if (channel == "fs") != (g.path is not None):
                    raise ValueError(f"{where}: file-tool grants, and only they, name a path")
                if (channel == "mcp") != (g.server is not None):
                    raise ValueError(f"{where}: mcp grants, and only they, name a server")
                if (channel == "connectors") != (g.service is not None):
                    raise ValueError(f"{where}: connector grants, and only they, name a service")
                if channel in ("mcp", "connectors") and g.resource is None:
                    raise ValueError(f"{where}: {channel} grants name a resource")
        if self.policy is not None and not self.policy:
            raise ValueError("policy: declare at least one entry, or omit it for the meet")
        return self


class ManifestError(ValueError):
    pass


def parse_manifest(data, source="<manifest>"):
    try:
        return Manifest.model_validate(data)
    except ValidationError as e:
        raise ManifestError(f"{source}: {e}") from None


def load_manifest(path):
    with open(path) as f:
        return parse_manifest(yaml.safe_load(f), path)
