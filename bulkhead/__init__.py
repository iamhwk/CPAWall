"""Bulkhead (working name): projects as principals for LLM agent platforms.

Prototype of CPAWall, after the authors' design document (design-v0.4.2).
Each project gets its own partition (user and network namespace, Landlock,
HOME, browser profile), a single egress through a policy enforcement point
(PEP), and one resource-level reference policy that a deterministic PDP
enforces on every channel. See MILESTONES.md for the milestone status.
"""

__version__ = "0.1.0"
