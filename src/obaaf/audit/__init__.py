"""The settings audit: read a repository's GitHub settings, read-only, and record what was and was not read.

`obaaf check` reads workflow files. The incidents that hurt the first adopter were all in repository
settings, which no workflow file shows. This package reads those settings through GitHub's REST API with
GET requests only, writes them to a snapshot file, and can later work from that file with no network.

This first part reads and records. It applies no rule yet.
"""

from obaaf.audit.github import API_VERSION, DEFAULT_API, ApiUrlError, Client, ReplayTransport, UrllibTransport
from obaaf.audit.settings import BY_KEY, FORMAT, OWNER_REPO, REASONS, SETTINGS, Setting, take
from obaaf.audit.snapshot import SnapshotError, load, write

__all__ = ["API_VERSION", "ApiUrlError", "BY_KEY", "Client", "DEFAULT_API", "FORMAT", "OWNER_REPO", "REASONS",
           "ReplayTransport", "SETTINGS", "Setting", "SnapshotError", "UrllibTransport", "load", "take", "write"]
