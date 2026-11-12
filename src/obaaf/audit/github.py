"""A GitHub REST client that can only read.

The settings audit must never change anything, so this client has one verb, GET, and no way to send a
body. It sends a token only to the API host it was built for, follows a redirect only to that same host,
and stops asking as soon as GitHub says the rate limit is reached.

What the answers mean is decided in :mod:`obaaf.audit.settings`; this module only fetches them and says,
for an answer that is not a plain success, why it could not be used.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from obaaf import __version__

DEFAULT_API = "https://api.github.com"
# The version GitHub's REST reference used in its examples when this was written (2026-11-12).
API_VERSION = "2026-03-10"
TIMEOUT_SECONDS = 20
MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 3
MAX_PAGES = 10
PER_PAGE = 100
LOOPBACK = ("127.0.0.1", "localhost", "::1")
# Response headers worth keeping in a recording. Request headers are never recorded: one of them is the token.
RECORDED_HEADERS = ("content-type", "link", "location", "retry-after", "x-accepted-github-permissions",
                    "x-github-api-version-selected", "x-ratelimit-limit", "x-ratelimit-remaining",
                    "x-ratelimit-reset", "x-ratelimit-resource")


class ApiUrlError(ValueError):
    """The API address is not one this client will talk to."""


def check_api_url(url: str) -> str:
    """Return the API base without a trailing slash, or raise: HTTPS only, except on this machine."""
    parts = urllib.parse.urlsplit(url or "")
    host = parts.hostname or ""
    if parts.username or parts.password or parts.query or parts.fragment or not host:
        raise ApiUrlError(f"--api-url must be a plain address such as {DEFAULT_API}, got {url!r}")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in LOOPBACK):
        raise ApiUrlError("--api-url must use https (plain http is accepted only for this machine, for tests)")
    return url.rstrip("/")


@dataclass
class Raw:
    """One HTTP answer as it came off the wire. Status 0 means no answer was received."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect inside urllib: it would resend the Authorization header to the new host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102 - urllib's interface
        return None


class UrllibTransport:
    """The real network. TLS certificates are always verified; nothing here can turn that off."""

    def __init__(self) -> None:
        self._opener = self._build(urllib.request.ProxyHandler())
        # A server on this machine (tests) is reached directly, whatever proxy the environment names.
        self._local = self._build(urllib.request.ProxyHandler({}), urllib.request.HTTPHandler())

    @staticmethod
    def _build(*extra) -> urllib.request.OpenerDirector:
        # Built by hand so that only http(s) is ever opened: no file: or ftp: handler is installed, and
        # plain http exists only in the opener used for this machine.
        opener = urllib.request.OpenerDirector()
        for handler in (_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                        urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(),
                        urllib.request.UnknownHandler(), *extra):
            opener.add_handler(handler)
        return opener

    def get(self, url: str, headers: dict[str, str]) -> Raw:
        request = urllib.request.Request(url, headers=headers, method="GET")
        host = urllib.parse.urlsplit(url).hostname or ""
        opener = self._local if host in LOOPBACK else self._opener
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                return self._raw(response.status, response.headers, response)
        except urllib.error.HTTPError as exc:
            with exc:
                return self._raw(exc.code, exc.headers, exc)
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return Raw(0, error=f"{type(reason).__name__}: {reason}"[:300])
        except (ValueError, http.client.HTTPException) as exc:
            # The text of these errors can quote a header, and one header is the token: name the error only.
            return Raw(0, error=f"the request failed ({type(exc).__name__})")

    @staticmethod
    def _raw(status: int, headers, stream) -> Raw:
        try:
            body = stream.read(MAX_BODY_BYTES + 1)
        except OSError as exc:
            return Raw(0, error=f"the answer broke off: {exc}"[:300])
        return Raw(int(status), {k.lower(): v for k, v in (headers.items() if headers else [])}, body)


class ReplayTransport:
    """Answers from a recording instead of the network (tests, and looking at a recording someone sent).

    A request the recording does not hold is answered with status 0 and is listed in ``missing``, so a test
    can assert that the reader asked for nothing it was not expected to ask for.
    """

    def __init__(self, entries: list[dict], api: str = DEFAULT_API) -> None:
        self.api = api
        self.missing: list[str] = []
        self.seen: list[tuple[str, dict[str, str]]] = []
        self._answers: dict[str, list[dict]] = {}
        for entry in entries:
            self._answers.setdefault(entry["path"], []).append(entry)

    @classmethod
    def load(cls, directory: str | Path, api: str = DEFAULT_API) -> "ReplayTransport":
        data = json.loads((Path(directory) / "responses.json").read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("format") != RECORDING_FORMAT or not isinstance(
                data.get("responses"), list):
            raise ValueError(f"{directory}: not an {RECORDING_FORMAT} recording")
        return cls(data["responses"], api=api)

    def get(self, url: str, headers: dict[str, str]) -> Raw:
        path = url[len(self.api):] if url.startswith(self.api) else url
        self.seen.append((path, dict(headers)))
        answers = self._answers.get(path)
        if not answers:
            self.missing.append(path)
            return Raw(0, error="not in the recording")
        entry = answers.pop(0) if len(answers) > 1 else answers[0]
        body = entry.get("body")
        raw = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
        headers_out = {str(k).lower(): str(v) for k, v in (entry.get("headers") or {}).items()}
        return Raw(int(entry.get("status", 0)), headers_out, raw, str(entry.get("error", "")))


RECORDING_FORMAT = "obaaf-api-recording/v0.1"


@dataclass
class Answer:
    """A parsed answer. ``data`` is the JSON body on success; otherwise ``code`` and ``why`` say what went wrong."""

    status: int
    data: object = None
    code: str = ""      # "", or one of the reason codes in obaaf.audit.settings.REASONS
    why: str = ""       # plain words for a person
    accepted: str = ""  # GitHub's X-Accepted-GitHub-Permissions header, when it sent one
    message: str = ""   # GitHub's own error message, cleaned
    link: str = ""      # the Link header, which names the next page of a list

    @property
    def ok(self) -> bool:
        return not self.code


def plain(text: object, limit: int = 200) -> str:
    """Text from the API made safe to print: no control or direction-changing characters, bounded length."""
    cleaned = "".join(
        "?" if (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F or 0x202A <= ord(ch) <= 0x202E
                or 0x2066 <= ord(ch) <= 0x2069 or ord(ch) in (0x200E, 0x200F, 0x2028, 0x2029)) else ch
        for ch in str(text))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


class Client:
    """Read-only access to one API host. Every request is logged by path and status, never by header."""

    def __init__(self, transport=None, api: str = DEFAULT_API, token: str | None = None) -> None:
        self.api = check_api_url(api)
        self.transport = transport or UrllibTransport()
        self._token = token or None
        self.requests: list[dict] = []
        self.recorded: list[dict] = []
        self.rate_limited = ""  # set to the reason once GitHub says the limit is reached; no request follows

    @property
    def authenticated(self) -> bool:
        return self._token is not None

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
                   "User-Agent": f"obaaf/{__version__} (settings audit; read-only)"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _same_host(self, url: str) -> bool:
        ours, theirs = urllib.parse.urlsplit(self.api), urllib.parse.urlsplit(url)
        return (theirs.scheme, theirs.hostname, theirs.port) == (ours.scheme, ours.hostname, ours.port)

    def get(self, path: str) -> Answer:
        """GET one path under the API base and classify the answer."""
        if self.rate_limited:
            return Answer(0, code="rate_limited", why=f"not requested: {self.rate_limited}")
        url = self.api + path
        raw = Raw(0, error="no request was made")
        for _ in range(MAX_REDIRECTS + 1):
            raw = self.transport.get(url, self._headers())
            if self._token and self._token in raw.error:
                raw.error = raw.error.replace(self._token, "[token]")
            shown = url[len(self.api):] if url.startswith(self.api) else url
            self.requests.append({"path": shown, "status": raw.status})
            self._record(shown, raw)
            if raw.status not in (301, 302, 307, 308):
                break
            target = urllib.parse.urljoin(url, raw.headers.get("location", ""))
            if not self._same_host(target):
                return Answer(raw.status, code="unexpected",
                              why=f"GitHub redirected to another host ({plain(urllib.parse.urlsplit(target).hostname)}), "
                                  "which is not followed")
            url = target
        else:
            return Answer(raw.status, code="unexpected", why=f"more than {MAX_REDIRECTS} redirects")
        return self._classify(raw)

    def _record(self, path: str, raw: Raw) -> None:
        try:
            body: object = json.loads(raw.body.decode("utf-8")) if raw.body else None
        except (ValueError, UnicodeDecodeError):
            body = raw.body[:2000].decode("utf-8", "replace")
        entry = {"path": path, "status": raw.status,
                 "headers": {k: v for k, v in sorted(raw.headers.items()) if k in RECORDED_HEADERS}, "body": body}
        if raw.error:
            entry["error"] = raw.error
        self.recorded.append(entry)

    def _classify(self, raw: Raw) -> Answer:
        host = urllib.parse.urlsplit(self.api).hostname
        if raw.status == 0:
            return Answer(0, code="network", why=f"no answer from {host} ({plain(raw.error)})")
        if len(raw.body) > MAX_BODY_BYTES:
            return Answer(raw.status, code="unexpected", why="the answer was larger than 5 MB and was not read")
        data: object = None
        message = ""
        if raw.body:
            try:
                data = json.loads(raw.body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError):
                if 200 <= raw.status < 300:
                    return Answer(raw.status, code="unexpected", why="the answer was not JSON")
        if isinstance(data, dict) and isinstance(data.get("message"), str):
            message = plain(data["message"], 160)
        accepted = plain(raw.headers.get("x-accepted-github-permissions", ""), 200)
        said = f'; GitHub said "{message}"' if message else ""
        if raw.status in (403, 429) and (raw.headers.get("x-ratelimit-remaining") == "0"
                                         or "retry-after" in raw.headers or "rate limit" in message.lower()):
            self.rate_limited = "GitHub's rate limit was reached" + _reset_text(raw.headers) + (
                "" if self.authenticated else " (without a token GitHub allows 60 requests an hour for each "
                                              "IP address)")
            return Answer(raw.status, code="rate_limited", why=self.rate_limited, message=message)
        if 200 <= raw.status < 300:
            return Answer(raw.status, data=data, link=raw.headers.get("link", ""))
        if raw.status == 401:
            return Answer(401, code="unauthorized", why="GitHub did not accept the token (HTTP 401)" + said,
                          accepted=accepted, message=message)
        if raw.status == 403:
            return Answer(403, code="forbidden", why="this caller is not allowed to read it (HTTP 403)" + said,
                          accepted=accepted, message=message)
        if raw.status == 404:
            return Answer(404, code="not_found",
                          why="GitHub answered 404, which it also sends when the caller may not see something" + said,
                          accepted=accepted, message=message)
        if raw.status >= 500:
            return Answer(raw.status, code="server_error", why=f"GitHub had an error (HTTP {raw.status})" + said,
                          message=message)
        return Answer(raw.status, code="unexpected", why=f"unexpected answer (HTTP {raw.status})" + said,
                      accepted=accepted, message=message)

    def get_all(self, path: str, key: str | None = None) -> Answer:
        """GET every page of a list. ``key`` names the array inside a wrapper object such as ``{"secrets": [...]}``.

        On success ``data`` is the full list. A page that fails makes the whole list fail: half a list is
        not a list.
        """
        joiner = "&" if "?" in path else "?"
        url_path = f"{path}{joiner}per_page={PER_PAGE}"
        items: list = []
        total = None
        for _ in range(MAX_PAGES):
            answer = self.get(url_path)
            if not answer.ok:
                return answer
            page = answer.data
            if key is not None:
                if not isinstance(page, dict) or not isinstance(page.get(key), list):
                    return Answer(answer.status, code="unexpected",
                                  why=f"the answer did not hold a list named {key!r}, as GitHub documents")
                if isinstance(page.get("total_count"), int) and not isinstance(page.get("total_count"), bool):
                    total = page["total_count"]
                page = page[key]
            if not isinstance(page, list):
                return Answer(answer.status, code="unexpected", why="the answer was not a list, as GitHub documents")
            items.extend(page)
            next_url = _next_link(answer.link)
            if not next_url:
                break
            if not self._same_host(next_url) or not next_url.startswith(self.api + "/"):
                return Answer(answer.status, code="unexpected", why="the next page was on another host")
            url_path = next_url[len(self.api):]
        else:
            return Answer(200, code="unexpected",
                          why=f"more than {MAX_PAGES * PER_PAGE} entries; the list was not read to its end")
        if total is not None and total != len(items):
            return Answer(200, code="unexpected",
                          why=f"GitHub said there were {total} entries and returned {len(items)}")
        return Answer(200, data=items)

    def recording_text(self) -> str:
        """GitHub's answers as received, as JSON. Request headers are not in it; the token is cut out of
        the answers too, in case a server ever echoed it."""
        text = json.dumps({"format": RECORDING_FORMAT, "api": self.api, "responses": self.recorded}, indent=2,
                          ensure_ascii=True) + "\n"
        return text.replace(self._token, "[token]") if self._token else text


def _next_link(header: str) -> str:
    for part in header.split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"\s*$', part)
        if match:
            return match.group(1)
    return ""


def _reset_text(headers: dict[str, str]) -> str:
    reset = headers.get("x-ratelimit-reset", "")
    if reset.isdigit() and headers.get("x-ratelimit-remaining") == "0":
        try:
            return datetime.fromtimestamp(int(reset), tz=timezone.utc).strftime("; it resets at %H:%M UTC")
        except (OverflowError, OSError, ValueError):
            return ""
    retry = headers.get("retry-after", "")
    return f"; GitHub asks for a wait of {int(retry)} seconds" if retry.isdigit() else ""
