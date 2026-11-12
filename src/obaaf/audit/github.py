"""A GitHub REST client that can only read.

The settings audit must never change anything, so this client has one verb, GET, and no way to send a
body. It sends a token only to the API host it was built for, follows a redirect only to that same host,
never fetches an address taken from a response header other than such a redirect, and stops asking as soon
as GitHub says the rate limit is reached. The token is cut out of everything that comes back before any
other code sees it.

What the answers mean is decided in :mod:`obaaf.audit.settings`; this module only fetches them and says,
for an answer that is not a plain success, why it could not be used.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import time
import unicodedata
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
TIMEOUT_SECONDS = 20          # for each read from the socket
REQUEST_SECONDS = 60          # for one whole answer, however slowly it arrives
MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_JSON_DEPTH = 100          # GitHub's answers are a handful of levels deep
RECORDED_TEXT_CHARS = 2000    # how much of an answer that is not JSON a recording keeps
RECORDED_ERROR_CHARS = 300    # and how much of a transport error
MAX_REDIRECTS = 3
MAX_PAGES = 10
PER_PAGE = 100
LOOPBACK = ("127.0.0.1", "localhost", "::1")
RECORDING_FORMAT = "obaaf-api-recording/v0.1"
# Response headers worth keeping in a recording. Request headers are never recorded: one of them is the token.
RECORDED_HEADERS = ("content-type", "link", "location", "retry-after", "x-accepted-github-permissions",
                    "x-github-api-version-selected", "x-ratelimit-limit", "x-ratelimit-remaining",
                    "x-ratelimit-reset", "x-ratelimit-resource")
REDACTED = "[token]"


class ApiUrlError(ValueError):
    """The API address is not one this client will talk to."""


def check_api_url(url: str) -> str:
    """Return the API base without a trailing slash, or raise: HTTPS only, except on this machine."""
    url = url or ""
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        parts, host, port = None, "", None
    plain_address = (parts is not None and host and url == url.strip() and len(url) <= 300
                     and "@" not in parts.netloc
                     and "?" not in url and "#" not in url and "\\" not in url
                     and (port is None or 0 < port < 65536))
    if not plain_address:
        raise ApiUrlError(f"--api-url must be a plain address such as {DEFAULT_API}")
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
        self.context = ssl.create_default_context()
        self._opener = self._build(urllib.request.ProxyHandler())
        # A server on this machine (tests) is reached directly, whatever proxy the environment names.
        self._local = self._build(urllib.request.ProxyHandler({}), urllib.request.HTTPHandler())

    def _build(self, *extra) -> urllib.request.OpenerDirector:
        # Built by hand so that only http(s) is ever opened: no file: or ftp: handler is installed, and
        # plain http exists only in the opener used for this machine.
        opener = urllib.request.OpenerDirector()
        for handler in (_NoRedirect(), urllib.request.HTTPSHandler(context=self.context),
                        urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(),
                        urllib.request.UnknownHandler(), *extra):
            opener.add_handler(handler)
        return opener

    def get(self, url: str, headers: dict[str, str]) -> Raw:
        try:
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
            return Raw(0, error=f"{type(reason).__name__}: {reason}")
        except (ValueError, http.client.HTTPException) as exc:
            # The text of these errors can quote a header, and one header is the token: name the error only.
            return Raw(0, error=f"the request failed ({type(exc).__name__})")

    @staticmethod
    def _raw(status: int, headers, stream) -> Raw:
        deadline = time.monotonic() + REQUEST_SECONDS
        chunks, size = [], 0
        while size <= MAX_BODY_BYTES:
            if time.monotonic() > deadline:
                return Raw(0, error=f"the answer took more than {REQUEST_SECONDS} seconds to arrive")
            chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        merged: dict[str, str] = {}
        for name in ({k.lower() for k in headers.keys()} if headers else ()):
            # A header may be sent on several lines; all of them count.
            merged[name] = ", ".join(headers.get_all(name) or [])
        return Raw(int(status), merged, b"".join(chunks))


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
        raw = body.encode("utf-8", "surrogatepass") if isinstance(body, str) else json.dumps(body).encode("utf-8")
        headers_out = {str(k).lower(): str(v) for k, v in (entry.get("headers") or {}).items()}
        return Raw(int(entry.get("status", 0)), headers_out, raw, str(entry.get("error", "")))


@dataclass
class Answer:
    """A parsed answer. ``data`` is the JSON body on success; otherwise ``code`` and ``why`` say what went wrong."""

    status: int
    data: object = None
    code: str = ""       # "", or one of the reason codes in obaaf.audit.settings.REASONS
    why: str = ""        # plain words for a person
    accepted: str = ""   # GitHub's X-Accepted-GitHub-Permissions header, when it sent one
    message: str = ""    # GitHub's own error message, cleaned for display
    exact: str = ""      # the same message exactly as it came; the one to compare, never the one to print
    more: bool = False   # a Link header named a next page

    @property
    def ok(self) -> bool:
        return not self.code


def plain(text: object, limit: int = 200) -> str:
    """Text from outside made safe to print on one line: nothing that moves the cursor, changes direction,
    hides, or cannot be encoded, and a bounded length. Every such character becomes a question mark, and
    every kind of space, or run of spaces, becomes one space."""
    cleaned = "".join("?" if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
                      else " " if unicodedata.category(ch) == "Zs" else ch for ch in str(text))
    # Runs of spaces become one: a long run could push the rest of a value to the start of the next
    # line of a terminal, where it would read as a line of the report.
    cleaned = re.sub(r" {2,}", " ", cleaned)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


# Characters that are not the ASCII double quote and read as one: curly and low double quotes, double
# primes, the ditto mark, the full-width quote. Single quotes and apostrophes are left alone; names have them.
QUOTE_LOOKALIKES = frozenset(map(chr, (0x201C, 0x201D, 0x201E, 0x201F, 0x2033, 0x2036, 0x301D, 0x301E, 0x301F,
                                       0xFF02, 0x02BA, 0x02DD, 0x02EE, 0x05F4, 0x3003)))


def quoted(name: object, limit: int = 60) -> str:
    """A name from outside, in double quotes, which it cannot close early to imitate the rest of its line.
    A character that looks like a double quotation mark without being one becomes a question mark."""
    cleaned = "".join("?" if ch in QUOTE_LOOKALIKES else ch for ch in plain(name, limit))
    return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _no_constants(name: str):
    raise ValueError(f"{name} is not JSON")


def _finite(text: str) -> float:
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError("a number too large to be one is not JSON this client reads")
    return value


def parse_json(data: bytes):
    """Strict JSON: NaN and Infinity, which Python would accept, are refused, and so is a number such as
    1e999, which Python would read as infinity and then write back as the word."""
    return json.loads(data.decode("utf-8"), parse_constant=_no_constants, parse_float=_finite)


class _TooDeep(ValueError):
    """An answer is nested more deeply than this client examines."""


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
        try:
            ours, theirs = urllib.parse.urlsplit(self.api), urllib.parse.urlsplit(url)
            return ("@" not in theirs.netloc
                    and (theirs.scheme, theirs.hostname, theirs.port) == (ours.scheme, ours.hostname, ours.port))
        except ValueError:
            return False

    # -- the token never leaves this class in anything that came back
    def _scrub_text(self, text: str) -> str:
        return text.replace(self._token, REDACTED) if self._token and self._token in text else text

    def _scrub(self, value, depth: int = 0):
        """A copy of parsed JSON with the token cut out of every string, keys included.

        An answer nested more deeply than :data:`MAX_JSON_DEPTH` is refused, with or without a token: no
        part of an answer is ever passed on unexamined."""
        if depth > MAX_JSON_DEPTH:
            raise _TooDeep()
        if isinstance(value, str):
            return self._scrub_text(value)
        if isinstance(value, list):
            return [self._scrub(v, depth + 1) for v in value]
        if isinstance(value, dict):
            return {self._scrub(k, depth + 1): self._scrub(v, depth + 1) for k, v in value.items()}
        return value

    def get(self, path: str) -> Answer:
        """GET one path under the API base and classify the answer."""
        if self.rate_limited:
            return Answer(0, code="rate_limited", why=f"not requested: {self.rate_limited}")
        url = self.api + path
        for _ in range(MAX_REDIRECTS + 1):
            raw = self.transport.get(url, self._headers())
            # Cut out the token first, shorten afterwards: shortening first could leave part of a token.
            raw.error = self._scrub_text(raw.error)[:RECORDED_ERROR_CHARS]
            raw.headers = {k: self._scrub_text(v) for k, v in raw.headers.items()}
            body, parsed, refused = self._parse(raw)
            shown = url[len(self.api):] if url.startswith(self.api) else url
            self.requests.append({"path": shown, "status": raw.status})
            self._record(shown, raw, body, parsed)
            if raw.status not in (301, 302, 307, 308):
                return self._classify(raw, body, parsed, refused)
            target = urllib.parse.urljoin(url, raw.headers.get("location", ""))
            if not self._same_host(target) or not target.startswith(self.api + "/"):
                return Answer(raw.status, code="unexpected",
                              why="GitHub redirected to another address, which is not followed")
            url = target
        return Answer(0, code="unexpected", why=f"more than {MAX_REDIRECTS} redirects")

    def _parse(self, raw: Raw) -> tuple[object, bool, str]:
        """The body as JSON with the token cut out, whether it could be used as JSON, and if not, why."""
        if not raw.body or len(raw.body) > MAX_BODY_BYTES:
            return None, False, "the answer was not JSON"
        try:
            return self._scrub(parse_json(raw.body)), True, ""
        except (_TooDeep, RecursionError):
            return None, False, f"the answer was nested more than {MAX_JSON_DEPTH} levels deep and was not examined"
        except (ValueError, UnicodeDecodeError):
            return None, False, "the answer was not JSON"

    def _record(self, path: str, raw: Raw, body: object, parsed: bool) -> None:
        if not parsed and raw.body:
            # The token is cut out of the whole text before the text is shortened, so that a token lying
            # across the cut cannot leave its first characters behind.
            body = self._scrub_text(raw.body.decode("utf-8", "replace"))[:RECORDED_TEXT_CHARS]
        entry = {"path": path, "status": raw.status,
                 "headers": {k: v for k, v in sorted(raw.headers.items()) if k in RECORDED_HEADERS}, "body": body}
        if raw.error:
            entry["error"] = raw.error
        self.recorded.append(entry)

    def _classify(self, raw: Raw, data: object, parsed: bool, refused: str = "") -> Answer:
        host = urllib.parse.urlsplit(self.api).hostname
        if raw.status == 0:
            return Answer(0, code="network", why=f"no answer from {host} ({plain(raw.error)})")
        if len(raw.body) > MAX_BODY_BYTES:
            return Answer(raw.status, code="unexpected", why="the answer was larger than 5 MB and was not read")
        exact = data["message"] if isinstance(data, dict) and isinstance(data.get("message"), str) else ""
        message = plain(exact, 160)
        accepted = plain(raw.headers.get("x-accepted-github-permissions", ""), 200)
        said = f"; GitHub said {quoted(message, 160)}" if message else ""
        limited = raw.status == 429 or (raw.status == 403 and (
            raw.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in raw.headers
            or "rate limit" in message.lower()))
        if limited:
            self.rate_limited = "GitHub's rate limit was reached" + _reset_text(raw.headers) + (
                "" if self.authenticated else " (without a token GitHub allows 60 requests an hour for each "
                                              "IP address)")
            return Answer(raw.status, code="rate_limited", why=self.rate_limited, message=message)
        if 200 <= raw.status < 300:
            if not parsed:
                return Answer(raw.status, code="unexpected", why=refused or "the answer was not JSON")
            return Answer(raw.status, data=data, more=_names_next_page(raw.headers.get("link", "")))
        if raw.status == 401:
            return Answer(401, code="unauthorized", why="GitHub did not accept the token (HTTP 401)" + said,
                          accepted=accepted, message=message)
        if raw.status == 403:
            return Answer(403, code="forbidden", why="this caller is not allowed to read it (HTTP 403)" + said,
                          accepted=accepted, message=message)
        if raw.status == 404:
            return Answer(404, code="not_found",
                          why="GitHub answered 404, which it also sends when the caller may not see something" + said,
                          accepted=accepted, message=message, exact=exact)
        if raw.status >= 500:
            return Answer(raw.status, code="server_error", why=f"GitHub had an error (HTTP {raw.status})" + said,
                          message=message)
        return Answer(raw.status, code="unexpected", why=f"unexpected answer (HTTP {raw.status})" + said,
                      accepted=accepted, message=message)

    def get_all(self, path: str, key: str | None = None) -> Answer:
        """GET every page of a list. ``key`` names the array inside a wrapper such as ``{"secrets": [...]}``.

        Pages are asked for by number, 100 entries at a time. The list is complete when a page comes back
        with fewer than 100 entries and no Link header naming a next page; an address in a Link header is
        never fetched. A wrapper must carry ``total_count``, and it must equal what was read. A page that
        fails, a list longer than the cap, or a count that disagrees makes the whole list fail: half a list
        is not a list.
        """
        joiner = "&" if "?" in path else "?"
        items: list = []
        total = None
        for number in range(1, MAX_PAGES + 1):
            answer = self.get(f"{path}{joiner}per_page={PER_PAGE}" + (f"&page={number}" if number > 1 else ""))
            if not answer.ok:
                return answer
            page = answer.data
            if key is not None:
                if not isinstance(page, dict) or not isinstance(page.get(key), list):
                    return Answer(answer.status, code="unexpected",
                                  why=f"the answer did not hold a list named {key!r}, as GitHub documents")
                count = page.get("total_count")
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    return Answer(answer.status, code="unexpected",
                                  why="the answer did not say how many entries there are (total_count), as "
                                      "GitHub documents")
                if total is not None and count != total:
                    return Answer(answer.status, code="unexpected", why="the count of entries changed between pages")
                total = count
                page = page[key]
            if not isinstance(page, list):
                return Answer(answer.status, code="unexpected", why="the answer was not a list, as GitHub documents")
            items.extend(page)
            if len(page) < PER_PAGE and not answer.more:
                break
            if not page:
                return Answer(answer.status, code="unexpected",
                              why="an empty page named a next page; the list was not read to its end")
        else:
            return Answer(200, code="unexpected",
                          why=f"{MAX_PAGES * PER_PAGE} entries or more; the list was not read to its end")
        if total is not None and total != len(items):
            return Answer(200, code="unexpected",
                          why=f"GitHub said there were {total} entries and returned {len(items)}")
        return Answer(200, data=items)

    def recording_text(self) -> str:
        """GitHub's answers as received, as JSON. Request headers are not in it, and the token was cut out
        of the answers when they arrived, in case a server ever echoed it."""
        return json.dumps({"format": RECORDING_FORMAT, "api": self.api, "responses": self.recorded}, indent=2,
                          ensure_ascii=True) + "\n"


def _names_next_page(header: str) -> bool:
    """Whether a Link header names a next page, read generously: any relation list that includes ``next``,
    quoted or not, in any case. Being wrong in this direction only costs one more request."""
    return bool(re.search(r"""\brel\s*=\s*(?:"[^"]*\bnext\b[^"]*"|'[^']*\bnext\b[^']*'|next\b)""", header, re.I))


def _reset_text(headers: dict[str, str]) -> str:
    reset = headers.get("x-ratelimit-reset", "")
    if re.fullmatch(r"[0-9]{1,12}", reset) and headers.get("x-ratelimit-remaining") == "0":
        try:
            return datetime.fromtimestamp(int(reset), tz=timezone.utc).strftime("; it resets at %H:%M UTC")
        except (OverflowError, OSError, ValueError):
            return ""
    retry = headers.get("retry-after", "")
    return f"; GitHub asks for a wait of {int(retry)} seconds" if re.fullmatch(r"[0-9]{1,6}", retry) else ""
