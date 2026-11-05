"""Evidence acquisition: the only place HowlProof records where a source's bytes came from.

Nothing here runs during `evaluate`. Retrieval is an explicit operator action
(`howlproof acquire`) that writes an *acquisition record* and the raw bytes into an
**acquisition store**: a directory the operator owns, outside any claim bundle. An
evaluation later verifies a bundle's evidence against that store.

What this does and does not establish:

* A RETRIEVED record says HowlProof's own fetcher received these bytes from that
  location at that time, through validated redirects. It does not say the bytes are true.
* An OPERATOR_FILE record says an operator handed HowlProof a file and attested to where
  it came from. The origin is as attested, not observed.
* Records carry a digest over their own content, so an edited record or swapped bytes is
  detected. That is tamper *evidence*, not authentication: anyone who can write to the
  store can forge a record. There is no signing key and no execution boundary here, and
  this module does not pretend otherwise.

Fetching is bounded and SSRF-resistant: http(s) only, default ports only, no credentials in
the URL, every resolved address and every redirect hop must be a global unicast address,
the connection is pinned to the address that was validated, size, time and redirects are
capped, and only inert text content types are kept. Downloaded content is stored verbatim
and never executed or interpreted.
"""

from __future__ import annotations

import getpass
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from howlproof import __version__

ID_PATTERN = re.compile(r"^acq-[0-9a-f]{16}$")
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
SAFE_CONTENT_TYPES = frozenset(
    {
        "text/html",
        "text/plain",
        "text/markdown",
        "text/x-markdown",
        "text/csv",
        "text/xml",
        "application/xml",
        "application/xhtml+xml",
        "application/json",
    }
)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*$")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")


class AcquireError(ValueError):
    """A retrieval or store operation was refused or failed. The message says why."""


@dataclass(frozen=True)
class FetchLimits:
    max_bytes: int = 2 * 1024 * 1024
    timeout: float = 10.0
    redirects: int = 3


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


Transport = Callable[[str, str, int, str, str, dict[str, str], FetchLimits], Response]
Resolver = Callable[[str, int], list[Any]]


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


# -- policy -----------------------------------------------------------------------------


def check_address(address: str) -> None:
    """Refuse anything that is not a global unicast address, including embedded IPv4."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as bad:
        raise AcquireError(f"{address!r} is not an IP address") from bad
    candidates = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            candidates.append(ip.ipv4_mapped)
        if ip in _NAT64 or ip in _SIX_TO_FOUR or ip in _TEREDO:
            raise AcquireError(f"{address} is a non-public (translated or tunnelled) address")
    for candidate in candidates:
        if not candidate.is_global or candidate.is_multicast:
            raise AcquireError(f"{address} is a non-public address")


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: str
    port: int
    target: str
    url: str


def validate_url(url: str) -> ParsedUrl:
    """Syntax-level policy. Name resolution is checked separately, per request."""
    if not isinstance(url, str) or not url or len(url) > 2000 or re.search(r"[\s\x00-\x1f]", url):
        raise AcquireError("url is empty, too long or contains whitespace or control characters")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise AcquireError(f"scheme {parts.scheme!r} is not supported; use http or https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise AcquireError("credentials in a url are not allowed")
    host = (parts.hostname or "").lower()
    if not host:
        raise AcquireError("url has no host")
    try:
        port = parts.port
    except ValueError as bad:
        raise AcquireError("url has an invalid port") from bad
    default = 443 if parts.scheme == "https" else 80
    if port not in (None, default):
        raise AcquireError(f"port {port} is not allowed; only the default port is permitted")
    if _is_ip(host):
        check_address(host)  # a literal IP is judged directly
    elif re.fullmatch(r"[0-9a-fx.]+", host):
        # decimal, hex and octal spellings of an address (2130706433, 0x7f000001, 0177.0.0.1)
        raise AcquireError(f"numeric host form {host!r} is not accepted")
    elif not _HOSTNAME.match(host) or host.endswith(".localhost"):
        raise AcquireError(f"host {host!r} is not a public DNS name")
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return ParsedUrl(parts.scheme, host, default, target, parts.geturl())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _resolve(host: str, port: int, resolve: Resolver) -> str:
    """Resolve and validate every answer; return the one address the connection is pinned to."""
    if _is_ip(host):
        check_address(host)
        return host
    try:
        infos = resolve(host, port)
    except OSError as bad:
        raise AcquireError(f"cannot resolve {host}: {bad}") from bad
    addresses = [str(info[4][0]) for info in infos]
    if not addresses:
        raise AcquireError(f"{host} resolved to no addresses")
    for address in addresses:
        check_address(address)  # one private answer refuses the whole name
    return addresses[0]


def _default_resolve(host: str, port: int) -> list[Any]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def _default_transport(
    scheme: str,
    ip: str,
    port: int,
    host: str,
    target: str,
    headers: dict[str, str],
    limits: FetchLimits,
) -> Response:
    deadline = time.monotonic() + limits.timeout
    sock = socket.create_connection((ip, port), timeout=limits.timeout)
    try:
        if scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        connection = http.client.HTTPConnection(host, port, timeout=limits.timeout)
        connection.sock = sock  # already connected to the validated address
        connection.request("GET", target, headers=headers)
        reply = connection.getresponse()
        chunks: list[bytes] = []
        size = 0
        while size <= limits.max_bytes:
            if time.monotonic() > deadline:
                raise TimeoutError("overall time limit exceeded")
            chunk = reply.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return Response(
            reply.status, {k.lower(): v for k, v in reply.getheaders()}, b"".join(chunks)
        )
    finally:
        sock.close()


# -- retrieval --------------------------------------------------------------------------


def acquire_url(
    url: str,
    *,
    limits: FetchLimits | None = None,
    transport: Transport | None = None,
    resolve: Resolver | None = None,
    now: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Fetch one URL under the policy above. Returns (record without id, raw bytes)."""
    limits = limits or FetchLimits()
    transport = transport or _default_transport
    resolve = resolve or _default_resolve
    current = validate_url(url)
    requested = current.url
    redirects: list[str] = []
    headers = {
        "User-Agent": f"howlproof-acquire/{__version__}",
        "Accept": "text/html,text/plain,text/markdown,application/json,application/xml",
        "Accept-Encoding": "identity",
    }
    for hop in range(limits.redirects + 1):
        ip = _resolve(current.host, current.port, resolve)
        try:
            reply = transport(
                current.scheme, ip, current.port, current.host, current.target, headers, limits
            )
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as bad:
            raise AcquireError(f"request to {current.url} failed: {bad}") from bad
        if reply.status in REDIRECT_STATUSES:
            location = reply.headers.get("location", "")
            if not location:
                raise AcquireError(f"redirect from {current.url} carried no location")
            if hop == limits.redirects:
                raise AcquireError(f"too many redirects (more than {limits.redirects})")
            current = validate_url(urljoin(current.url, location))
            redirects.append(current.url)
            continue
        if reply.status != 200:
            raise AcquireError(f"{current.url} returned status {reply.status}")
        content_type = reply.headers.get("content-type", "")
        if content_type.split(";")[0].strip().lower() not in SAFE_CONTENT_TYPES:
            raise AcquireError(
                f"content type {content_type or '(none)'!r} is not an accepted text type"
            )
        if len(reply.body) > limits.max_bytes:
            raise AcquireError(f"response is larger than {limits.max_bytes} bytes")
        record = {
            "kind": "RETRIEVED",
            "method": f"{current.scheme}_get",
            "requested_url": requested,
            "observed_url": current.url,
            "redirects": redirects,
            "retrieved_at": now or utc_now(),
            "http_status": reply.status,
            "content_type": content_type,
            "content_sha256": hashlib.sha256(reply.body).hexdigest(),
            "size": len(reply.body),
            "tool": f"howlproof/{__version__}",
            "limitations": [
                (
                    "bytes were received from the observed location at the recorded time; "
                    "this does not show the content is accurate or current"
                )
            ],
        }
        return record, reply.body
    raise AcquireError("redirect handling ended unexpectedly")  # pragma: no cover


def acquire_file(
    path: Path,
    *,
    source_url: str | None = None,
    operator: str | None = None,
    limits: FetchLimits | None = None,
    now: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Register a file the operator already holds. Its origin is attested, not observed."""
    limits = limits or FetchLimits()
    try:
        size = path.stat().st_size
        if size > limits.max_bytes:
            raise AcquireError(f"{path} is larger than {limits.max_bytes} bytes")
        raw = path.read_bytes()
    except OSError as bad:
        raise AcquireError(f"cannot read {path}: {bad}") from bad
    try:
        who = operator or getpass.getuser()
    except (KeyError, OSError):
        who = "unknown"
    record = {
        "kind": "OPERATOR_FILE",
        "method": "operator_supplied_file",
        "requested_url": None,
        "observed_url": None,
        "claimed_source_url": source_url,
        "attested_by": who,
        "redirects": [],
        "retrieved_at": now or utc_now(),
        "http_status": None,
        "content_type": None,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "tool": f"howlproof/{__version__}",
        "limitations": [
            (
                "file was supplied by the operator and not fetched by howlproof; "
                "where it came from is as attested, not observed"
            )
        ],
    }
    return record, raw


# -- the store --------------------------------------------------------------------------


@dataclass
class Verified:
    status: str
    record: dict[str, Any] | None = None
    raw: bytes = b""


class AcquisitionStore:
    """`raw/<sha256>` holds bytes; `records/<id>.json` holds one acquisition event each."""

    def __init__(self, root: Path):
        self.root = Path(root)

    @staticmethod
    def record_digest(record: dict[str, Any]) -> str:
        body = {k: v for k, v in record.items() if k != "record_sha256"}
        return hashlib.sha256(canonical_json(body)).hexdigest()

    def add(self, record: dict[str, Any], raw: bytes) -> dict[str, Any]:
        if hashlib.sha256(raw).hexdigest() != record.get("content_sha256"):
            raise AcquireError("record digest does not match the bytes being stored")
        sealed = dict(record)
        sealed["id"] = "acq-" + hashlib.sha256(canonical_json(record)).hexdigest()[:16]
        sealed["record_sha256"] = self.record_digest(sealed)
        (self.root / "raw").mkdir(parents=True, exist_ok=True)
        (self.root / "records").mkdir(parents=True, exist_ok=True)
        (self.root / "raw" / sealed["content_sha256"]).write_bytes(raw)
        (self.root / "records" / f"{sealed['id']}.json").write_text(
            json.dumps(sealed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return sealed

    def log_failure(self, source: str, error: str, now: str | None = None) -> None:
        """Failed attempts are recorded too; a missing source must be explainable."""
        self.root.mkdir(parents=True, exist_ok=True)
        entry = {"at": now or utc_now(), "source": source, "error": error}
        with (self.root / "attempts.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def verify(self, acquisition_id: Any, pointer_sha256: Any) -> Verified:
        """Check a bundle's pointer against the store. Never raises on bad input."""
        if not isinstance(acquisition_id, str) or not ID_PATTERN.match(acquisition_id):
            return Verified("MISSING")
        path = self.root / "records" / f"{acquisition_id}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return Verified("MISSING")
        if not isinstance(record, dict) or record.get("record_sha256") != self.record_digest(
            record
        ):
            return Verified("RECORD_TAMPERED")
        if record.get("id") != acquisition_id or record.get("content_sha256") != pointer_sha256:
            return Verified("POINTER_MISMATCH", record)
        digest = str(record["content_sha256"])
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            return Verified("RECORD_TAMPERED")
        try:
            raw = (self.root / "raw" / digest).read_bytes()
        except OSError:
            return Verified("MISSING", record)
        if hashlib.sha256(raw).hexdigest() != digest:
            return Verified("BYTES_MISMATCH", record)
        return Verified("OBSERVED", record, raw)
