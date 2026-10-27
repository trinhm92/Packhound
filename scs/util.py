"""Small helpers: logging, subprocess, HTTP with retries, cache paths."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

from scs import __version__

USER_AGENT = f"scs/{__version__} (Packhound)"
_verbose = False


def set_verbose(v: bool) -> None:
    global _verbose
    _verbose = v


_log_sinks: list = []  # extra receivers (the GUI streams progress from here)


def add_log_sink(fn) -> None:
    _log_sinks.append(fn)


def remove_log_sink(fn) -> None:
    if fn in _log_sinks:
        _log_sinks.remove(fn)


def log(msg: str) -> None:
    print(f"[scs] {msg}", file=sys.stderr)
    for sink in list(_log_sinks):
        try:
            sink(msg)
        except JobCancelled:
            raise
        except Exception:
            pass


def debug(msg: str) -> None:
    if _verbose:
        print(f"[scs:debug] {msg}", file=sys.stderr)


def host_id() -> str:
    """Stable machine name: macOS adds/drops ".local" (and DHCP may add a domain) as networks change."""
    import socket
    return normalize_host(socket.gethostname())


def normalize_host(name: str) -> str:
    return name.split(".")[0].lower() if name else name


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    p = Path(base) / "scs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    p = Path(base) / "scs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def run(cmd: list[str], timeout: int = 120, env_extra: Optional[dict] = None) -> Optional[str]:
    """Run a command and return stdout, or None if it is missing or fails."""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired) as e:
        debug(f"command {cmd[0]} failed: {e}")
        return None
    if r.returncode != 0:
        debug(f"command {' '.join(cmd)} exited {r.returncode}: {r.stderr[:300]}")
        return None
    return r.stdout


class HttpError(Exception):
    pass


class JobCancelled(BaseException):
    """Raised from log() when the GUI cancels a job (BaseException: not swallowed by `except Exception`)."""


# CA bundles maintained by the OS, used when Python's own store is empty (python.org builds and
# frozen apps ship without certificates; Windows loads its system store automatically).
CA_FALLBACKS = ["/etc/ssl/cert.pem",                       # macOS (Apple-maintained), Alpine
                "/etc/ssl/certs/ca-certificates.crt",      # Debian / Ubuntu
                "/etc/pki/tls/certs/ca-bundle.crt",        # Fedora / RHEL
                "/etc/ssl/ca-bundle.pem"]                  # openSUSE
_ssl_ctx = None


def ssl_context():
    global _ssl_ctx
    if _ssl_ctx is None:
        import ssl
        ctx = ssl.create_default_context()
        if not ctx.cert_store_stats().get("x509_ca"):
            for cafile in [os.environ.get("SSL_CERT_FILE", ""), *CA_FALLBACKS]:
                if cafile and os.path.isfile(cafile):
                    ctx.load_verify_locations(cafile=cafile)
                    debug(f"TLS: using CA bundle {cafile}")
                    break
        _ssl_ctx = ctx
    return _ssl_ctx


def urlopen(req, timeout: float = 60):
    return urllib.request.urlopen(req, timeout=timeout, context=ssl_context())


def _is_cert_error(e: BaseException) -> bool:
    import ssl
    reason = getattr(e, "reason", e)
    return isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(reason)


def http_json(url: str, payload: Any = None, headers: Optional[dict] = None,
              timeout: int = 60, retries: int = 3) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    last: Exception = HttpError("no attempt")
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 404:
                raise HttpError(f"404 {url}") from e
            if e.code not in (429, 500, 502, 503, 504):
                raise HttpError(f"HTTP {e.code} {url}") from e
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last = e
            if _is_cert_error(e):  # permanent: retrying only wastes the user's time
                raise HttpError(f"cannot verify the HTTPS certificate of {urllib.parse.urlparse(url).hostname} "
                                f"(no trusted CA certificates available): {e}") from e
        time.sleep(2 ** attempt * 1.5)
    raise HttpError(f"{url}: {last}")


def http_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as e:
        raise HttpError(f"{url}: {e}") from e


def read_json(path: Path | str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path | str, data: Any) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, default=str)
    os.replace(tmp, path)


def cache_fresh(path: Path, max_age_s: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime < max_age_s
    except FileNotFoundError:
        return False
