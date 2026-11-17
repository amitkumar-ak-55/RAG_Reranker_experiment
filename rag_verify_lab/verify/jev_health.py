from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
import time
from urllib.parse import urlparse

import httpx

from ..config import settings
from .jev import JEV_CONTRACT, jev_url

logger = logging.getLogger(__name__)


@dataclass
class JEVHealth:
    configured: bool
    reachable: bool
    authenticated: bool
    model_accepted: bool
    latency_ms: float | None
    http_status: int | None
    error_message: str
    url: str
    url_problems: list[str]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def check_jev_url(base_url: str) -> list[str]:
    problems: list[str] = []
    if base_url != base_url.strip() or base_url[:1] in {"'", '"'} or base_url[-1:] in {"'", '"'}:
        problems.append("JEV_BASE_URL has whitespace or quotes")
    parsed = urlparse(base_url.strip().strip("'\""))
    if parsed.scheme != "https":
        problems.append("JEV_BASE_URL is missing the https:// scheme")
    if parsed.path.endswith("/"):
        problems.append("JEV_BASE_URL has a trailing slash")
    if "/v1/v1" in parsed.path:
        problems.append("JEV_BASE_URL has duplicated /v1 path segments")
    if parsed.path.endswith("/chat/completions") or parsed.path.endswith("/systemone"):
        problems.append("JEV_BASE_URL contains a full endpoint path")
    return problems


def _safe_body(response: httpx.Response, api_key: str) -> str:
    body = response.text[:300]
    return body.replace(api_key, "[REDACTED]") if api_key else body


def jev_health() -> dict[str, object]:
    base_url = settings.jev_base_url
    url = f"{base_url.strip().strip(chr(39) + chr(34)).rstrip('/')}{JEV_CONTRACT['path']}" if base_url else ""
    url_problems = check_jev_url(base_url) if base_url else []
    configured = bool(settings.jev_api_key and base_url and settings.jev_model)
    result = JEVHealth(configured, False, False, False, None, None, "", url, url_problems)
    if not configured:
        result.error_message = "JEV_API_KEY, JEV_BASE_URL, and JEV_MODEL are required"
        return result.as_dict()
    started = time.perf_counter()
    payload = {
        "model": settings.jev_model,
        "state": "test",
        "questions": {"health": {"type": "noul", "instructions": "Is this service responding?"}},
    }
    try:
        response = httpx.post(
            url,
            headers={"Authorization": "Bearer " + settings.jev_api_key, "Content-Type": "application/json"},
            json=payload,
            timeout=15,
        )
        result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        result.http_status = response.status_code
        body = _safe_body(response, settings.jev_api_key)
        if response.status_code in {401, 403}:
            result.reachable = True
            result.error_message = f"Authentication failed: HTTP {response.status_code}; body={body}"
        elif response.status_code == 404 or "unknown model" in body.lower():
            result.reachable = True
            result.authenticated = response.status_code != 404
            result.error_message = f"Model or endpoint rejected: HTTP {response.status_code}; body={body}"
        elif response.status_code == 200:
            data = response.json()
            if not isinstance(data, dict) or not isinstance(data.get("answers"), dict):
                raise ValueError("response has no parseable answers object")
            result.reachable = result.authenticated = result.model_accepted = True
        else:
            result.reachable = True
            result.error_message = f"JEV request failed: {url} status={response.status_code} body={body}"
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        result.error_message = f"JEV network error: {exc}"
    except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        result.reachable = True
        result.error_message = f"JEV response error: {exc}"
    if result.error_message:
        logger.error("%s", result.error_message)
    return result.as_dict()
