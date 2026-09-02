"""
sources.py — ThreatLens extensible integration layer.

This module owns ALL external integrations (threat-intel sources + LLM
explainer) and nothing else. app.py never talks to an external API
directly — it only calls functions/classes defined here.

Extensibility pattern
----------------------
Threat-intel sources implement the `IntelSource` abstract base class and
return data normalized to a single common schema (see `normalize_virustotal_response`
docstring / the dict shape below). New sources register themselves in the
`SOURCE_REGISTRY` dict at the bottom of this file — app.py iterates over
that registry and never needs to change when a new source is added.

Normalized schema every source's `fetch()` must return:
    {
        "indicator": str,
        "type": "ip" | "domain" | "url",
        "verdict": "malicious" | "suspicious" | "harmless" | "unknown",
        "stats": {"malicious": int, "suspicious": int, "harmless": int, "undetected": int},
        "metadata": {...},   # source-specific extras, rendered as key/value pairs
        "raw": {...},        # original response, for the expandable raw JSON view
    }
"""

from __future__ import annotations

import re
import json
from abc import ABC, abstractmethod
from typing import Optional

import requests

DEFAULT_TIMEOUT = 15  # seconds, applied to every external call


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class SourceError(Exception):
    """Base exception for any intel-source failure. app.py catches this
    (and its subclasses) uniformly, regardless of which source raised it."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class AuthError(SourceError):
    """Raised on 401/403 — bad or missing API key."""


class NotFoundError(SourceError):
    """Raised on 404 — indicator has no data at this source."""


class RateLimitError(SourceError):
    """Raised on 429 — source rate limit hit."""


class LLMError(Exception):
    """Raised when the LLM explanation step fails. Kept separate from
    SourceError since a failed LLM call should not block showing the
    raw intel data (see app.py error-handling requirement)."""


# --------------------------------------------------------------------------- #
# Indicator validation
# --------------------------------------------------------------------------- #

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)


def validate_indicator(indicator: str, indicator_type: str) -> bool:
    """Basic sanity check that `indicator` looks like the selected type.
    Not a full RFC-grade validator — just enough to stop obvious
    mismatches (e.g. a domain being submitted as an IP)."""
    indicator = (indicator or "").strip()
    if not indicator:
        return False

    if indicator_type == "ip":
        if _IPV4_RE.match(indicator):
            octets = indicator.split(".")
            return all(0 <= int(o) <= 255 for o in octets)
        return bool(_IPV6_RE.match(indicator) and ":" in indicator)

    if indicator_type == "domain":
        return bool(_DOMAIN_RE.match(indicator))

    if indicator_type == "url":
        return bool(_URL_RE.match(indicator))

    return False


# --------------------------------------------------------------------------- #
# Intel source interface
# --------------------------------------------------------------------------- #

class IntelSource(ABC):
    """Common interface every threat-intel source must implement.

    To add a new source: subclass this, implement `fetch()` returning
    the normalized schema documented at the top of this file, then add
    one line to SOURCE_REGISTRY at the bottom. No other file changes."""

    name: str = "base"
    supported_types: list[str] = []

    @abstractmethod
    def fetch(self, indicator: str, indicator_type: str, api_key: str) -> dict:
        """Fetch + normalize data for `indicator`. Must raise a
        SourceError (or subclass) on failure — never raise a raw
        requests exception up to app.py."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# VirusTotal implementation
# --------------------------------------------------------------------------- #

_VT_ENDPOINTS = {
    "ip": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "domain": "https://www.virustotal.com/api/v3/domains/{}",
    "url": "https://www.virustotal.com/api/v3/urls/{}",
}


def _vt_url_id(url: str) -> str:
    """VirusTotal's /urls/ endpoint expects a URL-safe base64 id of the URL
    (no padding), per their v3 API spec."""
    import base64

    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def normalize_virustotal_response(raw: dict, indicator: str, indicator_type: str) -> dict:
    """Map a raw VirusTotal v3 JSON payload into the common internal schema."""
    attributes = raw.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif harmless > 0:
        verdict = "harmless"
    else:
        verdict = "unknown"

    metadata = {}
    if indicator_type == "ip":
        metadata = {
            "Country": attributes.get("country"),
            "AS Owner": attributes.get("as_owner"),
            "ASN": attributes.get("asn"),
            "Reputation": attributes.get("reputation"),
        }
    elif indicator_type == "domain":
        metadata = {
            "Reputation": attributes.get("reputation"),
            "Registrar": attributes.get("registrar"),
            "Creation Date": attributes.get("creation_date"),
        }
    elif indicator_type == "url":
        metadata = {
            "Final URL": attributes.get("url"),
            "Title": attributes.get("title"),
            "Reputation": attributes.get("reputation"),
        }
    # Drop empty/None values so the UI doesn't render blank rows.
    metadata = {k: v for k, v in metadata.items() if v not in (None, "")}

    return {
        "indicator": indicator,
        "type": indicator_type,
        "verdict": verdict,
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        },
        "metadata": metadata,
        "raw": raw,
    }


class VirusTotalSource(IntelSource):
    name = "VirusTotal"
    supported_types = ["ip", "domain", "url"]

    def fetch(self, indicator: str, indicator_type: str, api_key: str) -> dict:
        if indicator_type not in self.supported_types:
            raise SourceError(f"VirusTotal does not support type '{indicator_type}'.")

        if indicator_type == "url":
            path_value = _vt_url_id(indicator)
        else:
            path_value = indicator

        url = _VT_ENDPOINTS[indicator_type].format(path_value)
        headers = {"x-apikey": api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        except requests.exceptions.Timeout:
            raise SourceError("VirusTotal request timed out. Please try again.")
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"Network error contacting VirusTotal: {exc}")

        if resp.status_code == 200:
            try:
                raw = resp.json()
            except ValueError:
                raise SourceError("VirusTotal returned an unparseable response.")
            return normalize_virustotal_response(raw, indicator, indicator_type)

        if resp.status_code in (401, 403):
            raise AuthError(
                "VirusTotal rejected the API key (unauthorized).", status_code=resp.status_code
            )
        if resp.status_code == 404:
            raise NotFoundError(
                "No data available for this indicator on VirusTotal.", status_code=404
            )
        if resp.status_code == 429:
            raise RateLimitError(
                "VirusTotal rate limit reached. Please wait and try again.", status_code=429
            )

        raise SourceError(
            f"VirusTotal request failed (HTTP {resp.status_code}).",
            status_code=resp.status_code,
        )


# Registry: new sources register here in ONE line. app.py iterates this
# dict — it never needs editing when a source is added. Example for a
# future source:
#     from sources import AbuseIPDBSource
#     SOURCE_REGISTRY["abuseipdb"] = AbuseIPDBSource()
SOURCE_REGISTRY: dict[str, IntelSource] = {
    "virustotal": VirusTotalSource(),
}


# --------------------------------------------------------------------------- #
# LLM explainer (Groq)
# --------------------------------------------------------------------------- #

GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "openai/gpt-oss-120b"

_LEVEL_INSTRUCTIONS = {
    "Beginner": (
        "Explain in plain, everyday language with no jargon. Define any technical "
        "term you must use. Focus on what this means for the reader in practical "
        "terms and why it matters to them."
    ),
    "Intermediate": (
        "Use some technical terminology but briefly explain context where it helps. "
        "Assume the reader knows basic internet/security concepts but is not a "
        "security professional."
    ),
    "Expert": (
        "Be concise and technical. Assume familiarity with threat-intelligence "
        "terminology (verdicts, detection engines, reputation scores, ASN/WHOIS "
        "data). Skip basic definitions."
    ),
}


def _default_prompt_template(intel: dict, knowledge_level: str) -> list[dict]:
    """Builds the Groq chat messages. Swappable independently of the
    data-fetching logic — pass a different callable into LLMExplainer
    to change prompting strategy without touching VirusTotalSource."""
    level_instruction = _LEVEL_INSTRUCTIONS.get(knowledge_level, _LEVEL_INSTRUCTIONS["Intermediate"])

    system = (
        "You are a threat-intelligence analyst assistant. You are given normalized "
        "scan data for a single indicator (IP, domain, or URL) and must explain the "
        "risk to the user. Be accurate, do not invent details not present in the "
        "data, and stay within 150-250 words unless the Expert level requires more "
        "technical density. " + level_instruction
    )

    user = (
        f"Indicator: {intel['indicator']} (type: {intel['type']})\n"
        f"Verdict: {intel['verdict']}\n"
        f"Detection stats: {json.dumps(intel['stats'])}\n"
        f"Metadata: {json.dumps(intel['metadata'])}\n\n"
        "Write a risk explanation for this indicator tailored to the requested "
        "knowledge level. If the verdict is 'unknown' or all stats are zero, say "
        "clearly that there isn't enough data to draw a conclusion rather than "
        "guessing."
    )

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


class LLMExplainer:
    """Wraps the Groq chat-completion call. The prompt-building function
    is injected (`prompt_fn`) so the prompting strategy — or the model
    provider entirely — can be swapped without touching sources that
    fetch intel data."""

    def __init__(self, prompt_fn=_default_prompt_template, model: str = GROQ_MODEL):
        self.prompt_fn = prompt_fn
        self.model = model

    def explain(self, intel: dict, knowledge_level: str, api_key: str) -> str:
        messages = self.prompt_fn(intel, knowledge_level)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 600,
        }

        try:
            resp = requests.post(
                GROQ_CHAT_URL, headers=headers, json=payload, timeout=DEFAULT_TIMEOUT
            )
        except requests.exceptions.Timeout:
            raise LLMError("Groq request timed out.")
        except requests.exceptions.RequestException as exc:
            raise LLMError(f"Network error contacting Groq: {exc}")

        if resp.status_code != 200:
            try:
                detail = resp.json().get("error", {}).get("message", resp.text)
            except ValueError:
                detail = resp.text
            raise LLMError(f"Groq request failed (HTTP {resp.status_code}): {detail}")

        try:
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, ValueError):
            raise LLMError("Groq returned an unexpected response shape.")