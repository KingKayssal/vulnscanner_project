"""
Template-driven detection engine.

Templates are YAML files describing a single check. This module loads
templates from a directory and, given a fetched HTTP response, decides
whether a template's matcher fires. New checks are added by dropping in
a new YAML file -- no code changes required for passive/simple checks.

Supported matcher types (extend as needed):
  - header-absence          : passive, one HTTP response
  - header-value-present     : passive, one HTTP response
  - path-probe               : active, needs a probe request to a fixed path
  - reflected-marker         : active, needs a request with an injected marker
"""
import os
import glob
import random
import string
import dataclasses
from typing import Optional, Any
import yaml


@dataclasses.dataclass
class LoadedTemplate:
    id: str
    name: str
    severity: str
    category: str
    cwe: str
    cvss_base_vector: str
    description: str
    remediation: str
    matcher: dict
    raw: dict


@dataclasses.dataclass
class HTTPResponseLike:
    """Minimal shape the engine needs from an HTTP response."""
    url: str
    status_code: int
    headers: dict
    text: str
    request_summary: str = ""


@dataclasses.dataclass
class MatchResult:
    template: LoadedTemplate
    matched: bool
    confirmed: bool
    evidence: str = ""


def load_templates(templates_dir: str) -> list[LoadedTemplate]:
    templates = []
    for path in glob.glob(os.path.join(templates_dir, "*.yaml")):
        with open(path) as f:
            data = yaml.safe_load(f)
        info = data["info"]
        templates.append(LoadedTemplate(
            id=data["id"],
            name=info["name"],
            severity=info["severity"],
            category=info.get("category", "misc"),
            cwe=info.get("cwe", ""),
            cvss_base_vector=info["cvss_base_vector"],
            description=info.get("description", "").strip(),
            remediation=info.get("remediation", "").strip(),
            matcher=data["matcher"],
            raw=data,
        ))
    return templates


def _headers_ci(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def match_header_absence(resp: HTTPResponseLike, matcher: dict) -> Optional[str]:
    h = _headers_ci(resp.headers)
    missing = [name for name in matcher["headers"] if name.lower() not in h]
    if matcher.get("condition") == "any-missing" and missing:
        return f"Missing headers: {', '.join(missing)}"
    return None


def match_header_value_present(resp: HTTPResponseLike, matcher: dict) -> Optional[str]:
    h = _headers_ci(resp.headers)
    found = [(name, h[name.lower()]) for name in matcher["headers"] if name.lower() in h and h[name.lower()]]
    if matcher.get("condition") == "any-present-with-value" and found:
        return "; ".join(f"{n}: {v}" for n, v in found)
    return None


def match_path_probe(resp: HTTPResponseLike, matcher: dict) -> Optional[str]:
    if matcher.get("condition") == "status-200-and-body-contains":
        if resp.status_code == 200 and matcher.get("body_contains", "") in resp.text:
            snippet = resp.text[:200].replace("\n", " ")
            return f"HTTP 200 at {resp.url}; body snippet: {snippet!r}"
    return None


def match_reflected_marker(resp: HTTPResponseLike, matcher: dict, marker: str) -> Optional[str]:
    # crude but effective for a candidate finding: marker present, unescaped
    # (i.e. not HTML-entity-encoded)
    if marker in resp.text:
        escaped_variant = marker.replace("<", "&lt;").replace(">", "&gt;")
        if escaped_variant not in resp.text or marker in resp.text:
            return f"Marker '{marker}' reflected unescaped in response body at {resp.url}"
    return None


def generate_marker(prefix: str = "sc4n_") -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{suffix}<b>"  # harmless HTML tag, not a script -- non-destructive


def evaluate_template(
    template: LoadedTemplate,
    resp: HTTPResponseLike,
    marker: Optional[str] = None,
) -> MatchResult:
    m = template.matcher
    mtype = m["type"]

    evidence = None
    if mtype == "header-absence":
        evidence = match_header_absence(resp, m)
    elif mtype == "header-value-present":
        evidence = match_header_value_present(resp, m)
    elif mtype == "path-probe":
        evidence = match_path_probe(resp, m)
    elif mtype == "reflected-marker":
        evidence = match_reflected_marker(resp, m, marker or "")
    else:
        raise ValueError(f"Unknown matcher type: {mtype}")

    matched = evidence is not None
    requires_confirmation = m.get("requires_confirmation", False)
    # passive checks are self-confirming; active checks marked
    # requires_confirmation get a second pass in the orchestrator
    confirmed = matched and not requires_confirmation

    return MatchResult(
        template=template,
        matched=matched,
        confirmed=confirmed,
        evidence=evidence or "",
    )


if __name__ == "__main__":
    tpls = load_templates(os.path.join(os.path.dirname(__file__), "..", "templates"))
    print(f"Loaded {len(tpls)} templates:")
    for t in tpls:
        print(f"  - {t.id} [{t.severity}] matcher={t.matcher['type']}")
