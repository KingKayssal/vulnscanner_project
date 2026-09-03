"""
CVSS v3.1 scoring for confirmed findings.

Each template defines a *base* vector. At finding-creation time the
scan engine may adjust individual metrics based on real context observed
during the scan (e.g. PR: N -> L if the endpoint actually required auth,
or UI: N -> R if exploitation needs a user click), then recompute the score.
"""
from dataclasses import dataclass
from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError


@dataclass
class CVSSResult:
    vector: str
    base_score: float
    severity: str  # None / Low / Medium / High / Critical


def score_vector(vector: str) -> CVSSResult:
    """Compute a CVSS score from a full v3.1 vector string."""
    try:
        c = CVSS3(vector)
    except CVSS3MalformedError as e:
        raise ValueError(f"Invalid CVSS vector '{vector}': {e}")
    return CVSSResult(
        vector=vector,
        base_score=c.base_score,
        severity=c.severities()[0],
    )


def adjust_vector(base_vector: str, **overrides: str) -> str:
    """
    Take a base CVSS vector string and override specific metrics.
    e.g. adjust_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", PR="L")
    """
    parts = base_vector.split("/")
    prefix, metrics = parts[0], parts[1:]
    metric_map = dict(m.split(":") for m in metrics)
    metric_map.update(overrides)
    ordered_keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    new_metrics = "/".join(f"{k}:{metric_map[k]}" for k in ordered_keys if k in metric_map)
    return f"{prefix}/{new_metrics}"


def severity_bucket(score: float) -> str:
    """Map a numeric base score to our internal severity enum."""
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


if __name__ == "__main__":
    # quick self-test
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    r = score_vector(v)
    print(r)
    print("bucket:", severity_bucket(r.base_score))

    v2 = adjust_vector(v, PR="H", UI="N")
    r2 = score_vector(v2)
    print(r2)
