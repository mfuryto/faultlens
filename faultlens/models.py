"""Serializable observations, kept independent from collection and rendering."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import __version__


@dataclass(frozen=True)
class Observation:
    key: str
    value: Any
    unit: str
    source: str
    state: str = "normal"
    confidence: str = "Confirmed"
    explanation: str = "Directly observed; this does not establish a root cause."
    limitations: tuple[str, ...] = ()
    thresholds: dict[str, float] = field(default_factory=dict)


def unavailable(key: str, source: str, explanation: str) -> Observation:
    return Observation(key, None, "", source, "unavailable", "Unknown", explanation)


def report(command: str, observations: list[Observation]) -> dict:
    return {"schema_version": 1, "version": __version__, "command": command,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "observations": [asdict(item) for item in observations],
            "limitations": ["A point-in-time observation is not a diagnosis or proof of system health.",
                            "Restricted permissions and containers can hide or change available evidence.",
                            "Reads are sequential, not atomic; collected_at marks report completion."]}
