import re
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, field_validator


class Event(BaseModel):
    """One normalised log event. Every parser produces this."""
    ts: datetime                      # naive, UTC
    source_type: str                  # "auth" | "web" | "firewall"
    host: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    action: str                       # login_failed | login_success | http_request | fw_block | fw_allow
    status: Optional[str] = None      # HTTP code for web, ALLOW/BLOCK for firewall
    message: str = ""                 # short human-readable text (URL path for web)
    raw: str                          # the original line, untouched


class Mitre(BaseModel):
    id: str
    name: str
    tactic: str


class Alert(BaseModel):
    """What a detector produces. One alert = one suspicious pattern from one source."""
    id: str = ""
    detector: str                     # bruteforce | portscan | webattack
    title: str
    src_ip: Optional[str] = None
    users: List[str] = []
    first_seen: datetime
    last_seen: datetime
    count: int                        # number of events that make up the pattern
    severity: str                     # P1 (critical) .. P4 (low)
    score: int
    score_reasons: List[str] = []
    mitre: List[Mitre] = []
    details: dict = {}
    evidence: List[str] = []          # raw log lines, at most 10


class Incident(BaseModel):
    """The agent's final, validated answer for one alert."""
    title: str
    severity: Literal["P1", "P2", "P3", "P4"]
    verdict: Literal["true_positive", "likely_false_positive", "needs_review"]
    confidence: Literal["low", "medium", "high"]
    summary: str
    evidence: List[str] = []
    mitre: List[str] = []
    recommended_actions: List[str] = []
    reasoning: str = ""
    guardrail_notes: List[str] = []   # filled by code, never by the model

    @field_validator("mitre")
    @classmethod
    def only_technique_ids(cls, v):
        return [t.upper() for t in v if re.fullmatch(r"[Tt]\d{4}(\.\d{3})?", t.strip())]
