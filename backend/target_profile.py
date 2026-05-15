"""Dynamic target profile (Tier 1 / Phase 8B) — one profile per scan_id."""

from __future__ import annotations

from pydantic import BaseModel, Field


class EndpointSpec(BaseModel):
    """HTTP surface used for exploitation (single focus vuln per scan)."""

    path: str = "/login"
    method: str = "POST"
    injection_field: str = "username"
    fixed_json: dict[str, str] = Field(default_factory=dict)
    sink_summary: str = ""
    line_hint: int | None = None


class TargetProfile(BaseModel):
    scan_id: str = ""
    vuln_type: str
    endpoint: EndpointSpec
    breach_markers: list[str] = Field(default_factory=list)
    seed_payloads: list[str] = Field(default_factory=list)
    attack_surface_text: str = ""
    degraded: bool = False


_profiles: dict[str, TargetProfile] = {}


def store_profile(scan_id: str, profile: TargetProfile) -> None:
    profile.scan_id = scan_id
    _profiles[scan_id] = profile


def get_profile(scan_id: str) -> TargetProfile | None:
    return _profiles.get(scan_id)


def clear_profile(scan_id: str) -> None:
    _profiles.pop(scan_id, None)
