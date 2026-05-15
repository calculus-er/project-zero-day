"""Latest Blue Swarm remediation state (in-memory, per last breach)."""

from typing import Any, Optional


class RemediationStore:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._data: dict[str, Any] = {
            "status": "idle",
            "scan_id": None,
            "vuln_type": None,
            "winning_payload": None,
            "diagnosis": None,
            "fix_summary": None,
            "patch_path": None,
            "patch_filename": None,
            "diff_preview": None,
            "verified": None,
            "logic_verified": None,
            "live_still_vulnerable": None,
            "verification_note": None,
        }

    def start(self, scan_id: str, vuln_type: str, winning_payload: str) -> None:
        self._data = {
            "status": "running",
            "scan_id": scan_id,
            "vuln_type": vuln_type,
            "winning_payload": winning_payload,
            "diagnosis": None,
            "fix_summary": None,
            "patch_path": None,
            "patch_filename": None,
            "diff_preview": None,
            "verified": None,
            "logic_verified": None,
            "live_still_vulnerable": None,
            "verification_note": None,
        }

    def complete(
        self,
        diagnosis: str,
        fix_summary: str,
        patch_path: str,
        patch_filename: str,
        diff_preview: str,
        verified: bool = False,
        logic_verified: bool = False,
        live_still_vulnerable: bool = True,
        verification_note: str = "",
    ) -> None:
        self._data["status"] = "complete"
        self._data["diagnosis"] = diagnosis
        self._data["fix_summary"] = fix_summary
        self._data["patch_path"] = patch_path
        self._data["patch_filename"] = patch_filename
        self._data["diff_preview"] = diff_preview
        self._data["verified"] = verified
        self._data["logic_verified"] = logic_verified
        self._data["live_still_vulnerable"] = live_still_vulnerable
        self._data["verification_note"] = verification_note

    def fail(self, message: str) -> None:
        self._data["status"] = "failed"
        self._data["fix_summary"] = message

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)


remediation = RemediationStore()
