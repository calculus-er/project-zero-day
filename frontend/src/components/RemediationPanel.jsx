export default function RemediationPanel({ remediation, visible }) {
  if (!visible) return null;

  const status = remediation?.status || "idle";

  if (status === "idle") {
    return (
      <section className="remediation-panel remediation-panel--idle">
        <h2 className="panel-title remediation-title">BLUE SWARM</h2>
        <p className="remediation-placeholder">Awaiting breach…</p>
      </section>
    );
  }

  if (status === "running") {
    return (
      <section className="remediation-panel remediation-panel--running">
        <h2 className="panel-title remediation-title">BLUE SWARM</h2>
        <p className="remediation-status-line">REMEDIATING…</p>
        <p className="remediation-meta">
          Delta → Epsilon generating patch for{" "}
          <code>{remediation.vuln_type}</code>
        </p>
      </section>
    );
  }

  if (status === "failed") {
    return (
      <section className="remediation-panel remediation-panel--failed">
        <h2 className="panel-title remediation-title">BLUE SWARM</h2>
        <p className="remediation-status-line">REMEDIATION FAILED</p>
        <p className="remediation-meta">{remediation.fix_summary}</p>
      </section>
    );
  }

  return (
    <section className="remediation-panel remediation-panel--complete">
      <h2 className="panel-title remediation-title">BLUE SWARM — PATCH READY</h2>
      <p className="remediation-status-line">REMEDIATION COMPLETE</p>
      <p className="remediation-label">Diagnosis (Delta)</p>
      <p className="remediation-text">{remediation.diagnosis}</p>
      <p className="remediation-label">Fix (Epsilon)</p>
      <p className="remediation-text">{remediation.fix_summary}</p>
      <p className="remediation-label">Payload</p>
      <pre className="remediation-code">{remediation.winning_payload}</pre>
      {remediation.used_template_fallback && (
        <p className="remediation-verify remediation-verify--live">
          Patched with deterministic template fallback (LLM rewrite failed validation).
        </p>
      )}
      {remediation.arena_source_path && (
        <p className="remediation-meta">
          Written: <code>{remediation.arena_source_path}</code>
        </p>
      )}
      {remediation.logic_verified && (
        <p className="remediation-meta">
          Compose:{" "}
          {remediation.target_restarted
            ? "`docker compose restart` ran"
            : "no successful restart (disabled or compose error — see feed)"}
          {" · "}
          {remediation.target_health_ok === true
            ? "/health OK"
            : remediation.target_health_ok === false
              ? "/health timed out"
              : "/health not polled"}
        </p>
      )}
      <p
        className={
          remediation.logic_verified
            ? "remediation-verify remediation-verify--pass"
            : "remediation-verify remediation-verify--fail"
        }
      >
        {remediation.logic_verified
          ? "LOGIC: Winning payload blocked by remediated code"
          : "LOGIC: Patch did not block exploit"}
      </p>
      <p className="remediation-verify remediation-verify--live">
        {remediation.live_still_vulnerable
          ? "LIVE: Arena still exploitable until patch is deployed"
          : "LIVE: Arena no longer accepts exploit"}
      </p>
      {remediation.verification_note && (
        <p className="remediation-text">{remediation.verification_note}</p>
      )}
      <p className="remediation-label">Patch file</p>
      <p className="remediation-meta">
        <code>logs/patches/{remediation.patch_filename}</code>
      </p>
      <p className="remediation-label">Diff preview</p>
      <pre className="remediation-diff">{remediation.diff_preview}</pre>
    </section>
  );
}
