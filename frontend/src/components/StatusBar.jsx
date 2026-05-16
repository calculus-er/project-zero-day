export default function StatusBar({ currentAgent, phase, attemptCount }) {
  return (
    <div className="status-bar">
      <div className="status-bar-row">
        <span>CURRENT AGENT</span>
        <span className="value">{currentAgent || "—"}</span>
      </div>
      <div className="status-bar-row">
        <span>PHASE</span>
        <span className="value">{phase || "STANDBY"}</span>
      </div>
      <div className="status-bar-row">
        <span>ATTEMPTS</span>
        <span className="value">{attemptCount}</span>
      </div>
    </div>
  );
}
