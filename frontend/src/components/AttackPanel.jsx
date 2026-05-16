export default function AttackPanel({
  targetUrl,
  setTargetUrl,
  vulnLabel,
  setVulnLabel,
  scanStatus,
  webhookConnected,
  webhookUrl,
  wsConnected,
  onLaunch,
  isScanning,
}) {
  const badgeClass = scanStatus.toLowerCase();

  return (
    <div className="attack-panel">
      <label className="terminal-label" htmlFor="target-url">
        TARGET URL
      </label>
      <input
        id="target-url"
        className="terminal-input"
        type="text"
        value={targetUrl}
        onChange={(e) => setTargetUrl(e.target.value)}
        disabled={isScanning}
      />

      <label className="terminal-label" htmlFor="vuln-type">
        VULNERABILITY TYPE
      </label>
      <select
        id="vuln-type"
        className="terminal-select"
        value={vulnLabel}
        onChange={(e) => setVulnLabel(e.target.value)}
        disabled={isScanning}
      >
        <option value="SQL INJECTION">SQL INJECTION</option>
        <option value="COMMAND INJECTION">COMMAND INJECTION</option>
      </select>

      <button
        type="button"
        className={`launch-btn${isScanning ? " scanning" : ""}`}
        onClick={onLaunch}
        disabled={isScanning}
      >
        LAUNCH ATTACK
      </button>

      <div className="webhook-row">
        <span
          className={`webhook-dot${webhookConnected ? " connected" : ""}`}
          title={webhookConnected ? "Ngrok connected" : "Ngrok not connected"}
        />
        <span className="webhook-label">
          WEBHOOK {webhookConnected ? "ONLINE" : "OFFLINE"}
        </span>
      </div>
      {webhookUrl && (
        <p className="webhook-label" style={{ marginTop: 6, wordBreak: "break-all" }}>
          {webhookUrl}
        </p>
      )}

      <div className={`status-badge ${badgeClass}`}>{scanStatus}</div>

      <p className={`ws-indicator${wsConnected ? " live" : ""}`}>
        WS {wsConnected ? "CONNECTED" : "DISCONNECTED"}
      </p>
    </div>
  );
}
