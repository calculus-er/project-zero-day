import { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE, WS_URL, vulnTypeToApi } from "./config";
import AgentLog from "./components/AgentLog";
import AttackPanel from "./components/AttackPanel";
import BreachAlert from "./components/BreachAlert";
import JournalView from "./components/JournalView";
import RemediationPanel from "./components/RemediationPanel";
import StatusBar from "./components/StatusBar";

function statusToLabel(status) {
  const map = {
    idle: "IDLE",
    running: "SCANNING",
    breached: "BREACHED",
    failed: "FAILED",
  };
  return map[status] || status.toUpperCase();
}

export default function App() {
  const [targetUrl, setTargetUrl] = useState("http://localhost:5000");
  const [vulnLabel, setVulnLabel] = useState("SQL INJECTION");
  const [messages, setMessages] = useState([]);
  const [journalEntries, setJournalEntries] = useState([]);
  const [scanStatus, setScanStatus] = useState("IDLE");
  const [rawStatus, setRawStatus] = useState("idle");
  const [wsConnected, setWsConnected] = useState(false);
  const [webhookConnected, setWebhookConnected] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState(null);
  const [breachTrigger, setBreachTrigger] = useState(0);
  const [currentAgent, setCurrentAgent] = useState("—");
  const [phase, setPhase] = useState("STANDBY");
  const [remediation, setRemediation] = useState({ status: "idle" });

  const wsRef = useRef(null);
  const pollRef = useRef(null);

  const isScanning = rawStatus === "running";

  const fetchWebhookStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/webhook/status`);
      const data = await res.json();
      console.log("[App] webhook status:", data);
      setWebhookConnected(Boolean(data.ngrok_connected));
      setWebhookUrl(data.webhook_url || null);
    } catch (err) {
      console.error("[App] webhook status failed:", err);
      setWebhookConnected(false);
    }
  }, []);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      const data = await res.json();
      console.log("[App] status poll:", data);
      setRawStatus(data.status);
      setScanStatus(statusToLabel(data.status));
      if (typeof data.ngrok_connected === "boolean") {
        setWebhookConnected(data.ngrok_connected);
      }
      if (data.status === "running") setPhase("RED SWARM ACTIVE");
      else if (data.status === "breached") {
        if (data.remediation_status === "running") setPhase("BLUE SWARM");
        else if (data.remediation_status === "complete") setPhase("REMEDIATED");
        else setPhase("BREACH");
      } else if (data.status === "failed") setPhase("EXHAUSTED");
      else setPhase("STANDBY");
    } catch (err) {
      console.error("[App] status fetch failed:", err);
    }
  }, []);

  const fetchRemediation = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/remediation`);
      const data = await res.json();
      setRemediation(data);
    } catch (err) {
      console.error("[App] remediation fetch failed:", err);
    }
  }, []);

  const fetchJournal = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/journal`);
      const data = await res.json();
      setJournalEntries(data.entries || []);
    } catch (err) {
      console.error("[App] journal fetch failed:", err);
    }
  }, []);

  const handleWsMessage = useCallback((event) => {
    try {
      const data = JSON.parse(event.data);
      console.log("[App] ws message:", data);

      setMessages((prev) => [...prev, data]);
      setCurrentAgent(data.agent || "—");

      if (data.level === "breach") {
        setBreachTrigger(Date.now());
        setScanStatus("BREACHED");
        setRawStatus("breached");
        setPhase("BREACH");
      }

      if (data.agent === "WEBHOOK") setPhase("AUTO-TRIGGER");
      if (data.agent === "ALPHA") setPhase("RECON");
      if (data.agent === "BETA") setPhase("EXPLOIT");
      if (data.agent === "GAMMA") setPhase("ANALYSIS");
      if (data.agent === "DELTA") setPhase("BLUE — DIAGNOSIS");
      if (data.agent === "EPSILON") setPhase("BLUE — PATCH");
      if (data.agent === "ZETA") setPhase("BLUE — VERIFY");
      if (data.level === "success" && data.agent === "ZETA") setPhase("REMEDIATED");
    } catch (err) {
      console.error("[App] ws parse error:", err);
    }
  }, []);

  useEffect(() => {
    console.log("[App] connecting WebSocket:", WS_URL);
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("[App] WebSocket connected");
      setWsConnected(true);
    };

    ws.onmessage = handleWsMessage;

    ws.onclose = () => {
      console.log("[App] WebSocket closed");
      setWsConnected(false);
    };

    ws.onerror = (err) => {
      console.error("[App] WebSocket error:", err);
      setWsConnected(false);
    };

    fetchStatus();
    fetchWebhookStatus();

    return () => {
      ws.close();
    };
  }, [handleWsMessage, fetchStatus, fetchWebhookStatus]);

  useEffect(() => {
    const webhookPoll = setInterval(fetchWebhookStatus, 5000);
    return () => clearInterval(webhookPoll);
  }, [fetchWebhookStatus]);

  useEffect(() => {
    if (isScanning || rawStatus === "breached") {
      fetchJournal();
      fetchRemediation();
      pollRef.current = setInterval(() => {
        fetchJournal();
        fetchRemediation();
        fetchStatus();
      }, 3000);
    } else {
      fetchJournal();
      fetchRemediation();
    }

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [isScanning, rawStatus, fetchJournal, fetchRemediation, fetchStatus]);

  const handleLaunch = async () => {
    console.log("[App] launching attack:", targetUrl, vulnLabel);
    setMessages([]);
    setJournalEntries([]);
    setScanStatus("SCANNING");
    setRawStatus("running");
    setPhase("RED SWARM ACTIVE");
    setRemediation({ status: "idle" });

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          vuln_type: vulnTypeToApi(vulnLabel),
        }),
      });
      const data = await res.json();
      console.log("[App] scan response:", data);

      if (data.status === "already_running") {
        setScanStatus("SCANNING");
        return;
      }

      fetchStatus();
      fetchJournal();
    } catch (err) {
      console.error("[App] scan failed:", err);
      setScanStatus("FAILED");
      setRawStatus("failed");
    }
  };

  return (
    <div className="war-room">
      <div className="scanline-overlay" aria-hidden="true" />
      <div className="scanline-beam" aria-hidden="true" />

      <BreachAlert trigger={breachTrigger} />

      <div className="panels">
        <aside className="panel panel-left">
          <h1 className="hero-title">PROJECT ZERO-DAY</h1>
          <AttackPanel
            targetUrl={targetUrl}
            setTargetUrl={setTargetUrl}
            vulnLabel={vulnLabel}
            setVulnLabel={setVulnLabel}
            scanStatus={scanStatus}
            webhookConnected={webhookConnected}
            webhookUrl={webhookUrl}
            wsConnected={wsConnected}
            onLaunch={handleLaunch}
            isScanning={isScanning}
          />
          <StatusBar
            currentAgent={currentAgent}
            phase={phase}
            attemptCount={journalEntries.length}
          />
        </aside>

        <main className="panel panel-center">
          <h2 className="panel-title">AGENT FEED</h2>
          <AgentLog messages={messages} />
        </main>

        <aside className="panel panel-right panel-right-stack">
          <div className="panel-right-journal">
            <h2 className="panel-title">ATTACK JOURNAL</h2>
            <JournalView entries={journalEntries} />
          </div>
          <RemediationPanel
            remediation={remediation}
            visible={
              rawStatus === "breached" ||
              remediation.status === "running" ||
              remediation.status === "complete"
            }
          />
        </aside>
      </div>
    </div>
  );
}
