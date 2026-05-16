import { useEffect, useRef } from "react";
import { formatTime } from "../config";

export default function AgentLog({ messages }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <div className="agent-feed">
      {messages.length === 0 && (
        <p className="log-entry log-msg info">
          <span className="log-text">AWAITING AGENT TRANSMISSIONS...</span>
        </p>
      )}
      {messages.map((entry, index) => (
        <div
          key={`${entry.timestamp}-${index}`}
          className={`log-entry log-msg ${entry.level}`}
        >
          <span className="log-time">{formatTime(entry.timestamp)}</span>
          <span className="log-agent">[{entry.agent}]</span>
          <span className="log-text">{entry.message}</span>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  );
}
