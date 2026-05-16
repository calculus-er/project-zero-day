export default function JournalView({ entries }) {
  return (
    <div className="journal-panel">
      <p className="journal-count">ATTEMPTS: {entries.length}</p>
      <div className="journal-list">
        {entries.length === 0 ? (
          <p className="journal-empty">NO JOURNAL ENTRIES YET</p>
        ) : (
          entries.map((entry) => {
            const truncated =
              entry.payload && entry.payload.length > 40
                ? `${entry.payload.slice(0, 40)}...`
                : entry.payload || "—";
            const outcomeClass =
              entry.outcome === "breached" ? "breached" : "failed";
            const outcomeLabel =
              entry.outcome === "breached" ? "BREACH" : "FAILED";

            return (
              <div
                key={`attempt-${entry.attempt_number}`}
                className="journal-entry"
              >
                <div className="attempt">#{entry.attempt_number}</div>
                <div className="payload">{truncated}</div>
                <div className={`journal-outcome ${outcomeClass}`}>
                  {outcomeLabel}
                </div>
                {entry.outcome === "failed" && entry.gamma_critique && (
                  <p className="journal-critique">{entry.gamma_critique}</p>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
