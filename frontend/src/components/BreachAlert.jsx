import { useEffect, useState } from "react";

export default function BreachAlert({ trigger }) {
  const [visible, setVisible] = useState(false);
  const [phase, setPhase] = useState("blink");

  useEffect(() => {
    if (!trigger) return;

    setVisible(true);
    setPhase("blink");

    const fadeTimer = setTimeout(() => setPhase("fade-out"), 1600);
    const hideTimer = setTimeout(() => {
      setVisible(false);
      setPhase("blink");
    }, 2500);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(hideTimer);
    };
  }, [trigger]);

  if (!visible) return null;

  return (
    <div className={`breach-overlay ${phase}`}>
      <h1 className="breach-title">⚠ SYSTEM BREACH CONFIRMED ⚠</h1>
      <p className="breach-subtitle">UNAUTHORIZED ACCESS ACHIEVED</p>
    </div>
  );
}
