// StatusBar -- bottom strip: lab identity + severity legend.
// Static, no data dependency, safe under HMR.
export default function StatusBar() {
  return (
    <div style={{
      height: 24, flexShrink: 0, background: "var(--bg1)",
      borderTop: "1px solid var(--ln2)", display: "flex", alignItems: "center",
      padding: "0 12px", gap: 14, fontSize: 9.5, fontFamily: "var(--mono)",
      color: "var(--t3)", letterSpacing: "0.03em",
    }}>
      <span style={{ color: "var(--t2)" }}>SOC ATELIER · LYNX CONSOLE</span>
      <span>telemetry: Sysmon · Suricata · Elastic Defend (Linux)</span>
      <span style={{ flex: 1 }} />
      <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <i style={{ width: 7, height: 7, borderRadius: 2, background: "var(--red)", display: "inline-block" }} />
        critical
        <i style={{ width: 7, height: 7, borderRadius: 2, background: "var(--amb)", display: "inline-block" }} />
        high
        <i style={{ width: 7, height: 7, borderRadius: 2, background: "var(--teal)", display: "inline-block" }} />
        medium
        <i style={{ width: 7, height: 7, borderRadius: 2, background: "var(--t4)", display: "inline-block" }} />
        low
      </span>
    </div>
  )
}
