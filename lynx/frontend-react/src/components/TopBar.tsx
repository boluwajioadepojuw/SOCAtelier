import { useLynx } from "../LynxContext"

export default function TopBar() {
  const { activeView, selectedCase, selectedBehavior, setSelectedCase, setSelectedBehavior } = useLynx()

  return (
    <div style={{
      height: 36, background: "var(--bg1)", borderBottom: "1px solid var(--ln2)",
      display: "flex", alignItems: "center", padding: "0 14px", flexShrink: 0,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, paddingRight: 14, borderRight: "1px solid var(--ln2)" }}>
        <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
          <circle cx="7" cy="7" r="5.4" fill="none" stroke="var(--amb)" strokeWidth="1.4" />
          <circle cx="7" cy="7" r="1.8" fill="var(--amb)" />
        </svg>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700, letterSpacing: "0.16em", color: "var(--amb)" }}>
          LYNX
        </span>
        <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", letterSpacing: "0.08em", textTransform: "uppercase" }}>
          SOC console
        </span>
      </div>

      {activeView === "investigation" && (selectedCase || selectedBehavior) && (
        <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "0 14px", borderLeft: "1px solid var(--ln2)" }}>
          <span
            style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t3)", cursor: "pointer", padding: "2px 4px" }}
            onClick={() => { setSelectedCase(null); setSelectedBehavior(null) }}
          >Queue</span>
          {selectedCase && <>
            <span style={{ color: "var(--t4)", fontSize: 10 }}>›</span>
            <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", padding: "2px 4px" }}>{selectedCase.case_id}</span>
          </>}
          {selectedBehavior && <>
            <span style={{ color: "var(--t4)", fontSize: 10 }}>›</span>
            <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", padding: "2px 4px" }}>
              {selectedBehavior.process_name || selectedBehavior.description || selectedBehavior.behavior_id}
            </span>
          </>}
        </div>
      )}

      <div style={{ flex: 1 }} />

      <div style={{
        width: 22, height: 22, borderRadius: "50%", background: "var(--amb2)",
        border: "1px solid var(--amb3)", display: "flex", alignItems: "center",
        justifyContent: "center", fontSize: 9, fontWeight: 700, color: "var(--amb)",
      }}>AN</div>
    </div>
  )
}
