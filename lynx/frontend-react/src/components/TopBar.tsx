import { useLynx } from "../LynxContext"
import LynxEye from "./LynxEye"

export default function TopBar() {
  const { activeView, selectedCase, selectedBehavior, setSelectedCase, setSelectedBehavior } = useLynx()

  return (
    <div style={{
      height: 36, background: "var(--bg1)", borderBottom: "1px solid var(--ln2)",
      display: "flex", alignItems: "center", padding: "0 14px", gap: 0, flexShrink: 0,
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 7,
        paddingRight: 14, borderRight: "1px solid var(--ln2)",
      }}>
        <LynxEye size={15} />
        <span style={{
          fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700,
          letterSpacing: "0.16em", color: "var(--amb)",
        }}>LYNX</span>
      </div>

      {/* Static system labels — no fake health dots */}
      <div style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: "0 14px", borderRight: "1px solid var(--ln2)",
      }}>
        {(["ES", "Fleet", "ILM"] as string[]).map(label => (
          <span key={label} style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)" }}>
            {label}
          </span>
        ))}
      </div>

      {/* View nav lives in the vertical rail; this bar is status + breadcrumb */}

      {/* Breadcrumb — only on investigation view */}
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
              {selectedBehavior.process_name || selectedBehavior.behavior_id}
            </span>
          </>}
        </div>
      )}

      <div style={{ flex: 1 }} />

      {/* Dead search bar removed */}

      {/* Avatar changed from FE to AN (Analyst — neutral) */}
      <div style={{
        width: 22, height: 22, borderRadius: "50%", background: "var(--amb2)",
        border: "1px solid var(--amb3)", display: "flex", alignItems: "center",
        justifyContent: "center", fontSize: 9, fontWeight: 700, color: "var(--amb)",
        marginLeft: 10,
      }}>AN</div>
    </div>
  )
}
