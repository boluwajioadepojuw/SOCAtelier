// TabStrip -- horizontal view switcher + right-drawer toggle.
// Replaces the old vertical icon rail: the workspace reads top-down,
// and the Intel/Actions panel is a collapsible drawer, not a fixed rail.
import { useLynx } from "../LynxContext"
import type { View } from "../LynxContext"

const TABS: { key: View; label: string }[] = [
  { key: "investigation", label: "Cases" },
  { key: "actions", label: "Action Log" },
  { key: "hunt", label: "Hunt" },
  { key: "coverage", label: "Coverage" },
]

export default function TabStrip({ showRight, setShowRight }: { showRight: boolean; setShowRight: (v: boolean) => void }) {
  const { activeView, setActiveView } = useLynx()
  return (
    <div style={{
      height: 34, flexShrink: 0, background: "var(--bg1)",
      borderBottom: "1px solid var(--ln2)", display: "flex", alignItems: "stretch",
      padding: "0 10px", gap: 2,
    }}>
      {TABS.map(({ key, label }) => {
        const active = activeView === key
        return (
          <button
            key={key}
            onClick={() => setActiveView(key)}
            style={{
              background: "transparent", border: "none", cursor: "pointer",
              padding: "0 12px", fontSize: 10.5, fontFamily: "var(--mono)",
              letterSpacing: "0.05em", color: active ? "var(--t1)" : "var(--t3)",
              borderBottom: active ? "2px solid var(--amb)" : "2px solid transparent",
              transition: "color 0.12s, border-color 0.12s",
            }}
          >
            {label}
          </button>
        )
      })}
      <span style={{ flex: 1 }} />
      <button
        onClick={() => setShowRight(!showRight)}
        style={{
          background: showRight ? "var(--amb2)" : "transparent",
          border: showRight ? "1px solid var(--amb3)" : "1px solid transparent",
          borderRadius: 3, cursor: "pointer", padding: "0 10px", margin: "5px 0",
          fontSize: 10, fontFamily: "var(--mono)", color: showRight ? "var(--amb)" : "var(--t3)",
        }}
      >
        {showRight ? "hide intel panel" : "intel panel"}
      </button>
    </div>
  )
}
