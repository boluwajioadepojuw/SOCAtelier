import { useLynx } from "../LynxContext"
import type { View } from "../LynxContext"
import { SearchOutlined, FileDoneOutlined, ExperimentOutlined, RadarChartOutlined } from "@ant-design/icons"

const ITEMS: { key: View; label: string; Icon: any }[] = [
  { key: "investigation", label: "Cases", Icon: SearchOutlined },
  { key: "actions", label: "Actions", Icon: FileDoneOutlined },
  { key: "hunt", label: "Hunt", Icon: ExperimentOutlined },
  { key: "coverage", label: "Coverage", Icon: RadarChartOutlined },
]

export default function NavRail() {
  const { activeView, setActiveView } = useLynx()

  return (
    <div style={{
      width: 58, flexShrink: 0, background: "var(--bg1)",
      borderRight: "1px solid var(--ln)",
      display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 8,
    }}>
      {ITEMS.map(({ key, label, Icon }) => {
        const active = activeView === key
        return (
          <div
            key={key}
            onClick={() => setActiveView(key)}
            title={label}
            style={{
              width: 44, padding: "8px 0 5px", marginBottom: 4, borderRadius: 4,
              cursor: "pointer", display: "flex", flexDirection: "column",
              alignItems: "center", gap: 3,
              color: active ? "var(--amb)" : "var(--t3)",
              background: active ? "var(--amb2)" : "transparent",
              border: active ? "1px solid var(--amb3)" : "1px solid transparent",
              transition: "color 0.12s, background 0.12s",
            }}
          >
            <Icon style={{ fontSize: 15 }} />
            <span style={{ fontSize: 8, fontFamily: "var(--mono)", letterSpacing: "0.04em" }}>{label}</span>
          </div>
        )
      })}
    </div>
  )
}
