import { useState } from "react"
import { LynxProvider } from "./LynxContext"
import { useLynx } from "./LynxContext"
import TopBar from "./components/TopBar"
import TabStrip from "./components/TabStrip"
import LeftRail from "./components/LeftRail"
import RightRail from "./components/RightRail"
import StatusBar from "./components/StatusBar"
import Investigation from "./pages/Investigation"
import ActionsLog from "./pages/ActionsLog"
import HuntWorkbench from "./pages/HuntWorkbench"
import CoverageMap from "./pages/CoverageMap"
import PhishingLab from "./pages/PhishingLab"

// Inner component reads view from context — no prop drilling
function AppInner() {
  const { activeView, setActiveView } = useLynx()
  const [showRight, setShowRight] = useState(false)
  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>
      <TopBar />
      <TabStrip showRight={showRight} setShowRight={setShowRight} />
      <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0 }}>
        <LeftRail />
        {activeView === "investigation" && <Investigation />}
        {activeView === "actions"       && <ActionsLog onNavigateToInvestigation={() => setActiveView("investigation")} />}
        {activeView === "hunt"          && <HuntWorkbench />}
        {activeView === "coverage"      && <CoverageMap />}
        {activeView === "phishing"      && <PhishingLab />}
        {activeView === "investigation" && showRight && (
          <div style={{ width: 300, flexShrink: 0, display: "flex", flexDirection: "column", background: "var(--bg1)", borderLeft: "1px solid var(--ln2)" }}>
            <div style={{ height: 26, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 8px", borderBottom: "1px solid var(--ln2)", fontSize: 9.5, fontFamily: "var(--mono)", color: "var(--t3)" }}>
              <span>INTEL / ACTIONS</span>
              <span onClick={() => setShowRight(false)} style={{ cursor: "pointer", color: "var(--t2)" }}>close x</span>
            </div>
            <div style={{ flex: 1, overflow: "hidden" }}><RightRail /></div>
          </div>
        )}
      </div>
      <StatusBar />
    </div>
  )
}

export default function App() {
  return (
    <LynxProvider>
      <AppInner />
    </LynxProvider>
  )
}
