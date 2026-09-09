import { LynxProvider } from "./LynxContext"
import { useLynx } from "./LynxContext"
import TopBar from "./components/TopBar"
import NavRail from "./components/NavRail"
import LeftRail from "./components/LeftRail"
import RightRail from "./components/RightRail"
import Investigation from "./pages/Investigation"
import ActionsLog from "./pages/ActionsLog"
import HuntWorkbench from "./pages/HuntWorkbench"
import CoverageMap from "./pages/CoverageMap"

// Inner component reads view from context — no prop drilling
function AppInner() {
  const { activeView, setActiveView } = useLynx()
  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>
      <TopBar />
      <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0 }}>
        <NavRail />
        <LeftRail />
        {activeView === "investigation" && <Investigation />}
        {activeView === "actions"       && <ActionsLog onNavigateToInvestigation={() => setActiveView("investigation")} />}
        {activeView === "hunt"          && <HuntWorkbench />}
        {activeView === "coverage"      && <CoverageMap />}
        {activeView === "investigation" && <RightRail />}
      </div>
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
