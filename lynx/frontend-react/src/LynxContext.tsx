import { createContext, useContext, useState } from "react"
import type { ReactNode } from "react"
import type { Case, Behavior } from "./types"

export type View = "investigation" | "actions" | "hunt" | "coverage" | "phishing"

export interface HuntPivot {
  templateId: string
  params: Record<string, string | number | boolean>
  label: string           // e.g. "Pivot: 10.77.30.10"
  sourceCase?: string     // originating case ID
  sourceBehavior?: string // originating behavior ID
}

interface LynxState {
  selectedCase: Case | null
  setSelectedCase: (c: Case | null) => void
  selectedBehavior: Behavior | null
  setSelectedBehavior: (b: Behavior | null) => void
  hoveredNodeId: number | null
  setHoveredNodeId: (id: number | null) => void
  activeRailTab: number
  setActiveRailTab: (n: number) => void
  // Navigation
  activeView: View
  setActiveView: (v: View) => void
  // Hunt pivot — set from CrossLayerTab, consumed by HuntWorkbench
  huntPivot: HuntPivot | null
  setHuntPivot: (p: HuntPivot | null) => void
}

const Ctx = createContext<LynxState>(null!)

export function LynxProvider({ children }: { children: ReactNode }) {
  const [selectedCase, setSelectedCase] = useState<Case | null>(null)
  const [selectedBehavior, setSelectedBehavior] = useState<Behavior | null>(null)
  const [hoveredNodeId, setHoveredNodeId] = useState<number | null>(null)
  const [activeRailTab, setActiveRailTab] = useState(0)
  const [activeView, setActiveView] = useState<View>("investigation")
  const [huntPivot, setHuntPivot] = useState<HuntPivot | null>(null)
  return (
    <Ctx.Provider value={{
      selectedCase, setSelectedCase,
      selectedBehavior, setSelectedBehavior,
      hoveredNodeId, setHoveredNodeId,
      activeRailTab, setActiveRailTab,
      activeView, setActiveView,
      huntPivot, setHuntPivot,
    }}>
      {children}
    </Ctx.Provider>
  )
}

// useLynx is the public accessor every page imports; it lives next to the
// provider it reads so the context object stays private to this module.
// eslint-disable-next-line react-refresh/only-export-components
export const useLynx = () => useContext(Ctx)
