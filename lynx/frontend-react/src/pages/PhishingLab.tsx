import { useState } from "react"

interface PhishingVerdict {
  ok: boolean
  score: number
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  sender: {
    from: string
    display_name: string
    reply_to: string | null
    return_path: string | null
    from_domain: string
  }
  subject: string
  indicators: {
    urls: string[]
    url_domains: string[]
    ip_literal_urls: string[]
    punycode_domains: string[]
    suspicious_tld_domains: string[]
    ips: string[]
    attachments: string[]
    unsafe_attachments: string[]
  }
  authentication: {
    has_auth_headers: boolean
    spf_fail: boolean
    dkim_fail: boolean
    dmarc_fail: boolean
  }
  findings: { title: string; detail: string; weight: number }[]
  mitre: { technique: string; name: string; reason: string }[]
  next_steps: string[]
}

const RISK_COLOR: Record<PhishingVerdict["risk"], string> = {
  LOW: "var(--grn)",
  MEDIUM: "var(--amb)",
  HIGH: "var(--red)",
  CRITICAL: "var(--red)",
}

const EXAMPLE = ["From: \"Microsoft Security\" <security@ms-support-verify.tk>",
  "Reply-To: attacker@example-evil.xyz",
  "Subject: Urgent: verify your password immediately",
  "Content-Type: text/plain",
  "",
  "Your account has been locked. Verify your password now:",
  "http://185.12.44.9/login and also https://xn--mcrsoft-9ya.com/verify"].join("\n")

export default function PhishingLab() {
  const [raw, setRaw] = useState("")
  const [verdict, setVerdict] = useState<PhishingVerdict | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [running, setRunning] = useState(false)

  async function analyze() {
    if (!raw.trim()) return
    setRunning(true)
    setError(null)
    setVerdict(null)
    try {
      const res = await fetch("/api/phishing/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw }),
      })
      const data = await res.json()
      if (!res.ok || !data.ok) throw new Error(data.detail || data.error || "analysis failed")
      setVerdict(data as PhishingVerdict)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setRunning(false)
    }
  }

  function loadExample() {
    setRaw(EXAMPLE)
    setVerdict(null)
    setError(null)
  }

  return (
    <div style={{ flex: 1, display: "flex", overflow: "hidden", background: "var(--bg0)" }}>
      {/* Input */}
      <div style={{ width: 380, flexShrink: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--ln)" }}>
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--ln)" }}>
          <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 4 }}>
            Phishing triage
          </div>
          <div style={{ fontSize: 11, color: "var(--t2)", lineHeight: 1.5 }}>
            Paste a raw email (headers + body). The analyzer extracts indicators, checks
            the classic L1 signals and maps findings onto MITRE ATT&CK - fully offline.
          </div>
        </div>
        <textarea
          value={raw}
          onChange={e => setRaw(e.target.value)}
          placeholder="Paste the raw email here..."
          spellCheck={false}
          style={{
            flex: 1, resize: "none", background: "var(--bg1)", color: "var(--t1)",
            border: "none", outline: "none", padding: "12px 16px", fontSize: 10.5,
            fontFamily: "var(--mono)", lineHeight: 1.5,
          }}
        />
        <div style={{ padding: "10px 16px", display: "flex", gap: 8, borderTop: "1px solid var(--ln)" }}>
          <button onClick={analyze} disabled={running || !raw.trim()} style={{
            padding: "6px 18px", background: "var(--teal)", color: "var(--bg0)",
            border: "none", borderRadius: 3, fontSize: 11, fontWeight: 700,
            cursor: running || !raw.trim() ? "not-allowed" : "pointer",
            opacity: running || !raw.trim() ? 0.6 : 1, letterSpacing: "0.04em",
          }}>{running ? "Analyzing..." : "Analyze"}</button>
          <button onClick={loadExample} style={{
            padding: "6px 12px", background: "transparent", color: "var(--t3)",
            border: "1px solid var(--ln2)", borderRadius: 3, fontSize: 10,
            cursor: "pointer", fontFamily: "var(--mono)",
          }}>Load example</button>
        </div>
      </div>

      {/* Result */}
      <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}>
        {!verdict && !error && (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8, color: "var(--t3)", height: "100%" }}>
            <div style={{ fontSize: 26, color: "var(--teal)" }}>PHISH</div>
            <div style={{ fontSize: 12, color: "var(--t2)" }}>Paste an email and run the analyzer</div>
            <div style={{ fontSize: 10, fontFamily: "var(--mono)" }}>Deterministic - no AI service required</div>
          </div>
        )}
        {error && (
          <div style={{ fontSize: 11, color: "var(--red)", fontFamily: "var(--mono)" }}>
            Failed: {error}
          </div>
        )}
        {verdict && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
              <div style={{
                fontSize: 30, fontWeight: 700, fontFamily: "var(--mono)",
                color: RISK_COLOR[verdict.risk],
              }}>{verdict.score}</div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: RISK_COLOR[verdict.risk], letterSpacing: "0.06em" }}>
                  {verdict.risk}
                </div>
                <div style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)" }}>
                  {verdict.findings.length} signal(s) · {verdict.mitre.length} MITRE mapping(s)
                </div>
              </div>
              <div style={{ marginLeft: "auto", textAlign: "right", maxWidth: 320 }}>
                <div style={{ fontSize: 10, color: "var(--t1)", fontWeight: 600 }}>{verdict.sender.display_name || verdict.sender.from}</div>
                <div style={{ fontSize: 9, color: "var(--t3)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {verdict.subject || "(no subject)"}
                </div>
              </div>
            </div>

            {/* Sender + authentication */}
            <div style={{ background: "var(--bg1)", border: "1px solid var(--ln2)", borderRadius: 4, padding: "10px 14px", marginBottom: 14 }}>
              <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 8 }}>
                Sender and authentication
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 6 }}>
                <div style={{ fontSize: 10 }}><span style={{ color: "var(--t4)" }}>From: </span><span style={{ fontFamily: "var(--mono)", color: "var(--t2)" }}>{verdict.sender.from}</span></div>
                <div style={{ fontSize: 10 }}><span style={{ color: "var(--t4)" }}>Reply-To: </span><span style={{ fontFamily: "var(--mono)", color: "var(--t2)" }}>{verdict.sender.reply_to || "-"}</span></div>
                <div style={{ fontSize: 10 }}><span style={{ color: "var(--t4)" }}>Return-Path: </span><span style={{ fontFamily: "var(--mono)", color: "var(--t2)" }}>{verdict.sender.return_path || "-"}</span></div>
                <div style={{ fontSize: 10 }}>
                  <span style={{ color: "var(--t4)" }}>Auth: </span>
                  <span style={{ fontFamily: "var(--mono)", color: verdict.authentication.has_auth_headers ? "var(--t2)" : "var(--amb)" }}>
                    {verdict.authentication.has_auth_headers
                      ? "SPF" + (verdict.authentication.spf_fail ? " FAIL" : " pass") + " · DKIM" + (verdict.authentication.dkim_fail ? " FAIL" : " pass") + " · DMARC" + (verdict.authentication.dmarc_fail ? " FAIL" : " pass")
                      : "no authentication headers"}
                  </span>
                </div>
              </div>
            </div>

            {/* Findings */}
            <div style={{ background: "var(--bg1)", border: "1px solid var(--ln2)", borderRadius: 4, padding: "10px 14px", marginBottom: 14 }}>
              <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 8 }}>
                Findings
              </div>
              {verdict.findings.map((f, i) => (
                <div key={i} style={{ display: "flex", gap: 10, marginBottom: 6, alignItems: "baseline" }}>
                  <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--amb)", width: 24, flexShrink: 0, textAlign: "right" }}>
                    +{f.weight}
                  </span>
                  <div>
                    <div style={{ fontSize: 10.5, color: "var(--t1)", fontWeight: 600 }}>{f.title}</div>
                    <div style={{ fontSize: 9.5, color: "var(--t3)", fontFamily: "var(--mono)" }}>{f.detail}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Indicators */}
            {(verdict.indicators.urls.length > 0 || verdict.indicators.attachments.length > 0 || verdict.indicators.ips.length > 0) && (
              <div style={{ background: "var(--bg1)", border: "1px solid var(--ln2)", borderRadius: 4, padding: "10px 14px", marginBottom: 14 }}>
                <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 8 }}>
                  Extracted indicators
                </div>
                {verdict.indicators.urls.length > 0 && (
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 9, color: "var(--t4)", marginBottom: 3 }}>URLs</div>
                    {verdict.indicators.urls.slice(0, 8).map(u => (
                      <div key={u} style={{ fontSize: 9.5, fontFamily: "var(--mono)", color: "var(--t2)", wordBreak: "break-all" }}>{u}</div>
                    ))}
                  </div>
                )}
                {verdict.indicators.ip_literal_urls.length > 0 && (
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 9, color: "var(--amb)", marginBottom: 3 }}>IP-literal URLs (host obfuscation)</div>
                    {verdict.indicators.ip_literal_urls.map(u => (
                      <div key={u} style={{ fontSize: 9.5, fontFamily: "var(--mono)", color: "var(--amb)", wordBreak: "break-all" }}>{u}</div>
                    ))}
                  </div>
                )}
                {verdict.indicators.punycode_domains.length > 0 && (
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 9, color: "var(--amb)", marginBottom: 3 }}>Punycode domains (lookalike)</div>
                    {verdict.indicators.punycode_domains.map(d => (
                      <div key={d} style={{ fontSize: 9.5, fontFamily: "var(--mono)", color: "var(--amb)" }}>{d}</div>
                    ))}
                  </div>
                )}
                {verdict.indicators.attachments.length > 0 && (
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 9, color: "var(--t4)", marginBottom: 3 }}>Attachments</div>
                    {verdict.indicators.attachments.map(a => {
                      const unsafe = verdict.indicators.unsafe_attachments.includes(a)
                      return (
                        <div key={a} style={{ fontSize: 9.5, fontFamily: "var(--mono)", color: unsafe ? "var(--red)" : "var(--t2)" }}>
                          {a}{unsafe ? " (unsafe type)" : ""}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )}

            {/* MITRE */}
            <div style={{ background: "var(--bg1)", border: "1px solid var(--ln2)", borderRadius: 4, padding: "10px 14px", marginBottom: 14 }}>
              <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 8 }}>
                MITRE ATT&CK
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                {verdict.mitre.map(m => (
                  <div key={m.technique} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                    <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--teal)", width: 76, flexShrink: 0 }}>{m.technique}</span>
                    <span style={{ fontSize: 10, color: "var(--t1)" }}>{m.name}</span>
                    <span style={{ fontSize: 9, color: "var(--t3)", fontFamily: "var(--mono)" }}>· {m.reason}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Next steps */}
            <div style={{ background: "var(--bg2)", border: "1px solid var(--teal3)", borderLeft: "3px solid var(--teal)", borderRadius: 4, padding: "10px 14px" }}>
              <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--teal)", textTransform: "uppercase", marginBottom: 8 }}>
                Next steps
              </div>
              {verdict.next_steps.map((s, i) => (
                <div key={i} style={{ fontSize: 10, color: "var(--t2)", display: "flex", gap: 6, marginBottom: 3 }}>
                  <span style={{ color: "var(--teal)" }}>→</span><span>{s}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
