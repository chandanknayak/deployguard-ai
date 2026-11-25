import React, { useEffect, useMemo, useState } from "react";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  import.meta.env.VITE_API_URL ||
  "https://deployguard-ai.onrender.com";

const DEMO_ASSESSMENTS = [
  {
    id: "pr-418",
    repo: "acme/payments-core",
    prNumber: 418,
    title: "Refactor ledger settlement lock & retry backoff",
    author: "r.patel",
    riskScore: 84,
    gateStatus: "BLOCK",
    blastRadiusHops: 4,
    affectedServices: ["ledger-worker", "checkout-api", "webhook-dispatcher", "audit-sink"],
    matchedIncidents: [
      { id: "INC-209", title: "Redis lock contention during peak settlement", similarity: 0.92 },
      { id: "INC-174", title: "Duplicate ledger debit on retry timeout", similarity: 0.85 },
    ],
    recommendation: "Hold merge. Add idempotency key guard on retry path and run canary on 5% traffic first.",
    updatedAt: "12m ago",
  },
  {
    id: "pr-421",
    repo: "acme/auth-gateway",
    prNumber: 421,
    title: "Update OAuth token refresh jitter window",
    author: "s.nair",
    riskScore: 46,
    gateStatus: "WARN",
    blastRadiusHops: 2,
    affectedServices: ["auth-gateway", "session-cache"],
    matchedIncidents: [
      { id: "INC-142", title: "Thundering herd on JWT key rotation", similarity: 0.74 },
    ],
    recommendation: "Proceed with caution. Monitor 401/429 spike and cache hit ratio for 15 minutes post-deploy.",
    updatedAt: "38m ago",
  },
  {
    id: "pr-425",
    repo: "acme/billing-ui",
    prNumber: 425,
    title: "Improve invoice CSV export formatting & headers",
    author: "a.verma",
    riskScore: 18,
    gateStatus: "PASS",
    blastRadiusHops: 1,
    affectedServices: ["billing-ui"],
    matchedIncidents: [],
    recommendation: "Safe to merge. Low blast radius and no matching high-severity incidents.",
    updatedAt: "1h ago",
  },
];

function deriveGateStatus(score, threshold = 70) {
  if (score >= threshold) return "BLOCK";
  if (score >= 40) return "WARN";
  return "PASS";
}

function badgeClasses(status) {
  switch (status) {
    case "BLOCK":
      return "bg-red-500/15 text-red-300 border-red-500/40";
    case "WARN":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    default:
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
  }
}

export default function App() {
  const [assessments, setAssessments] = useState(DEMO_ASSESSMENTS);
  const [selectedId, setSelectedId] = useState(DEMO_ASSESSMENTS[0].id);
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [apiOnline, setApiOnline] = useState(false);
  const [loading, setLoading] = useState(false);

  // Interactive PR Risk Simulator state
  const [simFilesChanged, setSimFilesChanged] = useState(8);
  const [simBlastHops, setSimBlastHops] = useState(3);
  const [simPastIncidents, setSimPastIncidents] = useState(1);
  const [simTouchesCore, setSimTouchesCore] = useState(true);

  useEffect(() => {
    let active = true;

    async function loadLiveData() {
      setLoading(true);
      try {
        const healthRes = await fetch(`${API_BASE}/healthz`, { signal: AbortSignal.timeout(5000) });
        if (!healthRes.ok) throw new Error("Health check failed");

        const listRes = await fetch(`${API_BASE}/assessments/`, { signal: AbortSignal.timeout(5000) });
        if (!active) return;

        setApiOnline(true);
        if (listRes.ok) {
          const payload = await listRes.json();
          const items = Array.isArray(payload)
            ? payload
            : payload?.results || payload?.items || payload?.assessments;
          if (Array.isArray(items) && items.length > 0) {
            const normalized = items.map((item, idx) => {
              const agent = item.agent_assessment || {};
              const blast = item.blast_radius || {};
              const score = Number(agent.risk_score ?? item.risk_score ?? item.riskScore ?? 25);
              return {
                id: item.assessment_id || item.id || item._id || `live-${idx}`,
                repo: item.repo_full_name || item.repo || item.repository || "unknown/repo",
                prNumber: item.pr_number ?? item.prNumber ?? idx + 1,
                title: item.pr_title || item.title || "Pull request assessment",
                author: item.pr_author || item.author || "ci-bot",
                riskScore: score,
                gateStatus: item.risk_level || item.gate_status || item.gateStatus || deriveGateStatus(score),
                blastRadiusHops: Number(blast.max_depth_reached ?? item.blast_radius_hops ?? item.blastRadiusHops ?? 1),
                affectedServices: blast.affected_services || item.affected_services || item.affectedServices || ["core-service"],
                matchedIncidents: item.matched_incidents || item.matchedIncidents || [],
                recommendation: agent.executive_summary || item.recommendation || "Review AST blast radius before merging.",
                updatedAt: item.created_at || item.updated_at || item.updatedAt || "Live",
              };
            });
            setAssessments(normalized);
            setSelectedId(normalized[0].id);
          }
        }
      } catch {
        if (active) {
          setApiOnline(false);
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    loadLiveData();
    return () => {
      active = false;
    };
  }, []);

  const filteredAssessments = useMemo(() => {
    return assessments.filter((item) => {
      const matchesStatus = filterStatus === "ALL" || item.gateStatus === filterStatus;
      const q = searchQuery.trim().toLowerCase();
      const matchesQuery =
        !q ||
        item.title.toLowerCase().includes(q) ||
        item.repo.toLowerCase().includes(q) ||
        String(item.prNumber).includes(q);
      return matchesStatus && matchesQuery;
    });
  }, [assessments, filterStatus, searchQuery]);

  const activeAssessment = useMemo(() => {
    return (
      filteredAssessments.find((a) => a.id === selectedId) ||
      filteredAssessments[0] ||
      assessments[0]
    );
  }, [filteredAssessments, selectedId, assessments]);

  const simulatedScore = useMemo(() => {
    const raw =
      simFilesChanged * 3.5 +
      simBlastHops * 11 +
      simPastIncidents * 16 +
      (simTouchesCore ? 18 : 0);
    return Math.min(99, Math.max(5, Math.round(raw)));
  }, [simFilesChanged, simBlastHops, simPastIncidents, simTouchesCore]);

  const simulatedGate = deriveGateStatus(simulatedScore);

  const metrics = useMemo(() => {
    const blocked = assessments.filter((a) => a.gateStatus === "BLOCK").length;
    const avgScore = assessments.length
      ? Math.round(assessments.reduce((acc, a) => acc + a.riskScore, 0) / assessments.length)
      : 0;
    const maxHops = assessments.reduce((max, a) => Math.max(max, a.blastRadiusHops), 0);
    return { blocked, avgScore, maxHops, total: assessments.length };
  }, [assessments]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold tracking-tight text-white">DeployGuard AI</h1>
              <span className="rounded-full border border-indigo-500/40 bg-indigo-500/15 px-2.5 py-0.5 text-xs font-medium text-indigo-300">
                Release Risk Gate
              </span>
            </div>
            <p className="mt-0.5 text-xs text-slate-400">
              AST Blast Radius · Historical Incident Vector Recall · Autonomous CI/CD Policy
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${
                apiOnline
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : "border-amber-500/40 bg-amber-500/10 text-amber-300"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  apiOnline ? "bg-emerald-400" : "bg-amber-400"
                }`}
              />
              {loading ? "Syncing API..." : apiOnline ? "Live Backend Connected" : "Demo Fallback Mode"}
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {/* Executive KPI Cards */}
        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
              Evaluated PRs
            </p>
            <p className="mt-2 text-2xl font-bold text-white">{metrics.total}</p>
            <p className="mt-1 text-xs text-slate-400">Active release candidates</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
              Blocked Releases
            </p>
            <p className="mt-2 text-2xl font-bold text-red-400">{metrics.blocked}</p>
            <p className="mt-1 text-xs text-slate-400">Score &gt;= 70 gate threshold</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
              Avg Risk Score
            </p>
            <p className="mt-2 text-2xl font-bold text-indigo-300">{metrics.avgScore}/100</p>
            <p className="mt-1 text-xs text-slate-400">Composite risk index</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
              Max Blast Radius
            </p>
            <p className="mt-2 text-2xl font-bold text-amber-300">{metrics.maxHops} hops</p>
            <p className="mt-1 text-xs text-slate-400">Dependency graph depth</p>
          </div>
        </section>

        {/* Assessments Queue + Detail Inspector */}
        <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-4 lg:col-span-5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-white">Pull Request Queue</h2>
              <div className="flex gap-1">
                {["ALL", "BLOCK", "WARN", "PASS"].map((status) => (
                  <button
                    key={status}
                    type="button"
                    onClick={() => setFilterStatus(status)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition ${
                      filterStatus === status
                        ? "bg-indigo-600 text-white"
                        : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                    }`}
                  >
                    {status}
                  </button>
                ))}
              </div>
            </div>

            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by repo, PR #, or title..."
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
            />

            <div className="space-y-2.5">
              {filteredAssessments.map((item) => {
                const isSelected = activeAssessment?.id === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSelectedId(item.id)}
                    className={`w-full rounded-lg border p-3 text-left transition ${
                      isSelected
                        ? "border-indigo-500 bg-slate-800/90"
                        : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-mono text-slate-400">
                        {item.repo} #{item.prNumber}
                      </span>
                      <span
                        className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${badgeClasses(
                          item.gateStatus
                        )}`}
                      >
                        {item.gateStatus} · {item.riskScore}
                      </span>
                    </div>
                    <p className="mt-1 text-sm font-medium text-white line-clamp-1">{item.title}</p>
                    <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
                      <span>by {item.author}</span>
                      <span>{item.blastRadiusHops} graph hops</span>
                      <span>{item.updatedAt}</span>
                    </div>
                  </button>
                );
              })}

              {filteredAssessments.length === 0 && (
                <p className="py-8 text-center text-sm text-slate-400">
                  No pull requests match the current filter.
                </p>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 lg:col-span-7">
            {activeAssessment ? (
              <div className="space-y-5">
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                  <div>
                    <p className="text-xs font-mono text-indigo-300">
                      {activeAssessment.repo} · Pull Request #{activeAssessment.prNumber}
                    </p>
                    <h2 className="mt-1 text-lg font-bold text-white">{activeAssessment.title}</h2>
                  </div>
                  <div className="text-right">
                    <span
                      className={`inline-block rounded-md border px-3 py-1 text-xs font-bold ${badgeClasses(
                        activeAssessment.gateStatus
                      )}`}
                    >
                      GATE: {activeAssessment.gateStatus}
                    </span>
                    <p className="mt-1 text-xs text-slate-400">
                      Risk Score: <strong className="text-white">{activeAssessment.riskScore}/100</strong>
                    </p>
                  </div>
                </div>

                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Blast Radius Services ({activeAssessment.blastRadiusHops} hops)
                  </h3>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {activeAssessment.affectedServices.map((svc) => (
                      <span
                        key={svc}
                        className="rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-mono text-slate-200"
                      >
                        {svc}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Historical Incident Matches
                  </h3>
                  {activeAssessment.matchedIncidents.length > 0 ? (
                    <div className="mt-2 space-y-2">
                      {activeAssessment.matchedIncidents.map((inc) => (
                        <div
                          key={inc.id}
                          className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 px-3.5 py-2.5 text-sm"
                        >
                          <div>
                            <span className="font-mono text-xs text-amber-300">{inc.id}</span>{" "}
                            <span className="text-slate-200">{inc.title}</span>
                          </div>
                          <span className="text-xs text-slate-400">
                            {Math.round(inc.similarity * 100)}% match
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-2 text-sm text-slate-400">
                      No similar historical incidents detected.
                    </p>
                  )}
                </div>

                <div className="rounded-lg border border-indigo-500/30 bg-indigo-950/30 p-4">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
                    Release Agent Recommendation
                  </h3>
                  <p className="mt-1.5 text-sm leading-relaxed text-slate-200">
                    {activeAssessment.recommendation}
                  </p>
                </div>
              </div>
            ) : null}
          </div>
        </section>

        {/* Interactive Risk Simulator */}
        <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-bold text-white">Release Risk Simulator</h2>
              <p className="text-xs text-slate-400">
                Model how diff size, dependency hops, incident history, and core paths affect the gate
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-sm text-slate-300">
                Simulated Score: <strong className="text-white">{simulatedScore}/100</strong>
              </span>
              <span
                className={`rounded-md border px-2.5 py-1 text-xs font-bold ${badgeClasses(
                  simulatedGate
                )}`}
              >
                {simulatedGate}
              </span>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-5 md:grid-cols-4">
            <label className="space-y-1.5 text-xs text-slate-300">
              <div className="flex justify-between">
                <span>Modified Files</span>
                <span className="font-mono text-white">{simFilesChanged}</span>
              </div>
              <input
                type="range"
                min="1"
                max="40"
                value={simFilesChanged}
                onChange={(e) => setSimFilesChanged(Number(e.target.value))}
                className="w-full accent-indigo-500"
              />
            </label>

            <label className="space-y-1.5 text-xs text-slate-300">
              <div className="flex justify-between">
                <span>Blast Radius Hops</span>
                <span className="font-mono text-white">{simBlastHops}</span>
              </div>
              <input
                type="range"
                min="0"
                max="6"
                value={simBlastHops}
                onChange={(e) => setSimBlastHops(Number(e.target.value))}
                className="w-full accent-indigo-500"
              />
            </label>

            <label className="space-y-1.5 text-xs text-slate-300">
              <div className="flex justify-between">
                <span>Past Incidents</span>
                <span className="font-mono text-white">{simPastIncidents}</span>
              </div>
              <input
                type="range"
                min="0"
                max="5"
                value={simPastIncidents}
                onChange={(e) => setSimPastIncidents(Number(e.target.value))}
                className="w-full accent-indigo-500"
              />
            </label>

            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 px-3.5 py-2.5">
              <span className="text-xs font-medium text-slate-300">Touches Critical Path</span>
              <input
                type="checkbox"
                checked={simTouchesCore}
                onChange={(e) => setSimTouchesCore(e.target.checked)}
                className="h-4 w-4 accent-indigo-500"
              />
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
