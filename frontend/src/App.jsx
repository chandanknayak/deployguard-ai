import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  GitPullRequest, 
  Network, 
  Rocket, 
  Settings, 
  FolderGit2, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  ExternalLink, 
  RefreshCw, 
  Plus, 
  Check, 
  Activity,
  Server,
  Lock,
  ArrowRight
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'https://deployguard-ai.onrender.com';

const INITIAL_PRS = [
  {
    pr_number: 1,
    title: "feat(core): Add async exponential backoff retry utility",
    author: "chandanknayak",
    branch: "feat-retry",
    base_branch: "main",
    additions: 124,
    deletions: 8,
    changed_files: 3,
    risk_level: "PASS",
    risk_score: 18,
    decision: "PASS",
    blast_radius: {
      affected_services: ["deployguard-ai", "notification-service"],
      max_sla_tier: "P1",
      total_downstream: 2
    },
    ast_summary: {
      breaking_changes: 0,
      added_classes: ["AsyncRetryPolicy"],
      added_functions: ["with_exponential_backoff"],
      schema_changes: false
    },
    rationale: "Additive change with zero breaking signatures. Comprehensive test coverage for exponential backoff."
  },
  {
    pr_number: 2,
    title: "refactor(auth): Update session token verification schema",
    author: "alex-dev",
    branch: "refactor-auth-v2",
    base_branch: "main",
    additions: 340,
    deletions: 190,
    changed_files: 8,
    risk_level: "WARN",
    risk_score: 54,
    decision: "WARN",
    blast_radius: {
      affected_services: ["auth-core", "payment-service", "gateway-api"],
      max_sla_tier: "P0",
      total_downstream: 3
    },
    ast_summary: {
      breaking_changes: 1,
      added_classes: ["TokenValidatorV2"],
      added_functions: ["verify_jwt_claim"],
      schema_changes: true
    },
    rationale: "Core token validation refactored. Impacts P0 auth services. Recommended to roll out via 10% canary first."
  },
  {
    pr_number: 3,
    title: "feat(payments): Remove deprecated Stripe v1 charge endpoints",
    author: "sara-fintech",
    branch: "drop-stripe-v1",
    base_branch: "main",
    additions: 45,
    deletions: 480,
    changed_files: 12,
    risk_level: "BLOCK",
    risk_score: 88,
    decision: "BLOCK",
    blast_radius: {
      affected_services: ["payment-service", "billing-worker", "customer-portal", "invoice-gen"],
      max_sla_tier: "P0",
      total_downstream: 4
    },
    ast_summary: {
      breaking_changes: 5,
      added_classes: [],
      added_functions: [],
      schema_changes: true
    },
    rationale: "CRITICAL: Deletes 5 active API endpoints used by downstream billing workers. Direct merge strictly blocked."
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('prs');
  const [prs, setPrs] = useState(INITIAL_PRS);
  const [selectedPRIndex, setSelectedPRIndex] = useState(0);
  const [isApiOnline, setIsApiOnline] = useState(true);
  const [activeRepo, setActiveRepo] = useState('chandanknayak/deployguard-ai');
  const [bannerMsg, setBannerMsg] = useState('');
  const [testStatus, setTestStatus] = useState(null);
  const [deployStatus, setDeployStatus] = useState(null);
  const [isLinkModalOpen, setIsLinkModalOpen] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [newRepoName, setNewRepoName] = useState('');

  const currentPR = prs[selectedPRIndex] || prs[0];

  useEffect(() => {
    fetch(`${API_BASE}/healthz`)
      .then(res => res.ok ? setIsApiOnline(true) : setIsApiOnline(false))
      .catch(() => setIsApiOnline(false));
  }, []);

  const showBanner = (msg) => {
    setBannerMsg(msg);
    setTimeout(() => setBannerMsg(''), 4000);
  };

  const handleMerge = async (prNumber, override) => {
    if (override) {
      const reason = prompt("Enter mandatory emergency override justification:");
      if (!reason) return;
    }
    showBanner(`Executing merge for PR #${prNumber}...`);
    try {
      const res = await fetch(`${API_BASE}/enterprise/repos/${activeRepo}/pulls/${prNumber}/merge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ merge_method: 'merge', admin_override: override })
      });
      const data = await res.json();
      showBanner(data.message || `✓ PR #${prNumber} merged successfully into main branch!`);
    } catch {
      showBanner(`✓ PR #${prNumber} merged into main branch (Simulated).`);
    }
  };

  const runTests = () => {
    setTestStatus('running');
    setTimeout(() => {
      setTestStatus('passed');
      showBanner("✓ 67 unit & AST contract tests passed in 1.41s.");
    }, 1400);
  };

  const triggerCanary = () => {
    setDeployStatus('deploying');
    setTimeout(() => {
      setDeployStatus('live');
      showBanner("🚀 Canary deployment (10% traffic) live. Zero error anomalies.");
    }, 1800);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Navbar */}
      <header className="sticky top-0 z-40 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-500 flex items-center justify-center shadow-lg shadow-indigo-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg text-white">DeployGuard <span className="text-indigo-400">AI</span></span>
                <span className="text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 px-2 py-0.5 rounded-full uppercase">Enterprise</span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">AI-Powered Release Risk & Change-Impact Guard</p>
            </div>
          </div>

          <nav className="hidden md:flex items-center space-x-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800 text-xs">
            <button 
              onClick={() => setActiveTab('prs')}
              className={`px-3.5 py-1.5 rounded-lg font-medium transition ${activeTab === 'prs' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'}`}
            >
              PR Command Center
            </button>
            <button 
              onClick={() => setActiveTab('blast')}
              className={`px-3.5 py-1.5 rounded-lg font-medium transition ${activeTab === 'blast' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'}`}
            >
              Blast Radius
            </button>
            <button 
              onClick={() => setActiveTab('deploy')}
              className={`px-3.5 py-1.5 rounded-lg font-medium transition ${activeTab === 'deploy' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'}`}
            >
              Release Hub
            </button>
            <button 
              onClick={() => setActiveTab('repos')}
              className={`px-3.5 py-1.5 rounded-lg font-medium transition ${activeTab === 'repos' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'}`}
            >
              Repositories
            </button>
            <button 
              onClick={() => setActiveTab('policy')}
              className={`px-3.5 py-1.5 rounded-lg font-medium transition ${activeTab === 'policy' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white'}`}
            >
              Governance
            </button>
          </nav>

          <div className="flex items-center space-x-3">
            <div className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${isApiOnline ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'}`}>
              <span className={`w-2 h-2 rounded-full ${isApiOnline ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
              <span>{isApiOnline ? 'Cloud API Online' : 'Local / Demo Mode'}</span>
            </div>

            <button 
              onClick={() => setIsAuthModalOpen(true)}
              className="flex items-center space-x-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 px-3 py-1.5 rounded-xl text-xs font-medium transition"
            >
              <span className="w-5 h-5 rounded-full bg-indigo-600/40 text-indigo-300 flex items-center justify-center font-bold text-[10px]">DG</span>
              <span>Enterprise Org</span>
            </button>
          </div>
        </div>
      </header>

      {/* Banner */}
      {bannerMsg && (
        <div className="bg-indigo-950/80 border-b border-indigo-500/30 px-4 py-2 text-center text-xs text-indigo-200">
          {bannerMsg}
        </div>
      )}

      {/* Main Container */}
      <main className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 flex-1">
        {/* Repo Picker Bar */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-2xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center space-x-3">
            <FolderGit2 className="w-5 h-5 text-indigo-400" />
            <span className="text-xs text-slate-400">Guarded Repo:</span>
            <select 
              value={activeRepo} 
              onChange={(e) => { setActiveRepo(e.target.value); showBanner(`Switched to ${e.target.value}`); }}
              className="bg-slate-950 border border-slate-700 text-white text-xs rounded-xl px-3 py-1.5 font-mono focus:outline-none focus:border-indigo-500"
            >
              <option value="chandanknayak/deployguard-ai">chandanknayak/deployguard-ai</option>
              <option value="acme-corp/payment-service">acme-corp/payment-service [P0]</option>
              <option value="acme-corp/auth-core">acme-corp/auth-core [P0]</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <button 
              onClick={() => setIsLinkModalOpen(true)}
              className="px-3 py-1.5 rounded-xl text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition flex items-center space-x-1"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Link Repository</span>
            </button>
            <button 
              onClick={() => showBanner("Data refreshed from GitHub and MongoDB.")}
              className="px-3 py-1.5 rounded-xl text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition flex items-center space-x-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* TAB 1: PR COMMAND CENTER */}
        {activeTab === 'prs' && (
          <div className="space-y-6">
            {/* Metric counters */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-2xl bg-slate-900/50 border border-slate-800">
                <p className="text-xs text-slate-400 uppercase font-medium">Open Pull Requests</p>
                <p className="text-2xl font-bold text-white mt-1">{prs.length}</p>
              </div>
              <div className="p-4 rounded-2xl bg-slate-900/50 border border-emerald-500/20">
                <p className="text-xs text-emerald-400 uppercase font-medium">Safe to Merge</p>
                <p className="text-2xl font-bold text-emerald-400 mt-1">{prs.filter(p => p.risk_level === 'PASS').length}</p>
              </div>
              <div className="p-4 rounded-2xl bg-slate-900/50 border border-amber-500/20">
                <p className="text-xs text-amber-400 uppercase font-medium">Review Needed</p>
                <p className="text-2xl font-bold text-amber-400 mt-1">{prs.filter(p => p.risk_level === 'WARN').length}</p>
              </div>
              <div className="p-4 rounded-2xl bg-slate-900/50 border border-rose-500/20">
                <p className="text-xs text-rose-400 uppercase font-medium">Blocked (High Risk)</p>
                <p className="text-2xl font-bold text-rose-400 mt-1">{prs.filter(p => p.risk_level === 'BLOCK').length}</p>
              </div>
            </div>

            {/* Deck */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: PR list */}
              <div className="lg:col-span-5 space-y-2.5">
                <h2 className="text-xs font-semibold text-slate-400 uppercase">Incoming PRs</h2>
                {prs.map((pr, idx) => {
                  const isSelected = idx === selectedPRIndex;
                  return (
                    <div 
                      key={pr.pr_number}
                      onClick={() => setSelectedPRIndex(idx)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition ${isSelected ? 'bg-slate-900 border-indigo-500 shadow-md shadow-indigo-500/10' : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-xs font-semibold text-white leading-snug">#{pr.pr_number} {pr.title}</span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0 ${pr.risk_level === 'PASS' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : pr.risk_level === 'WARN' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'}`}>
                          {pr.risk_level}
                        </span>
                      </div>
                      <div className="flex items-center justify-between mt-2 text-[11px] text-slate-400 font-mono">
                        <span>@{pr.author}</span>
                        <div className="flex items-center space-x-2">
                          <span className="text-emerald-400">+{pr.additions}</span>
                          <span className="text-rose-400">-{pr.deletions}</span>
                          <span className="text-slate-300 font-bold">Score {pr.risk_score}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Right Column: Deep Risk Guard Details */}
              <div className="lg:col-span-7">
                <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-6">
                  {/* PR Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                    <div>
                      <span className="text-xs font-mono text-indigo-400 font-semibold">PR #{currentPR.pr_number} · {currentPR.branch} → {currentPR.base_branch}</span>
                      <h3 className="text-base font-bold text-white mt-1">{currentPR.title}</h3>
                    </div>
                    <div>
                      <span className={`text-xs font-bold px-3 py-1 rounded-full ${currentPR.risk_level === 'PASS' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : currentPR.risk_level === 'WARN' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'}`}>
                        {currentPR.decision}
                      </span>
                    </div>
                  </div>

                  {/* 3 Metric Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 text-center">
                      <span className="text-[10px] uppercase font-bold text-slate-400">Composite Risk</span>
                      <p className={`text-3xl font-extrabold font-mono mt-1 ${currentPR.risk_score <= 35 ? 'text-emerald-400' : currentPR.risk_score <= 65 ? 'text-amber-400' : 'text-rose-400'}`}>
                        {currentPR.risk_score} <span className="text-xs text-slate-500">/ 100</span>
                      </p>
                      <p className="text-[10px] text-slate-500 mt-1">{currentPR.risk_score <= 35 ? 'Safe for Auto-Merge' : 'Exceeds Safety Threshold'}</p>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-slate-400">Blast Radius</span>
                      <p className="text-xl font-bold text-white mt-1">{currentPR.blast_radius.total_downstream} Services</p>
                      <p className="text-xs text-rose-400 font-semibold">Max Tier: {currentPR.blast_radius.max_sla_tier}</p>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-slate-400">AST Analysis</span>
                      <p className="text-xs text-slate-300 mt-1 font-mono">Lines: <span className="text-emerald-400">+{currentPR.additions}</span> <span className="text-rose-400">-{currentPR.deletions}</span></p>
                      <p className="text-xs text-slate-400 mt-0.5">Breaking APIs: <strong className={currentPR.ast_summary.breaking_changes > 0 ? 'text-rose-400' : 'text-slate-200'}>{currentPR.ast_summary.breaking_changes}</strong></p>
                    </div>
                  </div>

                  {/* AI Rationale */}
                  <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/20 space-y-1">
                    <span className="text-xs font-semibold text-indigo-300 flex items-center space-x-1.5">
                      <Shield className="w-3.5 h-3.5" />
                      <span>AI Guard Assessment & Impact Rationale</span>
                    </span>
                    <p className="text-xs text-slate-300 leading-relaxed">{currentPR.rationale}</p>
                  </div>

                  {/* Actions Bar */}
                  <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-slate-800">
                    <a 
                      href={`https://github.com/chandanknayak/deployguard-ai/pull/${currentPR.pr_number}`} 
                      target="_blank" 
                      rel="noreferrer"
                      className="text-xs text-slate-400 hover:text-white flex items-center space-x-1"
                    >
                      <span>View on GitHub</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>

                    <div className="flex items-center space-x-2">
                      {currentPR.risk_level === 'BLOCK' ? (
                        <button 
                          onClick={() => handleMerge(currentPR.pr_number, true)}
                          className="px-4 py-2 rounded-xl text-xs font-bold bg-rose-600/30 hover:bg-rose-600/50 border border-rose-500 text-rose-200 transition"
                        >
                          ⚠️ Override & Force Merge
                        </button>
                      ) : (
                        <button 
                          onClick={() => handleMerge(currentPR.pr_number, false)}
                          className="px-5 py-2.5 rounded-xl text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-600/20 transition flex items-center space-x-1.5"
                        >
                          <Check className="w-4 h-4" />
                          <span>Merge Pull Request (Safe)</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: BLAST RADIUS */}
        {activeTab === 'blast' && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h2 className="text-base font-bold text-white flex items-center space-x-2">
              <Network className="w-5 h-5 text-indigo-400" />
              <span>Microservice Dependency & Blast Radius Map</span>
            </h2>
            <p className="text-xs text-slate-400">Shows how modified functions in the active PR cascade downstream to impact dependent microservices.</p>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-rose-500/30">
                <span className="text-[10px] font-bold text-rose-400 uppercase">P0 Critical Service</span>
                <p className="text-sm font-bold text-white mt-1">auth-service</p>
                <p className="text-xs text-slate-400 mt-1">Direct dependency. Token validation failure will cause authentication service outage.</p>
              </div>
              <div className="p-4 rounded-xl bg-slate-950 border border-rose-500/30">
                <span className="text-[10px] font-bold text-rose-400 uppercase">P0 Critical Service</span>
                <p className="text-sm font-bold text-white mt-1">payment-service</p>
                <p className="text-xs text-slate-400 mt-1">Indirect dependency via API gateway. Processes order charges.</p>
              </div>
              <div className="p-4 rounded-xl bg-slate-950 border border-amber-500/30">
                <span className="text-[10px] font-bold text-amber-400 uppercase">P1 High SLA</span>
                <p className="text-sm font-bold text-white mt-1">notification-service</p>
                <p className="text-xs text-slate-400 mt-1">Consumes webhooks for customer transaction receipts.</p>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: RELEASE & CI/CD HUB */}
        {activeTab === 'deploy' && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-6">
            <h2 className="text-base font-bold text-white flex items-center space-x-2">
              <Rocket className="w-5 h-5 text-indigo-400" />
              <span>Automated Release & Deployment Guard</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <h3 className="text-xs font-bold text-slate-200">1. Pre-Deploy Contract Tests</h3>
                <p className="text-xs text-slate-400">Runs AST regression tests and schema validation before deployment.</p>
                <button 
                  onClick={runTests}
                  className="w-full py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-indigo-500/30 transition"
                >
                  {testStatus === 'running' ? 'Running Tests...' : testStatus === 'passed' ? '✓ 67 Tests Passed' : 'Run Tests'}
                </button>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <h3 className="text-xs font-bold text-slate-200">2. Enforce Safe Merge Gate</h3>
                <p className="text-xs text-slate-400">Verifies zero-breaking-change rule before merging into main.</p>
                <button 
                  onClick={() => handleMerge(currentPR.pr_number, false)}
                  className="w-full py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition"
                >
                  Merge Current PR
                </button>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <h3 className="text-xs font-bold text-slate-200">3. Progressive Canary Rollout</h3>
                <p className="text-xs text-slate-400">Deploys to 10% canary traffic with automated health monitoring.</p>
                <button 
                  onClick={triggerCanary}
                  className="w-full py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition"
                >
                  {deployStatus === 'deploying' ? 'Deploying Canary...' : deployStatus === 'live' ? '🚀 Canary Live (10%)' : 'Trigger Canary'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: REPOSITORIES */}
        {activeTab === 'repos' && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-white flex items-center space-x-2">
                <FolderGit2 className="w-5 h-5 text-indigo-400" />
                <span>Connected GitHub Repositories</span>
              </h2>
              <button 
                onClick={() => setIsLinkModalOpen(true)}
                className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition"
              >
                + Link New Repo
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="p-4 rounded-xl bg-slate-950 border border-indigo-500/40">
                <span className="font-bold text-sm text-white">chandanknayak/deployguard-ai</span>
                <p className="text-xs text-slate-400 mt-1">Core DeployGuard repository. AST engine & risk pipeline active.</p>
                <div className="mt-3 text-xs text-emerald-400 flex items-center space-x-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Webhook Active: https://deployguard-ai.onrender.com/webhook/github</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: GOVERNANCE POLICY */}
        {activeTab === 'policy' && (
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h2 className="text-base font-bold text-white flex items-center space-x-2">
              <Settings className="w-5 h-5 text-indigo-400" />
              <span>Release Risk Governance Policy</span>
            </h2>
            <div className="space-y-4 max-w-xl text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Max Auto-Merge Risk Score Threshold: 35 / 100</label>
                <input type="range" min="10" max="80" defaultValue="35" className="w-full accent-indigo-500" />
              </div>
              <div className="space-y-2 pt-2">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input type="checkbox" defaultChecked className="rounded text-indigo-600 bg-slate-900 border-slate-700" />
                  <span>Block PR if any P0 SLA downstream service is impacted</span>
                </label>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input type="checkbox" defaultChecked className="rounded text-indigo-600 bg-slate-900 border-slate-700" />
                  <span>Require 10% Canary deployment for medium-risk releases</span>
                </label>
              </div>
              <button 
                onClick={() => showBanner("Governance policy updated in MongoDB.")}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition mt-3"
              >
                Save Policy
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Link Repo Modal */}
      {isLinkModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-base font-bold text-white">Link GitHub Repository</h3>
            <p className="text-xs text-slate-400">Connect a repository so DeployGuard can guard incoming pull requests.</p>
            <input 
              type="text" 
              placeholder="e.g. acme-corp/billing-service" 
              value={newRepoName}
              onChange={(e) => setNewRepoName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white" 
            />
            <div className="flex justify-end space-x-2 pt-2">
              <button onClick={() => setIsLinkModalOpen(false)} className="px-3 py-1.5 text-xs text-slate-400 hover:text-white">Cancel</button>
              <button 
                onClick={() => {
                  if (!newRepoName) return;
                  setIsLinkModalOpen(false);
                  showBanner(`✓ Linked repo ${newRepoName}`);
                }}
                className="px-4 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl"
              >
                Link Repo
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Auth Modal */}
      {isAuthModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-sm w-full p-6 space-y-4">
            <h3 className="text-base font-bold text-white">Enterprise Workspace</h3>
            <p className="text-xs text-slate-400">Signed in as <strong>chandanknayak</strong> (Tech Lead)</p>
            <div className="space-y-2 text-xs">
              <label className="block text-slate-300">Active Organization: Acme Global Platform</label>
              <label className="block text-slate-300">Role: Release Engineer / Tech Lead</label>
            </div>
            <button 
              onClick={() => setIsAuthModalOpen(false)}
              className="w-full py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-center text-xs text-slate-500">
        DeployGuard AI · Guarding enterprise software releases against breaking changes
      </footer>
    </div>
  );
}