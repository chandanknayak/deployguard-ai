const API_BASE = window.location.origin;

const SANDBOX_PRESETS = {
  docs: {
    title: "docs: Update deployment runbook & README badges",
    filename: "README.md",
    base: "# DeployGuard\nInstall guide",
    head: "# DeployGuard AI\nUpdated installation guide and badges.",
    consumer: "",
    tests: false,
    p0: false,
  },
  safe: {
    title: "feat(utils): Add idempotent retry backoff helper",
    filename: "services/retry_helper.py",
    base: "def ping():\n    return 'ok'\n",
    head: "def ping():\n    return 'ok'\n\ndef retry_backoff(max_attempts: int = 3) -> int:\n    return max_attempts * 2\n",
    consumer: "",
    tests: true,
    p0: false,
  },
  warn: {
    title: "refactor(auth): Adjust JWT refresh jitter logic",
    filename: "services/auth_tokens.py",
    base: "def refresh_token(user_id: str, ttl: int = 3600) -> dict:\n    return {'user_id': user_id, 'ttl': ttl}\n",
    head: "def refresh_token(user_id: str, ttl: int = 3600) -> dict:\n    jitter = ttl + 30\n    return {'user_id': user_id, 'ttl': jitter}\n",
    consumer: "from fastapi import APIRouter\nfrom services.auth_tokens import refresh_token\nrouter = APIRouter()\n@router.post('/auth/refresh')\ndef handle_refresh(uid: str):\n    return refresh_token(uid)\n",
    tests: false,
    p0: false,
  },
  block: {
    title: "refactor(payments): Drop process_charge_v1 & break checkout",
    filename: "services/payments.py",
    base: "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.post('/v1/payments/charge')\ndef process_charge_v1(order_id: str, amount: int):\n    return {'ok': True}\n",
    head: "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.post('/v2/payments/charge')\ndef process_charge_v2(order_id: str, amount_cents: int, currency: str):\n    return {'ok': True}\n",
    consumer: "from fastapi import APIRouter\nfrom services.payments import process_charge_v1\nrouter = APIRouter()\n@router.post('/checkout/pay')\ndef pay(order_id: str):\n    return process_charge_v1(order_id, 500)\n",
    tests: false,
    p0: true,
  },
};

const STATE = {
  token: localStorage.getItem("deployguard_token") || null,
  user: JSON.parse(localStorage.getItem("deployguard_user") || "null"),
  isPublicSandbox: false,
  repos: [],
  activeRepo: "",
  prs: [],
  selectedPRIndex: 0,
  filterDecision: "ALL",
  availableGitHubRepos: [],
  teamMembers: [],
  collaborators: [],
  auditLogs: [],
  policy: { max_auto_merge_score: 35, staging_health_url: "", deploy_hook_url: "" },
};

let visNetwork = null;
let currentAuthMode = "login";

/* ========== SECURITY: HTML ESCAPE ========== */
function esc(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function extractError(data, fallback = "Operation failed") {
  if (!data) return fallback;
  if (typeof data.detail === "string") return data.detail;
  if (data.detail && typeof data.detail === "object") {
    return data.detail.reason || data.detail.message || JSON.stringify(data.detail);
  }
  return data.message || fallback;
}

function perms() {
  if (STATE.isPublicSandbox) {
    return {
      can_scan_pr: true, can_run_sandbox: true, can_open_pr: false,
      can_review_pr: false, can_merge_safe: false, can_override_block: false,
      can_deploy: false, can_edit_policy: false, can_manage_team: false, can_manage_repos: false,
    };
  }
  return STATE.user?.permissions || {
    can_scan_pr: true, can_run_sandbox: true, can_open_pr: true,
    can_review_pr: true, can_merge_safe: true, can_override_block: true,
    can_deploy: true, can_edit_policy: true, can_manage_team: true, can_manage_repos: true,
  };
}

function roleBadgeCls(role) {
  if (role === "devops_admin") return "role-devops_admin";
  if (role === "reviewer") return "role-reviewer";
  return "role-developer";
}

function roleLabel(role) {
  if (role === "devops_admin") return "DEVOPS ADMIN";
  if (role === "reviewer") return "REVIEWER";
  if (role === "developer") return "DEVELOPER";
  return "PUBLIC SANDBOX";
}

/* ========== BOOT ========== */
document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("webhook-url-display").innerText = `${API_BASE}/webhook/github`;
  const params = new URLSearchParams(window.location.search);
  const oauthToken = params.get("oauth_token");
  if (oauthToken) {
    STATE.token = oauthToken;
    localStorage.setItem("deployguard_token", oauthToken);
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  if (STATE.token) {
    try {
      const meRes = await fetch(`${API_BASE}/auth/me`, { headers: authHeaders() });
      if (meRes.ok) {
        STATE.user = await meRes.json();
        localStorage.setItem("deployguard_user", JSON.stringify(STATE.user));
        await enterDashboard();
        return;
      }
    } catch {}
    STATE.token = null;
    STATE.user = null;
    localStorage.removeItem("deployguard_token");
    localStorage.removeItem("deployguard_user");
  }

  if (params.get("demo") === "1" || window.location.pathname === "/demo") {
    await enterPublicSandbox();
    return;
  }
  showAuthScreen();
});

function showAuthScreen() {
  document.getElementById("auth-screen").classList.remove("hidden");
  document.getElementById("app-screen").classList.add("hidden");
}

async function enterDashboard() {
  document.getElementById("auth-screen").classList.add("hidden");
  document.getElementById("app-screen").classList.remove("hidden");
  document.getElementById("app-screen").classList.add("flex");
  updateUserHeader();
  await checkCloudHealth();
  await loadGovernancePolicy();
  if (!STATE.isPublicSandbox) {
    await loadRepositories();
    await loadTeamMembers();
    await loadPullRequests();
    await loadCollaborators();
    await loadAuditLogs();
    // Guide first-time users directly to Setup & Team if 0 repos connected
    if (STATE.repos.length === 0) {
      switchTab("setup");
    } else {
      switchTab("prs");
    }
  } else {
    STATE.repos = [];
    STATE.activeRepo = "";
    populateRepoSelectors();
    switchTab("prs");
    renderPRCards();
    renderPRDetails();
    // Auto-run a real public PR inspection on launch so zero fake feeds are needed
    await analyzePublicPRUrl(true);
  }
  renderSDLCBar();
}

function authHeaders() {
  const h = { "Content-Type": "application/json" };
  if (STATE.token) h["Authorization"] = `Bearer ${STATE.token}`;
  return h;
}

/* ========== AUTH ========== */
function togglePasswordVisibility() {
  const inp = document.getElementById("auth-password");
  const btn = inp.nextElementSibling;
  if (inp.type === "password") { inp.type = "text"; btn.innerText = "Hide"; }
  else { inp.type = "password"; btn.innerText = "Show"; }
}

function setAuthMode(mode) {
  currentAuthMode = mode;
  const isReg = mode === "register";
  document.getElementById("auth-tab-login").className = isReg
    ? "py-2.5 rounded-lg font-semibold text-slate-500 hover:text-slate-900 transition-all"
    : "py-2.5 rounded-lg font-semibold bg-white text-slate-900 shadow-sm transition-all";
  document.getElementById("auth-tab-register").className = isReg
    ? "py-2.5 rounded-lg font-semibold bg-white text-slate-900 shadow-sm transition-all"
    : "py-2.5 rounded-lg font-semibold text-slate-500 hover:text-slate-900 transition-all";
  document.getElementById("field-fullname").classList.toggle("hidden", !isReg);
  document.getElementById("field-company").classList.toggle("hidden", !isReg);
  document.getElementById("auth-heading").innerText = isReg ? "Create Workspace (DevOps Admin)" : "Sign in to Workspace";
  document.getElementById("auth-sub").innerText = isReg
    ? "You start as DevOps Admin and can add Developer & Reviewer teammates inside."
    : "Sign in as DevOps Admin, Reviewer, or Developer.";
  document.getElementById("auth-submit-btn").innerText = isReg ? "Create Workspace" : "Log In";
  document.getElementById("auth-error-box").classList.add("hidden");
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const errBox = document.getElementById("auth-error-box");
  const errText = document.getElementById("auth-error-text");
  errBox.classList.add("hidden");
  const email = document.getElementById("auth-email").value.trim().toLowerCase();
  const password = document.getElementById("auth-password").value;
  const fullName = document.getElementById("auth-fullname").value.trim() || email.split("@")[0];
  const company = document.getElementById("auth-company").value.trim() || "Engineering Workspace";
  const endpoint = currentAuthMode === "register" ? "/auth/register" : "/auth/login";
  const payload = currentAuthMode === "register"
    ? { email, password, full_name: fullName, company }
    : { email, password };

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      errText.innerText = extractError(data, "Authentication failed");
      errBox.classList.remove("hidden");
      return;
    }
    STATE.token = data.access_token;
    STATE.user = data.user;
    STATE.isPublicSandbox = false;
    localStorage.setItem("deployguard_token", STATE.token);
    localStorage.setItem("deployguard_user", JSON.stringify(STATE.user));
    await enterDashboard();
    showToast(`Signed in as ${data.user.email} (${roleLabel(data.user.role)})`, false, "✓");
  } catch {
    errText.innerText = "Could not reach backend server.";
    errBox.classList.remove("hidden");
  }
}

async function enterPublicSandbox() {
  STATE.token = null;
  STATE.user = { email: "guest-sandbox", company: "Live Public Sandbox", role: "sandbox", github_connected: false };
  STATE.isPublicSandbox = true;
  STATE.prs = [];
  await enterDashboard();
  showToast("Live Public Sandbox active — inspect any real GitHub PR or paste Python code!", false, "⚡");
}

function logout() {
  STATE.token = null; STATE.user = null; STATE.isPublicSandbox = false;
  STATE.repos = []; STATE.activeRepo = ""; STATE.prs = [];
  STATE.teamMembers = []; STATE.collaborators = []; STATE.auditLogs = [];
  localStorage.removeItem("deployguard_token");
  localStorage.removeItem("deployguard_user");
  showAuthScreen();
}

function updateUserHeader() {
  const u = STATE.user;
  if (!u) return;
  const p = perms();
  const comp = u.company || u.full_name || "Workspace";
  const role = STATE.isPublicSandbox ? "sandbox" : (u.role || "developer");

  document.getElementById("header-company-name").innerText = comp;
  document.getElementById("user-nav-email").innerText = u.email;
  document.getElementById("user-initials-badge").innerText = comp.slice(0, 2).toUpperCase();

  const rb = document.getElementById("header-role-badge");
  rb.innerText = roleLabel(role);
  rb.className = `text-[10px] font-black px-2 py-0.5 rounded-full uppercase tracking-wider ${roleBadgeCls(role)}`;

  document.getElementById("header-github-badge").innerText = STATE.isPublicSandbox
    ? "Public Sandbox · Real AST + Public GitHub PR Inspector"
    : u.github_connected
      ? `GitHub: @${u.github_username} (🔒 Encrypted)`
      : "GitHub not linked — link PAT in Setup to create/merge PRs";

  document.getElementById("btn-unlink-gh")?.classList.toggle("hidden", STATE.isPublicSandbox || !u.github_connected);
  document.getElementById("btn-switch-user")?.classList.toggle("hidden", STATE.isPublicSandbox);
  document.getElementById("team-add-form-wrap")?.classList.toggle("hidden", !p.can_manage_team);
  document.getElementById("btn-top-add-repo")?.classList.toggle("hidden", !p.can_manage_repos);
  document.getElementById("btn-top-demo-pr")?.classList.toggle("hidden", !p.can_open_pr);

  const policyBtn = document.getElementById("btn-save-policy");
  const policyLock = document.getElementById("policy-role-lock");
  if (policyBtn) {
    policyBtn.disabled = !p.can_edit_policy;
    policyBtn.classList.toggle("opacity-50", !p.can_edit_policy);
    policyBtn.classList.toggle("cursor-not-allowed", !p.can_edit_policy);
  }
  if (policyLock) {
    policyLock.innerText = p.can_edit_policy ? "DevOps Admin (Editable)" : `Read-Only (${roleLabel(role)})`;
  }
  const canaryBtn = document.getElementById("btn-canary");
  if (canaryBtn) {
    canaryBtn.disabled = !p.can_deploy;
    canaryBtn.classList.toggle("opacity-50", !p.can_deploy);
    canaryBtn.classList.toggle("cursor-not-allowed", !p.can_deploy);
  }
  const canaryFb = document.getElementById("canary-feedback-text");
  if (canaryFb && !p.can_deploy) {
    canaryFb.innerText = `Locked for ${roleLabel(role)} (DevOps Admin only)`;
  }
}

/* ========== SDLC PROGRESS BAR ========== */
function renderSDLCBar() {
  const el = document.getElementById("sdlc-steps-container");
  if (!el) return;
  const hasGH = !!STATE.user?.github_connected;
  const hasRepo = STATE.repos.length > 0;
  const hasTeam = STATE.teamMembers.length > 1;
  const hasScanned = STATE.prs.some(p => p.risk_level && p.risk_level !== "PENDING");
  const hasReviewOrMerge = STATE.auditLogs.some(l => String(l.action || "").includes("REVIEW") || String(l.action || "").includes("MERGE"));
  const hasDeploy = STATE.auditLogs.some(l => Boolean(l.deployment_id));

  const items = [
    { label: "1. GitHub PAT", done: hasGH, tab: "setup" },
    { label: "2. Repo Connected", done: hasRepo, tab: "setup" },
    { label: "3. Team Roles", done: hasTeam, tab: "setup" },
    { label: "4. PR AST Scanned", done: hasScanned, tab: "prs" },
    { label: "5. Reviewed / Merged", done: hasReviewOrMerge, tab: "prs" },
    { label: "6. Deployed", done: hasDeploy, tab: "release" },
  ];
  el.innerHTML = items.map(s => `
    <button onclick="switchTab('${s.tab}')" class="px-2.5 py-1 rounded-full font-bold text-[11px] border transition ${
      s.done
        ? "bg-emerald-50 text-emerald-700 border-emerald-200"
        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-indigo-50 hover:text-indigo-700"
    }">${s.done ? "✓" : "○"} ${esc(s.label)}</button>
  `).join("");
}

/* ========== HEALTH ========== */
async function checkCloudHealth() {
  const txt = document.getElementById("cloud-status-text");
  const dot = document.getElementById("cloud-status-dot");
  try {
    const r = await fetch(`${API_BASE}/readyz`);
    const d = await r.json();
    if (r.ok && d.status === "ready") {
      txt.innerText = "API + DB Online";
      dot.className = "w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse";
    } else {
      txt.innerText = "API Online (DB Offline)";
      dot.className = "w-1.5 h-1.5 rounded-full bg-amber-500";
    }
  } catch {
    txt.innerText = "Offline";
    dot.className = "w-1.5 h-1.5 rounded-full bg-rose-500";
  }
}

/* ========== GITHUB PAT CONNECT ========== */
function openConnectGitHubModal() {
  if (STATE.isPublicSandbox || !STATE.token) {
    showToast("Sign in to link and encrypt your GitHub Personal Access Token.", true, "⚠");
    return;
  }
  document.getElementById("gh-connect-feedback").classList.add("hidden");
  document.getElementById("modal-connect-gh").classList.remove("hidden");
}
function closeConnectGitHubModal() { document.getElementById("modal-connect-gh").classList.add("hidden"); }

async function submitConnectGitHub() {
  const pat = document.getElementById("gh-pat-input").value.trim();
  const fb = document.getElementById("gh-connect-feedback");
  if (!pat) return;
  fb.classList.remove("hidden");
  fb.className = "text-xs p-3 rounded-xl bg-slate-100 text-slate-700";
  fb.innerText = "Verifying & encrypting token...";
  try {
    const res = await fetch(`${API_BASE}/auth/connect-github`, {
      method: "POST", headers: authHeaders(), body: JSON.stringify({ github_token: pat }),
    });
    const data = await res.json();
    if (!res.ok) {
      fb.className = "text-xs p-3 rounded-xl bg-rose-50 text-rose-700 border border-rose-200";
      fb.innerText = extractError(data, "Invalid token");
      return;
    }
    STATE.user.github_connected = true;
    STATE.user.github_username = data.github_username;
    STATE.availableGitHubRepos = data.available_repos || [];
    localStorage.setItem("deployguard_user", JSON.stringify(STATE.user));
    document.getElementById("gh-pat-input").value = "";
    updateUserHeader();
    populateAvailableReposPicker();
    renderSDLCBar();
    closeConnectGitHubModal();
    showToast(`Linked & encrypted @${data.github_username} (${STATE.availableGitHubRepos.length} repos found)`, false, "🔒");
  } catch {
    fb.className = "text-xs p-3 rounded-xl bg-rose-50 text-rose-700";
    fb.innerText = "Connection error.";
  }
}

async function disconnectGitHubAccount() {
  if (!STATE.token) return;
  try {
    const res = await fetch(`${API_BASE}/auth/disconnect-github`, { method: "POST", headers: authHeaders() });
    if (res.ok) {
      STATE.user.github_connected = false;
      STATE.user.github_username = null;
      STATE.availableGitHubRepos = [];
      localStorage.setItem("deployguard_user", JSON.stringify(STATE.user));
      updateUserHeader();
      populateAvailableReposPicker();
      renderSDLCBar();
      showToast("GitHub token unlinked.", false, "✓");
    }
  } catch {}
}

function populateAvailableReposPicker() {
  const wrap = document.getElementById("available-repos-picker");
  const sel = document.getElementById("available-repos-select");
  if (!STATE.availableGitHubRepos.length) { wrap.classList.add("hidden"); return; }
  wrap.classList.remove("hidden");
  sel.innerHTML = `<option value="">-- Select from your GitHub --</option>`;
  STATE.availableGitHubRepos.forEach(r => {
    const opt = document.createElement("option");
    opt.value = r.full_name;
    opt.innerText = `${r.full_name} ${r.private ? "(Private)" : "(Public)"}`;
    sel.appendChild(opt);
  });
}

/* ========== REPOSITORIES & DEMO REPO CREATOR ========== */
async function loadRepositories() {
  STATE.repos = [];
  STATE.activeRepo = "";
  if (!STATE.token) { populateRepoSelectors(); return; }
  try {
    const r = await fetch(`${API_BASE}/repos`, { headers: authHeaders() });
    if (r.ok) {
      const d = await r.json();
      if (d.repos && d.repos.length) {
        STATE.repos = d.repos.map(x => ({
          name: x.full_name,
          sla: x.sla_tier || "P0",
          desc: x.description || "Connected Repository",
        }));
        STATE.activeRepo = STATE.repos[0].name;
      }
    }
    if (STATE.user?.github_connected) {
      const avail = await fetch(`${API_BASE}/repos/available`, { headers: authHeaders() });
      if (avail.ok) {
        const ad = await avail.json();
        STATE.availableGitHubRepos = ad.repos || [];
        populateAvailableReposPicker();
      }
    }
  } catch {}
  populateRepoSelectors();
}

function populateRepoSelectors() {
  const sel = document.getElementById("active-repo-select");
  sel.innerHTML = "";
  if (!STATE.repos.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.innerText = STATE.isPublicSandbox ? "Public URL Sandbox Mode" : "No repo connected yet";
    sel.appendChild(opt);
  } else {
    STATE.repos.forEach(r => {
      const opt = document.createElement("option");
      opt.value = r.name;
      opt.innerText = `${r.name} [${r.sla}]`;
      if (r.name === STATE.activeRepo) opt.selected = true;
      sel.appendChild(opt);
    });
  }
  renderRepoGrid();
}

function renderRepoGrid() {
  const grid = document.getElementById("repo-cards-grid");
  if (!grid) return;
  if (!STATE.repos.length) {
    grid.innerHTML = `
      <div class="col-span-full p-6 rounded-xl bg-slate-50 border border-dashed border-slate-300 text-center text-xs text-slate-500">
        No repository connected yet. Link your GitHub PAT above and click <strong>Create &amp; Seed Real GitHub Repo</strong> or connect an existing repo.
      </div>`;
    return;
  }
  const canManage = perms().can_manage_repos;
  grid.innerHTML = STATE.repos.map(r => `
    <div class="p-4 rounded-xl bg-white border border-slate-200 space-y-2 shadow-sm">
      <div class="flex items-center justify-between gap-2">
        <a href="https://github.com/${esc(r.name)}" target="_blank" class="font-bold text-xs text-indigo-600 hover:underline font-mono truncate">${esc(r.name)}</a>
        <span class="text-[10px] font-black px-2 py-0.5 rounded-md bg-rose-50 text-rose-700 border border-rose-200">${esc(r.sla)}</span>
      </div>
      <p class="text-[11px] text-slate-600 line-clamp-2">${esc(r.desc)}</p>
      <div class="flex items-center justify-between pt-2 border-t border-slate-100 text-[11px]">
        <button onclick="selectRepoFromGrid('${esc(r.name)}')" class="text-indigo-600 font-bold hover:underline">View PRs →</button>
        ${canManage ? `<button onclick="removeRepo('${esc(r.name)}')" class="text-rose-600 font-semibold">Disconnect</button>` : ""}
      </div>
    </div>
  `).join("");
}

function selectRepoFromGrid(name) {
  STATE.activeRepo = name;
  populateRepoSelectors();
  switchTab("prs");
  onRepoChanged();
}

async function onRepoChanged() {
  STATE.activeRepo = document.getElementById("active-repo-select").value;
  await loadPullRequests();
  await loadCollaborators();
}

async function createRealDemoRepo() {
  if (!perms().can_manage_repos) {
    showToast("Only DevOps Admin can create or connect workspace repos.", true, "🔒");
    return;
  }
  const repoName = document.getElementById("demo-repo-name").value.trim() || "deployguard-demo-payments";
  const isPrivate = document.getElementById("demo-repo-private").value === "true";
  const btn = document.getElementById("btn-create-demo-repo");
  btn.innerText = "Creating on GitHub...";
  btn.disabled = true;
  try {
    const res = await fetch(`${API_BASE}/repos/create-demo-repo`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ repo_name: repoName, private: isPrivate, sla_tier: "P0" }),
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(extractError(data, "Could not create demo repo"), true, "✗");
      return;
    }
    await loadRepositories();
    STATE.activeRepo = data.repo.full_name;
    populateRepoSelectors();
    await loadPullRequests();
    await loadCollaborators();
    await loadAuditLogs();
    renderSDLCBar();
    showToast(
      `${data.created_fresh ? "Created" : "Synced"} GitHub repo ${data.repo.full_name} (files seeded, graph ready)!`,
      false,
      "🚀"
    );
  } catch {
    showToast("Network error while creating GitHub repo.", true, "✗");
  } finally {
    btn.innerText = "🚀 Create & Seed Real GitHub Repo";
    btn.disabled = false;
  }
}

function openAddRepoModal() {
  if (!perms().can_manage_repos) {
    showToast("Only DevOps Admin can connect repositories.", true, "🔒");
    return;
  }
  document.getElementById("modal-add-repo").classList.remove("hidden");
}
function closeAddRepoModal() { document.getElementById("modal-add-repo").classList.add("hidden"); }

async function submitNewRepo() {
  const full = document.getElementById("new-repo-input").value.trim();
  const sla = document.getElementById("new-repo-sla").value;
  if (!full || !full.includes("/")) return alert("Enter valid owner/repo format");
  const [owner, repo] = full.split("/");

  try {
    const res = await fetch(`${API_BASE}/repos/connect`, {
      method: "POST", headers: authHeaders(),
      body: JSON.stringify({ owner, repo, sla_tier: sla }),
    });
    const data = await res.json();
    if (!res.ok) { showToast(extractError(data, "Could not connect repo"), true, "⚠"); return; }
    await loadRepositories();
    STATE.activeRepo = full;
    populateRepoSelectors();
    closeAddRepoModal();
    await loadPullRequests();
    await loadCollaborators();
    await loadAuditLogs();
    renderSDLCBar();
    showToast(`Connected ${full} [${sla}]`, false, "✓");
  } catch {
    showToast("Network error connecting repository.", true, "✗");
  }
}

async function removeRepo(full) {
  const [owner, repo] = full.split("/");
  const res = await fetch(`${API_BASE}/repos/${owner}/${repo}`, { method: "DELETE", headers: authHeaders() });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    showToast(extractError(d, "Failed to disconnect"), true, "✗");
    return;
  }
  await loadRepositories();
  await loadPullRequests();
  renderSDLCBar();
  showToast(`Disconnected ${full}`, false, "✓");
}

function copyWebhookUrl() {
  navigator.clipboard?.writeText(document.getElementById("webhook-url-display").innerText);
  showToast("Webhook URL copied!", false, "📋");
}

/* ========== WORKSPACE RBAC TEAM ========== */
async function loadTeamMembers() {
  const box = document.getElementById("workspace-members-list");
  if (!box || !STATE.token) return;
  try {
    const res = await fetch(`${API_BASE}/enterprise/team`, { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    STATE.teamMembers = data.members || [];
    renderTeamMembers();
    renderSDLCBar();
  } catch {}
}

function renderTeamMembers() {
  const box = document.getElementById("workspace-members-list");
  const swList = document.getElementById("switch-quick-list");
  const canManage = perms().can_manage_team;
  if (box) {
    if (!STATE.teamMembers.length) {
      box.innerHTML = `<p class="text-xs text-slate-400">No teammates added yet.</p>`;
    } else {
      box.innerHTML = STATE.teamMembers.map(m => {
        const isSelf = m.email === STATE.user?.email;
        return `
          <div class="p-3 rounded-xl bg-white border border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div class="min-w-0">
              <p class="font-bold text-slate-900 truncate">${esc(m.full_name)} ${isSelf ? "<span class='text-indigo-600'>(You)</span>" : ""}</p>
              <p class="text-[11px] text-slate-500 font-mono truncate">${esc(m.email)} ${m.github_username ? `· @${esc(m.github_username)}` : ""}</p>
            </div>
            <div class="flex items-center gap-2">
              ${canManage && !isSelf ? `
                <select onchange="changeMemberRole('${esc(m.email)}', this.value)" class="bg-slate-50 border border-slate-200 rounded-lg px-2 py-1 text-[11px] font-bold">
                  <option value="developer" ${m.role === "developer" ? "selected" : ""}>Developer</option>
                  <option value="reviewer" ${m.role === "reviewer" ? "selected" : ""}>Reviewer</option>
                  <option value="devops_admin" ${m.role === "devops_admin" ? "selected" : ""}>DevOps Admin</option>
                </select>
                <button onclick="removeMember('${esc(m.email)}')" class="text-rose-600 hover:text-rose-800 font-bold text-[11px]">✕</button>
              ` : `<span class="text-[10px] font-black px-2 py-0.5 rounded-full uppercase ${roleBadgeCls(m.role)}">${esc(roleLabel(m.role))}</span>`}
            </div>
          </div>`;
      }).join("");
    }
  }
  if (swList) {
    swList.innerHTML = STATE.teamMembers.map(m => `
      <button type="button" onclick="document.getElementById('sw-email').value='${esc(m.email)}'" class="w-full text-left p-2.5 rounded-lg border border-slate-200 hover:border-indigo-400 hover:bg-indigo-50/40 flex items-center justify-between">
        <span class="font-mono font-semibold text-slate-800">${esc(m.email)}</span>
        <span class="text-[10px] font-black px-2 py-0.5 rounded-full ${roleBadgeCls(m.role)}">${esc(roleLabel(m.role))}</span>
      </button>
    `).join("");
  }
}

async function addWorkspaceMember() {
  const fullName = document.getElementById("tm-name").value.trim();
  const email = document.getElementById("tm-email").value.trim().toLowerCase();
  const password = document.getElementById("tm-pass").value;
  const role = document.getElementById("tm-role").value;
  const ghUser = document.getElementById("tm-gh").value.trim();
  if (!fullName || !email || password.length < 8) {
    showToast("Enter valid Name, Email, and min 8-char Password.", true, "⚠");
    return;
  }
  const res = await fetch(`${API_BASE}/enterprise/team/members`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ full_name: fullName, email, password, role, github_username: ghUser }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(extractError(data, "Could not add teammate"), true, "✗"); return; }

  document.getElementById("tm-name").value = "";
  document.getElementById("tm-email").value = "";
  document.getElementById("tm-pass").value = "";
  document.getElementById("tm-gh").value = "";

  // Also optionally invite on active GitHub repo if GH handle supplied
  if (ghUser && STATE.activeRepo && STATE.activeRepo.includes("/") && STATE.user?.github_connected) {
    const [owner, repo] = STATE.activeRepo.split("/");
    await fetch(`${API_BASE}/repos/${owner}/${repo}/collaborators`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ github_username: ghUser, role }),
    }).catch(() => {});
    await loadCollaborators();
  }

  await loadTeamMembers();
  await loadAuditLogs();
  showToast(`Added ${email} as ${roleLabel(role)}!`, false, "✓");
}

async function changeMemberRole(email, newRole) {
  const res = await fetch(`${API_BASE}/enterprise/team/members/${encodeURIComponent(email)}`, {
    method: "PATCH", headers: authHeaders(), body: JSON.stringify({ role: newRole }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(extractError(data, "Role update failed"), true, "✗"); await loadTeamMembers(); return; }
  await loadTeamMembers();
  await loadAuditLogs();
  showToast(`Updated ${email} -> ${roleLabel(newRole)}`, false, "✓");
}

async function removeMember(email) {
  const res = await fetch(`${API_BASE}/enterprise/team/members/${encodeURIComponent(email)}`, {
    method: "DELETE", headers: authHeaders(),
  });
  const data = await res.json();
  if (!res.ok) { showToast(extractError(data, "Remove failed"), true, "✗"); return; }
  await loadTeamMembers();
  await loadAuditLogs();
  showToast(`Removed ${email}`, false, "✓");
}

/* ========== GITHUB COLLABORATORS ========== */
async function loadCollaborators() {
  const box = document.getElementById("github-collaborators-list");
  if (!box || !STATE.token || !STATE.activeRepo || !STATE.activeRepo.includes("/")) {
    if (box) box.innerHTML = `<p class="text-slate-400">Connect a repository first to manage GitHub collaborators.</p>`;
    return;
  }
  const [owner, repo] = STATE.activeRepo.split("/");
  try {
    const res = await fetch(`${API_BASE}/repos/${owner}/${repo}/collaborators`, { headers: authHeaders() });
    if (!res.ok) {
      box.innerHTML = `<p class="text-slate-400">Collaborators require repo push/admin GitHub PAT.</p>`;
      return;
    }
    const data = await res.json();
    STATE.collaborators = data.collaborators || [];
    if (!STATE.collaborators.length) {
      box.innerHTML = `<p class="text-slate-400">No external collaborators yet.</p>`;
      return;
    }
    box.innerHTML = STATE.collaborators.map(c => `
      <div class="p-2.5 rounded-xl bg-white border border-slate-200 flex items-center justify-between">
        <span class="font-mono font-bold text-slate-800">@${esc(c.login)}</span>
        <span class="text-[10px] font-black px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 uppercase">${esc(c.role_name || "collaborator")}</span>
      </div>
    `).join("");
  } catch {}
}

async function inviteGitHubCollaborator() {
  if (!perms().can_manage_repos) { showToast("Only DevOps Admin can invite GitHub collaborators.", true, "🔒"); return; }
  if (!STATE.activeRepo || !STATE.activeRepo.includes("/")) { showToast("Connect a GitHub repository first.", true, "⚠"); return; }
  const username = document.getElementById("collab-gh-user").value.trim();
  const role = document.getElementById("collab-role").value;
  if (!username) return;
  const [owner, repo] = STATE.activeRepo.split("/");
  const res = await fetch(`${API_BASE}/repos/${owner}/${repo}/collaborators`, {
    method: "POST", headers: authHeaders(), body: JSON.stringify({ github_username: username, role }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(extractError(data, "Invite failed"), true, "✗"); return; }
  document.getElementById("collab-gh-user").value = "";
  await loadCollaborators();
  await loadAuditLogs();
  showToast(`GitHub invitation sent to @${username} (${data.github_permission})`, false, "✉️");
}

/* ========== SWITCH USER / ROLE LOGIN ========== */
function openSwitchUserModal() {
  document.getElementById("sw-err").classList.add("hidden");
  renderTeamMembers();
  document.getElementById("modal-switch-user").classList.remove("hidden");
}
function closeSwitchUserModal() { document.getElementById("modal-switch-user").classList.add("hidden"); }

async function submitSwitchUser(e) {
  e.preventDefault();
  const errEl = document.getElementById("sw-err");
  errEl.classList.add("hidden");
  const email = document.getElementById("sw-email").value.trim().toLowerCase();
  const password = document.getElementById("sw-password").value;
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (!res.ok) {
    errEl.innerText = extractError(data, "Login failed");
    errEl.classList.remove("hidden");
    return;
  }
  STATE.token = data.access_token;
  STATE.user = data.user;
  STATE.isPublicSandbox = false;
  localStorage.setItem("deployguard_token", STATE.token);
  localStorage.setItem("deployguard_user", JSON.stringify(STATE.user));
  closeSwitchUserModal();
  await enterDashboard();
  showToast(`Switched account -> ${data.user.email} (${roleLabel(data.user.role)})`, false, "🔄");
}

/* ========== PULL REQUESTS & REAL GITHUB PR CREATION ========== */
async function loadPullRequests() {
  if (!STATE.activeRepo || !STATE.activeRepo.includes("/")) {
    STATE.prs = []; STATE.selectedPRIndex = 0;
    document.getElementById("pr-queue-status").innerText = STATE.isPublicSandbox ? "Public URL Mode" : "No repo connected";
    renderPRCards(); renderPRDetails();
    return;
  }
  const [owner, repo] = STATE.activeRepo.split("/");
  document.getElementById("pr-queue-status").innerText = "Syncing GitHub PRs...";
  let loaded = [];
  try {
    const r = await fetch(`${API_BASE}/repos/${owner}/${repo}/pulls`, { headers: authHeaders() });
    if (r.ok) {
      const d = await r.json();
      loaded = (d.pulls || []).map(normalizePR);
    }
  } catch {}
  if (loaded.length === 0 && STATE.token) {
    try {
      const ar = await fetch(`${API_BASE}/assessments/?limit=15&repo=${encodeURIComponent(STATE.activeRepo)}`, { headers: authHeaders() });
      if (ar.ok) {
        const ad = await ar.json();
        loaded = (ad.results || []).map(doc => normalizeAssessmentDoc(doc, repo));
      }
    } catch {}
  }
  STATE.prs = loaded;
  STATE.selectedPRIndex = 0;
  document.getElementById("pr-queue-status").innerText = loaded.length ? `${loaded.length} PRs loaded` : "0 open PRs";
  renderPRCards();
  renderPRDetails();
}

function openCreatePRModal() {
  if (STATE.isPublicSandbox || !STATE.token) { showToast("Sign in & connect a repo first.", true, "⚠"); return; }
  if (!STATE.activeRepo || !STATE.activeRepo.includes("/")) { showToast("Connect a GitHub repository in Step 1 first.", true, "⚠"); switchTab("setup"); return; }
  document.getElementById("cpr-repo-label").innerText = STATE.activeRepo;
  document.getElementById("modal-create-pr").classList.remove("hidden");
}
function closeCreatePRModal() { document.getElementById("modal-create-pr").classList.add("hidden"); }
function toggleCustomPRFields() {
  document.getElementById("cpr-custom-wrap").classList.toggle("hidden", document.getElementById("cpr-scenario").value !== "custom");
}

async function submitRealDemoPR() {
  const [owner, repo] = STATE.activeRepo.split("/");
  const scenario = document.getElementById("cpr-scenario").value;
  const title = document.getElementById("cpr-title").value.trim() || null;
  const btn = document.getElementById("btn-submit-demo-pr");
  btn.innerText = "Pushing branch & scanning...";
  btn.disabled = true;
  try {
    const res = await fetch(`${API_BASE}/repos/${owner}/${repo}/demo-pr`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        scenario,
        title,
        custom_filename: document.getElementById("cpr-filename").value.trim() || null,
        custom_code: document.getElementById("cpr-code").value || null,
      }),
    });
    const data = await res.json();
    if (!res.ok) { showToast(extractError(data, "Could not create PR on GitHub"), true, "✗"); return; }
    closeCreatePRModal();
    switchTab("prs");
    await loadPullRequests();
    await loadAuditLogs();
    renderSDLCBar();
    const verdict = data.analysis?.risk_level || "SCANNED";
    const score = data.analysis?.risk_score ?? 0;
    showToast(`Created real GitHub PR #${data.pr_number} -> ${verdict} (${score}/100)!`, verdict === "BLOCK", "🚀");
  } catch {
    showToast("Network error opening PR.", true, "✗");
  } finally {
    btn.innerText = "🚀 Push Branch & Open PR";
    btn.disabled = false;
  }
}

async function analyzePublicPRUrl(silentOnRateLimit = false) {
  const prUrl = document.getElementById("public-pr-url-input").value.trim();
  if (!prUrl) return;
  const btn = document.getElementById("btn-analyze-public-pr");
  btn.innerText = "Analyzing...";
  btn.disabled = true;
  try {
    const res = await fetch(`${API_BASE}/enterprise/analyze-public-pr`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ pr_url: prUrl }),
    });
    const data = await res.json();
    if (!res.ok) {
      if (!silentOnRateLimit) showToast(extractError(data, "Public PR inspection failed"), true, "⚠");
      return;
    }
    const pr = normalizePR(data);
    STATE.prs.unshift(pr);
    STATE.selectedPRIndex = 0;
    setPRFilter("ALL");
    renderPRCards();
    renderPRDetails();
    renderSDLCBar();
    if (!silentOnRateLimit) {
      showToast(`Live GitHub PR #${pr.pr_number}: ${pr.risk_level} (${pr.risk_score}/100)`, pr.risk_level === "BLOCK", "🔍");
    }
  } catch {
    if (!silentOnRateLimit) showToast("Could not analyze PR URL.", true, "✗");
  } finally {
    btn.innerText = "🔍 Inspect Real PR";
    btn.disabled = false;
  }
}

function normalizeAssessmentDoc(doc, repoFallback = "service") {
  const agent = doc.agent_assessment || {};
  const blast = doc.blast_radius || doc.blast_radius_summary || {};
  const riskLevel = doc.risk_level || agent.risk_level || "PASS";
  const score = doc.risk_score ?? agent.risk_score ?? (riskLevel === "BLOCK" ? 85 : riskLevel === "WARN" ? 50 : 0);
  const critSvcs = (blast.critical_services || []).map(s => s.service).filter(Boolean);
  const svcs = (blast.affected_services && blast.affected_services.length)
    ? blast.affected_services
    : (critSvcs.length ? critSvcs : [repoFallback]);
  return {
    pr_number: doc.pr_number,
    title: doc.pr_title || `PR #${doc.pr_number}`,
    author: doc.pr_author || "developer",
    branch: doc.head_branch || "feature",
    base_branch: doc.base_branch || "main",
    additions: doc.total_lines_added || 0,
    deletions: doc.total_lines_deleted || 0,
    changed_files: doc.total_files_changed || (doc.files_analysed || []).length || 1,
    risk_level: riskLevel,
    risk_score: score,
    decision: doc.decision || riskLevel,
    source: doc.source || "MANUAL_SCAN",
    is_docs_or_config_only: !!doc.is_docs_or_config_only,
    signals: doc.signal_breakdown || agent.signals || null,
    breaking_changes: doc.breaking_changes || [],
    dependency_edges: doc.dependency_edges || [],
    diff_preview: doc.diff_preview || null,
    recommended_tests: agent.recommended_tests || [],
    reviews: doc.reviews || [],
    review_status: doc.review_status || "UNREVIEWED",
    blast_radius: {
      affected_services: svcs,
      max_sla_tier: blast.max_sla_tier || (blast.has_p0_impact ? "P0" : "P1"),
      total_downstream: svcs.length,
    },
    plain_explanation: agent.executive_summary || `Evaluated as ${riskLevel} (${score}/100).`,
    rationale: agent.rationale || agent.detailed_rationale || "Analyzed by DeployGuard engine.",
  };
}

function normalizePR(pr) {
  const rawRisk = pr.risk_level;
  const risk = (rawRisk && rawRisk !== "UNKNOWN" && rawRisk !== "PENDING") ? rawRisk : "PENDING";
  const score = pr.risk_score ?? (risk === "BLOCK" ? 85 : risk === "WARN" ? 52 : risk === "PASS" ? 18 : 0);
  const blast = pr.blast_radius || {};
  const svcs = blast.affected_services || [STATE.activeRepo.split("/")[1] || "service"];
  return {
    pr_number: pr.pr_number || pr.number,
    repo: pr.repo || STATE.activeRepo || "",
    title: pr.title || `PR #${pr.pr_number || pr.number}`,
    author: pr.author || "dev",
    branch: pr.branch || pr.head_branch || "feature",
    base_branch: pr.base_branch || "main",
    url: pr.url || pr.html_url || null,
    additions: pr.additions || 0,
    deletions: pr.deletions || 0,
    changed_files: pr.changed_files || 1,
    risk_level: risk,
    risk_score: score,
    decision: pr.decision || risk,
    source: pr.source || null,
    is_docs_or_config_only: !!pr.is_docs_or_config_only,
    signals: (pr.signals && Object.keys(pr.signals).length) ? pr.signals : null,
    breaking_changes: pr.breaking_changes || [],
    dependency_edges: pr.dependency_edges || [],
    diff_preview: (pr.diff_preview && pr.diff_preview.length) ? pr.diff_preview : null,
    recommended_tests: pr.recommended_tests || [],
    reviews: pr.reviews || [],
    review_status: pr.review_status || "UNREVIEWED",
    blast_radius: { affected_services: svcs, max_sla_tier: blast.max_sla_tier || "P1", total_downstream: svcs.length },
    plain_explanation: pr.plain_explanation || (risk === "PENDING" ? "Not scanned yet. Click 'Scan PR'." : `${risk} (Score: ${score}/100).`),
    rationale: pr.rationale || `Affects ${svcs.length} service(s).`,
  };
}

function setPRFilter(decision) {
  STATE.filterDecision = decision;
  document.querySelectorAll("#pr-filter-pills .filter-pill").forEach(btn => {
    const active = btn.dataset.filter === decision;
    btn.className = active
      ? "filter-pill px-2.5 py-1 rounded-lg text-[11px] font-bold bg-indigo-600 text-white"
      : "filter-pill px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-slate-100 text-slate-600";
  });
  renderPRCards();
}

function getFilteredPRs() {
  const q = (document.getElementById("pr-search-input")?.value || "").trim().toLowerCase();
  return STATE.prs
    .map((pr, idx) => ({ pr, idx }))
    .filter(({ pr }) => {
      const matchStatus = STATE.filterDecision === "ALL" || pr.risk_level === STATE.filterDecision;
      const matchQuery = !q ||
        String(pr.pr_number).includes(q) ||
        (pr.title || "").toLowerCase().includes(q) ||
        (pr.author || "").toLowerCase().includes(q);
      return matchStatus && matchQuery;
    });
}

/* ========== RENDER PR CARDS & DETAILS (XSS-SAFE) ========== */
function renderPRCards() {
  const container = document.getElementById("pr-cards-list");
  container.innerHTML = "";
  let p = 0, w = 0, b = 0;
  STATE.prs.forEach(pr => {
    if (pr.risk_level === "PASS") p++; else if (pr.risk_level === "WARN") w++; else if (pr.risk_level === "BLOCK") b++;
  });

  const filtered = getFilteredPRs();
  if (STATE.prs.length === 0) {
    container.innerHTML = `<div class="p-6 text-center rounded-xl bg-white border border-slate-200 text-xs text-slate-500">No Pull Requests yet. Inspect any public PR URL above or click <strong>+ Open Test PR on GitHub</strong>.</div>`;
  } else if (filtered.length === 0) {
    container.innerHTML = `<div class="p-6 text-center rounded-xl bg-white border border-slate-200 text-xs text-slate-500">No PRs match your filter.</div>`;
  }

  filtered.forEach(({ pr, idx }) => {
    const isSelected = idx === STATE.selectedPRIndex;
    const badgeCls = pr.risk_level === "PASS" ? "badge-pass" : pr.risk_level === "WARN" ? "badge-warn" : pr.risk_level === "BLOCK" ? "badge-block" : "badge-pending";
    const card = document.createElement("div");
    card.className = `p-4 rounded-xl border-2 transition-all cursor-pointer card-lift ${
      isSelected ? "bg-indigo-50/80 border-indigo-500 shadow-md" : "bg-white border-slate-200 hover:border-slate-300 shadow-sm"
    }`;
    card.onclick = () => { STATE.selectedPRIndex = idx; renderPRCards(); renderPRDetails(); };
    card.innerHTML = `
      <div class="flex items-start justify-between gap-2">
        <span class="text-xs font-bold text-slate-900 leading-snug line-clamp-2">#${esc(pr.pr_number)} ${esc(pr.title)}</span>
        <span class="text-[10px] font-black px-2.5 py-1 rounded-full shrink-0 ${badgeCls}">${esc(pr.risk_level)}</span>
      </div>
      <p class="text-[11px] text-slate-500 mt-1.5 line-clamp-1">${esc(pr.plain_explanation)}</p>
      <div class="flex items-center justify-between mt-3 text-[11px] text-slate-500 font-mono">
        <div class="flex items-center space-x-2">
          <span>@${esc(pr.author)}</span>
          ${pr.review_status && pr.review_status !== "UNREVIEWED" ? `<span class="text-[9px] px-1.5 py-0.5 rounded bg-amber-50 text-amber-800 font-sans font-bold">${esc(pr.review_status)}</span>` : ""}
        </div>
        <div class="flex items-center space-x-2">
          <span class="text-emerald-600 font-bold">+${esc(pr.additions)}</span>
          <span class="text-rose-600 font-bold">-${esc(pr.deletions)}</span>
          <span class="text-slate-800 font-black bg-slate-100 px-2 py-0.5 rounded-md">${esc(pr.risk_score)}</span>
        </div>
      </div>
    `;
    container.appendChild(card);
  });

  document.getElementById("kpi-total").innerText = STATE.prs.length;
  document.getElementById("kpi-pass").innerText = p;
  document.getElementById("kpi-warn").innerText = w;
  document.getElementById("kpi-block").innerText = b;
}

function renderPRDetails() {
  const pr = STATE.prs[STATE.selectedPRIndex] || STATE.prs[0];
  const container = document.getElementById("pr-detail-deck");
  if (!pr) {
    container.innerHTML = `
      <div class="py-14 px-4 text-center space-y-4">
        <div class="w-16 h-16 mx-auto rounded-2xl bg-indigo-100 text-indigo-600 flex items-center justify-center text-2xl">🔍</div>
        <h3 class="text-lg font-extrabold text-slate-900">Ready for Live AST Risk Analysis</h3>
        <p class="text-xs text-slate-500 max-w-md mx-auto">Open a real PR on your connected repo, inspect any public GitHub PR URL above, or test code inside the AST Sandbox.</p>
        <div class="flex flex-wrap justify-center gap-2 pt-2">
          ${STATE.isPublicSandbox
            ? `<button onclick="analyzePublicPRUrl()" class="px-4 py-2.5 rounded-lg text-xs font-bold bg-indigo-600 text-white">🔍 Inspect Public PR</button>`
            : `<button onclick="openCreatePRModal()" class="px-4 py-2.5 rounded-lg text-xs font-bold bg-indigo-600 text-white">+ Open Test PR on GitHub</button>`}
          <button onclick="openSandboxModal()" class="px-4 py-2.5 rounded-lg text-xs font-bold bg-slate-900 text-white">⚡ Open AST Sandbox</button>
        </div>
      </div>`;
    return;
  }

  const p = perms();
  const badgeCls = pr.risk_level === "PASS" ? "badge-pass" : pr.risk_level === "WARN" ? "badge-warn" : pr.risk_level === "BLOCK" ? "badge-block" : "badge-pending";
  const scoreColor = pr.risk_score <= 35 ? "#059669" : pr.risk_score <= 65 ? "#d97706" : "#e11d48";
  const ringC = 2 * Math.PI * 34;
  const ringO = ringC - (Math.min(100, Math.max(0, pr.risk_score)) / 100) * ringC;
  const sig = pr.signals || { ast: 0, blast: 0, critical_path: 0, test_gap: 0 };
  const diffLines = pr.diff_preview || [{ type: "ctx", text: `  Modified ${pr.changed_files} file(s): +${pr.additions} / -${pr.deletions}` }];
  const bcs = pr.breaking_changes || [];
  const tests = pr.recommended_tests || [];
  const reviews = pr.reviews || [];
  const isRealRepoPR = STATE.token && STATE.activeRepo && STATE.activeRepo.includes("/") && pr.source !== "SIMULATION" && pr.source !== "PUBLIC_SANDBOX";

  let mergeBtnHtml = "";
  if (pr.decision === "MERGED") {
    mergeBtnHtml = `<span class="px-4 py-2.5 rounded-xl text-xs font-black bg-indigo-100 text-indigo-700 border border-indigo-200">✓ Merged</span>`;
  } else if (!isRealRepoPR) {
    mergeBtnHtml = `<span class="px-3.5 py-2 rounded-xl text-[11px] font-bold bg-slate-100 text-slate-500">Sandbox Read-Only</span>`;
  } else if (!p.can_merge_safe) {
    mergeBtnHtml = `<button disabled class="px-4 py-2.5 rounded-xl text-xs font-bold bg-slate-100 text-slate-400 border border-slate-200 cursor-not-allowed">🔒 Merge Locked (Developer)</button>`;
  } else if (pr.risk_level === "BLOCK" || pr.risk_score > (STATE.policy.max_auto_merge_score ?? 35)) {
    mergeBtnHtml = p.can_override_block
      ? `<button onclick="triggerActivePRMerge(true)" class="px-5 py-2.5 rounded-xl text-xs font-bold bg-rose-600 hover:bg-rose-700 text-white shadow-md">🛡️ DevOps Admin Override &amp; Merge</button>`
      : `<button disabled class="px-4 py-2.5 rounded-xl text-xs font-bold bg-rose-50 text-rose-400 border border-rose-200 cursor-not-allowed">🔒 Blocked — Needs DevOps Admin</button>`;
  } else {
    mergeBtnHtml = `<button onclick="triggerActivePRMerge(false)" class="px-5 py-2.5 rounded-xl text-xs font-bold bg-emerald-600 hover:bg-emerald-700 text-white shadow-md">✓ Merge PR on GitHub</button>`;
  }

  container.innerHTML = `
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-4">
      <div class="min-w-0">
        <div class="flex flex-wrap items-center gap-2 text-xs font-mono">
          <span class="font-black text-indigo-600">PR #${esc(pr.pr_number)}</span>
          <span class="text-slate-300">•</span>
          <span class="text-slate-500">${esc(pr.branch)} → ${esc(pr.base_branch)}</span>
          <span class="text-slate-300">•</span>
          <span class="text-slate-500">@${esc(pr.author)}</span>
          ${pr.url ? `<a href="${esc(pr.url)}" target="_blank" class="text-[11px] font-sans font-bold text-indigo-600 hover:underline">GitHub ↗</a>` : ""}
        </div>
        <h2 class="text-base font-extrabold text-slate-900 mt-1">${esc(pr.title)}</h2>
      </div>
      <span class="text-xs font-black px-4 py-2 rounded-xl shrink-0 ${badgeCls}">${esc(pr.decision)}</span>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-12 gap-4 items-stretch">
      <div class="sm:col-span-4 p-5 rounded-2xl bg-slate-50 border border-slate-200 flex flex-col items-center justify-center">
        <div class="relative w-28 h-28 flex items-center justify-center">
          <svg class="w-28 h-28 -rotate-90" viewBox="0 0 80 80">
            <circle cx="40" cy="40" r="34" stroke="#e2e8f0" stroke-width="6" fill="none" />
            <circle cx="40" cy="40" r="34" stroke="${scoreColor}" stroke-width="6" fill="none"
              stroke-linecap="round" class="gauge-ring"
              stroke-dasharray="${ringC.toFixed(1)}"
              stroke-dashoffset="${ringO.toFixed(1)}" />
          </svg>
          <div class="absolute text-center">
            <span class="text-3xl font-black font-mono" style="color:${scoreColor}">${esc(pr.risk_score)}</span>
            <span class="block text-[9px] font-bold text-slate-400 uppercase">/ 100</span>
          </div>
        </div>
        <span class="text-[11px] font-bold mt-2" style="color:${scoreColor}">
          ${pr.risk_level === "PASS" ? "✓ Safe Gate" : pr.risk_level === "WARN" ? "⚠ Review Required" : pr.risk_level === "BLOCK" ? "✗ Blocked by Gate" : "○ Pending Scan"}
        </span>
      </div>

      <div class="sm:col-span-8 p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-2.5">
        <div class="flex items-center justify-between text-[10px] font-black text-slate-400 uppercase tracking-wider">
          <span>Weighted Signals (40 / 30 / 20 / 10)</span>
          <span>${esc(pr.blast_radius.total_downstream)} Services · ${esc(pr.blast_radius.max_sla_tier)}</span>
        </div>
        ${[
          { label: "AST Structural Diff", weight: "40%", val: sig.ast ?? 0 },
          { label: "Blast Radius Impact", weight: "30%", val: sig.blast ?? 0 },
          { label: "Critical Path Sensitivity", weight: "20%", val: sig.critical_path ?? 0 },
          { label: "Test Coverage Gap", weight: "10%", val: sig.test_gap ?? 0 },
        ].map(s => {
          const barCol = s.val <= 35 ? "bg-emerald-500" : s.val <= 69 ? "bg-amber-500" : "bg-rose-500";
          return `
            <div class="space-y-1">
              <div class="flex justify-between text-[11px] text-slate-700">
                <span class="font-medium">${esc(s.label)} <span class="text-slate-400">(${s.weight})</span></span>
                <span class="font-mono font-bold">${esc(s.val)}%</span>
              </div>
              <div class="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                <div class="h-full ${barCol} rounded-full transition-all duration-700" style="width:${Number(s.val) || 0}%"></div>
              </div>
            </div>`;
        }).join("")}
      </div>
    </div>

    ${bcs.length ? `
      <div class="p-4 rounded-2xl bg-rose-50 border border-rose-200 space-y-1.5">
        <span class="text-[10px] font-black text-rose-700 uppercase tracking-wider">🚨 Breaking AST Changes (${bcs.length})</span>
        ${bcs.slice(0, 4).map(bc => `<p class="text-xs font-mono text-rose-800">• [${esc(bc.type)}] ${esc(bc.detail || bc.symbol)}</p>`).join("")}
      </div>
    ` : ""}

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-2 shadow-sm">
        <span class="text-[10px] font-black text-slate-400 uppercase tracking-wider">Affected Services &amp; Cross-File Edges</span>
        <div class="flex flex-wrap gap-1.5">
          ${pr.blast_radius.affected_services.map(svc => `<span class="px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono text-slate-800">${esc(svc)}</span>`).join("")}
        </div>
        ${(pr.dependency_edges || []).map(e => `<p class="text-[11px] font-mono text-rose-700 pt-1">↳ ${esc(e.source_file)}:${esc(e.symbol)} → ${esc(e.consumer_file)}</p>`).join("")}
      </div>

      <div class="p-4 rounded-2xl bg-slate-900 border border-slate-800 space-y-1 font-mono text-[11px]">
        <div class="text-[9px] text-slate-400 font-sans font-bold uppercase tracking-wider pb-1 border-b border-slate-800">Diff Preview (+${esc(pr.additions)} / -${esc(pr.deletions)})</div>
        ${diffLines.map(l => {
          const cls = l.type === "add" ? "text-emerald-400" : l.type === "del" ? "text-rose-400" : "text-slate-400";
          return `<div class="${cls} truncate">${esc(l.text)}</div>`;
        }).join("")}
      </div>
    </div>

    <div class="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-1.5">
      <span class="text-xs font-black text-slate-800">Gate Verdict &amp; Rationale</span>
      <p class="text-xs text-slate-800 font-semibold">${esc(pr.plain_explanation)}</p>
      <p class="text-[11px] text-slate-600">${esc(pr.rationale)}</p>
      ${tests.length ? `<p class="text-[11px] text-indigo-700 font-medium pt-1">Recommended Tests: ${tests.slice(0, 2).map(esc).join(" · ")}</p>` : ""}
    </div>

    <!-- Real PR Code Review Section (RBAC Enforced) -->
    ${isRealRepoPR ? `
      <div class="p-4 rounded-2xl bg-indigo-50/50 border border-indigo-200/80 space-y-3">
        <div class="flex items-center justify-between">
          <span class="text-xs font-extrabold text-slate-900">👁️ PR Code Review (GitHub + Workspace Audit)</span>
          <span class="text-[11px] font-bold text-slate-500">${reviews.length} review(s)</span>
        </div>
        ${reviews.length ? `
          <div class="space-y-1.5 max-h-28 overflow-y-auto">
            ${reviews.slice(0, 3).map(rv => `
              <div class="p-2 rounded-lg bg-white border border-slate-200 text-[11px] flex items-center justify-between gap-2">
                <span class="truncate"><strong>${esc(rv.reviewer_email)}</strong> (${esc(rv.reviewer_role)}): ${esc(rv.body)}</span>
                <span class="font-black px-2 py-0.5 rounded shrink-0 ${rv.decision === "APPROVE" ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"}">${esc(rv.decision)}</span>
              </div>
            `).join("")}
          </div>
        ` : ""}
        ${p.can_review_pr ? `
          <div class="flex flex-wrap gap-2 text-xs">
            <input type="text" id="pr-review-note" placeholder="Review feedback (e.g. Verified AST diff, safe for 10% canary)" class="flex-1 min-w-[200px] bg-white border border-slate-200 rounded-lg px-3 py-2">
            <button onclick="submitPRReview('APPROVE')" class="px-3 py-2 rounded-lg font-bold bg-emerald-600 hover:bg-emerald-700 text-white">✓ Approve</button>
            <button onclick="submitPRReview('REQUEST_CHANGES')" class="px-3 py-2 rounded-lg font-bold bg-amber-600 hover:bg-amber-700 text-white">⚠ Request Changes</button>
          </div>
        ` : `<p class="text-[11px] text-amber-800 font-semibold">🔒 Reviewer or DevOps Admin role required to post official GitHub PR reviews.</p>`}
      </div>
    ` : ""}

    <div class="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-slate-200">
      <div class="flex flex-wrap items-center gap-2 text-xs">
        ${isRealRepoPR ? `
          <button onclick="rescanActivePR()" class="px-4 py-2.5 rounded-xl bg-white hover:bg-slate-50 text-indigo-600 border border-slate-200 font-bold shadow-sm">Scan PR</button>
          <button onclick="rescanActivePR(true)" class="px-3.5 py-2.5 rounded-xl bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 font-semibold shadow-sm">↻ Re-sync</button>
        ` : ""}
        <button onclick="switchTab('blast')" class="px-3.5 py-2.5 rounded-xl bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 font-medium shadow-sm">Impact Map</button>
      </div>
      <div class="flex items-center space-x-2">${mergeBtnHtml}</div>
    </div>
  `;
}

/* ========== REAL SCAN, REVIEW & MERGE ========== */
async function rescanActivePR(isResync = false) {
  const pr = STATE.prs[STATE.selectedPRIndex];
  if (!pr || !STATE.activeRepo || !STATE.activeRepo.includes("/")) return;
  const [owner, repo] = STATE.activeRepo.split("/");
  showToast(`${isResync ? "Re-syncing" : "Scanning"} PR #${pr.pr_number}...`, false, "⏳");

  const ep = isResync
    ? `${API_BASE}/repos/${owner}/${repo}/pulls/${pr.pr_number}/resync`
    : `${API_BASE}/repos/${owner}/${repo}/pulls/${pr.pr_number}/analyze`;
  try {
    const res = await fetch(ep, { method: "POST", headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) { showToast(extractError(data, "Scan failed"), true, "✗"); return; }
    await loadPullRequests();
    await loadAuditLogs();
    renderSDLCBar();
    showToast(`PR #${pr.pr_number}: ${data.risk_level} (${data.risk_score}/100)`, data.risk_level === "BLOCK", "✓");
  } catch {
    showToast("Network error during PR scan.", true, "✗");
  }
}

async function submitPRReview(event) {
  const pr = STATE.prs[STATE.selectedPRIndex];
  if (!pr || !STATE.activeRepo || !STATE.activeRepo.includes("/")) return;
  const noteEl = document.getElementById("pr-review-note");
  const body = (noteEl?.value || "").trim() || `${event} review submitted via DeployGuard RBAC`;
  const [owner, repo] = STATE.activeRepo.split("/");
  const res = await fetch(`${API_BASE}/repos/${owner}/${repo}/pulls/${pr.pr_number}/reviews`, {
    method: "POST", headers: authHeaders(), body: JSON.stringify({ event, body }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(extractError(data, "Review failed"), true, "✗"); return; }
  await loadPullRequests();
  await loadAuditLogs();
  renderSDLCBar();
  showToast(`Submitted ${event} review for PR #${pr.pr_number} on GitHub!`, false, "👁️");
}

async function triggerActivePRMerge(isOverride) {
  const pr = STATE.prs[STATE.selectedPRIndex];
  if (!pr || !STATE.activeRepo || !STATE.activeRepo.includes("/")) return;
  const [owner, repo] = STATE.activeRepo.split("/");
  let overrideReason = "";
  if (isOverride) {
    overrideReason = prompt(`PR #${pr.pr_number} is BLOCKED (${pr.risk_score}/100). Enter DevOps Admin Override justification:`);
    if (!overrideReason) return;
  }
  showToast(`Merging PR #${pr.pr_number} on GitHub...`, false, "⏳");
  try {
    const res = await fetch(`${API_BASE}/repos/${owner}/${repo}/pulls/${pr.pr_number}/merge`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ merge_method: "squash", admin_override: isOverride, override: isOverride, override_reason: overrideReason }),
    });
    const data = await res.json();
    if (!res.ok) { showToast(extractError(data, "Merge rejected"), true, "✗"); return; }
    await loadPullRequests();
    await loadAuditLogs();
    renderSDLCBar();
    showToast(`Merged PR #${pr.pr_number} on GitHub!`, false, "✓");
  } catch {
    showToast("Network error during merge.", true, "✗");
  }
}

/* ========== REAL DEPLOY & PROBE (DEVOPS ADMIN ONLY) ========== */
async function triggerCanaryRollout() {
  if (!perms().can_deploy) {
    showToast("Permission denied: Only DevOps Admin can trigger deployments.", true, "🔒");
    return;
  }
  const pr = STATE.prs[STATE.selectedPRIndex];
  const [owner, repo] = (STATE.activeRepo || "org/service").split("/");
  const env = document.getElementById("deploy-env-select")?.value || "canary";
  const strategy = document.getElementById("deploy-strategy-select")?.value || "CANARY";
  const btn = document.getElementById("btn-canary");
  const fb = document.getElementById("canary-feedback-text");
  btn.innerText = "Verifying Health...";
  try {
    const res = await fetch(`${API_BASE}/enterprise/repos/${owner}/${repo}/deploy`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        environment: env,
        strategy,
        traffic_percent: strategy === "CANARY" ? 10 : 100,
        pr_number: pr?.pr_number || 1,
      }),
    });
    const data = await res.json();
    if (!res.ok) { showToast(extractError(data, "Deploy rejected"), true, "✗"); btn.innerText = "🚀 Deploy & Verify Health"; return; }
    const dep = data.deployment;
    fb.innerText = dep.latency_ms !== null ? `${dep.health_check} · ${dep.latency_ms}ms` : dep.health_check;
    fb.className = `text-[11px] text-center font-bold ${dep.status === "FAILED" ? "text-rose-600" : "text-emerald-600"}`;
    await loadAuditLogs();
    renderSDLCBar();
    showToast(`Deployment ${dep.deployment_id}: ${dep.health_check}`, dep.status === "FAILED", "🚀");
  } catch {
    showToast("Deploy probe failed.", true, "✗");
  } finally {
    btn.innerText = "🚀 Deploy & Verify Health";
  }
}

/* ========== AUDIT LOG ========== */
async function loadAuditLogs() {
  const term = document.getElementById("live-audit-terminal");
  if (!term || !STATE.token) return;
  try {
    const res = await fetch(`${API_BASE}/enterprise/audit?limit=35`, { headers: authHeaders() });
    if (res.ok) {
      const data = await res.json();
      STATE.auditLogs = data.logs || [];
      if (STATE.auditLogs.length) {
        term.innerHTML = STATE.auditLogs.map(l => {
          const ts = (l.timestamp || "").slice(0, 19).replace("T", " ");
          const act = String(l.action || l.strategy || "EVENT").toUpperCase();
          const roleStr = l.actor_role ? ` [${l.actor_role}]` : "";
          const msg = l.deployment_id
            ? `[${ts}] DEPLOY ${l.deployment_id} · ${l.repo} (${l.environment}) · ${l.health_check || l.status} by ${l.operator}${roleStr}`
            : `[${ts}] ${act} · ${l.repo || ""} ${l.pr_number ? `PR #${l.pr_number}` : ""} by ${l.operator || "system"}${roleStr}`;
          const cls = act.includes("BLOCK") || l.status === "FAILED" ? "text-rose-400" : act.includes("OVERRIDE") ? "text-amber-400" : "text-emerald-400";
          return `<p class="${cls}">${esc(msg)}</p>`;
        }).join("");
        return;
      }
    }
  } catch {}
  term.innerHTML = `<p class="text-slate-500">No workspace audit events recorded yet.</p>`;
}

/* ========== GOVERNANCE POLICY ========== */
async function loadGovernancePolicy() {
  try {
    const res = await fetch(`${API_BASE}/enterprise/policy`, { headers: authHeaders() });
    if (res.ok) {
      const p = await res.json();
      STATE.policy = p;
      document.getElementById("pol-org-name").value = p.organization_name || "DeployGuard Enterprise";
      document.getElementById("input-policy-score").value = p.max_auto_merge_score ?? 35;
      document.getElementById("label-policy-score").innerText = `${p.max_auto_merge_score ?? 35} / 100`;
      document.getElementById("pol-p0").checked = !!p.block_on_p0_sla;
      document.getElementById("pol-breaking").checked = !!p.block_on_api_changes;
      document.getElementById("pol-canary").checked = !!p.require_canary_for_medium_risk;
      document.getElementById("pol-staging-url").value = p.staging_health_url || "";
      document.getElementById("pol-deploy-hook").value = p.deploy_hook_url || "";
      const badge = document.getElementById("deploy-probe-badge");
      if (badge) badge.innerText = p.staging_health_url ? `Live Health Target: ${p.staging_health_url}` : "Dry-Run Mode (Set Staging URL in Policy)";
    }
  } catch {}
}

async function saveGovernancePolicy() {
  if (!perms().can_edit_policy) { showToast("Only DevOps Admin can modify Governance Policy.", true, "🔒"); return; }
  const payload = {
    organization_name: document.getElementById("pol-org-name").value.trim() || "DeployGuard Enterprise",
    max_auto_merge_score: parseInt(document.getElementById("input-policy-score").value, 10),
    block_on_p0_sla: document.getElementById("pol-p0").checked,
    block_on_api_changes: document.getElementById("pol-breaking").checked,
    require_canary_for_medium_risk: document.getElementById("pol-canary").checked,
    enforce_branch_protection: true,
    staging_health_url: document.getElementById("pol-staging-url").value.trim(),
    deploy_hook_url: document.getElementById("pol-deploy-hook").value.trim(),
  };
  const res = await fetch(`${API_BASE}/enterprise/policy`, {
    method: "POST", headers: authHeaders(), body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) { showToast(extractError(data, "Failed to save policy"), true, "✗"); return; }
  STATE.policy = payload;
  document.getElementById("policy-feedback").classList.remove("hidden");
  setTimeout(() => document.getElementById("policy-feedback").classList.add("hidden"), 2500);
  await loadAuditLogs();
  showToast("Governance settings saved!", false, "✓");
}

/* ========== IMPACT MAP ========== */
function renderBlastNetwork() {
  const canvas = document.getElementById("blast-network-canvas");
  if (!canvas || typeof vis === "undefined") return;
  const pr = STATE.prs[STATE.selectedPRIndex] || STATE.prs[0];
  const rootSvc = (STATE.activeRepo || "org/service").split("/")[1] || "service";
  const edges = pr?.dependency_edges || [];
  const svcs = pr?.blast_radius?.affected_services || [rootSvc];

  const nodesArr = [];
  const edgesArr = [];
  const addedIds = new Set();
  function pushNode(id, label, bg, border) {
    if (addedIds.has(id)) return;
    addedIds.add(id);
    nodesArr.push({ id, label, color: { background: bg, border }, shape: "box", font: { color: "white", size: 12, face: "Inter" }, borderWidth: 2 });
  }

  const prId = `pr-${pr?.pr_number || 1}`;
  pushNode(prId, `PR #${pr?.pr_number || 1}\n${pr?.risk_level || "SCAN"} (${pr?.risk_score ?? 0})`, "#4f46e5", "#3730a3");

  if (edges.length > 0) {
    edges.forEach(e => {
      const srcFileId = `file:${e.source_file}`;
      const symId = `sym:${e.symbol}`;
      const consId = `cons:${e.consumer_file}`;
      pushNode(srcFileId, `Modified File\n${e.source_file}`, "#0f172a", "#1e293b");
      pushNode(symId, `Symbol\n${e.symbol}`, "#7c3aed", "#5b21b6");
      const routeLabel = (e.consumer_routes || []).length ? `\n${e.consumer_routes.join(", ")}` : "";
      pushNode(consId, `Downstream Consumer\n${e.consumer_file}${routeLabel}`, "#e11d48", "#be123c");
      edgesArr.push({ from: prId, to: srcFileId, arrows: "to", color: { color: "#4f46e5" }, width: 2 });
      edgesArr.push({ from: srcFileId, to: symId, arrows: "to", color: { color: "#7c3aed" }, width: 2 });
      edgesArr.push({ from: symId, to: consId, arrows: "to", color: { color: "#e11d48" }, width: 2 });
    });
  } else {
    const rootId = `svc:${rootSvc}`;
    pushNode(rootId, `${rootSvc}\n(Modified)`, "#0f172a", "#1e293b");
    edgesArr.push({ from: prId, to: rootId, arrows: "to", color: { color: "#4f46e5" }, width: 3 });
    svcs.forEach(svc => {
      if (svc === rootSvc && svcs.length > 1) return;
      const isP0 = svc.includes("auth") || svc.includes("payment") || svc.includes("checkout") || pr?.blast_radius?.max_sla_tier === "P0";
      const sId = `svc:${svc}`;
      pushNode(sId, `${svc}\n[${isP0 ? "P0" : "P1"}]`, isP0 ? "#e11d48" : "#d97706", isP0 ? "#be123c" : "#b45309");
      if (sId !== rootId) edgesArr.push({ from: rootId, to: sId, arrows: "to", color: { color: isP0 ? "#e11d48" : "#64748b" }, width: 2 });
    });
  }

  if (visNetwork) visNetwork.destroy();
  visNetwork = new vis.Network(canvas, { nodes: new vis.DataSet(nodesArr), edges: new vis.DataSet(edgesArr) }, {
    physics: { stabilization: true },
    nodes: { margin: { top: 10, bottom: 10, left: 12, right: 12 } },
    layout: { hierarchical: { direction: "LR", sortMethod: "directed", levelSeparation: 190, nodeSpacing: 95 } },
  });

  document.getElementById("blast-service-cards").innerHTML = edges.length
    ? edges.map(e => `
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-1 shadow-sm">
        <span class="text-[10px] font-black text-violet-600 uppercase">Cross-File Dependency</span>
        <p class="text-xs font-extrabold text-slate-900 font-mono truncate">${esc(e.source_file)} → ${esc(e.consumer_file)}</p>
        <p class="text-xs text-slate-600 font-mono">Symbol: ${esc(e.symbol)}</p>
      </div>`).join("")
    : svcs.map(s => `
      <div class="p-4 rounded-2xl bg-white border border-slate-200 space-y-1 shadow-sm">
        <span class="text-[10px] font-black text-slate-400 uppercase">Service</span>
        <p class="text-sm font-extrabold text-slate-900 font-mono">${esc(s)}</p>
      </div>`).join("");
}

/* ========== TAB SWITCHING ========== */
function switchTab(tabKey) {
  ["setup", "prs", "blast", "release", "policy", "guide"].forEach(k => {
    const panel = document.getElementById(`tab-${k}`);
    if (panel) panel.classList.toggle("hidden", k !== tabKey);
    const btn = document.getElementById(`nav-btn-${k}`);
    if (btn) {
      btn.className = k === tabKey
        ? "px-2.5 py-2 rounded-lg bg-indigo-50 text-indigo-700 transition whitespace-nowrap"
        : "px-2.5 py-2 rounded-lg text-slate-600 hover:bg-slate-100 transition whitespace-nowrap";
    }
  });
  if (tabKey === "blast") setTimeout(renderBlastNetwork, 80);
  if (tabKey === "release") loadAuditLogs();
  if (tabKey === "setup" && !STATE.isPublicSandbox) { loadTeamMembers(); loadCollaborators(); }
}

/* ========== LIVE AST SANDBOX ========== */
function openSandboxModal() { loadSandboxPreset("block"); document.getElementById("modal-sandbox").classList.remove("hidden"); }
function closeSandboxModal() { document.getElementById("modal-sandbox").classList.add("hidden"); }

function loadSandboxPreset(key) {
  const p = SANDBOX_PRESETS[key] || SANDBOX_PRESETS.block;
  document.getElementById("sb-title").value = p.title;
  document.getElementById("sb-filename").value = p.filename;
  document.getElementById("sb-base").value = p.base;
  document.getElementById("sb-head").value = p.head;
  document.getElementById("sb-consumer").value = p.consumer;
  document.getElementById("sb-tests").checked = p.tests;
  document.getElementById("sb-p0").checked = p.p0;
}

async function runLiveSandboxAnalysis() {
  const btn = document.getElementById("sb-run-btn");
  btn.innerText = "Running AST Engine...";
  try {
    const res = await fetch(`${API_BASE}/enterprise/simulate-analyze`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        repo: STATE.activeRepo || "sandbox-org/payments-api",
        pr_title: document.getElementById("sb-title").value.trim() || "Sandbox AST Scan",
        filename: document.getElementById("sb-filename").value.trim() || "module.py",
        base_code: document.getElementById("sb-base").value,
        head_code: document.getElementById("sb-head").value,
        consumer_filename: "routes/checkout.py",
        consumer_code: document.getElementById("sb-consumer").value,
        has_tests: document.getElementById("sb-tests").checked,
        has_p0_impact: document.getElementById("sb-p0").checked,
      }),
    });
    if (!res.ok) { showToast("Simulation failed", true, "✗"); return; }
    const simPR = await res.json();
    STATE.prs.unshift(simPR);
    STATE.selectedPRIndex = 0;
    setPRFilter("ALL");
    renderPRCards();
    renderPRDetails();
    closeSandboxModal();
    switchTab("prs");
    showToast(`AST Engine Verdict: ${simPR.risk_level} (${simPR.risk_score}/100)`, simPR.risk_level === "BLOCK", "⚡");
  } catch {
    showToast("Backend unreachable.", true, "✗");
  } finally {
    btn.innerText = "▶ Run Real AST Analysis";
  }
}

async function refreshDashboard() {
  await checkCloudHealth();
  if (!STATE.isPublicSandbox) {
    await loadRepositories();
    await loadTeamMembers();
    await loadPullRequests();
    await loadCollaborators();
    await loadAuditLogs();
  }
  renderSDLCBar();
  showToast("Dashboard synced.", false, "↻");
}

function showToast(msg, isError = false, icon = "ℹ️") {
  const banner = document.getElementById("toast-banner");
  const box = document.getElementById("toast-box");
  document.getElementById("toast-text").innerText = msg;
  document.getElementById("toast-icon").innerText = icon;
  box.className = isError
    ? "toast-animate p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-center justify-between shadow-md"
    : "toast-animate p-3.5 rounded-xl bg-indigo-50 border border-indigo-200 text-xs text-indigo-800 flex items-center justify-between shadow-md";
  banner.classList.remove("hidden");
  setTimeout(() => banner.classList.add("hidden"), 5000);
}
