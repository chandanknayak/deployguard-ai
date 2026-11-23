# DeployGuard AI — Enterprise Web Application

A modern, high-performance web platform for AI-powered release risk assessment, AST impact analysis, downstream microservice blast radius visualization, and automated PR merge gates.

---

## 🌟 Features
- **🏢 PR Command Center**: Inspect incoming pull requests with real-time risk scores (0–100), decision badges (`PASS`, `WARN`, `BLOCK`), and AI reasoning.
- **🕸️ Microservice Blast Radius**: Live dependency graph showing how code changes cascade into mission-critical P0/P1 downstream services.
- **🚀 Safe Release & CI/CD Hub**: One-click safe merge with policy gates, administrative override justifications, and progressive 10% canary deployments.
- **📦 Multi-Repository Hub**: Connect and manage multiple enterprise repositories guarded by DeployGuard webhooks.
- **⚙️ Governance Policy**: Configurable auto-merge score thresholds, strict P0 SLA impact blocking, and breaking API detection.

---

## 🚀 One-Click Deploy to Vercel

You can deploy this frontend directly to Vercel:

1. Import this repository into [Vercel](https://vercel.com).
2. Set the **Root Directory** to `frontend`.
3. Add the Environment Variable:
   - `VITE_API_URL` = `https://deployguard-ai.onrender.com`
4. Click **Deploy**!

---

## 💻 Local Development

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the application.

---

## 🛡️ Backend Integration

The frontend connects out-of-the-box to the live DeployGuard AI backend running on Render:
- `https://deployguard-ai.onrender.com`
- Webhook endpoint: `https://deployguard-ai.onrender.com/webhook/github`
- Streamlit companion dashboard: `https://deployguard-ai.streamlit.app`
