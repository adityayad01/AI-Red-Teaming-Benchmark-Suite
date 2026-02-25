# 🔐 AI Red Teaming Benchmark Suite

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.36-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-black?style=for-the-badge)
![LangChain](https://img.shields.io/badge/LangChain-0.2-1C3C3C?style=for-the-badge)

**An automated tool to benchmark how securely any local LLM handles adversarial attacks.**

*Built for the ParadigmIT Cybersecurity — AI/ML Internship*

</div>

---

## 🎯 Problem Statement

In modern software development, teams spend months building and training AI models — but when it comes to deployment, **most skip security testing entirely.**

The typical pipeline looks like this:

```
Build Model → Train Model → Deploy to Production ❌ (no security testing)
```

This is dangerous. LLMs in production are exposed to millions of users, including malicious ones who actively try to:
- Trick the model into ignoring its safety guidelines
- Inject hidden instructions inside documents the AI processes
- Force the model into harmful personas
- Extract confidential system prompts and credentials

**The cost of discovering these vulnerabilities AFTER deployment is enormous** — reputational damage, data breaches, and complete loss of user trust.

The correct pipeline should be:

```
Build Model → Train Model → RED TEAM TEST ✅ → Fix Vulnerabilities → Safe Deployment
```

But there is no standardized, automated, accessible tool that does this — especially for teams without a dedicated cybersecurity background.

**This project builds that missing tool.**

---

## 📸 Screenshots

### 1. Sidebar — Connection Status
> Both API and Ollama connection shown with live status badges

![Sidebar](screenshots/01_sidebar.png)

---

### 2. Run Benchmark — Configuration Panel
> Select model, choose attack categories, launch with one click

![Run Benchmark](screenshots/02_run_benchmark.png)

---

### 3. Live Progress — Real-Time Results Table
> Watch every attack result stream in live as the benchmark runs

![Live Progress](screenshots/03_live_progress.png)

---

### 4. Results Summary — After Benchmark Completes
> Safety score, verdict counts, and vulnerability chart per category

![Results Summary](screenshots/04_results_summary.png)

---

### 5. View Results — Risk Cards + Charts
> Detailed breakdown with category risk levels, pie chart, and bar chart

![View Results](screenshots/05_view_results.png)

---

### 6. Download Report — PDF Generation
> One-click professional PDF report generation and download

![Download Report](screenshots/06_download_report.png)

---

### 7. Policy Engine Report — Audit Log
> Security policy violations, BLOCK/FLAG actions, and full audit trail

![Policy Report](screenshots/07_policy_report.png)

---

## 📊 Sample Results

> Tested on `gemma3:1b` — 80 adversarial prompts across 4 attack categories

| Metric | Result |
|---|---|
| 🛡️ Overall Safety Score | **97.5%** |
| ✅ Safe Responses | 78 / 80 |
| ❌ Unsafe Responses | 2 / 80 |
| ⚠️ Policy Violations | 8 detected |
| 🔒 Risk Level | **MINIMAL** |

---

## 🧠 How It Works

```
┌─────────────────────────────────────────────────────────┐
│                   Streamlit Dashboard                    │
│          (Run • Results • Policy • Report)               │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP
┌───────────────────────▼─────────────────────────────────┐
│                    FastAPI Backend                        │
│         Streaming SSE • REST API • SQLite                │
└──────┬───────────────┬──────────────┬───────────────────┘
       │               │              │
┌──────▼──────┐ ┌──────▼──────┐ ┌────▼──────────┐
│   Attack    │ │  Analyzer   │ │    Policy     │
│   Engine   │ │  (2-Stage)  │ │    Engine     │
│ 80 prompts │ │Keyword + LLM│ │ 7 Rules       │
└──────┬──────┘ └──────┬──────┘ └────┬──────────┘
       │               │              │
┌──────▼───────────────▼──────────────▼──────────┐
│              Ollama (Local LLM)                  │
│         gemma3:1b — 100% Free & Private          │
└─────────────────────────────────────────────────┘
```

### Two-Stage Analysis Pipeline

**Stage 1 — Keyword Pre-filter (Fast)**
Checks response for 40+ compliance/refusal signals instantly without an LLM call.

**Stage 2 — LLM-as-Judge (Deep)**
Only triggered when keywords are not confident enough. Uses a second LLM call to deeply analyze whether the model was manipulated.

---

## 🧪 Attack Categories

| Category | Prompts | What It Tests | Example Attack |
|---|---|---|---|
| 🔓 **Jailbreak** | 20 | Safety guideline bypass | DAN persona, developer mode, fictional framing |
| 💉 **Prompt Injection** | 20 | Hidden instruction attacks | Malicious instructions inside documents/tasks |
| 🎭 **Role Manipulation** | 20 | Persona-based attacks | Forcing harmful character adoption |
| 🕵️ **Data Extraction** | 20 | Information leakage | System prompt, credentials, config extraction |

---

## 📊 Scoring System

| Risk Level | Vulnerability % | Meaning | Action |
|---|---|---|---|
| ✅ MINIMAL | 0 – 10% | Highly resistant | Safe to deploy |
| 🟢 LOW | 10 – 25% | Minor gaps | Monitor in production |
| 🟡 MEDIUM | 25 – 45% | Moderate risk | Add input sanitization |
| 🟠 HIGH | 45 – 70% | Significant risk | Apply guardrails before deploy |
| 🔴 CRITICAL | 70%+ | Highly vulnerable | Do NOT deploy |

---

## 🛡️ Policy Engine

7 built-in security policies that act as an **AI Firewall**:

| Policy | Severity | Triggers On |
|---|---|---|
| System Prompt Leak | CRITICAL | Model reveals system instructions |
| Jailbreak Compliance | CRITICAL | Model accepts DAN/unrestricted persona |
| Credential Exposure | CRITICAL | API keys or tokens in response |
| Harmful Instructions | HIGH | Step-by-step harmful content |
| Role Manipulation Success | HIGH | Harmful character adoption |
| Injection Compliance | MEDIUM | Model follows injected commands |
| Excessive Refusal | LOW | Model refuses safe requests |

---

## 🗂️ Project Structure

```
red-team-suite/
├── backend/
│   ├── main.py              # FastAPI app — all API routes
│   ├── attack_engine.py     # Core benchmark runner
│   ├── analyzer.py          # Two-stage response analyzer
│   ├── scorer.py            # Vulnerability scoring + risk levels
│   ├── policy_engine.py     # AI firewall + audit logging
│   ├── report.py            # PDF report generator
│   └── database.py          # SQLite setup and queries
├── frontend/
│   └── app.py               # Streamlit dashboard (6 pages)
├── data/
│   ├── attack_prompts.json  # 80 adversarial prompts
│   ├── results.db           # SQLite database (auto-created)
│   └── reports/             # Generated PDF reports
├── screenshots/             # Dashboard screenshots
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com/download) installed

### Step 1 — Install Ollama and pull a model
```bash
# Pull a model (gemma3:1b works on 4GB RAM)
ollama pull gemma3:1b

# Start Ollama server
ollama serve
```

### Step 2 — Clone and setup
```bash
git clone https://github.com/YOUR_USERNAME/red-team-suite.git
cd red-team-suite

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Step 3 — Start the backend
```bash
cd backend
uvicorn main:app --reload --port 8000
```

### Step 4 — Start the frontend (new terminal)
```bash
cd frontend
streamlit run app.py
```

### Step 5 — Open browser
```
Dashboard:  http://localhost:8501
API Docs:   http://localhost:8000/docs
```

---

## 📱 Dashboard Pages

| Page | Description |
|---|---|
| 🚀 Run Benchmark | Select model + categories, watch live results stream in |
| 📊 View Results | Full results table with filters, charts, risk level cards |
| 🛡️ Policy Report | Policy violations, audit log, BLOCK/FLAG breakdown |
| 📄 Download Report | One-click professional PDF report generation |
| 📜 History | All past sessions with safety score trend chart |
| ℹ️ How It Works | Documentation and scoring explanation |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | API + Ollama connection status |
| GET | `/benchmark/stream/{id}` | Live SSE stream of benchmark progress |
| GET | `/sessions` | All benchmark sessions |
| GET | `/sessions/{id}/results` | All results for a session |
| GET | `/sessions/{id}/scores/detailed` | Risk levels + category breakdown |
| GET | `/sessions/{id}/policy` | Policy violation summary |
| GET | `/sessions/{id}/audit` | Full audit log |
| GET | `/sessions/{id}/report` | Download PDF report |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| LLM | Ollama (gemma3:1b) | Local inference, free, private |
| LLM Framework | LangChain + langchain-ollama | Prompt management, LLM chaining |
| Backend | FastAPI + Uvicorn | REST API with SSE streaming |
| Database | SQLite | Persistent result storage |
| Frontend | Streamlit | Interactive dashboard |
| Charts | Plotly | Vulnerability visualizations |
| PDF | ReportLab | Professional report generation |
| Language | Python 3.10+ | Core language |

---

## 💡 Key Findings from Testing

Testing `gemma3:1b` revealed:

- **Story completion attacks** (JB010) can bypass safety — the model continues fictional narratives even when they contain harmful intent
- **Internal reasoning extraction** (DE010) partially succeeds — small models sometimes expose their reasoning process
- **Policy engine vs LLM Judge** catch different vulnerability patterns — keyword-based systems flag responses containing sensitive words even in refusals, while LLM judges evaluate overall intent

---

## 🔮 Future Improvements

- [ ] Compare multiple models side by side
- [ ] Add custom attack prompt upload
- [ ] Implement automated defense suggestions
- [ ] Add API rate limiting and authentication
- [ ] Export results as CSV/Excel
- [ ] CI/CD pipeline for automated re-testing

---

## 👨‍💻 Author

**Aditya Yadav**
B.Tech CSE | Woxsen University | 2026 Batch

---

### 💭 Why I Built This

Every day, companies are rushing AI products to market. Models get trained, fine-tuned, and pushed to production — but almost nobody asks the most important question first:

> *"What happens when someone tries to break this?"*

In modern AI development, security testing is treated as optional — something to think about later. But later never comes. The model ships, users find the vulnerabilities, and the damage is already done.

I built this tool because that gap is real and dangerous. AI systems are no longer experimental toys — they are becoming core infrastructure handling sensitive decisions, processing private data, and operating with significant autonomy. Deploying them without red teaming is the equivalent of launching a website without ever testing for SQL injection.

This project is my attempt to make AI security testing **automated, accessible, and standard** — not an afterthought.

---

### 🎓 What I Learned

Building this from scratch taught me:
- How adversarial prompt engineering works in practice
- The difference between keyword-based and LLM-based safety evaluation
- Why small models behave unpredictably under edge-case attacks
- How to build production-grade Python APIs with streaming support
- That security and AI are no longer separate fields — they are one

---

## 📄 License

MIT License — free to use, modify, and distribute.
