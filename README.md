# 🕸️ LLM-Guided-Crawler-Secret-Hunter

> **High-Precision, Parallel Multi-Model LLM Web Reconnaissance Engine & Secret Hunter.**

`LLM-Guided-Crawler-Secret-Hunter` is an open-source cybersecurity reconnaissance tool that recursively crawls web targets, extracts client-side links and JavaScript dependencies deterministically, and audits code snippets in parallel across multiple LLMs to map attack surfaces, staging environments, internal API endpoints, debug flags, and developer leaks.

---

## 🌟 Key Features

* **Deterministic 0% Hallucination Extraction**: Uses `BeautifulSoup4` to pull 100% real `<a>` hrefs and `<script>` srcs before passing content to LLMs.
* **Parallel Multi-Model LLM Auditing**: Executes concurrent requests across multiple models (NVIDIA NIM / OpenAI API compatibility) using `ThreadPoolExecutor`.
* **Graphify Knowledge Engine**: Dynamically constructs an in-memory directed Knowledge Graph linking Page Nodes $\rightarrow$ Loaded Script Edges, Outgoing Links $\rightarrow$ AI Security Findings.
* **Staging & Leak Detection**: Filters UI noise (CSS, image media) to focus exclusively on staging subdomains (`staging.example.com`, `dev.*`), debug parameters (`DEBUG=true`, `cookietest`), and hidden API endpoints (`/r/*`, `/v1/*`).
* **Real-Time Live Markdown Reporting**: Appends discovered nodes to a structured `.md` report live as pages complete, preventing data loss on interruption.
* **Stateful Resume Engine**: Automatically parses existing Markdown reports to resume scans seamlessly without re-crawling visited URLs.

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/SSDEVIL108/LLM-Guided-Crawler-Secret-Hunter.git
cd LLM-Guided-Crawler-Secret-Hunter
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Set API Key
Set your NVIDIA NIM or OpenAI-compatible API key as an environment variable:

**On Linux/macOS:**
```bash
export NVIDIA_API_KEY="your_api_key_here"
```

**On Windows (PowerShell):**
```powershell
$env:NVIDIA_API_KEY="your_api_key_here"
```

---

## 🚀 Quick Usage

Run the crawler script directly:

```bash
python crawler.py
```

### Interactive Prompts:
1. **Target Website**: Enter target URL (e.g., `https://example.com`)
2. **Depth**: Set recursion depth (e.g., `1` for immediate links, `2` for deeper mapping).

---

## 🧠 System Architecture

```text
  ┌────────────────────────────────────────────────────────┐
  │                 Target URL Input                       │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │         Deterministic BS4 HTML & JS Parser             │
  │     (Extracts real links & script paths without LLM)   │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │       Knowledge Graph Engine (In-Memory Nodes)         │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │       Parallel Multi-Model LLM Security Auditor        │
  │  (Chunks source code & queries LLM ensemble concurrently)│
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │    Live Real-Time Markdown Report + Graphify ASCII     │
  └────────────────────────────────────────────────────────┘
```

---

## 📋 License

Distributed under the [MIT License](LICENSE).
