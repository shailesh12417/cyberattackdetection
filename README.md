# 🛡️ CyberGuard — AI-Powered Cyber Attack Detection Platform

> Detection of Cyber Attacks in Network Traffic using Machine Learning Techniques

A production-style cybersecurity platform that classifies network traffic in real time using a multi-model ML pipeline, presents results on a premium interactive dashboard, and provides AI-assisted incident triage through an integrated SOC analyst chatbot.

---

## ✨ Key Features

- **Multi-Model Benchmarking** — Trains and compares 5 ML models (Random Forest, Decision Tree, Logistic Regression, SVM, ANN) and automatically selects the best performer
- **5 Attack Categories** — Detects Normal, DoS, Probe, R2L, and U2R traffic patterns with severity classification
- **AI Analyst Assistant** — LangChain + LangGraph powered chatbot with Groq LLM for incident summarization and remediation guidance
- **Premium Dashboard** — Glassmorphism UI with animated particle backgrounds, interactive Chart.js visualizations, and real-time threat monitoring
- **Dataset Profile Support** — Built-in column mapping for NSL-KDD, CICIDS2017, UNSW-NB15, and custom CSV datasets
- **Explainability** — Per-record feature contributions, attack descriptions, confidence scores, and mitigation steps
- **Live Monitoring** — Simulated real-time traffic analysis with streaming alerts and activity feed

---

## 📸 Dashboard Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Hero banner, animated stat cards, attack distribution chart, threat radar, traffic timeline, severity breakdown, recent alerts |
| **Analysis** | JSON/CSV traffic input with dataset profile selection and batch analysis |
| **Predictions** | Paginated table with label, confidence, severity, probabilities per record |
| **Investigation** | Incident headline, risk indicators, immediate actions, model insight narrative |
| **Benchmark** | Side-by-side comparison of all trained models (accuracy, precision, recall, F1, ROC-AUC) |

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI, Uvicorn, Pydantic Settings |
| **ML Pipeline** | scikit-learn (Random Forest, Decision Tree, Logistic Regression, SVM, MLP), XGBoost |
| **AI Assistant** | LangChain, LangGraph, ChatGroq (Llama 3.3 70B) |
| **Frontend** | HTML5, CSS3 (Glassmorphism + Dark Mode), Vanilla JavaScript, Chart.js |
| **Data Processing** | Pandas, NumPy |
| **Testing** | Pytest, FastAPI TestClient |
| **Deployment** | Docker (Python 3.12-slim) |

---

## 📁 Project Structure

```
college_project/
├── app/
│   ├── api/
│   │   └── routes.py              # API endpoints (health, train, predict, chat, benchmark)
│   ├── core/
│   │   ├── config.py              # Pydantic settings from .env
│   │   └── logging.py             # Logging configuration
│   ├── schemas/
│   │   └── prediction.py          # 16 Pydantic request/response models
│   ├── services/
│   │   ├── model_service.py       # Model loading, prediction, dashboard payload
│   │   ├── training_service.py    # Full ML pipeline with 5-model benchmark
│   │   └── assistant_service.py   # LangGraph AI assistant with fallback
│   └── main.py                    # FastAPI app entrypoint
├── frontend/
│   ├── assets/
│   │   ├── app.js                 # Dashboard logic, charts, API calls, live monitor
│   │   ├── styles.css             # Premium dark theme with glassmorphism
│   │   └── particles.js           # Matrix rain + neon particle animation
│   └── index.html                 # Single-page application (5 pages)
├── data/
│   ├── network_traffic_sample.csv # Bootstrap sample dataset (15 records)
│   └── extended_network_traffic.csv # Extended synthetic dataset (100 records)
├── scripts/
│   ├── generate_dataset.py        # Synthetic dataset generator
│   └── train_model.py             # CLI training script
├── artifacts/
│   ├── model.joblib               # Trained model pipeline
│   ├── metadata.json              # Training metadata and feature info
│   ├── report.json                # Full benchmark report
│   └── report.html                # Human-readable HTML report
├── tests/
│   └── test_api.py                # API integration tests
├── Dockerfile                     # Production container
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variable template
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- pip

### 1. Clone and set up the environment

```powershell
cd college_project
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure environment variables

```powershell
Copy-Item .env.example .env
```

Edit `.env` and add your Groq API key (optional — the assistant falls back to rule-based responses without it):

```env
APP_NAME="Cyber Attack Detection Platform"
APP_ENV="development"
APP_HOST=0.0.0.0
APP_PORT=8000
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
GROQ_API_KEY="your_groq_api_key_here"
GROQ_MODEL="llama-3.3-70b-versatile"
MODEL_PATH=artifacts/model.joblib
METADATA_PATH=artifacts/metadata.json
REPORT_PATH=artifacts/report.json
```

### 3. Start the server

```powershell
uvicorn app.main:app --reload
```

### 4. Open the dashboard

```
http://127.0.0.1:8000
```

### 5. Train the model

Either use the dashboard **"Prepare Model"** button, or train via CLI:

```powershell
python scripts/train_model.py
```

---

## 🔌 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/health` | Health check and model readiness status |
| `GET` | `/api/v1/model/status` | Model metadata, LLM availability, feature info |
| `GET` | `/api/v1/dataset/profiles` | Available dataset profile names and descriptions |
| `GET` | `/api/v1/report` | Full training report with metrics (JSON) |
| `GET` | `/api/v1/report/html` | Download HTML model comparison report |
| `GET` | `/api/v1/benchmark` | Benchmark comparison of all trained models |
| `POST` | `/api/v1/train` | Train the model on a dataset with selected profile |
| `POST` | `/api/v1/predict` | Classify network records from JSON payload |
| `POST` | `/api/v1/predict/csv` | Classify network traffic from uploaded CSV (≤10MB) |
| `POST` | `/api/v1/chat` | Conversational security assistant |

### Example: Predict Request

```json
POST /api/v1/predict
{
  "records": [
    {
      "duration": 0,
      "src_bytes": 0,
      "dst_bytes": 0,
      "count": 240,
      "srv_count": 12,
      "same_srv_rate": 0.05,
      "diff_srv_rate": 0.87,
      "dst_host_count": 255,
      "dst_host_srv_count": 17,
      "protocol_type": "tcp",
      "service": "smtp",
      "flag": "S0"
    }
  ],
  "explain": true
}
```

---

## 🧠 ML Pipeline

### Feature Engineering

The pipeline derives 6 additional features from the raw network flow data:

| Feature | Formula | Purpose |
|---------|---------|---------|
| `total_bytes` | src_bytes + dst_bytes | Total traffic volume |
| `byte_ratio` | src_bytes / (dst_bytes + 1) | Asymmetry in traffic direction |
| `connection_pressure` | count + srv_count + dst_host_count | Connection flooding indicator |
| `service_diversity` | diff_srv_rate − same_srv_rate | Service scanning signal |
| `host_service_balance` | dst_host_srv_count / (dst_host_count + 1) | Host targeting pattern |
| `is_zero_payload` | (src_bytes + dst_bytes) == 0 | Empty probe detection |

### Preprocessing

- **Numeric features**: Median imputation → Robust scaling
- **Categorical features** (protocol_type, service, flag): Mode imputation → One-hot encoding

### Model Catalog

| Model | Configuration |
|-------|--------------|
| Random Forest | 300 trees, max_depth=18, balanced class weights |
| Decision Tree | max_depth=12, balanced class weights |
| Logistic Regression | max_iter=1500, balanced class weights |
| SVM (RBF kernel) | probability=True, balanced class weights |
| ANN (MLP) | Hidden layers (96, 48), ReLU, 600 epochs |

The best model is automatically selected based on the highest weighted F1-score.

### Attack Severity Mapping

| Category | Severity | Description |
|----------|----------|-------------|
| `normal` | 🟢 Low | Legitimate traffic |
| `probe` | 🟡 Medium | Reconnaissance and scanning |
| `dos` | 🟠 High | Denial-of-service flooding |
| `r2l` | 🔴 Critical | Remote-to-local intrusion |
| `u2r` | 🔴 Critical | Privilege escalation |

---

## 🤖 AI Assistant

The platform includes a **SOC Analyst Assistant** powered by LangGraph state machines:

- **Analysis Graph**: Summarizes prediction results and generates remediation steps
- **Chat Graph**: Conversational interface for security questions, model behavior, and mitigation guidance
- **LLM Backend**: ChatGroq with Llama 3.3 70B Versatile
- **Fallback Mode**: Rule-based responses and a built-in glossary when no API key is configured

---

## 🐳 Docker Deployment

```powershell
docker build -t cyberguard .
docker run -p 8000:8000 --env-file .env cyberguard
```

---

## 🧪 Running Tests

```powershell
pytest tests/ -v
```

Tests cover:
- Health endpoint
- Train and benchmark flow
- Prediction endpoint with dashboard insights
- CSV upload with invalid column validation
- Chat endpoint with DoS attack query

---

## 📊 Dataset Profiles

The platform supports multiple dataset formats through automatic column mapping:

| Profile | Description |
|---------|-------------|
| `custom` | User-supplied CSV with canonical columns |
| `sample` | Built-in bootstrap sample dataset |
| `nsl-kdd` | NSL-KDD style feature mapping |
| `cicids2017` | CICIDS2017 style feature mapping |
| `unsw-nb15` | UNSW-NB15 style feature mapping |

You can replace the default dataset with any CSV containing a `label` column (or equivalent target column for the selected profile).

---

## 🔮 Future Enhancements

- Integrate real-world datasets (NSL-KDD, CICIDS2017, UNSW-NB15)
- Add authentication and role-based access control
- Store predictions in PostgreSQL for audit trail
- Add XGBoost to the model benchmark catalog
- Implement background jobs for scheduled retraining
- Add confusion matrix heatmap to HTML report
- Deploy on AWS with CI/CD pipeline

---

## 📄 License

This project was developed as a college project for academic purposes.
