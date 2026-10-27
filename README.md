# CyberLens

**A GNN-Based Multi-Layer Security Assessment Framework with Context-Aware Risk Correlation for Web Applications**

## What it does

Web security tools (SAST/DAST) report vulnerabilities as isolated alerts, even though issues amplify each other. For example, an XSS flaw is worse when CSP is missing and cookies lack `HttpOnly`. CyberLens scans a web application across seven security layers (network, SSL/TLS, HTTP headers, cookies, application/injection, API, and client-side/dependencies), normalizes the findings, and links them in a vulnerability graph. Each finding becomes a node, and chaining, shared-context and shared-root-cause relationships become edges. A Graph Convolutional Network (GCN) baseline and a Graph Attention Network (GAT) then use that graph structure to produce context-aware risk scores and a prioritized remediation report, instead of treating each issue by severity alone.

It was evaluated on deliberately vulnerable apps: OWASP Juice Shop, DVWA, WebGoat, Mutillidae II, bWAPP, NodeGoat, crAPI, DVGA, Security Shepherd and VulnerableApp.


## Project structure

| Folder | Purpose |
|---|---|
| `Scanners/` | Per-layer scanners (network, SSL/TLS, headers, cookies, API, dependencies, fingerprinting) that emit findings in a common schema. |
| `normalization/` | Converts raw scanner output into a uniform finding format (type, severity, asset, layer, CVE/CWE, evidence). |
| `graph/` | Builds the vulnerability graph with relationship rules and renders it as interactive HTML. |
| `features/` | Turns each graph node into a numeric feature vector for the models. |
| `pyg/` | Converts graphs into PyTorch Geometric data objects. |
| `models/` | GCN and GAT model definitions. |
| `scoring/` | Risk-target computation, priority tiers and project/score configuration. |
| `training/` | Trains and tunes the GCN/GAT risk-score and link-prediction models. |
| `linking/` | Suggests likely missing relationships between findings using the trained link model. |
| `reporting/` | Generates the ranked vulnerability priority reports (JSON and Markdown). |
| `api/` | FastAPI server and web dashboard for uploading a scan and viewing results. |
| `output/` | Raw scan outputs for each target application. |
| `outputs/` | Generated artifacts: normalized findings, graphs, features, PyG data, checkpoints, training results and reports. |
| `screenshots/` | Images used in this README. |

## Quick start

```bash
pip install -r requirements.txt
python run_pipeline.py --help      # run the full pipeline on a scan file
python api/server.py               # dashboard at http://127.0.0.1:8000
```
