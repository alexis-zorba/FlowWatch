FlowWatch

Abstract

FlowWatch is a lightweight Windows-focused web application for real-time monitoring of network bandwidth and process I/O. Built with Python/Flask backend and vanilla JavaScript with Chart.js, it offers KPI cards, interactive charts, detailed tables, suspicious process detection by path, and JSON export. Easy to deploy and customize.

Features

Real-time monitoring of network Rx/Tx bandwidth.

Top processes by I/O delta and cumulative I/O.

KPI cards for at-a-glance metrics.

Interactive Chart.js graph of bandwidth history.

Suspicion detection: flags executables outside standard system directories.

JSON export of collected metrics.

Project Structure

flowwatch/
├── app.py              # Flask backend serving metrics and static files
├── static/
│   ├── index.html      # Single-page dashboard
│   └── LICENSE         # MIT License file
├── README.md           # This file
└── .gitignore          # Excludes __pycache__, venv, etc.

Getting Started

Clone the repository:

git clone https://github.com/<TUO_UTENTE>/flowwatch.git
cd flowwatch

Install dependencies:

pip install flask psutil

Run the application:

python app.py

Open your browser and navigate to http://127.0.0.1:5000.

Usage

Metrics auto-refresh every 2 seconds.

Click Export JSON to download the latest metrics file: stats_<timestamp>.json.

Suspicious processes are highlighted in light red.

.gitignore

__pycache__/
*.py[cod]
venv/
.env
stats_*.json

License

This project is licensed under the MIT License. See LICENSE for details.
