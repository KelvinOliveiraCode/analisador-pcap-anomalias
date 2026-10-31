# analisador-pcap-anomalias

**English** · [Português (Brasil)](README.md)

[![Python 3](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#) [![scapy](https://img.shields.io/badge/scapy-3776AB?style=flat-square)](#) [![pandas](https://img.shields.io/badge/pandas-150458?style=flat-square&logo=pandas)](#) [![pytest](https://img.shields.io/badge/pytest-26%20tests-0A9EDC?style=flat-square&logo=pytest)](#) [![MIT License](https://img.shields.io/badge/License-MIT-f4c430?style=flat-square)](LICENSE)

## What it is

**PCAP anomaly analyser**: reads a PCAP file (captured network traffic), extracts packets, computes per-protocol statistics and **detects anomalies** — hosts with excessive byte volumes or protocols with an abnormal packet count. It is an educational network-traffic analysis and security lab.

## Status

An educational lab, working and tested (26 tests).

## Features

- **PCAP reading** (`analisador.py`): `ler_pcap` — loads packets from a PCAP file and normalises them into `Pacote` dataclasses; `estatisticas_dataframe` builds a pandas DataFrame.
- **Detection** (`detector.py`): `detectar_anomalias` — volume per host (bytes) and atypical protocol (packets); returns a list of `Anomalia` with severity (high/medium/low).
- **Report** (`relatorio.py`): text output with sections per anomaly type.
- **CLI**: `analisador-pcap <pcap> [--limiar-volume] [--limiar-protocolo] [--saida]`.

## Architecture

An `analisador_pcap_anomalias` package with `analisador.py` (reading/statistics), `detector.py` (anomaly rules) and `relatorio.py` (output).

## Stack

- Python ≥ 3.10, scapy, pandas
- pytest (dev)

## Repository layout

```
analisador-pcap-anomalias/
├── pyproject.toml · BRIEF.md
├── src/analisador_pcap_anomalias/
│   ├── analisador.py   # PCAP reading + statistics
│   ├── detector.py     # anomaly detection
│   ├── relatorio.py    # text output
│   └── cli.py          # CLI
├── tests/              # 26 tests
└── LICENSE             # MIT
```

## Prerequisites and installation

```bash
pip install -e .
```

## How to run

```bash
analisador-pcap capture.pcap
analisador-pcap capture.pcap --limiar-volume 500000 --limiar-protocolo 50 --saida report.txt
```

## Tests and quality

```bash
PYTHONPATH=src python -m pytest tests/
# 26 passed
```

## Technical decisions and trade-offs

- Scapy + pandas: a mature combination for traffic analysis; pandas enables fast aggregation but adds a dependency.
- Simple threshold-based anomalies: transparent and tunable; no ML or advanced heuristics.

## Known limitations

- Offline analysis (saved PCAP), not real-time.
- Detection by volume/protocol only; no payload analysis, signatures or fine temporal correlation.

## Development process

An individual project by Kelvin Oliveira, built with orchestrated AI agents and reviewed by the author.

## License and author

MIT — Copyright (c) 2026 Kelvin Rebelo de Oliveira. Author: [Kelvin Oliveira](https://github.com/KelvinOliveiraCode) · [Portfolio](https://kelvinoliveiracode.github.io/portfolio/)
