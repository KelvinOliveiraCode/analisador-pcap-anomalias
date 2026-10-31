# analisador-pcap-anomalias

[English](README.en.md) · **Português (Brasil)**

[![Python 3](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#) [![scapy](https://img.shields.io/badge/scapy-3776AB?style=flat-square)](#) [![pandas](https://img.shields.io/badge/pandas-150458?style=flat-square&logo=pandas)](#) [![pytest](https://img.shields.io/badge/pytest-26%20testes-0A9EDC?style=flat-square&logo=pytest)](#) [![MIT License](https://img.shields.io/badge/License-MIT-f4c430?style=flat-square)](LICENSE)

## O que é

**Analisador de anomalias em PCAP**: lê um arquivo PCAP (tráfego de rede capturado), extrai pacotes, calcula estatísticas por protocolo e **detecta anomalias** — hosts com volume excessivo de bytes ou protocolos com número anormal de pacotes. É um laboratório educacional de análise de tráfego e segurança de redes.

## Status

Laboratório educacional funcional e testado (26 testes).

## Funcionalidades

- **Leitura de PCAP** (`analisador.py`): `ler_pcap` — carrega pacotes de um arquivo PCAP e os normaliza em dataclasses `Pacote`; `estatisticas_dataframe` monta um DataFrame pandas.
- **Detecção** (`detector.py`): `detectar_anomalias` — volume por host (bytes) e protocolo atípico (pacotes); retorna lista de `Anomalia` com gravidade (alta/média/baixa).
- **Relatório** (`relatorio.py`): saída textual com seções por tipo de anomalia.
- **CLI**: `analisador-pcap <pcap> [--limiar-volume] [--limiar-protocolo] [--saida]`.

## Arquitetura

Pacote `analisador_pcap_anomalias` com `analisador.py` (leitura/estatísticas), `detector.py` (regras de anomalia) e `relatorio.py` (saída).

## Stack

- Python ≥ 3.10, scapy, pandas
- pytest (dev)

## Estrutura do repositório

```
analisador-pcap-anomalias/
├── pyproject.toml · BRIEF.md
├── src/analisador_pcap_anomalias/
│   ├── analisador.py   # leitura de PCAP + estatísticas
│   ├── detector.py     # detecção de anomalias
│   ├── relatorio.py    # saída textual
│   └── cli.py          # CLI
├── tests/              # 26 testes
└── LICENSE             # MIT
```

## Pré-requisitos e instalação

```bash
pip install -e .
```

## Como executar

```bash
analisador-pcap captura.pcap
analisador-pcap captura.pcap --limiar-volume 500000 --limiar-protocolo 50 --saida relatorio.txt
```

## Testes e qualidade

```bash
PYTHONPATH=src python -m pytest tests/
# 26 passed
```

## Decisões técnicas e trade-offs

- Scapy + pandas: combinação madura para análise de tráfego; pandas permite agregações rápidas mas adiciona dependência.
- Anomalias por limiares simples: transparente e ajustável; sem ML nem heurísticas avançadas.

## Limitações conhecidas

- Análise offline (PCAP salvo), não em tempo real.
- Detecção por volume/protocolo apenas; sem análise de payload, assinaturas ou correlação temporal fina.

## Processo de desenvolvimento

Projeto individual de Kelvin Oliveira, construído com agentes de IA orquestrados e revisado pelo autor.

## Licença e autor

MIT — Copyright (c) 2026 Kelvin Rebelo de Oliveira. Autor: [Kelvin Oliveira](https://github.com/KelvinOliveiraCode) · [Portfólio](https://kelvinoliveiracode.github.io/portfolio/)
