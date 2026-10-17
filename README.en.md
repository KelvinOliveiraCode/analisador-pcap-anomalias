# analisador-pcap-anomalias

## Description

PCAP traffic analyzer written in Python with scapy and pandas. Reads a capture file (.pcap), extracts IP packets, aggregates traffic by host and protocol, and detects volume and protocol anomalies based on configurable thresholds. Prints a textual report to the terminal and can save it to a UTF-8 file. Packets without an IP layer (for example, ARP) are ignored.

## Stack

- Python 3.10+
- scapy>=2.5.0 — PCAP reading
- pandas>=2.0 — per-protocol statistics
- pytest — tests

## Installation

Create a virtual environment and install the dependencies:

```
python -m venv .venv
.venv\Scripts\Activate.ps1      # Windows
source .venv/bin/activate       # Linux/macOS
pip install scapy pandas pytest
```

Install the package in editable mode (optional):

```
pip install -e .
```

## Usage

Run the analysis over a PCAP file:

```
python -m analisador_pcap_anomalias captura.pcap
```

With custom thresholds and report saved to a file:

```
python -m analisador_pcap_anomalias captura.pcap \
  --limiar-volume 500000 --limiar-protocolo 50 --saida relatorio.txt
```

Default thresholds: `--limiar-volume` of 1000000 bytes per host and `--limiar-protocolo` of 100 packets per protocol. The program prints the report to the terminal and exits with code 0. With `--saida`, it writes the same content to a UTF-8 file. After installing the package, the `analisador-pcap` command is also available.

Example program output:

```
RELATÓRIO DE ANOMALIAS — PCAP
========================================
Pacotes analisados: 120
Bytes totais: 180000

Anomalias encontradas: 2

[MEDIA] volume: 10.0.0.99 (pacotes=24, bytes=36000, limiar=20000)
    Host 10.0.0.99 excedeu o limiar de volume (36000 bytes > 20000).

[ALTA] protocolo: TCP (pacotes=40, bytes=4000, limiar=10)
    Protocolo TCP excedeu o limiar de pacotes (40 > 10).

Fim do relatório.
```

## Anomaly report

- volume: host whose total bytes as source and destination exceed `--limiar-volume`.
- protocol: protocol whose packet count exceeds `--limiar-protocolo`.
- severity: low when the value exceeds the threshold by less than 2x, medium between 2x and 5x, high from 5x onward. Proportional to how much the value exceeds the threshold.

## Tests

```
pytest
```

All tests generate their own synthetic and deterministic PCAPs with scapy; no external capture files are needed.

## License

MIT License

Copyright (c) 2026 Kelvin Oliveira

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Author

Kelvin Oliveira
