# analisador-pcap-anomalias

## Descrição / Description

Analisador de tráfego PCAP escrito em Python com scapy e pandas. Lê um arquivo de captura (.pcap), extrai os pacotes IP, agrega o tráfego por host e protocolo, e detecta anomalias de volume e de protocolo com base em limiares configuráveis. Gera um relatório textual no terminal e pode gravá-lo em arquivo UTF-8.

PCAP traffic analyzer written in Python with scapy and pandas. Reads a capture file (.pcap), extracts IP packets, aggregates traffic by host and protocol, and detects volume and protocol anomalies based on configurable thresholds. Prints a textual report to the terminal and can save it to a UTF-8 file.

## Stack

- Python 3.10+
- scapy — leitura de PCAP / PCAP reading
- pandas — estatísticas por protocolo / per-protocol statistics
- pytest — testes / tests

## Como usar / How to use

Crie um ambiente virtual e instale as dependências:

```
python -m venv .venv
.venv\Scripts\Activate.ps1      # Windows
source .venv/bin/activate       # Linux/macOS
pip install scapy pandas pytest
```

Instale o pacote em modo editável (opcional):

```
pip install -e .
```

Rode a análise sobre um arquivo PCAP:

```
python -m analisador_pcap_anomalias captura.pcap
```

Com limiares personalizados e relatório gravado em arquivo:

```
python -m analisador_pcap_anomalias captura.pcap \
  --limiar-volume 500000 --limiar-protocolo 50 --saida relatorio.txt
```

O programa imprime o relatório no terminal e encerra com código 0. Com `--saida`, grava o mesmo conteúdo em um arquivo UTF-8.

Exemplo de saída do programa:

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

## Como executar os testes / How to run tests

```
pytest
```

Todos os testes geram seus próprios PCAPs sintéticos com scapy; não são necessários arquivos de captura externos.

All tests generate their own synthetic PCAPs with scapy; no external capture files are needed.

## Relatório de anomalias / Anomaly report

- volume: host cuja soma de bytes (como origem e destino) ultrapassa `--limiar-volume`.
- protocolo: protocolo cuja contagem de pacotes ultrapassa `--limiar-protocolo`.
- gravidade: baixa, media ou alta, proporcional ao quanto o valor excede o limiar.

- volume: host whose total bytes (as source and destination) exceed `--limiar-volume`.
- protocolo: protocol whose packet count exceeds `--limiar-protocolo`.
- severity: baixa, media, or alta, proportional to how much the value exceeds the threshold.

## Licença / License

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

## Autor / Author

Kelvin Oliveira
