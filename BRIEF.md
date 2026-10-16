# BRIEF — analisador-pcap-anomalias

## Entregas

| Arquivo | Conteúdo |
|---|---|
| `pyproject.toml` | Metadados do projeto, dependências (scapy, pandas), entry point da CLI (`analisador-pcap`) e config do pytest (`pythonpath = ["src"]`, `testpaths = ["tests"]`). |
| `src/analisador_pcap_anomalias/__init__.py` | API pública e versão do pacote. |
| `src/analisador_pcap_anomalias/analisador.py` | Leitura de PCAP (`ler_pcap`) e estatísticas por protocolo em DataFrame pandas (`estatisticas_dataframe`). |
| `src/analisador_pcap_anomalias/detector.py` | Detecção de anomalias de volume (`detectar_volume`) e protocolo (`detectar_protocolo`) e `detectar_anomalias`. |
| `src/analisador_pcap_anomalias/relatorio.py` | Geração (`gerar_relatorio`) e gravação (`salvar_relatorio`) do relatório textual. |
| `src/analisador_pcap_anomalias/cli.py` | CLI argparse com `--limiar-volume`, `--limiar-protocolo` e `--saida`. |
| `src/analisador_pcap_anomalias/__main__.py` | Ponto de entrada `python -m analisador_pcap_anomalias`. |
| `tests/conftest.py` | Fixtures de PCAP sintético e determinístico (baixo tráfego, volume alto, protocolo dominante, vazio, com ARP). |
| `tests/test_analisador.py` | Testes de leitura de PCAP e estatísticas. |
| `tests/test_detector.py` | Testes de detecção de anomalias de volume e protocolo. |
| `tests/test_relatorio.py` | Testes de geração e gravação de relatório. |
| `tests/test_cli.py` | Teste da interface de linha de comando. |
| `README.md` | Documentação completa bilíngue PT-BR + EN. |
| `BRIEF.md` | Este arquivo. |

## Critérios de aceitação

- Relatório de anomalias de volume e protocolo: implementado em `detector.py` e `relatorio.py`.
- Testes que passem: 26 testes via pytest.
- README PT-BR + EN completo: título, descrição, como usar, testes, licença MIT, autor Kelvin Oliveira.

## Como verificar

1. Acesse o diretório do projeto:

   ```
   cd C:\Users\Kelvin\AppData\Local\Temp\opencode\github-staging\projects\analisador-pcap-anomalias
   ```

2. Crie e ative o ambiente virtual, e instale as dependências:

   ```
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install scapy pandas pytest
   ```

   No Linux/macOS, substitua a ativação por `source .venv/bin/activate`.

3. Rode o suíte de testes:

   ```
   .\.venv\Scripts\python.exe -m pytest -q
   ```

   Resultado esperado: `26 passed`.

4. Execute a CLI sobre um arquivo PCAP:

   ```
   .\.venv\Scripts\python.exe -m analisador_pcap_anomalias arquivo.pcap
   ```

## Resultado da verificação

- Comando de teste: `.\.venv\Scripts\python.exe -m pytest -q`
- Resultado dos testes: 26 passed
- Caminho do README: `C:\Users\Kelvin\AppData\Local\Temp\opencode\github-staging\projects\analisador-pcap-anomalias\README.md`
- Caminho do BRIEF: `C:\Users\Kelvin\AppData\Local\Temp\opencode\github-staging\projects\analisador-pcap-anomalias\BRIEF.md`
