"""Testes da interface de linha de comando."""

from __future__ import annotations

from analisador_pcap_anomalias.cli import main


def test_cli_executa_e_imprime_relatorio(pcap_baixo_traffico, capsys) -> None:
    codigo = main(
        [
            str(pcap_baixo_traffico),
            "--limiar-volume",
            "1000000",
            "--limiar-protocolo",
            "100",
        ]
    )
    assert codigo == 0
    capturado = capsys.readouterr()
    assert "RELATÓRIO DE ANOMALIAS" in capturado.out
    assert "Nenhuma anomalia detectada" in capturado.out
