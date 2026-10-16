"""Testes do módulo relatório: geração e gravação do relatório de anomalias."""

from __future__ import annotations

from pathlib import Path

from analisador_pcap_anomalias import Anomalia, gerar_relatorio, salvar_relatorio


def _anomalia_exemplo() -> Anomalia:
    return Anomalia(
        tipo="volume",
        alvo="10.0.0.99",
        protocolo=None,
        pacotes=24,
        bytes=36_000,
        limiar=20_000.0,
        gravidade="media",
        descricao="Host 10.0.0.99 excedeu o limiar de volume.",
    )


def test_relatorio_contem_cabecalho_e_totais() -> None:
    texto = gerar_relatorio([_anomalia_exemplo()], total_pacotes=50, total_bytes=50_000)
    assert "RELATÓRIO DE ANOMALIAS" in texto
    assert "Pacotes analisados: 50" in texto
    assert "Bytes totais: 50000" in texto


def test_relatorio_lista_anomalias() -> None:
    texto = gerar_relatorio([_anomalia_exemplo()], total_pacotes=50, total_bytes=50_000)
    assert "10.0.0.99" in texto
    assert "volume" in texto
    assert "36000" in texto


def test_relatorio_sem_anomalias_avisa() -> None:
    texto = gerar_relatorio([], total_pacotes=0, total_bytes=0)
    assert "Nenhuma anomalia detectada" in texto


def test_relatorio_gravidade_maiuscula() -> None:
    texto = gerar_relatorio([_anomalia_exemplo()], total_pacotes=1, total_bytes=1)
    assert "[MEDIA]" in texto


def test_salvar_relatorio_escreve_arquivo_utf8(tmp_path: Path) -> None:
    texto = gerar_relatorio([], total_pacotes=3, total_bytes=240)
    caminho = tmp_path / "relatorio.txt"
    salvar_relatorio(texto, caminho)
    assert caminho.read_text(encoding="utf-8") == texto
